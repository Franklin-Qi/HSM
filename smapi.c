
/*********************************************************************/
/* 文 件 名：  smapi.c                                               */
/* 版 本 号：  v1.1                                                  */
/* 所 有 者：                                                        */
/* 版    权：  Union Beijing                                         */
/* 功    能：  农行ICCM_密钥安全系统_第05号_加密机接口（国密）api      */
/* 维护记录： 1. 2008-6-11 by  Liwb                                  */
/*           2. 2008-12-11 by xusj                                   */
/*           3. 2012-07-11 by zhangx                                 */
/*           4. 2017-03-07 by zhaomx                                 */
/*********************************************************************/

#include "smapi.h"
#include "type.h"
#include "net.h"
#include "util.h"
#include "error.h"
#include "dump.h"
#include "sockpub.h"

#define	_HRTEST 1
#undef _HRTEST

#ifndef	_DEBUG
#define	_DEBUG	1
#endif
#define MDK_AC    0
#define MDK_ENC   1
#define MDK_MAC   2

#define debug     1
#define CBCIVLEN  8

#define COM_ENCRYPT    1
#define COM_DECRYPT    0
#define MAX_SIZE       2048

#define DES_ECB		0
#define DES_CBC		1

#define SM4        '1'
#define SM1        '2'
#define DES3       '3'
#define AES        '4'
#define DES2       '5'
#define DES1       '6'

#define ENC        '1'
#define DEC        '0'
#define ECB        '0'
#define CBC        '1'
#define FILL_80_N  '1'
#define FILL_80    '2'
#define FILL_00_N  '3'
#define FILL_00    '4'
#define FILL_x923  '5'

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

/* add by xusj 20081211 */
char            ip[15 + 1];
int             port;
/* xusj add end */

/* add by lisq 20120112 */
int		gUnionTimeout;
/* add by lisq 20120112 end */

UINT         unTimeout_ABC;
static int SEC_TIMEOUT = 0;

u8 ascii_table[16] =
{
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
};

int expiredate = 0;

void int2str(int len, u8 *a)
{
    u8 uq, ub, us, ug;

    uq =  len/1000;
    ub = len/100 - uq*10;
    us = len/10 -uq*100 -ub*10;
    ug = len - uq*1000 -ub*100 - us*10;
    a[0] = uq + 0x30;
    a[1] = ub + 0x30;
    a[2] = us + 0x30;
    a[3] = ug + 0x30;

    return;
}

void hex2asc(u8 dat, u8 **new)
{
    **new = ascii_table[dat >> 4];
    *new += 1;
    **new = ascii_table[dat & 0x0f];
    *new += 1;
}

int asc2hex(u8 dat, u8 *new)
{
    if ((dat >= '0') && (dat <= '9'))
        *new = dat - '0';
    else if ((dat >= 'A') && (dat <= 'F'))
        *new = dat - 'A' + 10;
    else if ((dat >= 'a') && (dat <= 'f'))
        *new = dat - 'a' + 10;
    else
        return -1;
    return 0;
}

void hex2str(u8 *read, u8 **write, int len)
{
    while (len--)
        hex2asc(*read++, write);
}

int str2hex(u8 *read, u8 *write, int len)
{
    u8 dat;

    while (len--)
    {
        if (asc2hex(*read++, &dat))
            return -1;
        *write = *write << 4 | dat;
        if (!(len & 1))
        {
            ++write;
        }
    }
    return 0;
}

int HSM_LINK(unsigned int nSock, int nMsgLen, u8 *pbSndBuf, u8 *pbRecvBuf)
{
    //int_dump("SEC_TIMEOUT", SEC_TIMEOUT);
    int ret;

    if (PSocketSendData(nSock, PKGHEAD_SIZE, pbSndBuf, nMsgLen, SEC_TIMEOUT) != 0)
    {
        return ERR_SNDDATA;
    }

    if ((ret = PSocketRecvData(nSock, PKGHEAD_SIZE, pbRecvBuf, SEC_TIMEOUT)) != 0 )
    {
    	//return ret;
        return ERR_RECVDATA;
    }
	if(pbRecvBuf[2] != '0' || pbRecvBuf[3] !='0'){
		return (pbRecvBuf[2]-'0') <<4 | (pbRecvBuf[3] - '0');
	}
	return 0;
	/*
    if (pbRecvBuf[0] != 'A')
    {
        if (pbRecvBuf[0]  != 0xA0 && pbRecvBuf[0] != 0xB0 && pbRecvBuf[0] != 0xC0)
            return pbRecvBuf[1];
        else
            return pbRecvBuf[9];
    }

    return 0;
    */
}

int key_hex2str(u8 *key , u8 keyalg , u8 *out)
{
	int ret = -1;
	u8 *tmpp;

	switch(keyalg){
		default:
			break;
		case DES1:
			tmpp = out;
			hex2str(key ,  &tmpp, 8);
			ret = 16;
			break;
		case DES2:
			tmpp = out+1;
			*out = 'X';
			hex2str(key ,  &tmpp, 16);
			ret = 33;
			break;
		case DES3:
			tmpp = out+1;
			*out = 'Y';
			hex2str(key ,  &tmpp, 24);
			ret = 49;
			break;
		case SM4:
			tmpp = out+1;
			*out = 'S';
			hex2str(key ,  &tmpp, 16);
			ret = 33;

			break;
	}
	return ret;
}

int key_str2hex(u8 *in , u8 *out , int*outlen)
{
	u8 flg;
	flg = in[0];
	switch(flg){
		case 'X':
		case 'S':
		case 'P':
		case 'L':
			*outlen = 16;
			return str2hex(in+1, out, 32);
			break;
		case 'Y':
			*outlen = 24;
			return str2hex(in+1, out, 48);
			break;
		default:
			*outlen = 8;
			return str2hex(in, out, 16);
			break;
	}
	return 0;
}

int pin2pinblock_nopan( u8 algflag ,char *plainpin,  u8 * pinblock)
{
	int pinlen , nTmpLen , i;
	u8 pin[16];
	pinlen = strlen(plainpin);

	if (pinlen <4 || pinlen > 12) {
		return ERR_PINLEN;
	}

	memset(pin, 0xFF, sizeof(pin));
	pin[0] = pinlen;
	if (pinlen % 2)
		nTmpLen = pinlen - 1;
	else
		nTmpLen = pinlen;
	for (i=0; i<nTmpLen; i+= 2)
	{
#ifndef SPEED
		if (!isdigit(plainpin[i]) || !isdigit(plainpin[i+1])) {
			return ERR_INPUT;
		}
#endif
		pin[i/2+1] = ((plainpin[i]-'0') << 4) | (plainpin[i+1]-'0');
	}
#ifdef DUMP
	data_dump("plain pinblock", pin, 16);
#endif

	if (pinlen % 2 != 0)
		pin[pinlen /2 +1] = ((plainpin[pinlen-1]- '0') <<4) | 0x0F;

	//
	//hex2str(pin, &pinblock, algflag == DES3 ? 8 : 16);
	memcpy(pinblock , pin , algflag == DES3 ? 8 : 16);

	return 0;

}

int SMAPIConnectSM(char *pszAddr, UINT nPort, UINT nTimeout,UINT *pnSock, char *szDeviceInfo)
{

    int       nRc;
    int       nCmd_len;
    int	      nSockid;
    char      cCmd_info[10];
    char      cRst_info[1000];
    char      cTmp[128];
    memset(cTmp,0,sizeof(cTmp));

    //parameters check  zhangx20120711
    if(nPort<0 || nTimeout<0 || !pszAddr || pszAddr[0]==0)
    {

	union_log("In SMAPIConnectSM::Input Parameter Error nPort=[%d] nTimeOut=[%d] pszAddr==NULL or pszAddr[0]==0");
	return CKR_PARAMETER_ERR;
    }
    if(NULL==pszAddr || NULL==pnSock || NULL==szDeviceInfo)
    {

        union_log("In SMAPIConnectSM::Point is NULL pszAddr,pnSock or szDeviceInfo");

	return CKR_PARAMETER_ERR;
    }
    if(strlen(pszAddr)>6&&strncmp((const char*)pszAddr,(const char*)"0.0.0.0",7)==0)
    {

        union_log("In SMAPIConnectSM::pszAddr Invalid ip=[%s]\n",pszAddr);
	return 4;
    }
   
    //parameters check end
  
    memset(cCmd_info, 0, sizeof(cCmd_info));
    memset(cRst_info, 0, sizeof(cRst_info));
#ifdef	_DEBUG
    union_log("In SMAPIConnectSM::HSM_IP = [%s],HSM_PORT = [%d]", pszAddr, nPort);
#endif

    gUnionTimeout = nTimeout;
    /* modify by chenf 20130606*/
    nSockid = UnionCreateSocketClient(pszAddr, nPort, nTimeout);
    if (nSockid <= 0)
    {
	union_err_log("In SMAPIConnectHSM::HsmCreateSocketClient failed! pszAddr=[%s] nPort=[%d] nTimeout=[%d] \n",pszAddr, nPort, nTimeout);
	return 4;
    }
    if(0!=SMAPIGetHsmStatus(nSockid,cTmp,szDeviceInfo))
    {
    	union_err_log("In SMAPIConnectHSM::HsmCreateSocketClient failed! pszAddr=[%s] nPort=[%d] nTimeout=[%d] \n",pszAddr, nPort, nTimeout);
	return 4;
    }
    *pnSock = nSockid;
    return CKR_SMAPI_OK;

}

int SMAPIDisconnectSM(UINT nSock)
{
    int nRc;

    //parameters check zhangx20120711
    if(UnionIsSocket(nSock)<1)
    {
    	union_err_log("In SMAPIDisconnectSM::UnionCloseSocket failed! nSock=[%d]\n",nSock);
    	//
			return 3;
    }
    //parameters check end

    nRc = UnionCloseSocket(nSock);
    if (nRc < 0) {
	    union_err_log("In SMAPIDisconnectSM::" \
		"UnionCloseSocket failed!");
	    return 4;
    }
    return CKR_SMAPI_OK;
}

int SMAPICmdNC(UINT nSock)
{

    int ret;
    char cRst_info[100];

    if(UnionIsSocket(nSock)<1)
    {
	return CKR_SOCKET_ERR;
    }
    memset(cRst_info, 0, sizeof cRst_info);

    ret = UnionHSMCmd(nSock, "11111111NC", 10, cRst_info, Timeout);
    if (ret < 0) {
	    printf("UnionHSMCmd err!ip=[%s],port=[%d]\n", ip, port);
	    return -1;
    }
    printf("succ cRst_info=[%s]\n", cRst_info);
    return 0;

}

int SMAPIGetHsmStatus(UINT nSock,  char szStatusCode[2], char szStatusMsg[200])
{
 
    int retCode=0;
    int nCmd_len;
    int nRc;
    int tl;
    char *p;
    char cCmd_info[500];
    char cRst_info[128];
    char cTmpBuf[2048];

    if(UnionIsSocket(nSock)<1)
    {
    	union_err_log("In SMAPIGetHsmStatus::nSock wrong! nSock=[%d]",nSock);
			return 1;
    }

    memcpy(szStatusCode,"NC",2) ;

    memset(cCmd_info, 0, sizeof(cCmd_info));
    memset(cRst_info, 0, sizeof(cRst_info));

    p = cCmd_info;
    memcpy(p, "NC", 2);
    p += 2;
    *p = 0;
    nCmd_len = p - cCmd_info;
    printf("cCmd_info:%s\n",cCmd_info);
#ifdef	_DEBUG
    union_log("In SMAPIGetHsmStatus::nCmd_len=[%d]," \
	"cCmd_info=[%s]", nCmd_len, cCmd_info);
#endif

    nRc = UnionHSMCmd(nSock, cCmd_info, nCmd_len, cRst_info, gUnionTimeout, &retCode);
    if (nRc < 0) {
	    union_err_log("In SMAPIGetHsmStatus::UnionHSMCmd wrong!");
	    return (3);
    }
#ifdef	_DEBUG
    union_log("In SMAPIGetHsmStatus::nRc=[%d]," \
	"cRst_info=[%s]", nRc, cRst_info);
#endif
    memcpy(szStatusCode,"00",2) ;
    memcpy(szStatusMsg,cRst_info,strlen(cRst_info));
    return 0;
}

int CheckACN(char * accon,int len)
{
    int i=0;
    if(len>19||len<12)
    {
	return -1;
    }
    
    for(i=0;i<len;i++)
    {
	if(accon[i]<'0'||accon[i]>'9')
	{
	    return -2;
	}
    }
    return 0;
}

int CheckPW(char * psw,int len)
{
    int i=0;
    if(len>12||len<4)
    {
	return -1;
    }
		
    for(i=0;i<len;i++)
    {
	if(psw[i]<'0'||psw[i]>'9')
	{
	    return -2;
	}
    }
    return 0;
}

int HexToInt(char source[],int len)
{
    char s[8];
    int i,m,temp=0,n;
    memset(s,0,sizeof(s));
    UnpackBCD(source,s,len*2);
    m=len*2;//
    for(i=0;i<m;i++)
    {
        if(s[i]>='A'&&s[i]<='F')//
         n=s[i]-'A'+10;
        else if(s[i]>='a'&&s[i]<='f')
         n=s[i]-'a'+10;
         else n=s[i]-'0';
        temp=temp*16+n;
    }
    return temp;
}

int CheckCmdReturn(int ret,char *funName,char *retstr)
{
    //printf("in check return ret=[%d] funname=[%s] retstr=[%s] \n",ret,funName,retstr);
    if(ret>0)return 0;
    switch(ret)
    {
	case -1:
	case -2:
		union_err_log("In [%s]::SOCKET RECIVE ERROR!",funName);
		return CKR_SENDFAIL_ERR;
                break;
	case -3:
		union_err_log("In [%s]::SOCKET RECIVE ERROR!",funName);
		return CKR_RCVTMOUT_ERR;
		break;
	case -4:
		union_err_log("In [%s]::HSM return not 00 return =[%s]parame error \n!",funName,retstr);
		return CKR_PARAMETER_ERR;
	defaut:
		break;		
    }
    return 0;	
}

/******************************************************  三未信安   ********************************************/
/**************************************************************************************************************
 * 6.1 PIN  转加密- 双主账号_ 国密版    （7.6.3转加密PIN-双主账号）（EN）
 * 功能描述: PIN 转加密-带主账号_国密版,（7.2.12 PIN 块从PIK1 到PIK2）.
 * 输入参数:
 *          nSock:                与加密机建立好链接的socket句柄
 *          Int nMode ：          转换类型. 1.2DES-->2DES,2.2DES-->SM4,3.SM4-->2DES,4.SM4-->SM4
 *	    char *pszSrcPan::     主帐号，ASCII 字符串，去掉校验位的最右12 个字符
 *	    int nSrcPanLen：      主帐号长度（字符数），13-19 位
 *	    char *pszDstPan::     主帐号，ASCII 字符串，去掉校验位的最右12 个字符
 *	    int nDstPanLen：      主帐号长度（字符数），13-19 位
 *          byte *pbSrcPinKey：   经HMK 加密的源Pik 的密文值，二进制数
 *          int nSrcPinKeyLen：   pbSrcPinKey 的长度，字节数
 *          byte *pbDestPinKey：  经HMK 加密的目的Pik 的密文值，二进制数
 *          int nDestPinKeyLen：  pbDestPinKey 的长度，字节数
 *          byte *pszSrcPinCipher 源Pin 密文，长度与源算法分组长度相等
 *
 * 输出参数:
 *          pbDestPinCipher:      目的Pin 密文,目的算法为DES 时长度为8 字节，目的算法为SM4 时长度为16 字节
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          2: 无效的密钥(密钥1或密钥2);
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9  其它错误
 *
 ***************************************************************************************/
int SMAPIConvertPinX98B_DoublePan(UINT nSock, int nMode, char *pszSrcPan, int nSrcPanLen, char *pszDstPan, int nDstPanLen, byte *pbSrcPinKey,
                                  int nSrcPinKeyLen, byte *pbDestPinKey, int nDestPinKeyLen, byte *pszSrcPinCipher, byte pbDes1tPinCipher[16])
{
	int rv = 0;
	unsigned char *pcReqCommandCode=(unsigned char *)"EN";
	unsigned char *pcResAckCode=(unsigned char *)"EO00";
	unsigned char  pbReqParas[MAX_BUFFER_SIZE]={0};
	unsigned int  uiReqParasLen=0;
	unsigned char pbResParas[MAX_BUFFER_SIZE]={0};
	unsigned int  uiResParasLen=MAX_BUFFER_SIZE;

	//返回参数
	unsigned char pbKey1WithID[50] = {0};
	unsigned char pbKey2WithID[50] = {0};
	unsigned int uiKey1WithIDLen = 0;
	unsigned int uiKey2WithIDLen = 0;

	//辅助参数
	unsigned int uiDivTimes = 0;		//源加密模式 和 目的加密模式 都写成ECB
	unsigned int uiSrcPinSize = 0;
	unsigned int uiDestPinSize = 0;
	unsigned int destPanFlag = 1;

	if (nMode<1 || nMode>4)
	{
		LOG(LOG_ERROR,nMode,"SMAPIConvertPinX98B_DoublePan->Mode");
		return ERR_INPUT_DATA;
	}
	if ((pszSrcPan==NULL) || GetNumCnt(pszSrcPan, (unsigned int *)&nSrcPanLen))
	{
		LOG(LOG_ERROR,ERR_INPUT_DATA,"SMAPIConvertPinX98B_DoublePan->SrcPan");
		return ERR_INPUT_DATA;
	}
	if ((pszDstPan==NULL) || GetNumCnt(pszDstPan, (unsigned int *)&nDstPanLen))
	{
		LOG(LOG_ERROR,ERR_INPUT_DATA,"SMAPIConvertPinX98B_DoublePan->DstPan");
		return ERR_INPUT_DATA;
	}
	if (pszSrcPinCipher==NULL)
	{
		LOG(LOG_ERROR,ERR_INPUT_DATA,"SMAPIConvertPinX98B_DoublePan->Cipher");
		return ERR_INPUT_DATA;
	}
	if (pbSrcPinKey==NULL)
	{
		LOG(LOG_ERROR,ERR_INPUT_DATA,"SMAPIConvertPinX98B_DoublePan->pbSrcPinKey");
		return ERR_INPUT_DATA;
	}
	if (pbDestPinKey==NULL)
	{
		LOG(LOG_ERROR,ERR_INPUT_DATA,"SMAPIConvertPinX98B_DoublePan->pbDestPinKey");
		return ERR_INPUT_DATA;
	}
	if (pbDes1tPinCipher==NULL)
	{
		LOG(LOG_ERROR,ERR_INPUT_DATA,"SMAPIConvertPinX98B_DoublePan->pbDes1tPinCipher");
		return ERR_INPUT_DATA;
	}
	if (nMode==1 || nMode==2)
	{
		uiSrcPinSize = 8;
	}
	else
	{
		uiSrcPinSize = 16;
	}
	if (nMode==1 || nMode==3)
	{
		uiDestPinSize = 8;
	}
	else
	{
		uiDestPinSize = 16;
	}
	if (nSrcPanLen<13 || nSrcPanLen>19)
	{
		LOG(LOG_ERROR,nSrcPanLen,"SMAPIConvertPinX98B_DoublePan->nSrcPanLen");
		return ERR_DATA_LEN;
	}
	if (nDstPanLen<13 || nDstPanLen>19)
	{
		LOG(LOG_ERROR,nDstPanLen,"SMAPIConvertPinX98B_DoublePan->nDstPanLen");
		return ERR_DATA_LEN;
	}
	switch(nSrcPinKeyLen)
	{
	case 8:
		Bin2Hex(pbSrcPinKey,nSrcPinKeyLen,(char *)pbKey1WithID);
		uiKey1WithIDLen = nSrcPinKeyLen*2;
		break;
	case 16:
		if (nMode==1 || nMode==2)
		{
			pbKey1WithID[0] = 'X';
		}
		else
		{
			pbKey1WithID[0] = 'S';
		}
		Bin2Hex(pbSrcPinKey,nSrcPinKeyLen,(char *)(pbKey1WithID + 1));
		uiKey1WithIDLen = nSrcPinKeyLen*2 +1;
		break;
	case 24:
		pbKey1WithID[0] = 'Y';
		Bin2Hex(pbSrcPinKey,nSrcPinKeyLen,(char *)(pbKey1WithID + 1));
		uiKey1WithIDLen = nSrcPinKeyLen*2 +1;
		break;
	default:
		LOG(LOG_ERROR,nSrcPinKeyLen,"SMAPIConvertPinX98B_DoublePan->nSrcPinKeyLen");
		return ERR_KEY_LEN;
		break;
	}

	switch(nDestPinKeyLen)
	{
	case 8:
		Bin2Hex(pbDestPinKey,nDestPinKeyLen,(char *)pbKey2WithID);
		uiKey2WithIDLen = nDestPinKeyLen*2;
		break;
	case 16:
		if (nMode==1 || nMode==3)
		{
			pbKey2WithID[0] = 'X';
		}
		else
		{
			pbKey2WithID[0] = 'S';
		}
		Bin2Hex(pbDestPinKey,nDestPinKeyLen,(char *)(pbKey2WithID + 1));
		uiKey2WithIDLen = nDestPinKeyLen*2 +1;
		break;
	case 24:
		pbKey2WithID[0] = 'Y';
		Bin2Hex(pbDestPinKey,nDestPinKeyLen,(char *)(pbKey2WithID + 1));
		uiKey2WithIDLen = nDestPinKeyLen*2 +1;
		break;
	default:
		LOG(LOG_ERROR,nDestPinKeyLen,"SMAPIConvertPinX98B_DoublePan->nDestPinKeyLen");
		return ERR_KEY_LEN;
		break;
	}

	uiReqParasLen = MESSAGE_HEADER_LEN;
	memcpy(pbReqParas + uiReqParasLen, pcReqCommandCode, 2);
	uiReqParasLen += 2;

	Int2Num((unsigned int)nMode,(char *)(pbReqParas + uiReqParasLen),1);
	uiReqParasLen += 1;

	memcpy(pbReqParas + uiReqParasLen,pbKey1WithID,uiKey1WithIDLen);
	uiReqParasLen += uiKey1WithIDLen;

	Int2Num(uiDivTimes,(char *)(pbReqParas + uiReqParasLen),1);
	uiReqParasLen += 1;

	memcpy(pbReqParas + uiReqParasLen,pbKey2WithID,uiKey2WithIDLen);
	uiReqParasLen += uiKey2WithIDLen;

	Int2Num(uiDivTimes,(char *)(pbReqParas + uiReqParasLen),1);
	uiReqParasLen += 1;

	Int2Num(1, (char *)(pbReqParas + uiReqParasLen),2);
	uiReqParasLen += 2;

	Int2Num(1, (char *)(pbReqParas + uiReqParasLen),2);
	uiReqParasLen += 2;

	Bin2Hex(pszSrcPinCipher,uiSrcPinSize,(char *)(pbReqParas+uiReqParasLen));
	uiReqParasLen += uiSrcPinSize<<1;

	memcpy(pbReqParas + uiReqParasLen, pszSrcPan+(nSrcPanLen-1-12), 12);
	uiReqParasLen += 12;

	Int2Num(destPanFlag, (char *)(pbReqParas + uiReqParasLen),1);
	uiReqParasLen += 1;

	memcpy(pbReqParas + uiReqParasLen, pszDstPan+(nDstPanLen-1-12), 12);
	uiReqParasLen += 12;

	//参数处理
	rv = SocketCommunication_Racal(nSock, pbReqParas, uiReqParasLen, pbResParas, &uiResParasLen, unTimeout_ABC);
	if (rv)
	{
		LOG(LOG_ERROR, rv, "SMAPIConvertPinX98B_DoublePan->SocketCommunication_Racal");
		return rv;
	}
	uiResParasLen = MESSAGE_HEADER_LEN ;
	if (memcmp(pbResParas + uiResParasLen,pcResAckCode,4) == 0)
	{
		uiResParasLen += 4;
		Hex2Bin((char *)(pbResParas + uiResParasLen),pbDes1tPinCipher,&uiDestPinSize);
		return ERR_OK;
	}
	else
	{
		rv = (pbResParas[MESSAGE_HEADER_LEN+2]-'0')*10+(pbResParas[MESSAGE_HEADER_LEN+3]-'0');
		if (memcmp(pbResParas+uiResParasLen,pcResAckCode,2) == 0)
		{
			LOG(LOG_ERROR, rv, "SMAPIConvertPinX98B_DoublePan");
			return rv;
		}
		else
		{
			LOG(LOG_ERROR, rv, "SMAPIConvertPinX98B_DoublePan");
			return ERR_OTHER;
		}
	}
}


/**************************************************************************************
 * 6.2 PIN  转加密_X98 到 IBM3624  （7.6.3转加密PIN-双主账号）（EN）
 * 功能描述: PIN 转加密_X98 到IBM3624（7.6.3 转加密PIN-双主账号）.
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          Int nMode ： 转换类型. 1: DES->IBM3624 2: 2DES->IBM3624 3: 3DES->IBM3624 4: SM4->IBM3624
 *	    int nX98Algo：X98 算法类型。1: X98A 2: X98B
 *	    char *pszSrcPan:: 当nX98Algo=1 时，pszPan = NULL, 当nX98Algo=2 时，源主帐号，ASCII 字符串，上层调用时传入
 *				全部的PAN 号，计算时使用PAN 号最右边的16 位
 *	    int nSrcPanLen：主帐号长度（字符数），13-19 位
 *	    char *pszDstPan:: 当nX98Algo=1 时，pszPan = NULL, 当nX98Algo=2 时，源主帐号，ASCII 字符串，上层调用时传入
 *		  	      全部的PAN 号，计算时使用PAN 号最右边的16 位
 *	    int nDstPanLen：主帐号长度（字符数），13-19 位
 *          byte *pbSrcPinKey：经HMK 加密的源Pik 的密文值，二进制数
 *          int nSrcPinKeyLen：pbSrcPinKey 的长度，字节数
 *          byte *pbDestPinKey：经HMK 加密的目的Pik 的密文值，二进制数
 *          int nDestPinKeyLen：pbDestPinKey 的长度，字节数
 *          byte *pszSrcPinCipher 源Pin密文，长度与nMode 定义的算法分组长度相等
 *
 * 输出参数:
 *          pbDestPinCipher: 目的Pin 密文,IBM3624 格式的Pin Offset，长度范围[1~12]
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          2: 无效的密钥(密钥1或密钥2);
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9: 其它错误
 *
 ***************************************************************************************/
int SMAPIConvertPinX98ToIBM3624(UINT nSock, int nMode, int nX98Algo, char *pszSrcPan, int nSrcPanLen, char *pszDstPan, int nDstPanLen, 
                                byte *pbPinKey, int nPinKeyLen, byte *pbIBM3624Key, int nIBM3624KeyLen, 
                                byte *pszSrcPinCipher, char pbDestPinCipher[13])
{
	int rv = 0;
	unsigned char *pcReqCommandCode=(unsigned char *)"EN";
	unsigned char *pcResAckCode=(unsigned char *)"EO00";
	unsigned char  pbReqParas[MAX_BUFFER_SIZE]={0};
	unsigned int  uiReqParasLen=0;
	unsigned char pbResParas[MAX_BUFFER_SIZE]={0};
	unsigned int  uiResParasLen=MAX_BUFFER_SIZE;

	//返回参数
	unsigned char pbKey1WithID[50] = {0};
	unsigned char pbKey2WithID[50] = {0};
	unsigned int uiKey1WithIDLen = 0;
	unsigned int uiKey2WithIDLen = 0;

	//辅助参数
	unsigned int uiDivTimes = 0;		
	unsigned int uiSrcPinSize = 0;
	unsigned int destPanFlag = 1;
	unsigned int srcPinBlockFormat = 1;
	unsigned int destPinBlockFormat = 50;
	int offsetLen = 0;

	if (pszDstPan == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIConvertPinX98ToIBM3624->pszDstPan");
		return ERR_INPUT_DATA;
	}
	if (pbPinKey == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIConvertPinX98ToIBM3624->pbPinKey");
		return ERR_INPUT_DATA;
	}
	if (pszSrcPinCipher == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIConvertPinX98ToIBM3624->pszSrcPinCipher");
		return ERR_INPUT_DATA;
	}

	if (nMode<1 || nMode>4)
	{
		LOG(LOG_ERROR,nMode,"SMAPIConvertPinX98ToIBM3624->Mode");
		return ERR_INPUT_DATA;
	}
	if (nX98Algo == 1)
	{
		srcPinBlockFormat = 7;//不带PAN
	}
	else if (nX98Algo == 2)
	{
		if ((pszSrcPan==NULL) || GetNumCnt(pszSrcPan, (unsigned int *)&nSrcPanLen))
		{
			LOG(LOG_ERROR,ERR_INPUT_DATA,"SMAPIConvertPinX98ToIBM3624->SrcPan");
			return ERR_INPUT_DATA;
		}

		if (nSrcPanLen<13 || nSrcPanLen>19)
		{
			LOG(LOG_ERROR,nSrcPanLen,"SMAPIConvertPinX98ToIBM3624->nSrcPanLen");
			return ERR_DATA_LEN;
		}
		srcPinBlockFormat = 1;//带PAN
	}
	else
	{
		LOG(LOG_ERROR,ERR_INPUT_DATA,"SMAPIConvertPinX98ToIBM3624->nX98Algo");
		return ERR_INPUT_DATA;
	}

	if ((pszDstPan==NULL) || GetNumCnt(pszDstPan, (unsigned int *)&nDstPanLen))
	{
		LOG(LOG_ERROR,ERR_INPUT_DATA,"SMAPIConvertPinX98ToIBM3624->DstPan");
		return ERR_INPUT_DATA;
	}

	if (nDstPanLen<16 || nDstPanLen>19)
	{
		LOG(LOG_ERROR,nDstPanLen,"SMAPIConvertPinX98ToIBM3624->nDstPanLen");
		return ERR_DATA_LEN;
	}

	if (pszSrcPinCipher==NULL)
	{
		LOG(LOG_ERROR,ERR_INPUT_DATA,"SMAPIConvertPinX98ToIBM3624->pszSrcPinCipher");
		return ERR_INPUT_DATA;
	}
	if (pbPinKey==NULL)
	{
		LOG(LOG_ERROR,ERR_INPUT_DATA,"SMAPIConvertPinX98ToIBM3624->pbPinKey");
		return ERR_INPUT_DATA;
	}

	if (pbIBM3624Key==NULL)
	{
		LOG(LOG_ERROR,ERR_INPUT_DATA,"SMAPIConvertPinX98ToIBM3624->pbIBM3624Key");
		return ERR_INPUT_DATA;
	}
	if (pbDestPinCipher==NULL)
	{
		LOG(LOG_ERROR,ERR_INPUT_DATA,"SMAPIConvertPinX98ToIBM3624->pbDestPinCipher");
		return ERR_INPUT_DATA;
	}
	if (nMode!=4)
	{
		uiSrcPinSize = 8;
	}
	else
	{
		uiSrcPinSize = 16;
	}

	switch(nPinKeyLen)
	{
	case 8:
		if (nMode != 1)
		{
			LOG(LOG_ERROR,nPinKeyLen,"SMAPIConvertPinX98ToIBM3624->nPinKeyLen");
			return ERR_KEY_LEN;
		}
		Bin2Hex(pbPinKey,nPinKeyLen,(char *)pbKey1WithID);
		uiKey1WithIDLen = nPinKeyLen*2;
		break;
	case 16:
		if (nMode==2)
		{
			pbKey1WithID[0] = 'X';
		}
		else if (nMode==4)
		{
			pbKey1WithID[0] = 'S';
		}
		else
		{
			LOG(LOG_ERROR,nPinKeyLen,"SMAPIConvertPinX98ToIBM3624->nPinKeyLen");
			return ERR_KEY_LEN;
		}
		Bin2Hex(pbPinKey,nPinKeyLen,(char *)(pbKey1WithID + 1));
		uiKey1WithIDLen = nPinKeyLen*2 +1;
		break;
	case 24:
		if (nMode != 3)
		{
			LOG(LOG_ERROR,nPinKeyLen,"SMAPIConvertPinX98ToIBM3624->nPinKeyLen");
			return ERR_KEY_LEN;
		}
		pbKey1WithID[0] = 'Y';
		Bin2Hex(pbPinKey,nPinKeyLen,(char *)(pbKey1WithID + 1));
		uiKey1WithIDLen = nPinKeyLen*2 +1;
		break;
	default:
		LOG(LOG_ERROR,nPinKeyLen,"SMAPIConvertPinX98ToIBM3624->nSrcPinKeyLen");
		return ERR_KEY_LEN;
		break;
	}

	switch(nIBM3624KeyLen)
	{
	case 8:
		Bin2Hex(pbIBM3624Key,nIBM3624KeyLen,(char *)pbKey2WithID);
		uiKey2WithIDLen = nIBM3624KeyLen*2;
		break;
	case 16:
		pbKey2WithID[0] = 'X';
		Bin2Hex(pbIBM3624Key,nIBM3624KeyLen,(char *)(pbKey2WithID + 1));
		uiKey2WithIDLen = nIBM3624KeyLen*2 +1;
		break;
	case 24:
		pbKey2WithID[0] = 'Y';
		Bin2Hex(pbIBM3624Key,nIBM3624KeyLen,(char *)(pbKey2WithID + 1));
		uiKey2WithIDLen = nIBM3624KeyLen*2 +1;
		break;
	default:
		LOG(LOG_ERROR,nIBM3624KeyLen,"SMAPIConvertPinX98ToIBM3624->nDestPinKeyLen");
		return ERR_KEY_LEN;
		break;
	}

	uiReqParasLen = MESSAGE_HEADER_LEN;
	memcpy(pbReqParas + uiReqParasLen, pcReqCommandCode, 2);
	uiReqParasLen += 2;

	if (nMode != 4)
	{
		nMode = 1;//该接口模式1-3都是DES
	}
	else
	{
		nMode = 3;
	}
	Int2Num((unsigned int)nMode,(char *)(pbReqParas + uiReqParasLen),1);
	uiReqParasLen += 1;

	memcpy(pbReqParas + uiReqParasLen,pbKey1WithID,uiKey1WithIDLen);
	uiReqParasLen += uiKey1WithIDLen;

	Int2Num(uiDivTimes,(char *)(pbReqParas + uiReqParasLen),1);
	uiReqParasLen += 1;

	memcpy(pbReqParas + uiReqParasLen,pbKey2WithID,uiKey2WithIDLen);
	uiReqParasLen += uiKey2WithIDLen;

	Int2Num(uiDivTimes,(char *)(pbReqParas + uiReqParasLen),1);
	uiReqParasLen += 1;

	Int2Num(srcPinBlockFormat, (char *)(pbReqParas + uiReqParasLen),2);//srcformat
	uiReqParasLen += 2;

	Int2Num(destPinBlockFormat, (char *)(pbReqParas + uiReqParasLen),2);//destformat
	uiReqParasLen += 2;

	Bin2Hex(pszSrcPinCipher,uiSrcPinSize,(char *)(pbReqParas+uiReqParasLen));
	uiReqParasLen += uiSrcPinSize<<1;
	if (srcPinBlockFormat==1)
	{
		memcpy(pbReqParas + uiReqParasLen, pszSrcPan+(nSrcPanLen-1-12), 12);
		uiReqParasLen += 12;
	}

	Int2Num(destPanFlag, (char *)(pbReqParas + uiReqParasLen),1);//destPanflag 16N
	uiReqParasLen += 1;

	memcpy(pbReqParas + uiReqParasLen, pszDstPan+nDstPanLen-16, 16);
	uiReqParasLen += 16;
	//参数处理
	rv = SocketCommunication_Racal(nSock, pbReqParas, uiReqParasLen, pbResParas, &uiResParasLen, unTimeout_ABC);
	if (rv)
	{
		LOG(LOG_ERROR, rv, "SMAPIConvertPinX98ToIBM3624->SocketCommunication_Racal");
		return rv;
	}
	uiResParasLen = MESSAGE_HEADER_LEN ;
	if (memcmp(pbResParas + uiResParasLen,pcResAckCode,4) == 0)
	{
		uiResParasLen += 4;

		while (*(pbResParas + uiResParasLen + offsetLen) != 'F')
		{
			offsetLen += 1;
		}
		memcpy(pbDestPinCipher,pbResParas + uiResParasLen,offsetLen);
		return ERR_OK;
	}
	else
	{
		rv = (pbResParas[MESSAGE_HEADER_LEN+2]-'0')*10+(pbResParas[MESSAGE_HEADER_LEN+3]-'0');
		if (memcmp(pbResParas+uiResParasLen,pcResAckCode,2) == 0)
		{
			LOG(LOG_ERROR, rv, "SMAPIConvertPinX98ToIBM3624");
			return rv;
		}
		else
		{
			LOG(LOG_ERROR, rv, "SMAPIConvertPinX98ToIBM3624");
			return ERR_OTHER;
		}
	}
}

/****************************************************************************************************************
1. 6.3 子密钥离散扩展1（主密钥加密子密钥）（7.6.15分散密钥并加密导出）  （EO）
2. 函数功能：
	将应用主密钥离散为子密钥使用传入的MasterKey 加密（DES）分散因子得到子密钥，再计算（DES）
	子密钥的校验值。返回被HMK 加密（DES）的密钥密文。
3. 输入参数：
	UINT nSock：连接的socket 句柄
	byte *pbMasterKey：被离散的应用主密钥(被HMK-3DES 加密)，二进制数，16 字节长。
	byte *pbFactor：分散因子，长度同主密钥
4. 输出参数：
	byte *pbSubKey：离散的子密钥的密文(被HMK-3DES 加密)，二进制数，16 字节长，
	char pszCheckValue[8]: 产生子密钥的效验值（DES 加密得到），是将CheckValue
	的前四个字节进行扩展，得到的8 个十六进制字符
5. 返回值：
	0： 执行成功
	1： 输入参数验证失败
	2： 无效的密钥(MasterKey)
	3： 向加密机发送数据失败
	4： 接收加密机数据超时
	5： 接收到的数据格式错
	9:  其他错误
*****************************************************************************************************************/
int SMAPIDisreteSubKeyExt1(UINT nSock, byte *pbMasterKey, byte *pbFactor, byte *pbSubKey, char pszCheckValue[8 + 1])
{
	int rv = 0;
	unsigned char *pcReqCommandCode=(unsigned char *)"EO1301X";
	unsigned char *pcResAckCode=(unsigned char *)"EP00";
	unsigned char  pbReqParas[MAX_BUFFER_SIZE]={0};
	unsigned int  uiReqParasLen=0;
	unsigned char pbResParas[MAX_BUFFER_SIZE]={0};
	unsigned int  uiResParasLen=MAX_BUFFER_SIZE;

	//返回参数
	unsigned int uiMasterKeyLen = 16;
	unsigned int uiFactorLen = 16;
	if(pbMasterKey==NULL)
	{
		LOG(LOG_ERROR,ERR_INPUT_DATA,"SMAPIDisreteSubKeyExt1->pbMasterKey");
		return ERR_INPUT_DATA;
	}
	if(pbFactor==NULL)
	{
		LOG(LOG_ERROR,ERR_INPUT_DATA,"SMAPIDisreteSubKeyExt1->pbFactor");
		return ERR_INPUT_DATA;
	}
	if(pbSubKey==NULL)
	{
		LOG(LOG_ERROR,ERR_INPUT_DATA,"SMAPIDisreteSubKeyExt1->pbSubKey");
		return ERR_INPUT_DATA;
	}
	if(pszCheckValue==NULL)
	{
		LOG(LOG_ERROR,ERR_INPUT_DATA,"SMAPIDisreteSubKeyExt1->pszCheckValue");
		return ERR_INPUT_DATA;
	}
	uiReqParasLen = MESSAGE_HEADER_LEN;
	memcpy(pbReqParas + uiReqParasLen, pcReqCommandCode, 7);
	uiReqParasLen += 7;

	Bin2Hex(pbMasterKey,uiMasterKeyLen,(char *)(pbReqParas + uiReqParasLen));
	uiReqParasLen += uiMasterKeyLen*2;

	memcpy(pbReqParas+uiReqParasLen,"11",2);
	uiReqParasLen += 2;

	Bin2Hex(pbFactor,uiFactorLen,(char *)(pbReqParas + uiReqParasLen));
	uiReqParasLen += uiFactorLen*2;

	rv = SocketCommunication_Racal(nSock, pbReqParas, uiReqParasLen, pbResParas, &uiResParasLen, unTimeout_ABC);

	if (rv)
	{
		LOG(LOG_ERROR, rv, "SMAPIDisreteSubKeyExt1->SocketCommunication_Racal");
		return rv;
	}
	uiResParasLen = MESSAGE_HEADER_LEN;
	if (memcmp(pbResParas + uiResParasLen,pcResAckCode,4) == 0)
	{
		uiResParasLen += 4;
		if(Num2Int((char *)(pbResParas + uiResParasLen),4)!=16)
		{
			LOG(LOG_ERROR, rv, "SMAPIDisreteSubKeyExt1->uiResDataLen");
			return ERR_DATA_LEN; 
		}
		uiResParasLen += 4;
		memcpy(pbSubKey,pbResParas + uiResParasLen,16);
		uiResParasLen += 16;

		memcpy( pszCheckValue, pbResParas+uiResParasLen, 8);
		pszCheckValue[8] = '\0';
		return ERR_OK;
	}
	else
	{
		rv = (pbResParas[MESSAGE_HEADER_LEN+2]-'0')*10+(pbResParas[MESSAGE_HEADER_LEN+3]-'0');
		if (memcmp(pbResParas+uiResParasLen,pcResAckCode,2) == 0)
		{
			LOG(LOG_ERROR, rv, "SMAPIDisreteSubKeyExt1");
			return rv;
		}
		else
		{
			LOG(LOG_ERROR, rv, "SMAPIDisreteSubKeyExt1");
			return ERR_OTHER;
		}
	}
}

/****************************************************************************************************************
1. 7.2 制卡密钥的导入（7.2.2 导入密钥）   （A6）
2. 函数功能：
	将制卡密钥(以KEK 加密)导入到加密机指定索引上
3. 输入参数：
	UINT nSock：连接的socket 句柄
	Int nKekIndex：传输主密钥的索引值(默认索引为257)
	byte *bKeyByKek：需要导入的制卡密钥(经过KEK 加密)
	int nKeyLen：制卡密钥的长度, 取值范围{8, 16, 24}
	char szCheckValue：制卡密钥的效验值， 8 个十六进制字符
	int nDestIndex：需要将密钥导入的索引位置，取值范围[258, 486]，该密钥默认的
	Tag 为3
4. 输出参数：无
5. 返回值：
	0： 执行成功
	1： 输入参数验证失败
	2： 无效的校验值
	3： 向加密机发送数据失败
	4： 接收加密机数据超时
	5： 接收到的数据格式错
	9:  其他错误
*****************************************************************************************************************/
int SMAPIImportKey(UINT nSock, int nKekIndex, byte *bKeyByKek, int nKeyLen, char szCheckValue[8 + 1],  int nDestIndex)
{
	int rv = 0;
	unsigned char *pcReqCommandCode=(unsigned char *)"A63";
	unsigned char *pcResAckCode=(unsigned char *)"A700";
	unsigned char  pbReqParas[MAX_BUFFER_SIZE]={0};
	unsigned int  uiReqParasLen=0;
	unsigned char pbResParas[MAX_BUFFER_SIZE]={0};
	unsigned int  uiResParasLen=MAX_BUFFER_SIZE;

	//辅助参数
	unsigned char pbKeyIndex1[50] = {0};						//传输密钥索引
	unsigned int uiKeyIndex1Len = 0;
	unsigned char pbKeyIndex2[50] = {0};						//目的密钥索引
	unsigned int uiKeyIndex2Len = 0;
	unsigned char pbKey[50] = {0};
	unsigned char pbKeyT[50] = {0};
	unsigned int uiKeyLen = 0;
	if(bKeyByKek == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIExportKey->bKeyByKek");
		return ERR_INPUT_DATA;
	}
	if (szCheckValue == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIExportKey->szCheckValue");
		return ERR_INPUT_DATA;
	}
	if (nKekIndex < 257 || nKekIndex > 486)
	{
		LOG(LOG_ERROR, rv, "SMAPIImportKey->nKekIndex");
		return ERR_KEY_INDEX;
	}
	if (nDestIndex < 258 || nDestIndex > 486)
	{
		LOG(LOG_ERROR, rv, "SMAPIImportKey->nDestIndex");
		return ERR_KEY_INDEX;
	}
	uiKeyIndex1Len = 5;
	memcpy(pbKeyIndex1, "K3",2);
	Int2Num(nKekIndex, (char *)(pbKeyIndex1+2), 3);				//传输密钥索引

	uiKeyIndex2Len = 5;
	memcpy(pbKeyIndex2, "K3",2);
	Int2Num(nDestIndex, (char *)(pbKeyIndex2+2), 3);			//目的密钥索引

	switch(nKeyLen)
	{
	case 8:
		pbKeyT[0] = 'Z';
		Bin2Hex(bKeyByKek,nKeyLen,(char *)pbKey);
		uiKeyLen = nKeyLen*2 ;
		break;
	case 16:
		pbKey[0] = 'X';
		pbKeyT[0] = 'X';
		Bin2Hex(bKeyByKek,nKeyLen,(char *)(pbKey + 1));
		uiKeyLen = nKeyLen*2 +1;
		break;
	case 24:
		pbKey[0] = 'Y';
		pbKeyT[0] = 'Y';
		Bin2Hex(bKeyByKek,nKeyLen,(char *)(pbKey + 1));
		uiKeyLen = nKeyLen*2 +1;
		break;
	default:
		LOG(LOG_ERROR, nKeyLen, "SMAPIImportKey->nKeyLen");
		return ERR_KEY_LEN;
		break;
	}

	uiReqParasLen = MESSAGE_HEADER_LEN;
	memcpy(pbReqParas + uiReqParasLen, pcReqCommandCode, 3);
	uiReqParasLen += 3;

	memcpy(pbReqParas + uiReqParasLen,pbKeyIndex1,uiKeyIndex1Len);
	uiReqParasLen += uiKeyIndex1Len;

	memcpy(pbReqParas + uiReqParasLen,pbKey,uiKeyLen);
	uiReqParasLen += uiKeyLen;

	memcpy(pbReqParas+uiReqParasLen,pbKeyT,1);
	uiReqParasLen += 1;

	memcpy(pbReqParas + uiReqParasLen,pbKeyIndex2,uiKeyIndex2Len);
	uiReqParasLen += uiKeyIndex2Len;

	memcpy(pbReqParas + uiReqParasLen,";",1);
	uiReqParasLen += 1;

	memcpy(pbReqParas + uiReqParasLen,szCheckValue,8);
	uiReqParasLen += 8;

	rv = SocketCommunication_Racal(nSock, pbReqParas, uiReqParasLen, pbResParas, &uiResParasLen, unTimeout_ABC);
	if (rv)
	{
		LOG(LOG_ERROR, rv, "SMAPIImportKey->SocketCommunication_Racal");
		return rv;
	}
	uiResParasLen = MESSAGE_HEADER_LEN ;
	if (memcmp(pbResParas + uiResParasLen,pcResAckCode,4) == 0)
	{		
		return ERR_OK;
	}
	else
	{
		rv = (pbResParas[MESSAGE_HEADER_LEN+2]-'0')*10+(pbResParas[MESSAGE_HEADER_LEN+3]-'0');
		if (memcmp(pbResParas+uiResParasLen,pcResAckCode,2) == 0)
		{
			LOG(LOG_ERROR, rv, "SMAPIImportKey");
			return rv;
		}
		else
		{
			LOG(LOG_ERROR, rv, "SMAPIImportKey");
			return ERR_OTHER;
		}
	}
}

/*********************************************************************************************************************
1: 7.3 分行数据加解密       （7.3.6 数据加解密）    （V2）
2. 函数功能： 调用加密机中指定索引位上存储的密钥对传入数据进行加解密
              注： 专供分行加解密数据使用，总行系统加解密使用数据库中存储的密钥
3. 输入参数： .
	UINT nSock：连接的socket 句柄
	int nEncrypt：加密、解密标志，1-加密；0-解密
	int nMode：加密模式，0-ECB；1-CBC
	注： CBC 模式的初始向量为8 字节全零二进制数"0000 0000 0000 0000"
	int nIndex：密钥索引位置，取值范围[257, 486]，其中257 为传输主密钥索引
	byte *bIndata：需要进行加密/解密的数据，二进制数，长度由nDataLen 指定
	int nDatalen：bIndata 的长度，取值范围[8，4096]且为8 的倍数
4. 输出参数：
	byte *bOutData：经过加密/解密之后的密文/明文数据，二进制数
5. 返回值：
        0： 执行成功
	1： 输入参数验证失败
	2： 无效的索引值
	3： 向加密机发送数据失败
	4： 接收加密机数据超时
	5： 接收到的数据格式错
	6： 指定索引位对应的密钥不存在
	9： 其他错误  
*******************************************************************************************************************/
int SMAPIEncryptData (UINT nSock, int nEncrypt, int nMode, int nIndex, byte *bIndata, int nDatalen, byte *bOutdata)
{
	int rv = 0;
	unsigned char *pcReqCommandCode=(unsigned char *)"V23";
	unsigned char *pcResAckCode=(unsigned char *)"V300";
	unsigned char  pbReqParas[MAX_BUFFER_SIZE*2]={0};
	unsigned int  uiReqParasLen=0;
	unsigned char pbResParas[MAX_BUFFER_SIZE*2]={0};
	unsigned int  uiResParasLen=MAX_BUFFER_SIZE*2;

	//辅助参数
	unsigned int uiPadMode = 1;			//不填充
	unsigned int uiKeyWithIDLen = 16;
	unsigned int uiDivTimes = 0;			//不分散
	unsigned char pbIV[16] = "0000000000000000";	
	unsigned int uiIVLen = 0;
	if (bIndata == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIEncryptData->bIndata");
		return ERR_INPUT_DATA;
	}
	if ((nIndex < 257)||(nIndex > 486))
	{
		LOG(LOG_ERROR, nIndex, "SMAPIEncryptData->nIndex");
		return ERR_DATA_LEN;
	}
	switch(nEncrypt)
	{
	case 0:
		nEncrypt = 0;
		break;
	case 1:
		nEncrypt = 1;
		break;
	default:
		LOG(LOG_ERROR, nEncrypt, "SMAPIEncryptData->nEncrypt");
		return ERR_OTHER;
	}
	switch(nMode)
	{
	case 0:
		break;
	case 1:
		uiIVLen = 16;
		break;
	default:
		LOG(LOG_ERROR, nMode, "SMAPIEncryptData->nMode");
		return ERR_OTHER;
	}
	if ((nDatalen%8 != 0)||(nDatalen < 8)||(nDatalen > 4096))
	{
		LOG(LOG_ERROR, nDatalen, "SMAPIEncryptData->bIndata");
		return ERR_DATA_LEN;
	}
	uiReqParasLen = MESSAGE_HEADER_LEN;
	memcpy(pbReqParas + uiReqParasLen, pcReqCommandCode, 3);
	uiReqParasLen += 3;

	memcpy(pbReqParas + uiReqParasLen,"K3",2);
	uiReqParasLen += 2;

	Int2Num(nIndex,(char *)pbReqParas + uiReqParasLen,3);
	uiReqParasLen += 3;

	Int2Num(uiDivTimes,(char *)pbReqParas + uiReqParasLen,1);
	uiReqParasLen += 1;

	Int2Num(nEncrypt,(char *)pbReqParas + uiReqParasLen,1);
	uiReqParasLen += 1;

	Int2Num(nMode,(char *)pbReqParas + uiReqParasLen,1);
	uiReqParasLen += 1;

	if (nMode == 1)
	{
		memcpy(pbReqParas + uiReqParasLen,pbIV,uiIVLen);
		uiReqParasLen += uiIVLen;
	}
	Int2Num(uiPadMode,(char *)pbReqParas + uiReqParasLen,1);
	uiReqParasLen += 1;

	Int2Num(nDatalen,(char *)pbReqParas + uiReqParasLen,4);
	uiReqParasLen += 4;

	memcpy(pbReqParas + uiReqParasLen, bIndata, nDatalen);
	uiReqParasLen += nDatalen;

	rv = SocketCommunication_Racal(nSock, pbReqParas, uiReqParasLen, pbResParas, &uiResParasLen, unTimeout_ABC);
	if (rv)
	{
		LOG(LOG_ERROR, rv, "SMAPIEncryptData->SocketCommunication_Racal");
		return rv;
	}

	uiResParasLen = MESSAGE_HEADER_LEN ;
	if(memcmp(pbResParas + uiResParasLen,pcResAckCode,4) == 0)
	{
		uiResParasLen += 4;
		uiKeyWithIDLen = Num2Int((char *)pbResParas + uiResParasLen, 4);
		uiResParasLen += 4;
		memcpy((char*)bOutdata, pbResParas + uiResParasLen, uiKeyWithIDLen);
		return ERR_OK;
	}
	else
	{
		rv = (pbResParas[MESSAGE_HEADER_LEN+2]-'0')*10+(pbResParas[MESSAGE_HEADER_LEN+3]-'0');
		if (memcmp(pbResParas+uiResParasLen,pcResAckCode,2) == 0)
		{
			LOG(LOG_ERROR, rv, "SMAPIEncryptData");
			return rv;
		}
		else
		{
			LOG(LOG_ERROR, rv, "SMAPIEncryptData");
			return ERR_OTHER;
		}
	}
}

/****************************************************************************************************************
1. 7.4 制卡密钥的导出（7.2.5 LMK 加密密钥）  (X2)
2. 函数功能：
	从加密机指定索引上将制卡密钥(以HMK 加密)导出(存入数据库)
3. 输入参数：
	UINT nSock：连接的socket 句柄
	int nIndex：需要将密钥导出的索引位置，取值范围[256, 486]，该密钥默认的Tag
	为3
4. 输出参数：
	byte *bKeyByKek：需要导出的制卡密钥(经过HMK 加密)
	int *pnKeyLen：制卡密钥的长度
	char szCheckValue：制卡密钥的效验值， 8 个十六进制字符
5. 返回值：
	0： 执行成功
	1： 输入参数验证失败
	2： 无效的索引值
	3： 向加密机发送数据失败
	4： 接收加密机数据超时
	5： 接收到的数据格式错
	9:  其他错误
*****************************************************************************************************************/
int SMAPIExportKey(UINT nSock, int nIndex, byte *bKeyByHMK, int *pnKeyLen, char szCheckValue[8 + 1])
{
	int rv = 0;
	unsigned char *pcReqCommandCode=(unsigned char *)"X23";   //KEK
	unsigned char *pcResAckCode=(unsigned char *)"X300";
	unsigned char  pbReqParas[MAX_BUFFER_SIZE]={0};
	unsigned int  uiReqParasLen=0;
	unsigned char pbResParas[MAX_BUFFER_SIZE]={0};
	unsigned int  uiResParasLen=MAX_BUFFER_SIZE;

	//辅助参数
	unsigned char pbKeyIndex[50] = {0};
	unsigned int uiKeyIndexLen = 0;
	unsigned char tmpKey[50] = {0};
	if (nIndex < 256 || nIndex > 486)
	{
		LOG(LOG_ERROR, rv, "SMAPIExportKey->nIndex");
		return ERR_KEY_INDEX;
	}

	uiKeyIndexLen = 5;
	memcpy(pbKeyIndex, "K3", 2);
	Int2Num(nIndex, (char *)(pbKeyIndex+2), 3);

	uiReqParasLen = MESSAGE_HEADER_LEN;
	memcpy(pbReqParas + uiReqParasLen, pcReqCommandCode, 3);
	uiReqParasLen += 3;

	memcpy(pbReqParas + uiReqParasLen,pbKeyIndex,uiKeyIndexLen);
	uiReqParasLen += uiKeyIndexLen;

	//参数处理
	rv = SocketCommunication_Racal(nSock, pbReqParas, uiReqParasLen, pbResParas, &uiResParasLen, unTimeout_ABC);
	if (rv)
	{
		LOG(LOG_ERROR, rv, "SMAPIExportKey->SocketCommunication_Racal");
		return rv;
	}
	uiResParasLen = MESSAGE_HEADER_LEN ;
	if (memcmp(pbResParas + uiResParasLen,pcResAckCode,4) == 0)
	{
		uiResParasLen += 4;

		if (pbResParas[uiResParasLen] == 'X')
		{
			*pnKeyLen = 16;
			memcpy(tmpKey,pbResParas + uiResParasLen+1,*pnKeyLen*2);
			uiResParasLen+=*pnKeyLen*2+1;
		} 
		else if (pbResParas[uiResParasLen] == 'Y')
		{
			*pnKeyLen = 24;
			memcpy(tmpKey,pbResParas + uiResParasLen+1,*pnKeyLen*2);
			uiResParasLen+=*pnKeyLen*2+1;
		}
		else
		{
			*pnKeyLen = 8;
			memcpy(tmpKey, pbResParas + uiResParasLen, *pnKeyLen*2);
			uiResParasLen+=*pnKeyLen*2;
		}

		Hex2Bin((char *)tmpKey,(unsigned char *) bKeyByHMK, (unsigned int*)pnKeyLen);
		memcpy( szCheckValue, pbResParas+uiResParasLen, 8);
		szCheckValue[8] = '\0';
		return ERR_OK;
	}
	else
	{
		rv = (pbResParas[MESSAGE_HEADER_LEN+2]-'0')*10+(pbResParas[MESSAGE_HEADER_LEN+3]-'0');
		if (memcmp(pbResParas+uiResParasLen,pcResAckCode,2) == 0)
		{
			LOG(LOG_ERROR, rv, "SMAPIExportKey");
			return rv;
		}
		else
		{
			LOG(LOG_ERROR, rv, "SMAPIExportKey");
			return ERR_OTHER;
		}
	}
}

/****************************************************************************************************************
1. 7.5 导出内部SM4 密钥_国密版（7.2.5LMK 加密密钥）  (X2)
2. 函数功能：
	从加密机指定索引上将制卡密钥(以HMK 加密)导出(存入数据库)
3. 输入参数：
	UINT nSock：连接的socket 句柄
	int nIndex：被导出密钥的索引位置，取值范围[256, 486]，该密钥默认的Tag 为3
4. 输出参数：
	byte *bKeyByHMK：需要导出的制卡密钥(经过HMK 加密)
	int *pnKeyLen：制卡密钥的长度
	char szCheckValue：制卡密钥的效验值， 8 个十六进制字符
5. 返回值：
	0： 执行成功
	1： 输入参数验证失败
	2： 无效的索引值
	3： 向加密机发送数据失败
	4： 接收加密机数据超时
	5： 接收到的数据格式错
	9:  其他错误
*****************************************************************************************************************/
int SMAPIExportKey_GM(UINT nSock, int nIndex,byte *bKeyByHMK, int *pnKeyLen, char szCheckValue[8 + 1])
{
	int rv = 0;
	unsigned char *pcReqCommandCode=(unsigned char *)"X21";
	unsigned char *pcResAckCode=(unsigned char *)"X300";
	unsigned char  pbReqParas[MAX_BUFFER_SIZE]={0};
	unsigned int  uiReqParasLen=0;
	unsigned char pbResParas[MAX_BUFFER_SIZE]={0};
	unsigned int  uiResParasLen=MAX_BUFFER_SIZE;

	//返回参数
	unsigned char pbKeyIndex[50] = {0};
	unsigned int uiKeyIndexLen = 0;

	//辅助参数
	unsigned char tmpKey[50] = {0};

	if (nIndex < 256 || nIndex > 486)
	{
		return 25;
	}

	uiKeyIndexLen = 5;
	memcpy(pbKeyIndex, "K3", 2);
	Int2Num(nIndex, (char *)(pbKeyIndex+2), 3);

	uiReqParasLen = MESSAGE_HEADER_LEN;
	memcpy(pbReqParas + uiReqParasLen, pcReqCommandCode, 3);
	uiReqParasLen += 3;

	memcpy(pbReqParas + uiReqParasLen,pbKeyIndex,uiKeyIndexLen);
	uiReqParasLen += uiKeyIndexLen;

	//参数处理
	rv = SocketCommunication_Racal(nSock, pbReqParas, uiReqParasLen, pbResParas, &uiResParasLen, unTimeout_ABC);
	if (rv)
	{
		LOG(LOG_ERROR, rv, "SMAPIExportKey_GM->SocketCommunication_Racal");
		return rv;
	}
	uiResParasLen = MESSAGE_HEADER_LEN ;
	if (memcmp(pbResParas + uiResParasLen,pcResAckCode,4) == 0)
	{
		uiResParasLen += 4;

		*pnKeyLen = 16;
		memcpy(tmpKey,pbResParas + uiResParasLen+1,*pnKeyLen*2);
		uiResParasLen+=*pnKeyLen*2+1;

		Hex2Bin((char *)tmpKey,(unsigned char *) bKeyByHMK, (unsigned int *)pnKeyLen);
		memcpy( szCheckValue, pbResParas+uiResParasLen, 8);
		szCheckValue[8] = '\0';
		return ERR_OK;
	}
	else
	{
		rv = (pbResParas[MESSAGE_HEADER_LEN+2]-'0')*10+(pbResParas[MESSAGE_HEADER_LEN+3]-'0');
		if (memcmp(pbResParas+uiResParasLen,pcResAckCode,2) == 0)
		{
			LOG(LOG_ERROR, rv, "SMAPIExportKey_GM");
			return rv;
		}
		else
		{
			LOG(LOG_ERROR, rv, "SMAPIExportKey_GM");
			return ERR_OTHER;
		}
	}
}

/****************************************************************************************************************
1. 6.4 子密钥离散扩展2（国密转加密子密钥）（7.6.15分散密钥并加密导出）   （EO）
2. 函数功能：
	将应用主密钥离散为卡子密钥或者会话子密钥，用传入的KEK-SM4 加密输出
	使用传入的MasterKey 加密（DES）分散因子得到子密钥，再计算（DES）
	子密钥的校验值。返回被KEK 加密（SM4）的密钥密文。
3. 输入参数：
	UINT nSock：连接的socket 句柄
	byte *pbKek：加密子密钥的KEK(被HMK 加密)，加密算法为SM4，二进制数，16 字节长。
	byte *pbMasterKey：被离散的应用主密钥(被HMK-3DES 加密)，二进制数，16 字节长。
	byte *pbFactor：分散因子，长度同主密钥
4. 输出参数：
	byte *pbSubKey：离散的子密钥的密文(被KEK-SM4 加密)，二进制数，16 字节长，
	char pszCheckValue[8]: 产生子密钥的效验值（DES 加密得到），是将CheckValue
	的前四个字节进行扩展，得到的8 个十六进制字符
5. 返回值：
	0： 执行成功
	1： 输入参数验证失败
	2： 无效的密钥(MasterKey、KEK)
	3： 向加密机发送数据失败
	4： 接收加密机数据超时
	5： 接收到的数据格式错
	9:  其他错误
*****************************************************************************************************************/
int SMAPIDisreteSubKeyExt2(UINT nSock, byte *pbKek, byte *pbMasterKey, byte *pbFactor, byte *pbSubKey, char pszCheckValue[8 + 1])
{
	int rv = 0;
	unsigned char *pcReqCommandCode=(unsigned char *)"EO2301X";
	unsigned char *pcResAckCode=(unsigned char *)"EP00";
	unsigned char  pbReqParas[MAX_BUFFER_SIZE]={0};
	unsigned int  uiReqParasLen=0;
	unsigned char pbResParas[MAX_BUFFER_SIZE]={0};
	unsigned int  uiResParasLen=MAX_BUFFER_SIZE;

	//返回参数
	char pbKey1WithID[50] = {0};
	char pbKey2WithID[50] = {0};
	char pbKey3WithID[50] = {0};
	unsigned int uiMasterKeyLen = 16;
	unsigned int uiFactorLen = 16;
	unsigned int uiKekLen = 16;
	//辅助参数
	if (pbMasterKey == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIDisreteSubKeyExt2->pbMasterKey");
		return ERR_INPUT_DATA;
	}
	if (pbKek == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIDisreteSubKeyExt2->pbKek");
		return ERR_INPUT_DATA;
	}
	if (pbFactor == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIDisreteSubKeyExt2->pbFactor");
		return ERR_INPUT_DATA;
	}
	if (pbSubKey == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIDisreteSubKeyExt2->pbKek");
		return ERR_INPUT_DATA;
	}
	if (pszCheckValue == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIDisreteSubKeyExt2->pszCheckValue");
		return ERR_INPUT_DATA;
	}
	uiReqParasLen = MESSAGE_HEADER_LEN;
	memcpy(pbReqParas + uiReqParasLen, pcReqCommandCode, 7);
	uiReqParasLen += 7;

	Bin2Hex(pbMasterKey,uiMasterKeyLen,pbKey1WithID);
	memcpy(pbReqParas + uiReqParasLen,pbKey1WithID,uiMasterKeyLen*2);
	uiReqParasLen += uiMasterKeyLen*2;

	memcpy(pbReqParas+uiReqParasLen,"11",2);
	uiReqParasLen += 2;

	Bin2Hex(pbFactor,uiFactorLen,pbKey2WithID);
	memcpy(pbReqParas + uiReqParasLen,pbKey2WithID,uiFactorLen*2);
	uiReqParasLen += uiFactorLen*2;

	memcpy(pbReqParas+uiReqParasLen,"1X",2);
	uiReqParasLen += 2;

	Bin2Hex(pbKek,uiKekLen,pbKey3WithID);
	memcpy(pbReqParas + uiReqParasLen,pbKey3WithID,uiKekLen*2);
	uiReqParasLen += uiKekLen*2;

	memcpy(pbReqParas+uiReqParasLen,"0",1);
	uiReqParasLen += 1;
	//参数处理
	rv = SocketCommunication_Racal(nSock, pbReqParas, uiReqParasLen, pbResParas, &uiResParasLen, unTimeout_ABC);
	if (rv)
	{
		LOG(LOG_ERROR, rv, "SMAPIDisreteSubKeyExt2->SocketCommunication_Racal");
		return rv;
	}
	uiResParasLen = MESSAGE_HEADER_LEN ;
	if (memcmp(pbResParas + uiResParasLen,pcResAckCode,4) == 0)
	{
		uiResParasLen += 4;
		if(Num2Int((char *)(pbResParas + uiResParasLen),4)!=16)
		{
			LOG(LOG_ERROR, rv, "SMAPIDisreteSubKeyExt2->uiResDataLen");
			return ERR_DATA_LEN; 
		}
		uiResParasLen += 4;
		memcpy(pbSubKey,pbResParas + uiResParasLen,16);
		uiResParasLen += 16;

		memcpy( pszCheckValue, pbResParas+uiResParasLen, 8);
		pszCheckValue[8] = '\0';
		return ERR_OK;
	}
	else
	{
		rv = (pbResParas[MESSAGE_HEADER_LEN+2]-'0')*10+(pbResParas[MESSAGE_HEADER_LEN+3]-'0');
		if (memcmp(pbResParas+uiResParasLen,pcResAckCode,2) == 0)
		{
			LOG(LOG_ERROR, rv, "SMAPIDisreteSubKeyExt2");
			return rv;
		}
		else
		{
			LOG(LOG_ERROR, rv, "SMAPIDisreteSubKeyExt2");
			return ERR_OTHER;
		}
	}

}

/****************************************************************************************************************
1. 8.2 数据转加密（7.3.5 数据转加密）    （VS）
2. 函数功能：
	将被decryptKeyIndex 索引指示的密钥加密的密文，转换为被密钥（encryptKey）加密的密文
3. 输入参数：
	UINT nSock：连接的socket 句柄
	Int decryptKeyIndex：解密密钥索引[257 486]。
	UINT decryptMech：解密密钥算法类型:
	decryptMech = 20 表示DES_ECB 算法
	decryptMech = 17 表示DES_CBC 算法
	decryptMech = 3 表示SM4_ECB 算法
	decryptMech = 4 表示SM4_CBC 算法
	decryptMech = 5 表示AES_ECB 算法（暂不支持）
	decryptMech = 6 表示AES_CBC 算法（暂不支持）
	char *encryptKey：经LMK 加密的加密密钥的密文值，16 进制ASCII 字符串。（例如：8 字节密钥，则该输入为16 个ASCII 字符串）
	UINT encryptMech：加密密钥算法类型：
	decryptMech = 20 表示DES_ECB 算法
	decryptMech = 17 表示DES_CBC 算法
	decryptMech = 3 表示SM4_ECB 算法
	decryptMech = 4 表示SM4_CBC 算法
	decryptMech = 5 表示AES_ECB 算法（暂不支持）
	decryptMech = 6 表示AES_CBC 算法（暂不支持）
	char *data：待处理数据，16 进制ASCII 字符串。
	char *decryptIV,：CBC 解密时的初始向量
	char *encryptIV,：CBC 加密时的初始向量
4. 输出参数：
	char *outData： 输出数据，16 进制ASCII 字符串。
5. 返回值： 
	0：成功
	其他：失败错误代码
*****************************************************************************************************************/
int SMAPIDecryptEncrypt(UINT nSock , int decryptKeyIndex, UINT decryptMech, char  *encryptKey, 
                        UINT encryptMech, char *data, char *decryptIV, char *encryptIV, 
                        char *outData)
{
	int rv = 0;
	unsigned char *pcReqCommandCode=(unsigned char *)"VS";
	unsigned char *pcResAckCode=(unsigned char *)"VT00";
	unsigned char  pbReqParas[MAX_BUFFER_SIZE]={0};
	unsigned int  uiReqParasLen=0;
	unsigned char pbResParas[MAX_BUFFER_SIZE]={0};
	unsigned int  uiResParasLen=MAX_BUFFER_SIZE;

	//辅助参数
	unsigned char ucKeyIndex1[16] = {0};
	unsigned int uiKeyIndex1Len = 0;
	unsigned char ucKey[64] = {0};
	unsigned int uiMode1 = 0;
	unsigned int uiKeyLen = 0;
	unsigned int uiMode2 = 0;
	unsigned int uiAlg1 = 0;
	unsigned int uiAlg2 = 0;
	unsigned int keyLen = 0;
	unsigned int decivLen = 0;
	unsigned int encivLen = 0;
	unsigned int uiInDataLen = 0;

	if (encryptKey == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIDecryptEncrypt->encryptKey");
		return ERR_INPUT_DATA;
	}
	if (data == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIDecryptEncrypt->data");
		return ERR_INPUT_DATA;
	}
	keyLen = (unsigned int)strlen((char*)encryptKey);

	uiInDataLen = (unsigned int)strlen((char*)data);
	switch(decryptMech)
	{
	case 20:
		uiMode1 = 3;
		uiAlg1 = 0;
		break;
	case 17:
		uiMode1 = 3;
		uiAlg1 = 1;
		break;
	case 3:
		uiMode1 = 1;
		uiAlg1 = 0;
		break;
	case 4:
		uiMode1 = 1;
		uiAlg1 = 1;
		break;
	default:
		LOG(LOG_ERROR, decryptMech, "SMAPIDecryptEncrypt->decryptMech");
		return ERR_INPUT_DATA;
		break;
	}
	switch(encryptMech)
	{
	case 20:
		uiMode2 = 3;
		uiAlg2 = 0;
		break;
	case 17:
		uiMode2 = 3;
		uiAlg2 = 1;
		break;
	case 3:
		uiMode2 = 1;
		uiAlg2 = 0;
		break;
	case 4:
		uiMode2 = 1;
		uiAlg2 = 1;
		break;
	default:
		LOG(LOG_ERROR, encryptMech, "SMAPIDecryptEncrypt->encryptMech");
		return ERR_INPUT_DATA;
		break;
	}
	if(decryptIV != NULL)
	{
		if (uiMode1 == 1)
		{
			decivLen = 32;
		} 
		else if(uiMode1 == 3)
		{
			decivLen = 16;
		}
	}
	if(encryptIV != NULL)
	{
		if (uiMode2 == 1)
		{
			encivLen = 32;
		} 
		else if(uiMode2 == 3  )
		{
			encivLen = 16;
		}
	}
	if (decryptKeyIndex < 257 || decryptKeyIndex >486)
	{
		LOG(LOG_ERROR, decryptKeyIndex, "SMAPIDecryptEncrypt->decryptKeyIndex");
		return ERR_KEY_INDEX;
	}

	if (encryptMech == 20 || encryptMech == 17)
	{ 
		if(keyLen != 16 && keyLen != 32 && keyLen != 48)
			return ERR_KEY_LEN;
	} 
	else
	{
		if(keyLen != 32)
			return ERR_KEY_LEN;
	}
	uiKeyIndex1Len = 5;
	memcpy(ucKeyIndex1, "K3",2);
	Int2Num(decryptKeyIndex,(char *)(ucKeyIndex1 + 2),3);
	switch(keyLen)
	{
	case 16:
		memcpy(ucKey,encryptKey,keyLen);
		uiKeyLen = keyLen;
		break;
	case 32:
		if (uiMode2 == 1 || uiMode2 == 3)
		{
			ucKey[0] = 'X';
		} 
		else
		{
			ucKey[0] = 'S';
		}
		memcpy(ucKey+1,encryptKey,keyLen);
		uiKeyLen = keyLen+1;
		break;
	case 48:
		ucKey[0] = 'Y';
		memcpy(ucKey+1,encryptKey,keyLen);
		uiKeyLen = keyLen+1;
		break;
	default:
		return ERR_KEY_LEN;
		break;
	}

	uiReqParasLen = MESSAGE_HEADER_LEN;
	memcpy(pbReqParas + uiReqParasLen, pcReqCommandCode, 2);
	uiReqParasLen += 2;

	Int2Num(uiMode1,(char *)(pbReqParas + uiReqParasLen),1);
	uiReqParasLen += 1;

	memcpy(pbReqParas + uiReqParasLen,ucKeyIndex1,uiKeyIndex1Len);
	uiReqParasLen += uiKeyIndex1Len;

	Int2Num(uiAlg1,(char *)(pbReqParas + uiReqParasLen),1);
	uiReqParasLen += 1;

	if (uiAlg1 == 1)
	{
		memcpy(pbReqParas + uiReqParasLen, decryptIV, decivLen);
		uiReqParasLen += decivLen;
	}

	Int2Num(uiMode2,(char *)(pbReqParas + uiReqParasLen),1);
	uiReqParasLen += 1;

	memcpy(pbReqParas + uiReqParasLen,ucKey,uiKeyLen);
	uiReqParasLen += uiKeyLen;

	Int2Num(uiAlg2,(char *)(pbReqParas + uiReqParasLen),1);
	uiReqParasLen += 1;

	if (uiAlg2 == 1)
	{
		memcpy(pbReqParas + uiReqParasLen, encryptIV, encivLen);
		uiReqParasLen += encivLen;
	}
	uiInDataLen /=2;
	Int2Num(uiInDataLen,(char *)(pbReqParas + uiReqParasLen),4);
	uiReqParasLen += 4;

	Hex2Bin(data, pbReqParas + uiReqParasLen, &uiInDataLen);
	uiReqParasLen += uiInDataLen;

	//参数处理
	rv = SocketCommunication_Racal(nSock, pbReqParas, uiReqParasLen, pbResParas, &uiResParasLen, unTimeout_ABC);
	if (rv)
	{
		LOG(LOG_ERROR, rv, "SMAPIDecryptEncrypt->SocketCommunication_Racal");
		return rv;
	}
	uiResParasLen = MESSAGE_HEADER_LEN ;
	if (memcmp(pbResParas + uiResParasLen,pcResAckCode,4) == 0)
	{
		uiResParasLen += 4;
		uiInDataLen = Num2Int((char *)(pbResParas + uiResParasLen),4);
		uiResParasLen += 4;
		Bin2Hex(pbResParas + uiResParasLen,uiInDataLen,outData);
		return ERR_OK;
	}
	else
	{
		rv = (pbResParas[MESSAGE_HEADER_LEN+2]-'0')*10+(pbResParas[MESSAGE_HEADER_LEN+3]-'0');
		if (memcmp(pbResParas+uiResParasLen,pcResAckCode,2) == 0)
		{
			LOG(LOG_ERROR, rv, "SMAPIDecryptEncrypt");
			return rv;
		}
		else
		{
			LOG(LOG_ERROR, rv, "SMAPIDecryptEncrypt");
			return ERR_OTHER;
		}
	}
}

/*******************************************************************************************************************
1. 8.3 数据加密（7.3.6 数据加解密）   (V2)
2. 函数功能：用mech 指定算法对明文数据进行加密。
3. 输入参数：
	UINT nSock：连接的socket 句柄
	char *encryptKey：经LMK 加密的加密密钥的密文值，16 进制ASCII 字符串。（例
	如：8 字节密钥，则该输入为16 个ASCII 字符串）
	UINT mech：算法类型：
	decryptMech = 20 表示DES_ECB 算法
	decryptMech = 17 表示DES_CBC 算法
	decryptMech = 3 表示SM4_ECB 算法
	decryptMech = 4 表示SM4_CBC 算法
	decryptMech = 5 表示AES_ECB 算法（暂不支持）
	decryptMech = 6 表示AES_CBC 算法（暂不支持）
	char *data：待处理数据，16 进制ASCII 字符串，数据长度为16 / 32 的整数倍
	char *IV,：CBC 解密时的初始向量
4. 输出参数：
	char *outData： 输出数据，16 进制ASCII 字符串
5. 返回值： 
    	0：成功
        其他：失败错误代码
*******************************************************************************************************************/
int SMAPIEncrypt(UINT  nSock ,char * encryptKey, UINT mech, char *data, char *IV , char *outData)
{
	int rv = 0;  
	unsigned char *pcReqCommandCode=(unsigned char *)"V2";
	unsigned char *pcResAckCode=(unsigned char *)"V300";
	unsigned char  pbReqParas[MAX_BUFFER_SIZE*2]={0};
	unsigned int  uiReqParasLen=0;
	unsigned char pbResParas[MAX_BUFFER_SIZE*2]={0};
	unsigned int  uiResParasLen=MAX_BUFFER_SIZE*2;
	unsigned int  dataLen=(unsigned int)strlen((char*)data)/2;
	//
	unsigned int uiAlgType = 0;	
	unsigned int uiMode = 0;	
	unsigned int uiPadMode = 1;				//不填充
	unsigned char pbKeyWithID[64] = {0};	//1A+32H
	unsigned int uiKeyWithIDLen = 16;
	unsigned int uiDivTimes = 0;			//不分散
	unsigned int uiFlag = 1;				//加密解密标识
	unsigned int uiIVLen = 0;
	uiKeyWithIDLen = (unsigned int)strlen((char*)encryptKey);
	if (encryptKey == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIEncrypt->encryptKey");
		return ERR_INPUT_DATA;
	}
	if (data == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIEncrypt->data");
		return ERR_INPUT_DATA;
	}
	switch(mech)
	{
	case 17:	 //DES_CBC
		uiMode = 1;
		uiIVLen = 16;
	case 20:	//DES_ECB
		uiAlgType = 3;
		switch(uiKeyWithIDLen)
		{
		case 16:
			break;
		case 32:
			pbKeyWithID[0] = 'X';
			break;
		case 48:
			pbKeyWithID[0] = 'Y';
			break;
		default:
			LOG(LOG_ERROR, uiKeyWithIDLen, "SMAPIEncrypt->uiKeyWithIDLen");
			return ERR_KEY_LEN;
		}
		if ((dataLen%8 != 0)||(dataLen < 8)||(dataLen > 4096))
		{
			LOG(LOG_ERROR, dataLen, "SMAPIEncrypt->dataLen");
			return ERR_DATA_LEN;
		}
		break;
	case 4:   //SM4_CBC
		uiMode = 1;
		uiIVLen = 32;
	case 3:  //SM4_ECB
		uiAlgType = 1;
		if (uiKeyWithIDLen==32)
		{
			pbKeyWithID[0] = 'S';
		}
		else
		{
			LOG(LOG_ERROR, uiKeyWithIDLen, "SMAPIEncrypt->uiKeyWithIDLen");
			return ERR_KEY_LEN;
		}
		if ((dataLen%16 != 0)||(dataLen < 16)||(dataLen > 4096))
		{
			LOG(LOG_ERROR, dataLen, "SMAPIEncrypt->dataLen");
			return ERR_DATA_LEN;
		}
		break;
	default:
		LOG(LOG_ERROR, mech, "SMAPIEncrypt->mech");
		return ERR_ALG_ID;
	}
	if (uiKeyWithIDLen ==16)
	{
		memcpy(pbKeyWithID,encryptKey,uiKeyWithIDLen);//1A+16H 32H 48H
	}
	else
	{
		memcpy(pbKeyWithID+1,encryptKey,uiKeyWithIDLen);//1A+16H 32H 48H
		uiKeyWithIDLen += 1;
	}
	uiReqParasLen = MESSAGE_HEADER_LEN;  //V2指令
	memcpy(pbReqParas + uiReqParasLen, pcReqCommandCode, 2);
	uiReqParasLen += 2;

	Int2Num(uiAlgType, (char *)(pbReqParas+uiReqParasLen),1);
	uiReqParasLen += 1;

	memcpy(pbReqParas + uiReqParasLen,pbKeyWithID,uiKeyWithIDLen);
	uiReqParasLen += uiKeyWithIDLen;

	Int2Num(uiDivTimes, (char *)(pbReqParas+uiReqParasLen),1);
	uiReqParasLen += 1;

	Int2Num(uiFlag, (char *)(pbReqParas+uiReqParasLen),1);
	uiReqParasLen += 1;

	Int2Num(uiMode, (char *)(pbReqParas+uiReqParasLen),1);
	uiReqParasLen += 1;
	if (uiMode == 1)
	{
		memcpy(pbReqParas + uiReqParasLen,IV,uiIVLen);
		uiReqParasLen += uiIVLen;
	}
	Int2Num(uiPadMode, (char *)(pbReqParas+uiReqParasLen),1);
	uiReqParasLen += 1;

	Int2Num(dataLen, (char *)(pbReqParas+uiReqParasLen),4);
	uiReqParasLen += 4;

	Hex2Bin(data,pbReqParas+uiReqParasLen,&dataLen);
	uiReqParasLen += dataLen;

	rv = SocketCommunication_Racal(nSock, pbReqParas, uiReqParasLen, pbResParas, &uiResParasLen, unTimeout_ABC);
	if (rv)
	{
		LOG(LOG_ERROR, rv, "SMAPIEncrypt->SocketCommunication_Racal");
		return rv;
	}
	uiResParasLen = MESSAGE_HEADER_LEN ;
	if(memcmp(pbResParas + uiResParasLen,pcResAckCode,4) == 0)
	{
		uiResParasLen += 4;

		uiKeyWithIDLen = Num2Int((char *)(pbResParas + uiResParasLen), 4);
		uiResParasLen += 4;
		Bin2Hex(pbResParas + uiResParasLen,uiKeyWithIDLen,outData);
		return ERR_OK;
	}
	else
	{
		rv = (pbResParas[MESSAGE_HEADER_LEN+2]-'0')*10+(pbResParas[MESSAGE_HEADER_LEN+3]-'0');
		if (memcmp(pbResParas+uiResParasLen,pcResAckCode,2) == 0)
		{
			LOG(LOG_ERROR, rv, "SMAPIEncrypt");
			return rv;
		}
		else
		{
			LOG(LOG_ERROR, rv, "SMAPIEncrypt");
			return rv;
		}
	}
}

/******************************************************************************************************************
1. 8.4 数据加密(索引版) （7.3.6 数据加解密）  (V2)
2. 函数功能：用mech 指定算法对明文数据进行加密。
3. 输入参数：
	UINT nSock：连接的socket 句柄
	int encryptKeyIndex：在加密机中的密钥索引。[257 486]
	UINT mech：算法类型：：
	decryptMech = 20 表示DES_ECB 算法
	decryptMech = 17 表示DES_CBC 算法
	decryptMech = 3 表示SM4_ECB 算法
	decryptMech = 4 表示SM4_CBC 算法
	decryptMech = 5 表示AES_ECB 算法（暂不支持）
	decryptMech = 6 表示AES_CBC 算法（暂不支持）
	char *data：待处理数据，十六进制ASCII 字符串
	char *IV,：CBC 解密时的初始向量
4. 输出参数：
	char *outData： 输出数据，十六进制ASCII 字符串
5. 返回值： 
	0：成功
	其他：失败错误代码
*********************************************************************************************************************/
int SMAPIEncrypt_index(UINT  nSock ,int encryptKeyIndex, UINT mech, char *data, char *IV, char *outData)
{
	int rv = 0;
	unsigned char *pcReqCommandCode=(unsigned char *)"V2";
	unsigned char *pcResAckCode=(unsigned char *)"V300";
	unsigned char  pbReqParas[MAX_BUFFER_SIZE*2]={0};
	unsigned int  uiReqParasLen=0;
	unsigned char pbResParas[MAX_BUFFER_SIZE*2]={0};
	unsigned int  uiResParasLen=MAX_BUFFER_SIZE*2;
	unsigned int  dataLen=(unsigned int)strlen((char*)data)/2;
	//
	unsigned int uiAlgType = 0;	
	unsigned int uiMode = 0;	
	unsigned int uiPadMode = 1;			//不填充
	unsigned int uiDivTimes = 0;		//不分散
	unsigned int uiFlag = 1;			//加密解密标识
	unsigned int uiIVLen = 0;

	if ((encryptKeyIndex < 256)||(encryptKeyIndex > 486))
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIEncrypt_index->encryptKeyIndex");
		return ERR_INPUT_DATA;
	}
	if (data == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIEncrypt_index->data");
		return ERR_INPUT_DATA;
	}
	switch(mech)
	{
	case 17:		//DES_CBC
		uiMode = 1;
		uiIVLen = 16;
	case 20:		//DES_ECB
		uiAlgType = 3;
		if ((dataLen%8 != 0)||(dataLen < 8)||(dataLen > 4096))
		{
			LOG(LOG_ERROR, dataLen, "SMAPIEncrypt_index->dataLen");
			return ERR_DATA_LEN;
		}
		break;
	case 4:		 //SM4_CBC
		uiMode = 1;
		uiIVLen = 32;
	case 3:		 //SM4_ECB
		uiAlgType = 1;
		if ((dataLen%16 != 0)||(dataLen < 16)||(dataLen > 4096))
		{
			LOG(LOG_ERROR, dataLen, "SMAPIEncrypt_index->dataLen");
			return ERR_DATA_LEN;
		}
		break;
	default:
		LOG(LOG_ERROR, mech, "SMAPIEncrypt_index->mech");
		return ERR_ALG_ID;
	}
	uiReqParasLen = MESSAGE_HEADER_LEN;  //V2指令
	memcpy(pbReqParas + uiReqParasLen, pcReqCommandCode, 2);
	uiReqParasLen += 2;

	Int2Num(uiAlgType, (char *)(pbReqParas+uiReqParasLen),1);
	uiReqParasLen += 1;

	memcpy(pbReqParas + uiReqParasLen,"K3",2);
	uiReqParasLen += 2;
	Int2Num(encryptKeyIndex, (char *)(pbReqParas+uiReqParasLen),3);
	uiReqParasLen += 3;

	Int2Num(uiDivTimes, (char *)(pbReqParas+uiReqParasLen),1);
	uiReqParasLen += 1;

	Int2Num(uiFlag, (char *)(pbReqParas+uiReqParasLen),1);
	uiReqParasLen += 1;

	Int2Num(uiMode, (char *)(pbReqParas+uiReqParasLen),1);
	uiReqParasLen += 1;
	if (uiMode == 1)
	{
		memcpy(pbReqParas + uiReqParasLen,IV,uiIVLen);
		uiReqParasLen += uiIVLen;

	}
	Int2Num(uiPadMode, (char *)(pbReqParas+uiReqParasLen),1);
	uiReqParasLen += 1;

	Int2Num(dataLen, (char *)(pbReqParas+uiReqParasLen),4);
	uiReqParasLen += 4;

	Hex2Bin(data,pbReqParas+uiReqParasLen,&dataLen);
	uiReqParasLen += dataLen;

	rv = SocketCommunication_Racal(nSock, pbReqParas, uiReqParasLen, pbResParas, &uiResParasLen, unTimeout_ABC);

	if (rv)
	{
		LOG(LOG_ERROR, rv, "SMAPIEncrypt_index->SocketCommunication_Racal");
		return rv;
	}
	uiResParasLen = MESSAGE_HEADER_LEN ;
	if(memcmp(pbResParas + uiResParasLen,pcResAckCode,4) == 0)
	{
		uiResParasLen += 4;

		uiReqParasLen = Num2Int((char *)(pbResParas + uiResParasLen), 4);
		uiResParasLen += 4;
		Bin2Hex(pbResParas + uiResParasLen,uiReqParasLen,outData);
		return ERR_OK;
	}
	else
	{
		rv = (pbResParas[MESSAGE_HEADER_LEN+2]-'0')*10+(pbResParas[MESSAGE_HEADER_LEN+3]-'0');
		if (memcmp(pbResParas+uiResParasLen,pcResAckCode,2) == 0)
		{
			LOG(LOG_ERROR, rv, "SMAPIEncrypt_index");
			return rv;
		}
		else
		{
			LOG(LOG_ERROR, rv, "SMAPIEncrypt_index");
			return ERR_OTHER;
		}
	}
}


/******************************************************************************************************************
1. 8.5 数据解密（7.3.6 数据加解密）   (V2)
2. 函数功能：
        用mech 指定算法对数据进行解密。
3. 输入参数：
	UINT nSock：连接的socket 句柄
	char * DecryptKey：经LMK 加密的解密密钥的密文值，16 进制ASCII 字符串。
                          （例如：8 字节密钥，则该输入为16 个ASCII 字符串）
	UINT mech：算法类型：
	decryptMech = 20 表示DES_ECB 算法
	decryptMech = 17 表示DES_CBC 算法
	decryptMech = 3 表示SM4_ECB 算法
	decryptMech = 4 表示SM4_CBC 算法
	decryptMech = 5 表示AES_ECB 算法（暂不支持）
	decryptMech = 6 表示AES_CBC 算法（暂不支持）
	char *data：待处理数据，16 进制ASCII 字符串
	char *IV,：CBC 解密时的初始向量
4. 输出参数：
	char *outData： 输出数据，16 进制ASCII 字符串
5. 返回值： 
	0：成功
	其他：失败错误代码
*********************************************************************************************************************/
int SMAPIDecrypt(UINT  nSock ,char * DecryptKey, UINT mech, char *data, char *IV,char *outData)
{
	int rv = 0;  
	unsigned char *pcReqCommandCode=(unsigned char *)"V2";
	unsigned char *pcResAckCode=(unsigned char *)"V300";
	unsigned char  pbReqParas[MAX_BUFFER_SIZE*2]={0};
	unsigned int  uiReqParasLen=0;
	unsigned char pbResParas[MAX_BUFFER_SIZE*2]={0};
	unsigned int  uiResParasLen=MAX_BUFFER_SIZE*2;
	unsigned int  dataLen=(unsigned int)strlen((char*)data)/2;
	//
	unsigned int uiAlgType = 0;	
	unsigned int uiMode = 0;	

	unsigned int uiPadMode = 1;				//不填充
	unsigned char pbKeyWithID[64] = {0};	//1A+32H
	unsigned int uiKeyWithIDLen = 16;
	unsigned int uiDivTimes = 0;			//不分散
	unsigned int uiFlag = 0;				//加密解密标识
	unsigned int uiIVLen = 0;
	uiKeyWithIDLen = (unsigned int)strlen((char*)DecryptKey);
	if (DecryptKey == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIDecrypt->DecryptKey");
		return ERR_INPUT_DATA;
	}
	if (data == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIDecrypt->data");
		return ERR_INPUT_DATA;
	}
	switch(mech)
	{
	case 17:	//DES_CBC
		uiMode = 1;
		uiIVLen = 16;
	case 20:	//DES_ECB
		uiAlgType = 3;
		switch(uiKeyWithIDLen)
		{
		case 16:
			break;
		case 32:
			pbKeyWithID[0] = 'X';
			break;
		case 48:
			pbKeyWithID[0] = 'Y';
			break;
		default:
			LOG(LOG_ERROR, uiKeyWithIDLen, "SMAPIDecrypt->uiKeyWithIDLen");
			return ERR_KEY_LEN;
		}
		if ((dataLen%8 != 0)||(dataLen < 8)||(dataLen > 4096))
		{
			LOG(LOG_ERROR, dataLen, "SMAPIDecrypt->dataLen");
			return ERR_DATA_LEN;
		}
		break;
	case 4:		//SM4_CBC
		uiMode = 1;
		uiIVLen = 32;
	case 3:		//SM4_ECB
		uiAlgType = 1;
		if (uiKeyWithIDLen==32)
		{
			pbKeyWithID[0] = 'S';
		}
		else
		{
			LOG(LOG_ERROR, uiKeyWithIDLen, "SMAPIDecrypt->uiKeyWithIDLen");
			return ERR_KEY_LEN;
		}
		if ((dataLen%16 != 0)||(dataLen < 16)||(dataLen > 4096))
		{
			LOG(LOG_ERROR, dataLen, "SMAPIDecrypt->dataLen");
			return ERR_DATA_LEN;
		}
		break;
	default:
		LOG(LOG_ERROR, mech, "SMAPIDecrypt->mech");
		return ERR_ALG_ID;
	}
	if (uiKeyWithIDLen ==16)
	{
		memcpy(pbKeyWithID,DecryptKey,uiKeyWithIDLen);//1A+16H 32H 48H
	}
	else
	{
		memcpy(pbKeyWithID+1,DecryptKey,uiKeyWithIDLen);//1A+16H 32H 48H
		uiKeyWithIDLen += 1;
	}
	uiReqParasLen = MESSAGE_HEADER_LEN;  //V2指令
	memcpy(pbReqParas + uiReqParasLen, pcReqCommandCode, 2);
	uiReqParasLen += 2;

	Int2Num(uiAlgType, (char *)(pbReqParas+uiReqParasLen),1);
	uiReqParasLen += 1;

	memcpy(pbReqParas + uiReqParasLen,pbKeyWithID,uiKeyWithIDLen);
	uiReqParasLen += uiKeyWithIDLen;

	Int2Num(uiDivTimes, (char *)(pbReqParas+uiReqParasLen),1);
	uiReqParasLen += 1;

	Int2Num(uiFlag, (char *)(pbReqParas+uiReqParasLen),1);
	uiReqParasLen += 1;

	Int2Num(uiMode, (char *)(pbReqParas+uiReqParasLen),1);
	uiReqParasLen += 1;
	if (uiMode == 1)
	{
		memcpy(pbReqParas + uiReqParasLen,IV,uiIVLen);
		uiReqParasLen += uiIVLen;
	}
	Int2Num(uiPadMode, (char *)(pbReqParas+uiReqParasLen),1);
	uiReqParasLen += 1;

	Int2Num(dataLen, (char *)(pbReqParas+uiReqParasLen),4);
	uiReqParasLen += 4;

	Hex2Bin(data,pbReqParas+uiReqParasLen,&dataLen);
	uiReqParasLen += dataLen;

	rv = SocketCommunication_Racal(nSock, pbReqParas, uiReqParasLen, pbResParas, &uiResParasLen, unTimeout_ABC);

	if (rv)
	{
		LOG(LOG_ERROR, rv, "SMAPIDecrypt->SocketCommunication_Racal");
		return rv;
	}
	uiResParasLen = MESSAGE_HEADER_LEN ;
	if(memcmp(pbResParas + uiResParasLen,pcResAckCode,4) == 0)
	{
		uiResParasLen += 4;

		uiKeyWithIDLen = Num2Int((char *)(pbResParas + uiResParasLen), 4);
		uiResParasLen += 4;
		Bin2Hex(pbResParas + uiResParasLen,uiKeyWithIDLen,outData);
		return ERR_OK;
	}
	else
	{
		rv = (pbResParas[MESSAGE_HEADER_LEN+2]-'0')*10+(pbResParas[MESSAGE_HEADER_LEN+3]-'0');
		if (memcmp(pbResParas+uiResParasLen,pcResAckCode,2) == 0)
		{
			LOG(LOG_ERROR, rv, "SMAPIDecrypt");
			return rv;
		}
		else
		{
			LOG(LOG_ERROR, rv, "SMAPIDecrypt");
			return rv;
		}
	}
}


/********************************************************************************************************************
1. 8.6 数据解密(索引版) （7.3.6 数据加解密） (V2)
2. 函数功能：
	用mech 指定算法对数据进行解密。
3. 输入参数：
	UINT nSock：连接的socket 句柄
	int DecryptKeyIndex：在加密机中的密钥索引。16 进制ASCII 字符串。（例如：8
	字节密钥，则该输入为16 个ASCII 字符串）
	UINT mech：算法类型：
	decryptMech = 20 表示DES_ECB 算法
	decryptMech = 17 表示DES_CBC 算法
	decryptMech = 3 表示SM4_ECB 算法
	decryptMech = 4 表示SM4_CBC 算法
	decryptMech = 5 表示AES_ECB 算法（暂不支持）
	decryptMech = 6 表示AES_CBC 算法（暂不支持）
	char *data：待处理数据，16 进制ASCII 字符串
	char *IV：CBC 解密时的初始向量
4. 输出参数：
	char *outData： 输出数据，16 进制ASCII 字符串
5. 返回值：
	0：成功
	其他：失败错误代码
*********************************************************************************************************************/
int SMAPIDecrypt_index(UINT  nSock ,int DecryptKeyIndex, UINT mech, char *data, char *IV , char *outData)
{
	int rv = 0;
	unsigned char *pcReqCommandCode=(unsigned char *)"V2";
	unsigned char *pcResAckCode=(unsigned char *)"V300";
	unsigned char  pbReqParas[MAX_BUFFER_SIZE*2]={0};
	unsigned int  uiReqParasLen=0;
	unsigned char pbResParas[MAX_BUFFER_SIZE*2]={0};
	unsigned int  uiResParasLen=MAX_BUFFER_SIZE*2;
	unsigned int  dataLen=(unsigned int)strlen((char*)data)/2;
	//
	unsigned int uiAlgType = 0;	
	unsigned int uiMode = 0;	

	unsigned int uiPadMode = 1;			//不填充
	unsigned int uiDivTimes = 0;		//不分散
	unsigned int uiFlag = 0;		  //加密解密模式
	unsigned int uiIVLen = 0;

	if ((DecryptKeyIndex < 256)||(DecryptKeyIndex > 486))
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIDecrypt_index->DecryptKeyIndex");
		return ERR_INPUT_DATA;
	}
	if (data == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIDecrypt_index->data");
		return ERR_INPUT_DATA;
	}
	switch(mech)
	{
	case 17:	 //DES_CBC
		uiMode = 1;
		uiIVLen = 16;
	case 20:	//DES_ECB
		uiAlgType = 3;
		if ((dataLen%8 != 0)||(dataLen < 8)||(dataLen > 4096))
		{
			LOG(LOG_ERROR, dataLen, "SMAPIDecrypt_index->dataLen");
			return ERR_DATA_LEN;
		}
		break;
	case 4:		//SM4_CBC
		uiMode = 1;
		uiIVLen = 32;
	case 3:		 //SM4_ECB
		uiAlgType = 1;
		if ((dataLen%16 != 0)||(dataLen < 16)||(dataLen > 4096))
		{
			LOG(LOG_ERROR, dataLen, "SMAPIDecrypt_index->dataLen");
			return ERR_DATA_LEN;
		}
		break;
	default:
		LOG(LOG_ERROR, mech, "SMAPIDecrypt_index->mech");
		return ERR_ALG_ID;
	}
	uiReqParasLen = MESSAGE_HEADER_LEN;  //V2指令
	memcpy(pbReqParas + uiReqParasLen, pcReqCommandCode, 2);
	uiReqParasLen += 2;

	Int2Num(uiAlgType, (char *)(pbReqParas+uiReqParasLen),1);
	uiReqParasLen += 1;

	memcpy(pbReqParas + uiReqParasLen,"K3",2);
	uiReqParasLen += 2;
	Int2Num(DecryptKeyIndex, (char *)(pbReqParas+uiReqParasLen),3);
	uiReqParasLen += 3;

	Int2Num(uiDivTimes, (char *)(pbReqParas+uiReqParasLen),1);
	uiReqParasLen += 1;

	Int2Num(uiFlag, (char *)(pbReqParas+uiReqParasLen),1);
	uiReqParasLen += 1;

	Int2Num(uiMode, (char *)(pbReqParas+uiReqParasLen),1);
	uiReqParasLen += 1;
	if (uiMode == 1)
	{
		memcpy(pbReqParas + uiReqParasLen,IV,uiIVLen);
		uiReqParasLen += uiIVLen;
	}
	Int2Num(uiPadMode, (char *)(pbReqParas+uiReqParasLen),1);
	uiReqParasLen += 1;

	Int2Num(dataLen, (char *)(pbReqParas+uiReqParasLen),4);
	uiReqParasLen += 4;

	Hex2Bin(data,pbReqParas+uiReqParasLen,&dataLen);
	uiReqParasLen += dataLen;

	rv = SocketCommunication_Racal(nSock, pbReqParas, uiReqParasLen, pbResParas, &uiResParasLen, unTimeout_ABC);

	if (rv)
	{
		LOG(LOG_ERROR, rv, "SMAPIDecrypt_index->SocketCommunication_Racal");
		return rv;
	}
	uiResParasLen = MESSAGE_HEADER_LEN ;
	if(memcmp(pbResParas + uiResParasLen,pcResAckCode,4) == 0)
	{
		uiResParasLen += 4;

		uiReqParasLen = Num2Int((char *)(pbResParas + uiResParasLen), 4);
		uiResParasLen += 4;

		Bin2Hex(pbResParas + uiResParasLen,uiReqParasLen,outData);
		return ERR_OK;
	}
	else
	{
		rv = (pbResParas[MESSAGE_HEADER_LEN+2]-'0')*10+(pbResParas[MESSAGE_HEADER_LEN+3]-'0');
		if (memcmp(pbResParas+uiResParasLen,pcResAckCode,2) == 0)
		{
			LOG(LOG_ERROR, rv, "SMAPIDecrypt_index");
			return rv;
		}
		else
		{
			LOG(LOG_ERROR, rv, "SMAPIDecrypt_index");
			return ERR_OTHER;
		}
	}
}

/****************************************************************************************************************
1. 8.7 密钥分散（7.6.15 分散密钥并加密导出）  (EO)
2. 函数功能：
	对输入主密钥（masterKey 由LMK 保护的密钥）进行分散。
3. 输入参数：
	UINT nSock：连接的socket 句柄
	char *masterKey：经LMK 加密的主密钥的密文值。
	UINT mech：分散算法类型：
	decryptMech = 20 表示DES_ECB 算法
	decryptMech = 17 表示DES_CBC 算法
	decryptMech = 3 表示SM4_ECB 算法
	decryptMech = 4 表示SM4_CBC 算法
	decryptMech = 5 表示AES_ECB 算法（暂不支持）
	decryptMech = 6 表示AES_CBC 算法（暂不支持）
	char * divdata：分散数据，16 进制ASCII 字符串
	char *IV：CBC 解密时的初始向量
4. 输出参数：
	char * derivedKey：密钥分散后经LMK 加密的密钥，16 进制ASCII 字符串
5. 返回值： 
	0：成功
	其他：失败错误代码
*****************************************************************************************************************/
int SMAPIderiveKey(UINT  nSock, char *masterKey, UINT mech, char *divdata, char *IV , char *derivedKey)
{
	int rv = 0;
	unsigned char *pcReqCommandCode=(unsigned char *)"EO1";
	unsigned char *pcResAckCode=(unsigned char *)"EP00";
	unsigned char  pbReqParas[MAX_BUFFER_SIZE*2]={0};
	unsigned int  uiReqParasLen=0;
	unsigned char pbResParas[MAX_BUFFER_SIZE*2]={0};
	unsigned int  uiResParasLen=MAX_BUFFER_SIZE*2;
	unsigned int  dataLen=(unsigned int)strlen((char*)divdata)/2;
	//
	unsigned int uiAlg = 3;	
	unsigned char pbKeyWithID[64] = {0};	//1A+32H
	unsigned int uiKeyWithIDLen = 16;
	unsigned int uiMode = 1;
	unsigned int uiIVLen = 0;
	uiKeyWithIDLen = (unsigned int)strlen((char*)masterKey);
	if (masterKey == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIderiveKey->masterKey");
		return ERR_INPUT_DATA;
	}
	if (divdata == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIderiveKey->divdata");
		return ERR_INPUT_DATA;
	}
	if (derivedKey == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIderiveKey->derivedKey");
		return ERR_INPUT_DATA;
	}
	switch(mech)
	{
	case 17:
		uiMode = 2;
		uiIVLen = 16;
	case 20:
		switch(uiKeyWithIDLen)
		{
		case 16:
			break;
		case 32:
			pbKeyWithID[0] = 'X';
			break;
		case 48:
			pbKeyWithID[0] = 'Y';
			break;
		default:
			LOG(LOG_ERROR, uiKeyWithIDLen, "SMAPIderiveKey->masterKey");
			return ERR_KEY_LEN;
		}
		if ((dataLen%8 != 0)||(dataLen < 8)||(dataLen > 4096))
		{
			LOG(LOG_ERROR, dataLen, "SMAPIderiveKey->divdata");
			return ERR_DATA_LEN;
		}
		break;
	case 4:
		uiMode = 2;
		uiIVLen = 32;
	case 3:
		uiAlg = 2;
		if (uiKeyWithIDLen==32)
		{
			pbKeyWithID[0] = 'S';
		}
		else
		{
			LOG(LOG_ERROR, uiKeyWithIDLen, "SMAPIderiveKey->masterKey");
			return ERR_KEY_LEN;
		}
		if ((dataLen%16 != 0)||(dataLen < 16)||(dataLen > 4096))
		{
			LOG(LOG_ERROR, dataLen, "SMAPIderiveKey->divdata");
			return ERR_DATA_LEN;
		}
		break;


		LOG(LOG_ERROR, mech, "SMAPIderiveKey->mech");
		return ERR_ALG_ID;
	}
	if (uiKeyWithIDLen ==16)
	{
		memcpy(pbKeyWithID,masterKey,uiKeyWithIDLen);//1A+16H 32H 48H

	} 
	else
	{
		memcpy(pbKeyWithID+1,masterKey,uiKeyWithIDLen);//1A+16H 32H 48H
		uiKeyWithIDLen += 1;
	}
	uiReqParasLen = MESSAGE_HEADER_LEN;
	memcpy(pbReqParas + uiReqParasLen, pcReqCommandCode, 3);
	uiReqParasLen += 3;

	Int2Num(uiAlg, (char *)(pbReqParas+uiReqParasLen),1);
	uiReqParasLen += 1;

	Int2Num(uiMode, (char *)(pbReqParas+uiReqParasLen),2);
	uiReqParasLen += 2;

	memcpy(pbReqParas + uiReqParasLen,pbKeyWithID,uiKeyWithIDLen);
	uiReqParasLen += uiKeyWithIDLen;

	Int2Num(2, (char *)(pbReqParas+uiReqParasLen),1);
	uiReqParasLen += 1;

	Int2Num(dataLen, (char *)(pbReqParas+uiReqParasLen),4);
	uiReqParasLen += 4;

	memcpy(pbReqParas + uiReqParasLen,divdata,dataLen*2);
	uiReqParasLen += dataLen*2;

	if (mech == 17||mech == 4)
	{	
		memcpy(pbReqParas + uiReqParasLen,IV,uiIVLen);
		uiReqParasLen += uiIVLen;
	}
	rv = SocketCommunication_Racal(nSock, pbReqParas, uiReqParasLen, pbResParas, &uiResParasLen, unTimeout_ABC);

	if (rv)
	{
		LOG(LOG_ERROR, rv, "SMAPIderiveKey->SocketCommunication_Racal");
		return rv;
	}
	uiResParasLen = MESSAGE_HEADER_LEN ;
	if(memcmp(pbResParas + uiResParasLen,pcResAckCode,4) == 0)
	{
		uiResParasLen += 4;

		uiReqParasLen = Num2Int((char *)(pbResParas + uiResParasLen), 4);
		uiResParasLen += 4;

		Bin2Hex(pbResParas + uiResParasLen,uiReqParasLen,derivedKey);
		return ERR_OK;
	}
	else
	{
		rv = (pbResParas[MESSAGE_HEADER_LEN+2]-'0')*10+(pbResParas[MESSAGE_HEADER_LEN+3]-'0');
		if (memcmp(pbResParas+uiResParasLen,pcResAckCode,2) == 0)
		{
			LOG(LOG_ERROR, rv, "SMAPIderiveKey");
			return rv;
		}
		else
		{
			LOG(LOG_ERROR, rv, "SMAPIderiveKey");
			return ERR_OTHER;
		}
	}

}

/****************************************************************************************************************
1. 8.8 密钥分散(索引版) （7.6.15 分散密钥并加密导出）  (EO)
2. 函数功能：
	对输入密钥索引指定的主密钥进行分散。
3. 输入参数：
	UINT nSock：连接的socket 句柄
	int masterKeyIndex：待分散密钥在加密机中的索引。
	UINT mech：分散算法类型：
	decryptMech = 20 表示DES_ECB 算法
	decryptMech = 17 表示DES_CBC 算法
	decryptMech = 3 表示SM4_ECB 算法
	decryptMech = 4 表示SM4_CBC 算法
	decryptMech = 5 表示AES_ECB 算法（暂不支持）
	decryptMech = 6 表示AES_CBC 算法（暂不支持）
	char *data：分散数据，16 进制ASCII 字符串
	char *IV：CBC 解密时的初始向量
4. 输出参数：
	char * derivedKey：密钥分散后经LMK 加密的密文输出数据，16 进制ASCII 字符串
5. 返回值： 
	0：成功
	其他：失败错误代码
*****************************************************************************************************************/
int SMAPIderiveKey_index(UINT  nSock,int masterKeyIndex, UINT mech, char *divdata, char *IV ,char *derivedKey)
{
	int rv = 0;
	unsigned char *pcReqCommandCode=(unsigned char *)"EO1";
	unsigned char *pcResAckCode=(unsigned char *)"EP00";
	unsigned char  pbReqParas[MAX_BUFFER_SIZE*2]={0};
	unsigned int  uiReqParasLen=0;
	unsigned char pbResParas[MAX_BUFFER_SIZE*2]={0};
	unsigned int  uiResParasLen=MAX_BUFFER_SIZE*2;
	unsigned int  dataLen=(unsigned int)strlen((char*)divdata)/2;

	//
	unsigned int uiAlg = 3;	
	unsigned int uiMode = 1;
	unsigned int uiIVLen = 0;
	if ((masterKeyIndex < 256)||(masterKeyIndex > 486))
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIderiveKey_index->masterKeyIndex");
		return ERR_INPUT_DATA;
	}
	if (divdata == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIderiveKey_index->divdata");
		return ERR_INPUT_DATA;
	}
	if (derivedKey == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIderiveKey_index->derivedKey");
		return ERR_INPUT_DATA;
	}
	switch(mech)
	{
	case 17:
		uiMode = 2;
		uiIVLen = 16;
	case 20:
		if ((dataLen%8 != 0)||(dataLen < 8)||(dataLen > 4096))
		{
			LOG(LOG_ERROR, dataLen, "SMAPIderiveKey_index->data");
			return ERR_DATA_LEN;
		}
		break;
	case 4:
		uiMode = 2;
		uiIVLen = 32;
	case 3:
		uiAlg = 2;
		if ((dataLen%16 != 0)||(dataLen < 16)||(dataLen > 4096))
		{
			LOG(LOG_ERROR, dataLen, "SMAPIderiveKey_index->data");
			return ERR_DATA_LEN;
		}
		break;
	default:
		LOG(LOG_ERROR, rv, "SMAPIderiveKey_index->mech");
		return ERR_ALG_ID;
	}

	uiReqParasLen = MESSAGE_HEADER_LEN;
	memcpy(pbReqParas + uiReqParasLen, pcReqCommandCode, 3);
	uiReqParasLen += 3;

	Int2Num(uiAlg, (char *)(pbReqParas+uiReqParasLen),1);
	uiReqParasLen += 1;

	Int2Num(uiMode, (char *)(pbReqParas+uiReqParasLen),2);
	uiReqParasLen += 2;

	memcpy(pbReqParas + uiReqParasLen,"K3",2);
	uiReqParasLen += 2;

	Int2Num(masterKeyIndex, (char *)(pbReqParas+uiReqParasLen),3);
	uiReqParasLen += 3;

	Int2Num(2, (char *)(pbReqParas+uiReqParasLen),1);
	uiReqParasLen += 1;

	Int2Num(dataLen, (char *)(pbReqParas+uiReqParasLen),4);
	uiReqParasLen += 4;

	memcpy(pbReqParas + uiReqParasLen,divdata,dataLen*2);
	uiReqParasLen += dataLen*2;

	if (mech == 17||mech == 4)
	{
		memcpy(pbReqParas + uiReqParasLen,IV,uiIVLen);
		uiReqParasLen += uiIVLen;
	}
	rv = SocketCommunication_Racal(nSock, pbReqParas, uiReqParasLen, pbResParas, &uiResParasLen, unTimeout_ABC);

	if (rv)
	{
		LOG(LOG_ERROR, rv, "SMAPIderiveKey_index->SocketCommunication_Racal");
		return rv;
	}
	uiResParasLen = MESSAGE_HEADER_LEN ;
	if(memcmp(pbResParas + uiResParasLen,pcResAckCode,4) == 0)
	{
		uiResParasLen += 4;

		uiReqParasLen = Num2Int((char *)(pbResParas + uiResParasLen), 4);
		uiResParasLen += 4;
		Bin2Hex(pbResParas + uiResParasLen,uiReqParasLen,derivedKey);

		return ERR_OK;
	}
	else
	{
		rv = (pbResParas[MESSAGE_HEADER_LEN+2]-'0')*10+(pbResParas[MESSAGE_HEADER_LEN+3]-'0');
		if (memcmp(pbResParas+uiResParasLen,pcResAckCode,2) == 0)
		{
			LOG(LOG_ERROR, rv, "SMAPIderiveKey_index");
			return rv;
		}
		else
		{
			LOG(LOG_ERROR, rv, "SMAPIderiveKey_index");
			return ERR_OTHER;
		}
	}
}


/********************************************************************************************************************
1. 8.9 产生随机数（7.6.9 产生随机数）  （TE）
2. 函数功能：
	产生输入长度的随机数。
3. 输入参数：
	UINT nSock：连接的socket 句柄
	int rdmLength：需要产生随机数的长度。
4. 输出参数：
	char *outData： 随机数，ASCII 字符串。（例如需要产生8 字节随机数，则该返
	回值为16 个ASCII 字符串）
5. 返回值：
	0：成功
	其他：失败错误代码
*********************************************************************************************************************/
int SMAPIGenerateRandom(UINT  nSock, int rdmLength,char * outData)
{
	int rv = 0;
	unsigned char *pcReqCommandCode=(unsigned char *)"TE";
	unsigned char *pcResAckCode=(unsigned char *)"TF00";
	unsigned char  pbReqParas[MAX_BUFFER_SIZE]={0};
	unsigned int  unReqParasLen=0;
	unsigned char pbResParas[MAX_BUFFER_SIZE]={0};
	unsigned int  unResParasLen=MAX_BUFFER_SIZE;

	//返回参数
	unsigned int uiTemLen;
	// 
	if (rdmLength<1||rdmLength>MAX_BUFFER_SIZE)
	{
		return ERR_INPUT_DATA;
	}
	unReqParasLen=MESSAGE_HEADER_LEN;

	memcpy(pbReqParas + unReqParasLen, pcReqCommandCode, 2);
	unReqParasLen += 2;

	Int2Num(rdmLength, (char *)pbReqParas + unReqParasLen, 4);
	unReqParasLen += 4;

	rv = SocketCommunication_Racal(nSock, pbReqParas,  unReqParasLen, pbResParas, &unResParasLen, unTimeout_ABC);
	if (rv)
	{
		LOG(LOG_ERROR, rv, "SMAPIGenerateRandom->SocketCommunication_Racal");
		return rv;
	}
	uiTemLen = MESSAGE_HEADER_LEN;
	if ((pbResParas[MESSAGE_HEADER_LEN]=='T')&&(pbResParas[MESSAGE_HEADER_LEN+1]=='F')&&(pbResParas[MESSAGE_HEADER_LEN+2]=='0')&&(pbResParas[MESSAGE_HEADER_LEN+3]=='0'))
	{
		uiTemLen += 4;
		Bin2Hex(pbResParas+uiTemLen,rdmLength,outData);
		return ERR_OK;
	}
	else
	{
		return (pbResParas[MESSAGE_HEADER_LEN+2]-'0')*10+(pbResParas[MESSAGE_HEADER_LEN+3]-'0');
		if (memcmp(pbResParas+unResParasLen,pcResAckCode,2) == 0)
		{
			LOG(LOG_ERROR, rv, "SMAPIGenerateRandom");
			return rv;
		}
		else
		{
			LOG(LOG_ERROR, rv, "SMAPIGenerateRandom");
			return ERR_OTHER;
		}
	}
}

/****************************************************************************************************************
1. 8.10 密钥转加密（7.6.11 密钥转加密增强型）  （KG）
2. 函数功能：
	用mech 指定算法对密钥进行转加密，即将key 由LMK 加密转为由
	wrapKey 对应的密钥加密。
3. 输入参数：
	UINT nSock：连接的socket 句柄
	char * wrapKey：经LMK 加密的加密密钥的密文值，16 进制ASCII 字符串。（例
	如：8 字节密钥，则该输入为16 个ASCII 字符串）
	UINT mech：算法类型：decryptMech = 20 表示DES_ECB 算法。
	decryptMech = 17 表示DES_CBC 算法。
	char * key：待处理的密钥数据，16 进制ASCII 字符串，数据长度为16 的整数倍。
	（该密钥数据同样经LMK 加密）
	char *IV：CBC 解密时的初始向量
4. 输出参数：
	char *outData： 输出密钥，16 进制ASCII 字符串，即由wrapKey 加密的Key 的密文
5. 返回值： 
	0：成功
	其他：失败错误代码
*****************************************************************************************************************/
int SMAPIwrap(UINT  nSock ,char *wrapKey, UINT mech, char *key, char *IV , char *outData)
{
	int rv = 0;
	unsigned char *pcReqCommandCode=(unsigned char *)"KGT";
	unsigned char *pcResAckCode=(unsigned char *)"KH00";
	unsigned char  pbReqParas[MAX_BUFFER_SIZE]={0};
	unsigned int  uiReqParasLen=0;
	unsigned char pbResParas[MAX_BUFFER_SIZE]={0};
	unsigned int  uiResParasLen=MAX_BUFFER_SIZE;

	//返回参数
	unsigned char pbKey1WithID[50] = {0};
	unsigned char pbKey2WithID[50] = {0};
	unsigned int uiKey1WithIDLen = 0;
	unsigned int uiKey2WithIDLen = 16;

	int wrapKeyLen=0, keyLen=0, ivLen=0;
	//辅助参数
	int tmpLen = 0;
	if (wrapKey == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIwrap->wrapKey");
		return ERR_INPUT_DATA;
	}
	if (key == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIwrap->key");
		return ERR_INPUT_DATA;
	}
	wrapKeyLen=(int)strlen((char*)wrapKey);
	keyLen=(int)strlen((char*)key);
	if(IV == NULL)
		ivLen = 0;
	else
		ivLen=(int)strlen((char*)IV);
	switch(wrapKeyLen)
	{
	case 16:
		break;
	case 32:
		pbKey1WithID[0] = 'X';
		break;
	case 48:
		pbKey1WithID[0] = 'Y';
		break;
	default:
		LOG(LOG_ERROR, wrapKeyLen, "SMAPIwrap->nwrapKeyLen");
		return ERR_KEY_LEN;
		break;
	}
	if (wrapKeyLen ==16)
	{
		memcpy(pbKey1WithID,wrapKey,wrapKeyLen);
	} 
	else
	{
		memcpy(pbKey1WithID + 1,wrapKey,wrapKeyLen);
		uiKey1WithIDLen = wrapKeyLen +1;
	}
	switch(keyLen)
	{
	case 16:
		break;
	case 32:
		pbKey2WithID[0] = 'X';
		break;
	case 48:
		pbKey2WithID[0] = 'Y';
		break;
	default:
		LOG(LOG_ERROR, keyLen, "SMAPIwrap->nKeyLen");
		return ERR_KEY_LEN;
		break;
	}
	if (keyLen ==16)
	{
		memcpy(pbKey2WithID,key,keyLen);

	} 
	else
	{
		memcpy(pbKey2WithID + 1,key,keyLen);
		uiKey2WithIDLen = keyLen +1;
	}
	uiReqParasLen = MESSAGE_HEADER_LEN;
	memcpy(pbReqParas + uiReqParasLen, pcReqCommandCode, 3);
	uiReqParasLen += 3;

	if (mech == 20)
	{
		Int2Num(1, (char *)(pbReqParas+uiReqParasLen), 2);
		ivLen=0;
	} 
	else if (mech == 17)
	{
		Int2Num(2, (char *)(pbReqParas+uiReqParasLen), 2);
		if (ivLen >= 16)
		{
			ivLen=16;		
		} 
		else
		{
			LOG(LOG_ERROR, ivLen, "SMAPIwrap->ivLen");
			return ERR_DATA_LEN;
		}
	}
	else
	{
		LOG(LOG_ERROR, mech, "SMAPIwrap->mech");
		return ERR_ALG_ID;
	}
	uiReqParasLen += 2;
	Int2Num(0, (char *)(pbReqParas+uiReqParasLen), 2);
	uiReqParasLen += 2;

	memcpy(pbReqParas+uiReqParasLen, IV, ivLen);
	uiReqParasLen += ivLen;

	memcpy(pbReqParas + uiReqParasLen,pbKey1WithID,uiKey1WithIDLen);
	uiReqParasLen += uiKey1WithIDLen;

	memcpy(pbReqParas + uiReqParasLen,pbKey2WithID,uiKey2WithIDLen);
	uiReqParasLen += uiKey2WithIDLen;

	//参数处理
	rv = SocketCommunication_Racal(nSock, pbReqParas, uiReqParasLen, pbResParas, &uiResParasLen, unTimeout_ABC);
	if (rv)
	{
		LOG(LOG_ERROR, rv, "SMAPIwrap->SocketCommunication_Racal");
		return rv;
	}
	uiResParasLen = MESSAGE_HEADER_LEN ;
	if (memcmp(pbResParas + uiResParasLen,pcResAckCode,4) == 0)
	{
		uiResParasLen += 4;

		tmpLen = Num2Int((char *)(pbResParas+uiResParasLen), 4);
		uiResParasLen+=4;
		memcpy(outData, pbResParas+uiResParasLen,tmpLen*2);
		return ERR_OK;
	}
	else
	{
		rv = (pbResParas[MESSAGE_HEADER_LEN+2]-'0')*10+(pbResParas[MESSAGE_HEADER_LEN+3]-'0');
		if (memcmp(pbResParas+uiResParasLen,pcResAckCode,2) == 0)
		{
			LOG(LOG_ERROR, rv, "SMAPIwrap");
			return rv;
		}
		else
		{
			LOG(LOG_ERROR, rv, "SMAPIwrap");
			return ERR_OTHER;
		}
	}
}

/****************************************************************************************************************
1. 8.11 密钥转加密(索引版) （7.6.11 密钥转加密增强型）    （KG）
2. 函数功能：
	用mech 指定算法对密钥进行转加密，即将key 由LMK 加密转为由
	wrapKeyIndex 索引对应的密钥加密。
3. 输入参数：
	UINT nSock：连接的socket 句柄
	int wrapKeyIndex：密钥索引
	UINT mech：算法类型：decryptMech = 20 表示DES_ECB 算法。
	decryptMech = 17 表示DES_CBC 算法。
	char * key：待处理的密钥数据，16 进制ASCII 字符串，数据长度为16 的整数倍。
	（该密钥数据同样经LMK 加密）
	char *IV：CBC 解密时的初始向量
4. 输出参数：
	char *outData： 输出密钥，16 进制ASCII 字符串，即由wrapKeyIndex 索引对应
	密钥加密Key 的密文
5. 返回值： 
	0：成功
	其他：失败错误代码
*****************************************************************************************************************/
int SMAPIwrap_index (UINT  nSock,int wrapKeyIndex,UINT mech,char *key,char *IV ,char *outData)
{
	int rv = 0;
	unsigned char *pcReqCommandCode=(unsigned char *)"KGT";
	unsigned char *pcResAckCode=(unsigned char *)"KH00";
	unsigned char  pbReqParas[MAX_BUFFER_SIZE]={0};
	unsigned int  uiReqParasLen=0;
	unsigned char pbResParas[MAX_BUFFER_SIZE]={0};
	unsigned int  uiResParasLen=MAX_BUFFER_SIZE;

	//返回参数
	unsigned char pbKey1WithID[50] = {0};
	unsigned char pbKey2WithID[50] = {0};
	unsigned int uiKey1WithIDLen = 0;
	unsigned int uiKey2WithIDLen = 16;

	int keyLen=0, ivLen=0;
	//辅助参数
	int tmpLen = 0;
	if (key == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIwrap_index->key");
		return ERR_INPUT_DATA;
	}
	keyLen=(int)strlen((char*)key);
	if(IV == NULL)
		ivLen = 0;
	else
		ivLen=(int)strlen((char*)IV);
	uiKey1WithIDLen = 5;
	pbKey1WithID[0] = 'K';
	pbKey1WithID[1] = '3';
	Int2Num(wrapKeyIndex,(char *)(pbKey1WithID + 2),3);

	switch(keyLen)
	{
	case 16:
		break;
	case 32:
		pbKey2WithID[0] = 'X';
		break;
	case 48:
		pbKey2WithID[0] = 'Y';
		break;
	default:
		LOG(LOG_ERROR, keyLen, "SMAPIwrap_index->nwrapKeyLen");
		return ERR_KEY_LEN;
		break;
	}
	if (keyLen ==16)
	{
		memcpy(pbKey2WithID,key,keyLen);

	} 
	else
	{
		memcpy(pbKey2WithID + 1,key,keyLen);
		uiKey2WithIDLen = keyLen +1;
	}

	uiReqParasLen = MESSAGE_HEADER_LEN;
	memcpy(pbReqParas + uiReqParasLen, pcReqCommandCode, 3);
	uiReqParasLen += 3;

	if (mech == 20)
	{
		Int2Num(1, (char *)(pbReqParas+uiReqParasLen), 2);
		ivLen=0;
	} 
	else if (mech == 17)
	{
		Int2Num(2, (char *)(pbReqParas+uiReqParasLen), 2);
		if (ivLen >= 16)
		{
			ivLen =  16;
		} 
		else
		{
			LOG(LOG_ERROR, ivLen, "SMAPIwrap_index->ivLen");
			return ERR_INPUT_DATA;
		}
	}
	else
	{
		LOG(LOG_ERROR, mech, "SMAPIwrap_index->mech");
		return ERR_ALG_ID;
	}
	uiReqParasLen += 2;
	Int2Num(0, (char *)(pbReqParas+uiReqParasLen), 2);
	uiReqParasLen += 2;
	memcpy(pbReqParas+uiReqParasLen, IV, ivLen);
	uiReqParasLen += ivLen;

	memcpy(pbReqParas + uiReqParasLen,pbKey1WithID,uiKey1WithIDLen);
	uiReqParasLen += uiKey1WithIDLen;

	memcpy(pbReqParas + uiReqParasLen,pbKey2WithID,uiKey2WithIDLen);
	uiReqParasLen += uiKey2WithIDLen;

	//参数处理
	rv = SocketCommunication_Racal(nSock, pbReqParas, uiReqParasLen, pbResParas, &uiResParasLen, unTimeout_ABC);
	if (rv)
	{
		LOG(LOG_ERROR, rv, "SMAPIwrap_index->SocketCommunication_Racal");
		return rv;
	}
	uiResParasLen = MESSAGE_HEADER_LEN ;
	if (memcmp(pbResParas + uiResParasLen,pcResAckCode,4) == 0)
	{
		uiResParasLen += 4;

		tmpLen = Num2Int((char *)(pbResParas+uiResParasLen), 4);
		uiResParasLen+=4;
		memcpy(outData, pbResParas+uiResParasLen,tmpLen*2);
		return ERR_OK;
	}
	else
	{
		rv = (pbResParas[MESSAGE_HEADER_LEN+2]-'0')*10+(pbResParas[MESSAGE_HEADER_LEN+3]-'0');
		if (memcmp(pbResParas+uiResParasLen,pcResAckCode,2) == 0)
		{
			LOG(LOG_ERROR, rv, "SMAPIwrap_index");
			return rv;
		}
		else
		{
			LOG(LOG_ERROR, rv, "SMAPIwrap_index");
			return ERR_OTHER;
		}
	}
}

/********************************************************************************************************************
1. 8.12 MAC 计算（7.2.13 产生MAC）                           （MS）
2. 函数功能：
        当mech = 1 时用PBOC2.0 双倍长模式计算输入数据的MAC 值。算法
        当mech = 2 时用PBOC2.0 单倍长模式计算输入数据的MAC 值。其算法;
	当mech = 3 时用SM4 计算输入数据的MAC 值。算法详见下图B；
	数据data 的填充算法如下：将输入输入按照8 / 16 字节为单位分为若干数据块，若最
	后的数据块的长度为8 / 16 字节，填充“0x800000000000…”;若最后数据块长度小于
	8 / 16 字节，首先填充0x80，再填充若干个0x00，使得最后的数据块长度为8 / 16 字
	节。

3. 输入参数：
	UINT nSock：连接的socket 句柄
	char *MACKey：经LMK 加密的MAC 密钥的密文值，16 进制ASCII 字符串。
	UINT mech：算法类型：1、2、3
	char *data：需要计算MAC 的数据，类型为十六进制ASCII 字符串
	char *IV：初始向量
4. 输出参数：
	char * Mac：Mac 的计算结果，16 位十六进制ASCII 字符串
5. 返回值： 
	0：成功
	其他：失败错误代码
*****************************************************************************************************************/
int SMAPIPBOCMAC(UINT  nSock,char *MACKey,UINT mech,char *data,char *IV,char * Mac)
{
	int rv = 0;
	unsigned char *pcReqCommandCode=(unsigned char *)"MS0";
	unsigned char *pcResAckCode=(unsigned char *)"MT00";
	unsigned char  pbReqParas[MAX_BUFFER_SIZE]={0};
	unsigned int  uiReqParasLen=0;
	unsigned char pbResParas[MAX_BUFFER_SIZE]={0};
	unsigned int  uiResParasLen=MAX_BUFFER_SIZE;

	//辅助参数
	unsigned char pbKeyWithID[50] = {0};
	unsigned int uiKeyWithIDLen = 0;
	unsigned int uiInDataLen = (unsigned int)strlen((char*)data);
	unsigned int uiAlgType = 0;
	unsigned int uiIVLen = 0;
	unsigned int MacAlog = 0;

	if (MACKey == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIPBOCMAC->MACKey");
		return ERR_INPUT_DATA;
	}

	if (data == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIPBOCMAC->data");
		return ERR_INPUT_DATA;
	}
	if (IV == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIPBOCMAC->IV");
		return ERR_INPUT_DATA;
	}
	uiInDataLen = (unsigned int)strlen((char*)data);
	uiInDataLen /= 2;
	switch(mech)
	{
	case 1:
		pbKeyWithID[0] = 'X';
		memcpy(pbKeyWithID + 1,MACKey,32);
		uiKeyWithIDLen = 1+32; 
		uiIVLen = 16;
		MacAlog = 4;
		uiAlgType = 3;
		break;
	case 2:
		memcpy(pbKeyWithID,MACKey,16);
		uiKeyWithIDLen = 16; 
		uiIVLen = 16;
		MacAlog = 5;
		uiAlgType = 3;
		break;
	case 3:
		pbKeyWithID[0] = 'S';
		memcpy(pbKeyWithID + 1,MACKey,32);
		uiKeyWithIDLen = 1+32; 
		uiIVLen = 32;
		MacAlog = 4;
		uiAlgType = 1;
		break;
	default:
		LOG(LOG_ERROR, mech, "SMAPIPBOCMAC->mech");
		return ERR_ALG_ID;
		break;
	}
	uiReqParasLen += MESSAGE_HEADER_LEN;
	memcpy(pbReqParas + uiReqParasLen, pcReqCommandCode, 3);
	uiReqParasLen += 3;

	Int2Num(MacAlog, (char *)(pbReqParas+uiReqParasLen),1);
	uiReqParasLen += 1;

	Int2Num(uiAlgType, (char *)(pbReqParas+uiReqParasLen),1);
	uiReqParasLen += 1;

	memcpy(pbReqParas + uiReqParasLen,pbKeyWithID,uiKeyWithIDLen);
	uiReqParasLen += uiKeyWithIDLen;

	memcpy(pbReqParas +uiReqParasLen,IV,uiIVLen);
	uiReqParasLen += uiIVLen;

	Int2Num(uiInDataLen, (char *)(pbReqParas+uiReqParasLen),4);
	uiReqParasLen += 4;

	Hex2Bin(data, pbReqParas+uiReqParasLen,&uiInDataLen);
	uiReqParasLen += uiInDataLen;

	rv = SocketCommunication_Racal(nSock, pbReqParas, uiReqParasLen, pbResParas, &uiResParasLen, unTimeout_ABC);
	if (rv)
	{
		LOG(LOG_ERROR, rv, "SMAPIPBOCMAC->SocketCommunication_Racal");
		return rv;
	}
	uiResParasLen = MESSAGE_HEADER_LEN ;
	if(memcmp(pbResParas + uiResParasLen,pcResAckCode,4) == 0)
	{
		uiResParasLen += 4;
		memcpy(Mac,pbResParas + uiResParasLen,uiIVLen);
		return ERR_OK;
	}
	else
	{
		rv = (pbResParas[MESSAGE_HEADER_LEN+2]-'0')*10+(pbResParas[MESSAGE_HEADER_LEN+3]-'0');
		if (memcmp(pbResParas+uiResParasLen,pcResAckCode,2) == 0)
		{
			LOG(LOG_ERROR, rv, "SMAPIPBOCMAC");
			return rv;
		}
		else
		{
			LOG(LOG_ERROR, rv, "SMAPIPBOCMAC");
			return ERR_OTHER;
		}
	}
}

/****************************************************************************************************************
1. 8.13 MAC 计算(索引版) （7.2.13 产生MAC）    （MS）
2. 函数功能：
	当mech = 1 时用PBOC2.0 双倍长模式计算输入数据的MAC 值。算法
	当mech = 2 时用PBOC2.0 单倍长模式计算输入数据的MAC 值。其算法
	当mech = 3 时用SM4 计算输入数据的MAC 值。算法详见下图B；
	数据data 的填充算法如下：将输入输入按照8 / 16 字节为单位分为若干数据块，若最
	后的数据块的长度为8 / 16 字节，填充“0x80000000000000…”;若最后数据块长度小
	于8 / 16 字节，首先填充0x80，再填充若干个0x00，使得最后的数据块长度为8 / 16字节。
3. 输入参数：
	UINT nSock：连接的socket 句柄
	int MACKeyIndex：MAK 密钥在加密机中的密钥索引，范围为[257，486]，并且该密钥为双倍长(16 字节)
	UINT mech：算法类型：1 、2、3
	char *data：需要计算MAC 的数据，类型为十六进制ASCII 字符串
	char *IV：初始向量
4. 输出参数：
	char * Mac：Mac 的计算结果，16 位十六进制ASCII 字符串
5. 返回值：
	0：成功
	其他：失败错误代码
*****************************************************************************************************************/
int SMAPIPBOCMAC_index(UINT  nSock , int MACKeyIndex, UINT mech,char *data, char *IV,  char * Mac)
{
	int rv = 0;
	unsigned char *pcReqCommandCode=(unsigned char *)"MS0";
	unsigned char *pcResAckCode=(unsigned char *)"MT00";
	unsigned char  pbReqParas[MAX_BUFFER_SIZE]={0};
	unsigned int  uiReqParasLen=0;
	unsigned char pbResParas[MAX_BUFFER_SIZE]={0};
	unsigned int  uiResParasLen=MAX_BUFFER_SIZE;

	unsigned int uiInDataLen = (unsigned int)strlen((char*)data);
	unsigned int uiAlgType = 0, uiIVLen = 0;
	unsigned int MACAlog = 0;
	//unsigned int uiMACLen = 8;

	if (data == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIPBOCMAC->data");
		return ERR_INPUT_DATA;
	}
	if (IV == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIPBOCMAC->IV");
		return ERR_INPUT_DATA;
	}

	uiInDataLen = (unsigned int)strlen((char*)data);
	uiInDataLen /= 2;
	switch(mech)
	{
	case 1:
		uiIVLen = 16;
		uiAlgType = 3;
		MACAlog = 4;
		break;
	case 2:
		uiIVLen = 16;
		uiAlgType = 3;
		MACAlog = 5;
		break;
	case 3:
		uiIVLen = 32;
		MACAlog = 4;
		uiAlgType = 1;
		break;
	default:
		LOG(LOG_ERROR, mech, "SMAPIPBOCMAC_index->mech");
		return ERR_ALG_ID;
		break;
	}

	uiReqParasLen += MESSAGE_HEADER_LEN;
	memcpy(pbReqParas + uiReqParasLen, pcReqCommandCode, 3);
	uiReqParasLen += 3;

	Int2Num(MACAlog, (char *)(pbReqParas+uiReqParasLen),1);
	uiReqParasLen += 1;

	Int2Num(uiAlgType, (char *)(pbReqParas+uiReqParasLen),1);
	uiReqParasLen += 1;

	memcpy(pbReqParas + uiReqParasLen,"K3",2);
	uiReqParasLen += 2;

	Int2Num(MACKeyIndex, (char *)(pbReqParas+uiReqParasLen),3);
	uiReqParasLen += 3;

	memcpy(pbReqParas +uiReqParasLen,IV,uiIVLen);
	uiReqParasLen += uiIVLen;

	Int2Num(uiInDataLen, (char *)(pbReqParas+uiReqParasLen),4);
	uiReqParasLen += 4;

	Hex2Bin(data, pbReqParas+uiReqParasLen,&uiInDataLen);
	uiReqParasLen += uiInDataLen;

	rv = SocketCommunication_Racal(nSock, pbReqParas, uiReqParasLen, pbResParas, &uiResParasLen, unTimeout_ABC);
	if (rv)
	{
		LOG(LOG_ERROR, rv, "SMAPIPBOCMAC_index->SocketCommunication_Racal");
		return rv;
	}
	uiResParasLen = MESSAGE_HEADER_LEN ;
	if(memcmp(pbResParas + uiResParasLen,pcResAckCode,4) == 0)
	{
		uiResParasLen += 4;
		memcpy(Mac,pbResParas + uiResParasLen,uiIVLen);
		return ERR_OK;
	}
	else
	{
		rv = (pbResParas[MESSAGE_HEADER_LEN+2]-'0')*10+(pbResParas[MESSAGE_HEADER_LEN+3]-'0');
		if (memcmp(pbResParas+uiResParasLen,pcResAckCode,2) == 0)
		{
			LOG(LOG_ERROR, rv, "SMAPIPBOCMAC_index");
			return rv;
		}
		else
		{
			LOG(LOG_ERROR, rv, "SMAPIPBOCMAC_index");
			return ERR_OTHER;
		}
	}
}

/****************************************************************************************************************
1. 8.14 密钥转加密增强型（7.6.11 密钥转加密增强型）    （KG）
2. 函数功能：
	用mech 指定算法对密钥进行转加密，即将key 由LMK 加密转为由
	wrapKey 对应的密钥加密。
	加密机操作步骤：
	步骤1：用LMK 解密wrapKey。
	步骤2：用LMK 解密key，得到PlainKey
	步骤3：计算DATALEN = LEN(prePix + PlainKey)
	步骤4：Data= DATALEN + prePix + PlainKey，填充数据方式同1.11 小
	节MAC 计算的填充方式。如果prePix 为空，则无密钥前缀
	步骤5：用步骤1 解密的wrapKey 和mech 制定算法加密Data，将结
	果通过outData 数据返回。
3. 输入参数：
	UINT nSock：连接的socket 句柄
	char * wrapKey：经LMK 加密的加密密钥的密文值，16 进制ASCII 字符串。（例
	如：8 字节密钥，则该输入为16 个ASCII 字符串）
	UINT mech：算法类型：decryptMech = 20 表示DES_ECB 算法。
	decryptMech = 17 表示DES_CBC 算法。
	char * key：待处理的密钥数据，16 进制ASCII 字符串，数据长度为16 的整数倍。
	（该密钥数据同样经LMK 加密）
	char *IV：CBC 解密时的初始向量
	char *prePix 待处理的密钥前缀。
4. 输出参数：
	char *outData： 输出密钥，16 进制ASCII 字符串，即由wrapKey 加密的Key 的密文
5. 返回值： 
	0：成功
	其他：失败错误代码
*****************************************************************************************************************/
int SMAPIwrapEnhance(UINT  nSock,char * wrapKey,UINT mech,char *key,char *IV,char *prePix,char *outData)
{
	int rv = 0;
	unsigned char *pcReqCommandCode=(unsigned char *)"KGT";
	unsigned char *pcResAckCode=(unsigned char *)"KH00";
	unsigned char  pbReqParas[MAX_BUFFER_SIZE]={0};
	unsigned int  uiReqParasLen=0;
	unsigned char pbResParas[MAX_BUFFER_SIZE]={0};
	unsigned int  uiResParasLen=MAX_BUFFER_SIZE;

	//返回参数
	unsigned char pbKey1WithID[50] = {0};
	unsigned char pbKey2WithID[50] = {0};
	unsigned int uiKey1WithIDLen = 0;
	unsigned int uiKey2WithIDLen = 16;


	//辅助参数
	int tmpLen = 0;
	unsigned int  wrapKeyLen=0, keyLen=0, ivLen=0, prePixLen=0;
	if (wrapKey == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIwrapEnhance->wrapKey");
		return ERR_INPUT_DATA;
	}
	if (key == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIwrapEnhance->key");
		return ERR_INPUT_DATA;
	}

	if (wrapKey == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIwrapEnhance->wrapKey");
		return ERR_INPUT_DATA;
	}
	if (key == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIwarpEnhance->key");
		return ERR_INPUT_DATA;
	}
	wrapKeyLen=(unsigned int)strlen((char*)wrapKey);
	keyLen=(unsigned int)strlen((char*)key);
	if(IV == NULL)
		ivLen = 0;
	else
		ivLen=(unsigned int)strlen((char*)IV);
	prePixLen=(unsigned int)strlen((char*)prePix);

	switch(wrapKeyLen)
	{
	case 16:
		break;
	case 32:
		pbKey1WithID[0] = 'X';
		break;
	case 48:
		pbKey1WithID[0] = 'Y';
		break;
	default:
		LOG(LOG_ERROR, wrapKeyLen, "SMAPIwrapEnhance->nwrapKeyLen");
		return ERR_KEY_LEN;
		break;
	}
	if (wrapKeyLen ==16)
	{
		memcpy(pbKey1WithID,wrapKey,wrapKeyLen);
	} 
	else
	{
		memcpy(pbKey1WithID + 1,wrapKey,wrapKeyLen);
		uiKey1WithIDLen = wrapKeyLen +1;
	}
	switch(keyLen)
	{
	case 16:
		break;
	case 32:
		pbKey2WithID[0] = 'X';
		break;
	case 48:
		pbKey2WithID[0] = 'Y';
		break;
	default:
		LOG(LOG_ERROR, keyLen, "SMAPIwrapEnhance->nKeyLen");
		return ERR_KEY_LEN;
		break;
	}
	if (keyLen ==16)
	{
		memcpy(pbKey2WithID,key,keyLen);

	} 
	else
	{
		memcpy(pbKey2WithID + 1,key,keyLen);
		uiKey2WithIDLen = keyLen +1;
	}
	uiReqParasLen = MESSAGE_HEADER_LEN;
	memcpy(pbReqParas + uiReqParasLen, pcReqCommandCode, 3);
	uiReqParasLen += 3;

	if (mech == 20)
	{
		Int2Num(1, (char *)(pbReqParas+uiReqParasLen), 2);
		ivLen=0;
	} 
	else if (mech == 17)
	{
		Int2Num(2, (char *)(pbReqParas+uiReqParasLen), 2);

		if (ivLen >= 16)
		{
			ivLen=16;
		} 
		else
		{
			LOG(LOG_ERROR, ivLen, "SMAPIwrapEnhance->ivLen");
			return ERR_INPUT_DATA;
		}
	}
	else
	{
		LOG(LOG_ERROR, mech, "SMAPIwrapEnhance->mech");
		return ERR_ALG_ID;
	}
	uiReqParasLen += 2;

	if (prePix!=NULL)
	{
		Int2Num(prePixLen/2, (char *)(pbReqParas+uiReqParasLen), 2);
		uiReqParasLen += 2;
		memcpy(pbReqParas+uiReqParasLen, prePix, prePixLen);
		uiReqParasLen += prePixLen;
	}
	memcpy(pbReqParas+uiReqParasLen, IV, ivLen);
	uiReqParasLen += ivLen;

	memcpy(pbReqParas + uiReqParasLen,pbKey1WithID,uiKey1WithIDLen);
	uiReqParasLen += uiKey1WithIDLen;

	memcpy(pbReqParas + uiReqParasLen,pbKey2WithID,uiKey2WithIDLen);
	uiReqParasLen += uiKey2WithIDLen;

	//参数处理
	rv = SocketCommunication_Racal(nSock, pbReqParas, uiReqParasLen, pbResParas, &uiResParasLen, unTimeout_ABC);

	if (rv)
	{
		LOG(LOG_ERROR, rv, "SMAPIwrapEnhance->SocketCommunication_Racal");
		return rv;
	}
	uiResParasLen = MESSAGE_HEADER_LEN ;
	if (memcmp(pbResParas + uiResParasLen,pcResAckCode,4) == 0)
	{
		uiResParasLen += 4;

		tmpLen = Num2Int((char *)(pbResParas+uiResParasLen), 4);
		uiResParasLen+=4;
		memcpy(outData, pbResParas+uiResParasLen,tmpLen*2);
		return ERR_OK;
	}
	else
	{
		rv = (pbResParas[MESSAGE_HEADER_LEN+2]-'0')*10+(pbResParas[MESSAGE_HEADER_LEN+3]-'0');
		if (memcmp(pbResParas+uiResParasLen,pcResAckCode,2) == 0)
		{
			LOG(LOG_ERROR, rv, "SMAPIwrapEnhance");
			return rv;
		}
		else
		{
			LOG(LOG_ERROR, rv, "SMAPIwrapEnhance");
			return ERR_OTHER;
		}
	}
}

/****************************************************************************************************************
1. 8.15 密钥转加密增强型(索引版) （7.6.11 密钥转加密增强型）     （KG）
2. 函数功能：
	用mech 指定算法对密钥进行转加密，即将key 由LMK 加密转为由
	wrapKey 对应的密钥加密。
	加密机操作步骤：
	步骤1：用LMK 解密key，得到PlainKey
	步骤2：计算DATALEN = LEN(prePix + PlainKey)
	步骤3：Data= DATALEN +prePix + PlainKey，填充数据方式同1.11 小节MAC
	计算的填充方式。如果prePix 为空，则无密钥前缀
	步骤4：用wrapKeyIndex 指定的密钥索引和mech 制定算法加密Data，将结
	果通过outData 数据返回。
3. 输入参数：
	UINT nSock：连接的socket 句柄
	int wrapKeyIndex：指定的转加密密钥索引
	UINT mech：算法类型：decryptMech = 20 表示DES_ECB 算法。
	decryptMech = 17 表示DES_CBC 算法。
	char * key：待处理的密钥数据，16 进制ASCII 字符串，数据长度为16 的整数倍。
	（该密钥数据经LMK 加密）
	char *IV：CBC 解密时的初始向量
	char *prePix 待处理的密钥前缀。
4. 输出参数：
	char *outData： 输出密钥，16 进制ASCII 字符串，即由wrapKey 加密的Key 的密文
5. 返回值： 
	0：成功
	其他：失败错误代码
*****************************************************************************************************************/
int SMAPIwrapEnhance_index (UINT  nSock ,int wrapKeyIndex, UINT mech, char *key, char *IV, char *prePix ,  char *outData)
{
	int rv = 0;
	unsigned char *pcReqCommandCode=(unsigned char *)"KGT";
	unsigned char *pcResAckCode=(unsigned char *)"KH00";
	unsigned char  pbReqParas[MAX_BUFFER_SIZE]={0};
	unsigned int  uiReqParasLen=0;
	unsigned char pbResParas[MAX_BUFFER_SIZE]={0};
	unsigned int  uiResParasLen=MAX_BUFFER_SIZE;

	//返回参数
	unsigned char pbKey1WithID[50] = {0};
	unsigned char pbKey2WithID[50] = {0};
	unsigned int uiKey1WithIDLen = 0;
	unsigned int uiKey2WithIDLen = 16;

	//辅助参数
	int tmpLen = 0;
	unsigned int  keyLen=0, ivLen=0, prePixLen=0;
	if (key == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIwrapEnhance_index->key");
		return ERR_INPUT_DATA;
	}

	keyLen=(unsigned int)strlen((char*)key);
	if(IV == NULL)
		ivLen = 0;
	else
		ivLen=(unsigned int)strlen((char*)IV);
	prePixLen=(unsigned int)strlen((char*)prePix);

	switch(keyLen)
	{
	case 16:
		break;
	case 32:
		pbKey2WithID[0] = 'X';
		break;
	case 48:
		pbKey2WithID[0] = 'Y';
		break;
	default:
		LOG(LOG_ERROR, keyLen, "SMAPIwrapEnhance_index->nKeyLen");
		return ERR_KEY_LEN;
		break;
	}
	if (keyLen ==16)
	{
		memcpy(pbKey2WithID,key,keyLen);
	} 
	else
	{
		memcpy(pbKey2WithID + 1,key,keyLen);
		uiKey2WithIDLen = keyLen +1;
	}
	uiReqParasLen = MESSAGE_HEADER_LEN;
	memcpy(pbReqParas + uiReqParasLen, pcReqCommandCode, 3);
	uiReqParasLen += 3;

	if (mech == 20)
	{
		Int2Num(1, (char *)(pbReqParas+uiReqParasLen), 2);
		ivLen=0;
	} 
	else if (mech == 17)
	{
		Int2Num(2, (char *)(pbReqParas+uiReqParasLen), 2);

		if (ivLen >= 16)
		{
			ivLen=16;
		} 
		else
		{
			LOG(LOG_ERROR, ivLen, "SMAPIwrapEnhance_index->ivLen");
			return ERR_INPUT_DATA;
		}
	}
	else
	{
		LOG(LOG_ERROR, mech, "SMAPIwrapEnhance_index->mech");
		return ERR_ALG_ID;
	}
	uiReqParasLen += 2;

	if (prePix!=NULL)
	{
		Int2Num(prePixLen/2, (char *)(pbReqParas+uiReqParasLen), 2);
		uiReqParasLen += 2;
		memcpy(pbReqParas+uiReqParasLen, prePix, prePixLen);
		uiReqParasLen += prePixLen;
	}
	memcpy(pbReqParas+uiReqParasLen, IV, ivLen);
	uiReqParasLen += ivLen;

	uiKey1WithIDLen = 5;
	pbKey1WithID[0] = 'K';
	pbKey1WithID[1] = '3';
	Int2Num(wrapKeyIndex,(char *)(pbKey1WithID + 2),3);

	memcpy(pbReqParas + uiReqParasLen,pbKey1WithID,uiKey1WithIDLen);
	uiReqParasLen += uiKey1WithIDLen;

	memcpy(pbReqParas + uiReqParasLen,pbKey2WithID,uiKey2WithIDLen);
	uiReqParasLen += uiKey2WithIDLen;

	//参数处理
	rv = SocketCommunication_Racal(nSock, pbReqParas, uiReqParasLen, pbResParas, &uiResParasLen, unTimeout_ABC);

	if (rv)
	{
		LOG(LOG_ERROR, rv, "SMAPIwrapEnhance_index->SocketCommunication_Racal");
		return rv;
	}
	uiResParasLen = MESSAGE_HEADER_LEN ;
	if (memcmp(pbResParas + uiResParasLen,pcResAckCode,4) == 0)
	{
		uiResParasLen += 4;

		tmpLen = Num2Int((char *)(pbResParas+uiResParasLen), 4);
		uiResParasLen+=4;
		memcpy(outData, pbResParas+uiResParasLen,tmpLen*2);
		return ERR_OK;
	}
	else
	{
		rv = (pbResParas[MESSAGE_HEADER_LEN+2]-'0')*10+(pbResParas[MESSAGE_HEADER_LEN+3]-'0');
		if (memcmp(pbResParas+uiResParasLen,pcResAckCode,2) == 0)
		{
			LOG(LOG_ERROR, rv, "SMAPIwrapEnhance_index");
			return rv;
		}
		else
		{
			LOG(LOG_ERROR, rv, "SMAPIwrapEnhance_index");
			return ERR_OTHER;
		}
	}
}

/****************************************************************************************************************
1. 8.16 密钥转加密扩展型（7.6.12 密钥转加密扩展型）    （KH）
2. 函数功能：
	用以下算法对主控密钥进行转加密。其中，主控密钥= KeyMac^ KeyEnc^
	KeyDek。算法描述如下：
	步骤1：用LMK 解密KeyMac、KeyEnc、KeyDek 得到PlainKeyMac、
	Plain KeyEnc、PlainKeyDek。
	步骤2： Data1= PlainKeyMac^ PlainKeyEnc ^ PlainKeyDek
	步骤3： Data2= 长度(KeyHeader + Data1)+ KeyHeader + Data1 +填充
	数据，其中，长度为1 字节，填充数据方式同1.11 小节MAC 计算的填充方式。
	步骤4、用LMK 解密出wrapKey 明文，即PlainwrapKey
	步骤5、用PlainwrapKey 密钥和mech 制定算法加密Data2，将结果通过outData 数据返回。
3. 输入参数：
	UINT nSock：连接的socket 句柄
	char * KeyMac：经LMK 加密的加密密钥的密文值，16 进制ASCII 字符串。
	char * KeyEnc：经LMK 加密的加密密钥的密文值，16 进制ASCII 字符串。
	char * KeyDek：经LMK 加密的加密密钥的密文值，16 进制ASCII 字符串。
	char* KeyHeader：密钥头数据，16 进制ASCII 字符串。
	char *wrapKey,：经LMK 加密的转加密密钥密文值，16 进制ASCII 字符串。
	UINT mech：分散算法类型： mech = 20 表示DES_ECB 算法。
	           mech = 17 表示DES_CBC 算法。
	char *IV：当mech =CBC 时的初始向量，16 进制ASCII 字符串。
4. 输出参数：
	char *outData： 输出的转加密之后的密钥，16 进制ASCII 字符串
5. 返回值： 
	0：成功
	其他：失败错误代码
*****************************************************************************************************************/
int SMAPIwrap_ext(UINT  nSock , char  *KeyMac, char  *KeyEnc, char  *KeyDek , char  *KeyHeader,char  *wrapKey, UINT mech,  char *IV , char *outData)
{
	int rv = 0;
	unsigned char *pcReqCommandCode=(unsigned char *)"KH";
	unsigned char *pcResAckCode=(unsigned char *)"KI00";
	unsigned char  pbReqParas[MAX_BUFFER_SIZE]={0};
	unsigned int  uiReqParasLen=0;
	unsigned char pbResParas[MAX_BUFFER_SIZE]={0};
	unsigned int  uiResParasLen=MAX_BUFFER_SIZE;

	//辅助参数
	unsigned int uiKeyMacLen = (unsigned int)strlen((char*)KeyMac);
	unsigned int uiKeyEncLen = (unsigned int)strlen((char*)KeyEnc);
	unsigned int uiKeyDekLen = (unsigned int)strlen((char*)KeyDek);
	unsigned int uiKeyHeaderLen = (unsigned int)strlen((char*)KeyHeader);
	unsigned int uiwrapKeyLen = (unsigned int)strlen((char*)wrapKey);
	unsigned int uiIVLen;
	if (KeyMac == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIwrap_ext->KeyMac");
		return ERR_INPUT_DATA;
	}
	if (KeyEnc == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIwrap_ext->KeyENC");
		return ERR_INPUT_DATA;
	}
	if(KeyDek == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIwrap_ext->KeyDek");
		return ERR_INPUT_DATA;
	}
	if(KeyHeader == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIwrap_ext->KeyHeader");
		return ERR_INPUT_DATA;
	}
	if(wrapKey == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIwrap_ext->wrapKey,");
		return ERR_INPUT_DATA;
	}
	if(IV == NULL)
		uiIVLen = 0;
	else
		uiIVLen=(unsigned int)strlen((char*)IV);

	if (!((uiKeyMacLen==uiKeyEncLen)&&(uiKeyMacLen==uiKeyDekLen)))
	{
		LOG(LOG_ERROR, uiKeyMacLen, "SMAPIwrap_ext->uiKeyMacLen");
		return ERR_INPUT_DATA;
	}
	switch(uiKeyMacLen)
	{
	case 16:
	case 32:
	case 48:
		break;
	default:
		LOG(LOG_ERROR, uiKeyMacLen, "SMAPIwrap_ext->uiKeyMacLen");
		return ERR_INPUT_DATA;
	}
	switch(mech)
	{
	case 17:
		mech = 2;
		if (uiIVLen!= 16)
		{
			LOG(LOG_ERROR, uiIVLen, "SMAPIwrap_ext_index->uiIVLen");
			return ERR_INPUT_DATA;
		}
		break;
	case 20:
		mech = 1;
		break;
	default:
		LOG(LOG_ERROR, mech, "SMAPIwrap_ext->mech");
		return ERR_ALG_ID;
	}
	if (uiwrapKeyLen!= 32)
	{
		LOG(LOG_ERROR, uiwrapKeyLen, "SMAPIwrap_ext->wrapKey");
		return ERR_KEY_LEN;
	}
	uiKeyMacLen /= 2;
	uiKeyEncLen /= 2;
	uiKeyDekLen /= 2;
	uiKeyHeaderLen /= 2;

	uiReqParasLen = MESSAGE_HEADER_LEN;
	memcpy(pbReqParas+uiReqParasLen, pcReqCommandCode, 2);
	uiReqParasLen += 2;

	Int2Num(mech, (char *)(pbReqParas+uiReqParasLen), 2);
	uiReqParasLen += 2;

	memcpy(pbReqParas+uiReqParasLen, "X", 1);
	uiReqParasLen += 1;

	memcpy(pbReqParas+uiReqParasLen, wrapKey, uiwrapKeyLen);
	uiReqParasLen += uiwrapKeyLen;

	Int2Num(uiKeyMacLen, (char *)(pbReqParas+uiReqParasLen), 2);
	uiReqParasLen += 2;

	Hex2Bin(KeyMac, pbReqParas+uiReqParasLen,&uiKeyMacLen);
	uiReqParasLen += uiKeyMacLen;

	Int2Num(uiKeyEncLen, (char *)(pbReqParas+uiReqParasLen), 2);
	uiReqParasLen += 2;

	Hex2Bin(KeyEnc, pbReqParas+uiReqParasLen,&uiKeyEncLen);
	uiReqParasLen += uiKeyEncLen;

	Int2Num(uiKeyDekLen, (char *)(pbReqParas+uiReqParasLen), 2);
	uiReqParasLen += 2;

	Hex2Bin(KeyDek, pbReqParas+uiReqParasLen,&uiKeyDekLen);
	uiReqParasLen += uiKeyDekLen;

	Int2Num(uiKeyHeaderLen, (char *)(pbReqParas+uiReqParasLen), 2);
	uiReqParasLen += 2;

	Hex2Bin(KeyHeader, pbReqParas+uiReqParasLen,&uiKeyHeaderLen);
	uiReqParasLen += uiKeyHeaderLen;

	if (mech == 2)
	{
		memcpy(pbReqParas+uiReqParasLen, IV, uiIVLen);
		uiReqParasLen += uiIVLen;
	}
	rv = SocketCommunication_Racal(nSock, pbReqParas, uiReqParasLen, pbResParas, &uiResParasLen, unTimeout_ABC);
	if (rv)
	{
		LOG(LOG_ERROR, rv, "SMAPIwrap_ext");
		return rv;
	}
	uiResParasLen = MESSAGE_HEADER_LEN ;
	if(memcmp(pbResParas + uiResParasLen,pcResAckCode,4) == 0)
	{
		uiResParasLen += 4;
		uiKeyMacLen = Num2Int((char *)(pbResParas + uiResParasLen),2);
		uiResParasLen += 2;
		Bin2Hex(pbResParas + uiResParasLen,uiKeyMacLen,outData);
		return ERR_OK;
	}
	else
	{
		rv = (pbResParas[MESSAGE_HEADER_LEN+2]-'0')*10+(pbResParas[MESSAGE_HEADER_LEN+3]-'0');
		if (memcmp(pbResParas+uiResParasLen,pcResAckCode,2) == 0)
		{
			LOG(LOG_ERROR, rv, "SMAPIwrap_ext");
			return rv;
		}
		else
		{
			LOG(LOG_ERROR, rv, "SMAPIwrap_ext");
			return ERR_OTHER;
		}
	}
}

/****************************************************************************************************************
 * 1. 8.17 密钥转加密扩展型（索引版）（7.6.12 密钥转加密扩展型）  （KH）
 * 2. 函数功能：
 *	用以下算法对主控密钥进行转加密。其中，主控密钥= KeyMac^ KeyEnc^
 *	KeyDek。算法描述如下：
 *	步骤1：用LMK 解密KeyMac、KeyEnc、KeyDek 得到PlainKeyMac、
 *	Plain KeyEnc、PlainKeyDek。
 *	步骤2： Data1= PlainKeyMac^ PlainKeyEnc ^ PlainKeyDek
 *	步骤3： Data2= 长度(KeyHeader + Data1)+ KeyHeader + Data1 +填充
 *	数据，其中，长度为1 字节，填充数据方式同1.11 小节MAC 计算的
 *	填充方式。
 *	步骤4、用wrapKeyIndex 指定密钥和mech 制定算法加密Data2，将
 *	结果通过outData 数据返回。
 * 3. 输入参数：
 *	UINT nSock：连接的socket 句柄
 *	char * KeyMac：经LMK 加密的加密密钥的密文值，16 进制ASCII 字符串。
 *	char * KeyEnc：经LMK 加密的加密密钥的密文值，16 进制ASCII 字符串。
 *	char * KeyDek：经LMK 加密的加密密钥的密文值，16 进制ASCII 字符串。
 *	char* KeyHeader：密钥头数据，16 进制ASCII 字符串。
 *	UINT wrapKeyIndex：转加密密钥索引 
 *	UINT mech：分散算法类型： 
 *                 mech = 20 表示DES_ECB 算法。
 *	           mech = 17 表示DES_CBC 算法。
 *	char *IV： 当mech =CBC 时的初始向量，16 进制ASCII 字符串。
 * 4. 输出参数：
 *	char *outData： 输出的转加密之后的密钥，16 进制ASCII 字符串
 * 5. 返回值： 
 *	0：成功
 *	其他：失败错误代码
*****************************************************************************************************************/
int SMAPIwrap_ext_index (UINT  nSock , char  *KeyMac, char  * KeyEnc, char  *KeyDek , char  *KeyHeader,UINT  wrapKeyIndex, 
                         UINT mech,  char *IV , char *outData)
{
	int rv = 0;
	unsigned char *pcReqCommandCode=(unsigned char *)"KH";
	unsigned char *pcResAckCode=(unsigned char *)"KI00";
	unsigned char  pbReqParas[MAX_BUFFER_SIZE]={0};
	unsigned int  uiReqParasLen=0;
	unsigned char pbResParas[MAX_BUFFER_SIZE]={0};
	unsigned int  uiResParasLen=MAX_BUFFER_SIZE;

	//
	unsigned int uiKeyMacLen = (unsigned int)strlen((char*)KeyMac);
	unsigned int uiKeyEncLen = (unsigned int)strlen((char*)KeyEnc);
	unsigned int uiKeyDekLen = (unsigned int)strlen((char*)KeyDek);
	unsigned int uiKeyHeaderLen = (unsigned int)strlen((char*)KeyHeader);
	unsigned int uiIVLen;
	if (KeyMac == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIwrap_ext_index->KeyMac");
		return ERR_INPUT_DATA;
	}
	if (KeyEnc == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIwrap_ext_index->KeyENC");
		return ERR_INPUT_DATA;
	}
	if(KeyDek == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIwrap_ext_index->KeyDek");
		return ERR_INPUT_DATA;
	}
	if(KeyHeader == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIwrap_ext_index->KeyHeader");
		return ERR_INPUT_DATA;
	}
	if(IV == NULL)
		uiIVLen = 0;
	else
		uiIVLen=(unsigned int)strlen((char*)IV);

	if (!((uiKeyMacLen==uiKeyEncLen)&&(uiKeyMacLen==uiKeyDekLen)))
	{
		return ERR_INPUT_DATA;
	}
	switch(uiKeyMacLen)
	{
	case 16:
	case 32:
	case 48:
		break;
	default:
		LOG(LOG_ERROR, uiKeyMacLen, "SMAPIwrap_ext_index->uiKeyMacLen");
		return ERR_INPUT_DATA;
	}
	switch(mech)
	{
	case 17:
		mech = 2;
		if (uiIVLen!= 16)
		{
			LOG(LOG_ERROR, uiIVLen, "SMAPIwrap_ext_index->uiIVLen");
			return ERR_INPUT_DATA;
		}
		break;
	case 20:
		mech = 1;
		break;
	default:
		LOG(LOG_ERROR, mech, "SMAPIwrap_ext_index->mech");
		return ERR_ALG_ID;
	}
	uiKeyMacLen /= 2;
	uiKeyEncLen /= 2;
	uiKeyDekLen /= 2;
	uiKeyHeaderLen /= 2;

	uiReqParasLen = MESSAGE_HEADER_LEN;
	memcpy(pbReqParas+uiReqParasLen, pcReqCommandCode, 2);
	uiReqParasLen += 2;

	Int2Num(mech, (char *)(pbReqParas+uiReqParasLen), 2);
	uiReqParasLen += 2;

	memcpy(pbReqParas+uiReqParasLen, "K3", 2);
	uiReqParasLen += 2;

	Int2Num(wrapKeyIndex, (char *)(pbReqParas+uiReqParasLen),3);
	uiReqParasLen += 3;

	Int2Num(uiKeyMacLen, (char *)(pbReqParas+uiReqParasLen), 2);
	uiReqParasLen += 2;

	Hex2Bin(KeyMac, pbReqParas+uiReqParasLen,&uiKeyMacLen);
	uiReqParasLen += uiKeyMacLen;

	Int2Num(uiKeyEncLen, (char *)(pbReqParas+uiReqParasLen), 2);
	uiReqParasLen += 2;

	Hex2Bin(KeyEnc, pbReqParas+uiReqParasLen,&uiKeyEncLen);
	uiReqParasLen += uiKeyEncLen;

	Int2Num(uiKeyDekLen, (char *)(pbReqParas+uiReqParasLen), 2);
	uiReqParasLen += 2;

	Hex2Bin(KeyDek, pbReqParas+uiReqParasLen,&uiKeyDekLen);
	uiReqParasLen += uiKeyDekLen;

	Int2Num(uiKeyHeaderLen, (char *)(pbReqParas+uiReqParasLen), 2);
	uiReqParasLen += 2;

	Hex2Bin(KeyHeader, pbReqParas+uiReqParasLen,&uiKeyHeaderLen);
	uiReqParasLen += uiKeyHeaderLen;

	if (mech == 2)
	{
		memcpy(pbReqParas+uiReqParasLen, IV, uiIVLen);
		uiReqParasLen += uiIVLen;
	}
	rv = SocketCommunication_Racal(nSock, pbReqParas, uiReqParasLen, pbResParas, &uiResParasLen, unTimeout_ABC);
	if (rv)
	{
		LOG(LOG_ERROR, rv, "SMAPIwrap_ext_index->SocketCommunication_Racal");
		return rv;
	}
	uiResParasLen = MESSAGE_HEADER_LEN ;
	if(memcmp(pbResParas + uiResParasLen,pcResAckCode,4) == 0)
	{
		uiResParasLen += 4;
		uiKeyMacLen = Num2Int((char *)(pbResParas + uiResParasLen),2);
		uiResParasLen += 2;
		Bin2Hex(pbResParas + uiResParasLen,uiKeyMacLen,outData);
		return ERR_OK;
	}
	else
	{
		rv = (pbResParas[MESSAGE_HEADER_LEN+2]-'0')*10+(pbResParas[MESSAGE_HEADER_LEN+3]-'0');
		if (memcmp(pbResParas+uiResParasLen,pcResAckCode,2) == 0)
		{
			LOG(LOG_ERROR, rv, "SMAPIwrap_ext_index");
			return rv;
		}
		else
		{
			LOG(LOG_ERROR, rv, "SMAPIwrap_ext_index");
			return ERR_OTHER;
		}
	}
}

/****************************************************************************************************************
1. 8.18 用LMK 加密密钥（7.6.13 用HMK 加密密钥扩展型）  （UX）
2. 函数功能：
	将密钥的明文，以LMK 加密，输出密文
3. 输入参数：
	UINT nSock：连接的socket 句柄
	char *pszPlainKey：密钥的明文，16 进制ASCII 字符串, 长度由nKeyLen 指定
	int nKeyLen：pszPlainKey 的长度，取值范围：{8,16,24}
4. 输出参数：
	char * pszKeyUnderLMK：被LMK 加密的密钥的密文
5. 返回值：
	0： 成功
	1： 输入参数验证失败
	3： 向加密机发送数据失败
	4： 接收加密机数据超时
	5： 接收到的数据格式错
	9:  其他错误
*****************************************************************************************************************/
int SMAPIEncryptKey_LMK(UINT nSock, char *pbPlainKey, char *pbKeyUnderHMK)
{
	int rv = 0;
	unsigned char *pcReqCommandCode=(unsigned char *)"UX0101";
	unsigned char *pcResAckCode=(unsigned char *)"UY00";
	unsigned char  pbReqParas[MAX_BUFFER_SIZE]={0};
	unsigned int  uiReqParasLen=0;
	unsigned char pbResParas[MAX_BUFFER_SIZE]={0};
	//unsigned char cmp[MAX_BUFFER_SIZE]={0};
	unsigned int  uiResParasLen = MAX_BUFFER_SIZE;
	unsigned int nKeyLen = (unsigned int)strlen(pbPlainKey);
	//参数处理
	nKeyLen /= 2;
	if (pbPlainKey == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIEncryptKey_LMK->pbPlainKey");
		return ERR_INPUT_DATA;
	}
	if (pbKeyUnderHMK == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIEncryptKey_LMK->pbKeyUnderHMK");
		return ERR_INPUT_DATA;
	}
	if (8 != nKeyLen && 16 != nKeyLen && 24 != nKeyLen)
	{
		LOG(LOG_ERROR, nKeyLen, "SMAPIEncryptKey_LMK->nKeyLen");
		return ERR_INPUT_DATA;
	}
	uiReqParasLen = MESSAGE_HEADER_LEN;
	memcpy(pbReqParas+uiReqParasLen, pcReqCommandCode, 6);
	uiReqParasLen += 6;

	Int2Num(nKeyLen, (char *)(pbReqParas+uiReqParasLen),2);
	uiReqParasLen += 2;

	Hex2Bin(pbPlainKey, pbReqParas + uiReqParasLen, &nKeyLen);
	uiReqParasLen += nKeyLen;
	rv = SocketCommunication_Racal(nSock, pbReqParas, uiReqParasLen, pbResParas, &uiResParasLen, unTimeout_ABC);

	if (rv)
	{
		LOG(LOG_ERROR, rv, "SMAPIEncryptKey_LMK->SocketCommunication_Racal");
		return rv;
	}
	uiResParasLen = MESSAGE_HEADER_LEN ;
	if(memcmp(pbResParas + uiResParasLen,pcResAckCode,4) == 0)
	{
		uiResParasLen += 6;
		Bin2Hex(pbResParas + uiResParasLen, nKeyLen, pbKeyUnderHMK);
		return ERR_OK;
	}
	else
	{
		rv = (pbResParas[MESSAGE_HEADER_LEN+2]-'0')*10+(pbResParas[MESSAGE_HEADER_LEN+3]-'0');
		if (memcmp(pbResParas+uiResParasLen,pcResAckCode,2) == 0)
		{
			LOG(LOG_ERROR, rv, "SMAPIEncryptKey_LMK");
			return rv;
		}
		else
		{
			LOG(LOG_ERROR, rv, "SMAPIEncryptKey_LMK");
			return ERR_OTHER;
		}
	}
}

/****************************************************************************************************************
 * 1. 8.19 用LMK 加密密钥扩展型（7.6.13 用HMK 加密密钥扩展型） （UX）
 * 2. 函数功能：
 *	将三个子密钥进行异或，之后用LMK 加密，输出密文。算法描述如下：
 *	步骤1：用LMK 解密pszKeyMac、pszKeyEnc、pszKeyDek 得到PlainKeyMac、
 *	       Plain KeyEnc、PlainKeyDek。 
 *	步骤2： Data= PlainKeyMac^ PlainKeyEnc ^ PlainKeyDek
 *	步骤3：使用LMK 加密Data 得到其子密钥并输出。
 * 3. 输入参数：
 *	UINT nSock：连接的socket 句柄
 *	char * pszKeyMac：经LMK 加密的加密密钥的密文值，16 进制ASCII 字符串。
 *	char * pszKeyEnc：经LMK 加密的加密密钥的密文值，16 进制ASCII 字符串。
 *	char * pszKeyDek：经LMK 加密的加密密钥的密文值，16 进制ASCII 字符串。
 * 4. 输出参数：
 *	char * pszKeyUnderLMK： 密钥异或之后经LMK 加密的密钥，16 进制ASCII 字符串
 * 5. 返回值： 
 *	0：成功
 *	其他：失败错误代码
*****************************************************************************************************************/
int SMAPIEncryptKeyExt(UINT  nSock,char  *pszKeyMac, char  * pszKeyEnc, char  *pszKeyDek , 
                       char  *pszKeyUnderLMK)
{
	int rv = 0;
	unsigned char *pcReqCommandCode=(unsigned char *)"UX";
	unsigned char *pcResAckCode=(unsigned char *)"UY00";
	unsigned char  pbReqParas[MAX_BUFFER_SIZE]={0};
	unsigned int  uiReqParasLen=0;
	unsigned char pbResParas[MAX_BUFFER_SIZE]={0};
	unsigned int  uiResParasLen=MAX_BUFFER_SIZE;

	//
	unsigned int uiKeyMacLen = (unsigned int)strlen((char*)pszKeyMac)/2;
	unsigned int uiKeyEncLen = (unsigned int)strlen((char*)pszKeyEnc)/2;
	unsigned int uiKeyDekLen = (unsigned int)strlen((char*)pszKeyDek)/2;
	if (pszKeyMac == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIEncrptKeyExt->pszKeyMac");
		return ERR_INPUT_DATA;
	}
	if (pszKeyEnc == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIEncrptKeyExt->pszKeyEnc");
		return ERR_INPUT_DATA;
	}
	if (pszKeyDek == NULL)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIEncrptKeyExt->pszKeyDek");
		return ERR_INPUT_DATA;
	}
	if((uiKeyMacLen !=uiKeyEncLen) || (uiKeyMacLen!=uiKeyDekLen))
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIEncrptKeyExt->uiKeyLen");
		return ERR_INPUT_DATA;
	}
	if(uiKeyMacLen !=8 && uiKeyMacLen!= 16 && uiKeyMacLen !=24)
	{
		LOG(LOG_ERROR, ERR_INPUT_DATA, "SMAPIEncrptKeyExt->uiKeyLen");
		return ERR_INPUT_DATA;
	}
	uiReqParasLen = MESSAGE_HEADER_LEN;
	memcpy(pbReqParas+uiReqParasLen, pcReqCommandCode, 2);
	uiReqParasLen += 2;

	Int2Num(1,(char *)(pbReqParas+uiReqParasLen), 2);
	uiReqParasLen += 2;

	Int2Num(2,(char *)(pbReqParas+uiReqParasLen), 2);
	uiReqParasLen += 2;

	Int2Num(uiKeyMacLen,(char *)(pbReqParas+uiReqParasLen), 2);
	uiReqParasLen += 2;

	Hex2Bin(pszKeyMac,pbReqParas+uiReqParasLen,&uiKeyMacLen);
	uiReqParasLen += uiKeyMacLen;

	Int2Num(uiKeyEncLen, (char *)(pbReqParas+uiReqParasLen), 2);
	uiReqParasLen += 2;

	Hex2Bin(pszKeyEnc, pbReqParas+uiReqParasLen,&uiKeyEncLen);
	uiReqParasLen += uiKeyEncLen;

	Int2Num(uiKeyDekLen, (char *)(pbReqParas+uiReqParasLen), 2);
	uiReqParasLen += 2;

	Hex2Bin(pszKeyDek, pbReqParas+uiReqParasLen,&uiKeyDekLen);
	uiReqParasLen += uiKeyDekLen;

	rv = SocketCommunication_Racal(nSock, pbReqParas, uiReqParasLen, pbResParas, &uiResParasLen, unTimeout_ABC);
	if (rv)
	{
		LOG(LOG_ERROR,rv,"SMAPIEncryptKeyExt->SocketCommunication_Racal");
		return rv;
	}
	uiResParasLen = MESSAGE_HEADER_LEN ;
	if(memcmp(pbResParas + uiResParasLen,pcResAckCode,4) == 0)
	{
		uiResParasLen += 4;
		uiKeyMacLen = Num2Int((char *)(pbResParas + uiResParasLen),2);
		uiResParasLen += 2;
		Bin2Hex(pbResParas + uiResParasLen,uiKeyMacLen,pszKeyUnderLMK);
		return ERR_OK;
	} 
	else
	{
		rv = (pbResParas[MESSAGE_HEADER_LEN+2]-'0')*10+(pbResParas[MESSAGE_HEADER_LEN+3]-'0');
		if (memcmp(pbResParas+uiResParasLen,pcResAckCode,2) == 0)
		{
			LOG(LOG_ERROR, rv, "SMAPIEncryptKeyExt");
			return rv;
		}
		else
		{
			LOG(LOG_ERROR, rv, "SMAPIEncryptKeyExt");
			return ERR_OTHER;
		}
	}
}

/******************************************************  卫士通   *********************************************************/
/***************************************************************************************************************************
 * 4.3 无主账号的ANSI X9.8 PIN加密 （V2）
 * 1.功能描述: 用ANSI X9.8 标准对PIN明文加密，主帐号不参与计算（7.3.6 数据加解密）
 * 2.输入参数:
 *          UINT nSock：连接的socket 句柄
 *          int nAlgo：算法类型。Single_Des = 1；Double_Des = 2 ；Triple_Des = 3
 *          byte *pbPinKey：经HMK 加密的Pik 的密文值，二进制数(nAlgo =1 时，8 字节长, nAlgo=2 时，16 字节长, nAlgo=3 时，24 字节长)
 *          char *pszPlainPin：Pin 的明文。buffer 长度：13 字节长。数字字符型
 *
 * 3.输出参数:
 *          u8 bCryptPin[8], Pin 的密文，8 字节长的二进制数
 * 4.返回值:
 *          0   成功;
 *          1： 输入参数验证失败
 *          2： 无效的密钥（PIK）
 *          3： 向加密机发送数据失败
 *          4： 接收加密机数据超时
 *          5： 接收到的数据格式错
 *          6： 明文数据格式错(Pin)
 *          9: 其他错误
 *
 ***************************************************************************************/
int SMAPIEncryptPinX98A(int nSock,int nAlgo,u8 *pbPinKey,char *pszPlainPin,
                        u8 bCryptPin[8])
{
	int iMsgLen = -1,  retval = -1;
	u8 secbuf_in[HSM_MAX_BUFFER_SIZE] = {0};
	u8 secbuf_out[HSM_MAX_BUFFER_SIZE] = {0};
	int dlen, i=0;
	int nkeylen = 0;

	nkeylen = strlen(pbPinKey);
#ifdef DUMP
	int_dump("nAlgo",nAlgo);
	int_dump("nkeylen",nkeylen);
	data_dump("pbPinKey",pbPinKey,nkeylen);
#endif
	if((nAlgo == 1 && nkeylen != 8)|| (nAlgo == 2 && nkeylen != 16)||(nAlgo == 3 && nkeylen != 24))
	{
		errlog("SMAPIEncryptPinX98A() failed, pbPinKey length is wrong");
		return ERR_KEY_LEN;
	}

	memset(secbuf_in, 0x00, sizeof(secbuf_in));
	memset(secbuf_out, 0x00, sizeof(secbuf_out));

	strcpy(secbuf_in , "V2");
	iMsgLen = 2;

	switch (nAlgo)
	{

	case 0x03:
	case 0x01:
	case 0x02:
		secbuf_in[iMsgLen ++] = DES3;
//		strncpy(&secbuf_in[iMsgLen], TAG3,3);
//		iMsgLen +=3;
		//PIK
		if(nAlgo == 3)
			retval = key_hex2str(pbPinKey , DES3 , &secbuf_in[iMsgLen]);
		else if(nAlgo == 2)
			retval = key_hex2str(pbPinKey , DES2 , &secbuf_in[iMsgLen]);
		else
			retval = key_hex2str(pbPinKey , DES1 , &secbuf_in[iMsgLen]);
		if(retval <0){
			errlog("SMAPIEncryptPinX98A() failed, pbPinKey is wrong");
			return ERR_INPUT;
		}
		iMsgLen += retval;
		//div num
		secbuf_in[iMsgLen ++] = '0';//dvs num
		//enc or dec
		secbuf_in[iMsgLen ++] = ENC; //enc
		//
		secbuf_in[iMsgLen ++] = ECB; //ECB
		//
		secbuf_in[iMsgLen ++] = FILL_80_N;
		//datalen
		sprintf(&secbuf_in[iMsgLen] , "%04d" , 8);
		iMsgLen +=4;
		//data

		retval = pin2pinblock_nopan(DES3, pszPlainPin, &secbuf_in[iMsgLen]);

		if(retval != 0){
			errlog("SMAPIEncryptPinX98A() failed, pszPlainPin is wrong");
			return retval;
		}
		iMsgLen +=8;

		break;
	default:
		errlog("SMAPIEncryptPinX98A() parameter nAlgo is invalid");
		return ERR_ALGO_FLAG;
	}


#ifdef DEBUG_ON
	nhLog(" iMsgLen:%d:\n", iMsgLen);
	nhLog("%s() send:\n", __func__);
	for(i=0;i<iMsgLen;i++)
	{
		nhLog("%02X", secbuf_in[i]);
	}
	nhLog("\n");
#endif

	if ((retval = HSM_LINK(nSock, iMsgLen, secbuf_in, secbuf_out)) != 0)
	{
		errlog("SMAPIEncryptPinX98A() call failed, errno=%d", retval);
		return retval;
	}
	else
	{

#ifdef DEBUG

	data_dump("secbuf_out", secbuf_out, 20);

#endif
		//memcpy(bCryptPin, &secbuf_out[1], 8);
		dlen = (secbuf_out[4]-'0')*1000 + (secbuf_out[5]-'0')*100 + \
				(secbuf_out[6]-'0')*10 +  (secbuf_out[7]-'0') ;

		printf("datoutlen = %d\n",dlen);
		if(dlen != 8){
			errlog("SMAPIEncryptPinX98A() call err datalen, datalen=%d", dlen);
			return ERR_RE_DATA;
		}
		//str2hex(&secbuf_out[8], bCryptPin , 16);
		memcpy(bCryptPin , &secbuf_out[8],8);
	}

	return 0;
}


/**************************************************************************************
 * 4.4 无主账号的ANSI X9.8 PIN加密__国密版 (V2)
 * 功能描述: 用ANSI X9.8 标准对PIN 明文加密，主帐号不参与计算（7.3.6 数据加解密）
 * 输入参数:
 *          UINT nSock：         连接的socket 句柄
 *          int nAlgo：          算法类型。1Des = 1; 2Des = 2; 3Des = 3; SM4 = 4
 *          byte *pbPinKey：     经HMK 加密的Pik 的密文值，二进制数
                                 (nAlgo =1 时，8 字节长, nAlgo=2 时，16 字节长, 
                                 nAlgo=3 时，24 字节长, nAlgo=4 时，16 字节长)
 *          char *pszPlainPin：  Pin 的明文。buffer 长度：13 字节长。数字字符型
 *
 * 输出参数:
 *          byte pbCryptPin[16]：Pin 的密文，nAlgo=1/2/3 时：8 字节长的二进制数；nAlgo=4 时：16 字节长的二进制数
 * 返回值:
 *          0   成功;
 *          1： 输入参数验证失败
 *          2： 无效的密钥（PIK）
 *          3： 向加密机发送数据失败
 *          4： 接收加密机数据超时
 *          5： 接收到的数据格式错
 *          6： 明文数据格式错(Pin)
 *          9:  其他错误
 *
 ***************************************************************************************/
int SMAPIEncryptPinX98A_GM(int nSock,int nAlgo,u8 *pbPinKey,char *pszPlainPin,
                           u8 bCryptPin[8])
{
	int iMsgLen = -1,  retval = -1;
	u8 secbuf_in[HSM_MAX_BUFFER_SIZE] = {0};
	u8 secbuf_out[HSM_MAX_BUFFER_SIZE] = {0};
	int dlen;
	int nkeylen = 0;

	nkeylen = strlen(pbPinKey);
#ifdef DUMP
	int_dump("nAlgo",nAlgo);
	int_dump("nkeylen",nkeylen);
	data_dump("pbPinKey",pbPinKey,nkeylen);
#endif
	if((nAlgo == 1 && nkeylen != 8)|| ((nAlgo == 2 || nAlgo == 4) && nkeylen != 16)||(nAlgo == 3 && nkeylen != 24))
	{
		errlog("SMAPIEncryptPinX98A_GM() failed, pbPinKey length is wrong");
		return ERR_KEY_LEN;
	}

	memset(secbuf_in, 0x00, sizeof(secbuf_in));
	memset(secbuf_out, 0x00, sizeof(secbuf_out));

	strcpy(secbuf_in , "V2");
	iMsgLen = 2;

	switch (nAlgo)
	{
	case 0x02:
	case 0x01:
	case 0x03:
		secbuf_in[iMsgLen ++] = DES3;
//		strncpy(&secbuf_in[iMsgLen], TAG3,3);
//		iMsgLen +=3;
		//PIK
		if(nAlgo == 3)
			retval = key_hex2str(pbPinKey , DES3 , &secbuf_in[iMsgLen]);
		else if(nAlgo == 2)
			retval = key_hex2str(pbPinKey , DES2 , &secbuf_in[iMsgLen]);
		else
			retval = key_hex2str(pbPinKey , DES1 , &secbuf_in[iMsgLen]);

		if(retval <0){
			errlog("SMAPIEncryptPinX98A_GM() failed, pbPinKey is wrong");
			return ERR_INPUT;
		}
		iMsgLen += retval;
		//div num
		secbuf_in[iMsgLen ++] = '0';
		//enc or dec
		secbuf_in[iMsgLen ++] = ENC; //enc
		//
		secbuf_in[iMsgLen ++] = ECB; //ECB
		//
		secbuf_in[iMsgLen ++] = FILL_80_N;
		//datalen
		sprintf(&secbuf_in[iMsgLen] , "%04d" , 8);
		iMsgLen +=4;
		//data

		retval = pin2pinblock_nopan(DES3, pszPlainPin, &secbuf_in[iMsgLen]);
		if(retval != 0){
			errlog("SMAPIEncryptPinX98A_GM() failed, pszPlainPin is wrong");
			return retval;
		}
		iMsgLen +=8;

		break;
	case 0x04:
		secbuf_in[iMsgLen ++] = SM4;
//		strncpy(&secbuf_in[iMsgLen], TAG3,3);
//		iMsgLen +=3;
		//PIK
		retval = key_hex2str(pbPinKey , SM4 , &secbuf_in[iMsgLen]);
		if(retval <0){
			errlog("SMAPIEncryptPinX98A_GM() failed, pbPinKey is wrong");
			return ERR_INPUT;
		}
		iMsgLen += retval;
		//div num
		secbuf_in[iMsgLen ++] = '0';
		//enc or dec
		secbuf_in[iMsgLen ++] = ENC; //enc
		//
		secbuf_in[iMsgLen ++] = ECB; //ECB
		//
		secbuf_in[iMsgLen ++] = FILL_80_N;
		//datalen
		sprintf(&secbuf_in[iMsgLen] , "%04d" , 16);
		iMsgLen +=4;
		//data

		retval = pin2pinblock_nopan(SM4, pszPlainPin, &secbuf_in[iMsgLen]);
		if(retval != 0){
			errlog("SMAPIEncryptPinX98A_GM() failed, pszPlainPin is wrong");
			return retval;
		}
		iMsgLen +=16;

		break;
	default:
		errlog("SMAPIEncryptPinX98A_GM() parameter nAlgo is invalid");
		return ERR_ALGO_FLAG;
	}


#ifdef DEBUG_ON
	nhLog(" iMsgLen:%d:\n", iMsgLen);
	nhLog("%s() send:\n", __func__);
	for(i=0;i<iMsgLen;i++)
	{
		nhLog("%02X", secbuf_in[i]);
	}
	nhLog("\n");
#endif

	if ((retval = HSM_LINK(nSock, iMsgLen, secbuf_in, secbuf_out)) != 0)
	{
		errlog("SMAPIEncryptPinX98A_GM() call failed, errno=%d", retval);
		return retval;
	}
	else
	{
		//memcpy(bCryptPin, &secbuf_out[1], 8);
#ifdef DEBUG

	data_dump("secbuf_out", secbuf_out, 20);

#endif
		dlen = (secbuf_out[4]-'0')*1000 + (secbuf_out[5]-'0')*100 + \
				(secbuf_out[6]-'0')*10 + (secbuf_out[7]-'0') ;
#ifdef DEBUG
	int_dump("bCryptPin dlen", dlen);
#endif

		if(nAlgo != 4)
		{//DES3
			if(dlen != 8)
			{
				errlog("SMAPIEncryptPinX98A_GM() call err datalen, datalen=%d", dlen);
				return ERR_RE_DATA;
			}
			//str2hex(&secbuf_out[8], bCryptPin , 16);
			memcpy(bCryptPin , &secbuf_out[8],8);
#ifdef DEBUG
	data_dump("bCryptPin", bCryptPin, 8);
#endif
		}else{//SM4
			if(dlen != 16)
			{
				errlog("SMAPIEncryptPinX98A_GM() call err datalen, datalen=%d", dlen);
				return ERR_RE_DATA;
			}
			//str2hex(&secbuf_out[8], bCryptPin , 32);
			memcpy(bCryptPin , &secbuf_out[8],16);
#ifdef DEBUG
	data_dump("bCryptPin", bCryptPin, 16);
#endif
		}
	}

	return 0;
}


/**************************************************************************************
 * 4.5 带主账号的ANSI X9.8 PIN加密 （BG）
 *功能描述: 用ANSI X9.8 标准对PIN 明文加密，主帐号参与计算（7.6.1 加密PIN）
 *输入参数:
 *          UINT nSock：连接的socket句柄
 *          int nAlgo：算法类型。1Des=1;2Des=2;3Des=3;
 *          char *pszPan: 主帐号，ASCII 字符串
 *          int nPanLen: 主帐号长度（字节数）
 *          byte *pbPinKey：经HMK加密的Pik的密文值，二进制数(nAlgo=1时，8字节长,nAlgo=2时，16字节长,nAlgo=3时，24字节长
 *          char *pszPlainPin：Pin的明文。buffer长度：13字节长。数字字符型
 *
 *输出参数:
 *          byte bCryptPin[8]：Pin的密文，nAlgo=1/2/3时：8字节长的二进制数
 *返回值:
 *          0--成功;
 *          1：输入参数验证失败
 *          2：无效的密钥（PIK）
 *          3：向加密机发送数据失败
 *          4：接收加密机数据超时
 *          5：接收到的数据格式错
 *          6：明文数据格式错(Pin)
 *          9:其他错误
 *
***************************************************************************************/
int SMAPIEncryptPinX98B(int nSock,int nAlgo,char *pszPan,int nPanLen,u8 *pbPinKey,char *pszPlainPin,
                        u8 bCryptPin[8])
{
	int iMsgLen = -1, pinlen = -1, retval = -1, i = 0;
	u8 secbuf_in[HSM_MAX_BUFFER_SIZE]= {0};
	u8 secbuf_out[HSM_MAX_BUFFER_SIZE]= {0};
	u8 pinwithpad[14];
	int nkeylen = 0;

	nkeylen = strlen(pbPinKey);
#ifdef DUMP
	int_dump("nAlgo",nAlgo);
	int_dump("nkeylen",nkeylen);
	data_dump("pbPinKey",pbPinKey,nkeylen);
#endif
	if((nAlgo == 1 && nkeylen != 8)|| (nAlgo == 2 && nkeylen != 16)||(nAlgo == 3 && nkeylen != 24))
	{
		errlog("SMAPIEncryptPinX98B() failed, pbPinKey length is wrong");
		return ERR_KEY_LEN;
	}
	memset(secbuf_in, 0x00, sizeof(secbuf_in));
	memset(secbuf_out, 0x00, sizeof(secbuf_out));
	strcpy(secbuf_in , "BG");
	iMsgLen = 2;
	switch (nAlgo)
	{
	case 0x02:
	case 0x01:
	case 0x03:
		secbuf_in[iMsgLen ++] = DES3;
		//PIK
		if(nAlgo ==3)
			retval = key_hex2str(pbPinKey , DES3 , &secbuf_in[iMsgLen]);
		else if(nAlgo ==2)
			retval = key_hex2str(pbPinKey , DES2 , &secbuf_in[iMsgLen]);
		else
			retval = key_hex2str(pbPinKey , DES1 , &secbuf_in[iMsgLen]);
		if(retval <0){
			errlog("SMAPIEncryptPinX98B() failed, pbPinKey is wrong");
			return ERR_INPUT;
		}
		iMsgLen += retval;
		//PIN
		pinlen = strlen(pszPlainPin);
		if ((pinlen < 4) || (pinlen > 12))
		{
			errlog("SMAPIEncryptPinX98B() plain PIN length is invalid");
			return ERR_PINLEN;
		}
		//sprintf(&secbuf_in[iMsgLen] , "%02d" , 13);
		//iMsgLen +=2;

		for (i = 0; i < pinlen; i++)
		{
			if (!isdigit(pszPlainPin[i]))
			{
				errlog("SMAPIEncryptPinX98B() failed, pszPlainPin is wrong");
				return ERR_PIN_INVALID;
			}
		}

		if (((nPanLen < 13) || (nPanLen > 19))|| (nPanLen != strlen(pszPan)))
		{
			errlog("SMAPIEncryptPinX98B() parameter nPanLen is invalid");
			return ERR_PAN_LEN;
		}
		for (i = 0; i < nPanLen; i++)
		{
			if (!isdigit(pszPan[i]))
			{
				errlog("SMAPIEncryptPinX98B() failed, pszPan is wrong");
				return ERR_PAN_INVALID;
			}
		}
		/*pin明文补F到13位*/
		memset(pinwithpad, 'F', 13);
		memcpy(pinwithpad, pszPlainPin, pinlen);

		memcpy(&secbuf_in[iMsgLen], pinwithpad, 13);
		iMsgLen += 13;

		/*取最右12位账号*/
		memcpy(&secbuf_in[iMsgLen], pszPan+nPanLen-13, 12);
		iMsgLen += 12;
		break;
	default:
		errlog("SMAPIEncryptPinX98B() parameter nAlgo is invalid");
		return ERR_ALGO_FLAG;
	}




#ifdef DEBUG_ON
	nhLog(" iMsgLen:%d:\n", iMsgLen);
	nhLog("%s() send:\n", __func__);
	for(i=0;i<iMsgLen;i++)
	{
		nhLog("%02X", secbuf_in[i]);
	}
	nhLog("\n");
#endif

	if ((retval = HSM_LINK(nSock, iMsgLen, secbuf_in, secbuf_out)) != 0)
	{
		errlog("SMAPIEncryptPINX98B() call failed, errno=%d", retval);
		return retval;
	}
	else
	{
		str2hex(&secbuf_out[4], bCryptPin , 16);
	#ifdef DUMP
		data_dump("outbCryptPin",bCryptPin,8);
	#endif
	}

	return 0;
}

/**************************************************************************************
 *4.6 带主账号的ANSI X9.8 PIN加密__国密版 （BG）
 *功能描述: 用ANSI X9.8 标准对PIN 明文加密，主帐号参与计算（7.6.1 加密PIN）
 *输入参数:
 *          UINT nSock：连接的socket句柄
 *          int nAlgo：算法类型。1Des=1; 2Des=2; 3Des=3; SM4 = 4
 *          char *pszPan: 主帐号，ASCII 字符串
 *          int nPanLen: 主帐号长度（字节数）
 *          byte *pbPinKey：经HMK加密的Pik的密文值，二进制数(nAlgo=1时，8字节长,nAlgo=2时，16字节长,nAlgo=3时，24字节长, nAlgo=4 时，16 字节长
 *          char *pszPlainPin：Pin的明文。buffer长度：13字节长。数字字符型
 *
 *输出参数:
 *          byte bCryptPin[16]：Pin的密文，nAlgo=1/2/3时：8字节长的二进制数;nAlgo=4 时：16 字节长的二进制数
 *返回值:
 *          0--成功;
 *          1：输入参数验证失败
 *          2：无效的密钥（PIK）
 *          3：向加密机发送数据失败
 *          4：接收加密机数据超时
 *          5：接收到的数据格式错
 *          6：明文数据格式错(Pin)
 *          9: 其他错误
 *
***************************************************************************************/
int SMAPIEncryptPinX98B_GM(int nSock,int nAlgo,char *pszPan,int nPanLen,u8 *pbPinKey,char *pszPlainPin,
                           u8 bCryptPin[16])
{
	int iMsgLen = -1, pinlen = -1, retval = -1, i = 0;
	u8 secbuf_in[HSM_MAX_BUFFER_SIZE]= {0};
	u8 secbuf_out[HSM_MAX_BUFFER_SIZE]= {0};
	u8 pinwithpad[13];
	int nkeylen = 0;

	nkeylen = strlen(pbPinKey);
#ifdef DUMP
	int_dump("nAlgo",nAlgo);
	int_dump("nkeylen",nkeylen);
	data_dump("pbPinKey",pbPinKey,nkeylen);
#endif
	if((nAlgo == 1 && nkeylen != 8)|| ((nAlgo == 2 || nAlgo == 4)&& nkeylen != 16)||(nAlgo == 3 && nkeylen != 24))
	{
		errlog("SMAPIEncryptPinX98B_GM() failed, pbPinKey length is wrong");
		return ERR_KEY_LEN;
	}

	memset(secbuf_in, 0x00, sizeof(secbuf_in));
	memset(secbuf_out, 0x00, sizeof(secbuf_out));
	strcpy(secbuf_in , "BG");
	iMsgLen = 2;
	switch (nAlgo)
	{
	case 0x02:
	case 0x01:
	case 0x03:
		secbuf_in[iMsgLen ++] = DES3;
		//PIK
		if(nAlgo ==3)
			retval = key_hex2str(pbPinKey , DES3 , &secbuf_in[iMsgLen]);
		else if(nAlgo ==2)
			retval = key_hex2str(pbPinKey , DES2 , &secbuf_in[iMsgLen]);
		else
			retval = key_hex2str(pbPinKey , DES1 , &secbuf_in[iMsgLen]);
		if(retval <0){
			errlog("SMAPIEncryptPinX98B_GM() failed, pbPinKey is wrong");
			return ERR_INPUT;
		}
		iMsgLen += retval;
		//PIN

		pinlen = strlen(pszPlainPin);
		if ((pinlen < 4) || (pinlen > 12))
		{
			errlog("SMAPIEncryptPinX98B_GM() plain PIN length is invalid");
			return ERR_PINLEN;
		}
//		sprintf(&secbuf_in[iMsgLen] , "%02d" , pinlen);
//		iMsgLen += 2;

		/*pin明文补F到13位*/
		memset(pinwithpad, 'F', 13);
		memcpy(pinwithpad, pszPlainPin, pinlen);

		memcpy(&secbuf_in[iMsgLen], pinwithpad, 13);

		iMsgLen += 13;

		//PAN

		if ((nPanLen < 13) || (nPanLen > 19) || (nPanLen != strlen(pszPan)))
		{
			errlog("SMAPIEncryptPinX98B_GM() parameter nPanLen is invalid");
			return ERR_PAN_LEN;
		}
		memcpy(&secbuf_in[iMsgLen], pszPan+nPanLen-13, 12);
		iMsgLen += 12;
		break;
	case 0x04:
		secbuf_in[iMsgLen ++] = SM4;
		//PIK
		retval = key_hex2str(pbPinKey , SM4 , &secbuf_in[iMsgLen]);
		if(retval <0){
			errlog("SMAPIEncryptPinX98B_GM() failed, pbPinKey is wrong");
			return ERR_INPUT;
		}
		iMsgLen += retval;

		pinlen = strlen(pszPlainPin);

		if ((pinlen < 4) || (pinlen > 12))
		{
			errlog("SMAPIEncryptPinX98B_GM() plain PIN length is invalid");
			return ERR_PINLEN;
		}
		//sprintf(&secbuf_in[iMsgLen] , "%02d" , pinlen);
	//	iMsgLen +=2;

		memset(pinwithpad, 'F', 13);
		memcpy(pinwithpad, pszPlainPin, pinlen);

		memcpy(&secbuf_in[iMsgLen], pinwithpad, 13);
		iMsgLen += 13;

		//PAN

		if ((nPanLen < 13) || (nPanLen > 19)||(nPanLen != strlen(pszPan)))
		{
			errlog("SMAPIEncryptPinX98B_GM() parameter nPanLen is invalid");
			return ERR_PAN_LEN;
		}
		memcpy(&secbuf_in[iMsgLen], pszPan+nPanLen-13, 12);
		iMsgLen += 12;
		break;
	default:
		errlog("SMAPIEncryptPinX98B_GM() parameter nAlgo is invalid");
		return ERR_ALGO_FLAG;
	}


	for (i = 0; i < pinlen; i++)
	{
		if (!isdigit(pszPlainPin[i]))
		{
			errlog("SMAPIEncryptPinX98B_GM() failed, pszPlainPin is wrong");
			return ERR_PIN_INVALID;
		}
	}

	for (i = 0; i < nPanLen; i++)
	{
		if (!isdigit(pszPan[i]))
		{
			errlog("SMAPIEncryptPinX98B_GM() failed, pszPan is wrong");
			return ERR_PAN_INVALID;
		}
	}

#ifdef DEBUG_ON
	nhLog(" iMsgLen:%d:\n", iMsgLen);
	nhLog("%s() send:\n", __func__);
	for(i=0;i<iMsgLen;i++)
	{
		nhLog("%02X", secbuf_in[i]);
	}
	nhLog("\n");
#endif

	if ((retval = HSM_LINK(nSock, iMsgLen, secbuf_in, secbuf_out)) != 0)
	{
		errlog("SMAPIEncryptPINX98B_GM() call failed, errno=%d", retval);
		return retval;
	}
	else
	{
		if(nAlgo == 3){//DES3
			str2hex(&secbuf_out[4], bCryptPin , 16);

		}else{//SM4

			str2hex(&secbuf_out[4], bCryptPin , 32);
		}
	#ifdef DUMP
		data_dump("outbCryptPin",bCryptPin,16);
	#endif
	}

	return 0;
}

/**************************************************************************************
 * 4.7 无主账号的ANSI X9.8 PIN解密 (V2)
 *功能描述: 用ANSI X9.8 标准对PIN 密文解密，主帐号不参与计算（7.3.6 数据加解密）
 *输入参数:
 *          UINT nSock：连接的socket句柄
 *          int nAlgo：算法类型。1Des=1; 2Des=2; 3Des=3;
 *          char *pbPinKey: 经HMK 加密的Pik 的密文值，二进制数;nAlgo=1时，8字节长,nAlgo=2时，16字节长,nAlgo=3时，24字节长
 *          byte *pbCryptPin：Pin 的密文，8 字节长的二进制数
 *
 *输出参数:
 *          byte szPlainPin[13]：buffer 长度：13 字节长。数字字符型
 *返回值:
 *          0--成功;
 *          1：输入参数验证失败
 *          2：无效的密钥（PIK）
 *          3：向加密机发送数据失败
 *          4：接收加密机数据超时
 *          5：接收到的数据格式错
 *          6：明文数据格式错(Pin)
 *          9:其他错误
 *
***************************************************************************************/
int SMAPIDecryptPinX98A(int nSock,int nAlgo,u8 *pbPinKey,u8 *pbCryptPin,
                        char szPlainPin[13])
{
	int iMsgLen = -1, retval = -1;

	u8 secbuf_in[HSM_MAX_BUFFER_SIZE]= {0};
	u8 secbuf_out[HSM_MAX_BUFFER_SIZE]= {0};
	u8 *tmpp;
	int dlen;
	int nkeylen = 0;

	nkeylen = strlen(pbPinKey);
#ifdef DUMP
	int_dump("nAlgo",nAlgo);
	int_dump("nkeylen",nkeylen);
	data_dump("pbPinKey",pbPinKey,nkeylen);
#endif
	if((nAlgo == 1 && nkeylen != 8)|| (nAlgo == 2 && nkeylen != 16)||(nAlgo == 3 && nkeylen != 24))
	{
		errlog("SMAPIEncryptPinX98A() failed, pbPinKey length is wrong");
		return ERR_KEY_LEN;
	}

	memset(secbuf_in, 0x00, sizeof(secbuf_in));
	memset(secbuf_out, 0x00, sizeof(secbuf_out));

	strcpy(secbuf_in , "V2");
	iMsgLen = 2;
	switch (nAlgo)
	{
	case 0x01:
	case 0x02:
	case 0x03:
		secbuf_in[iMsgLen ++] = DES3;
//		strncpy(&secbuf_in[iMsgLen], TAG3,3);
//		iMsgLen +=3;
		//PIK
		if(nAlgo ==1)
			retval = key_hex2str(pbPinKey , DES1 , &secbuf_in[iMsgLen]);
		else if(nAlgo ==2)
			retval = key_hex2str(pbPinKey , DES2 , &secbuf_in[iMsgLen]);
		else
			retval = key_hex2str(pbPinKey , DES3 , &secbuf_in[iMsgLen]);
		if(retval <0){
			errlog("SMAPIDecryptPinX98A() failed, pbPinKey is wrong");
			return ERR_INPUT;
		}
		iMsgLen += retval;
		//div num
		secbuf_in[iMsgLen ++] = '0';
		//enc or dec
		secbuf_in[iMsgLen ++] = DEC; //enc
		//
		secbuf_in[iMsgLen ++] = ECB; //ECB
		//
		secbuf_in[iMsgLen ++] = FILL_80_N;
		//datalen
		sprintf(&secbuf_in[iMsgLen] , "%04d" , 8);
		iMsgLen +=4;
		//data
		//tmpp = &secbuf_in[iMsgLen];
		//hex2str(pbCryptPin, &tmpp, 8);
		//iMsgLen +=16;
		memcpy(&secbuf_in[iMsgLen] , pbCryptPin , 8);
		iMsgLen +=8;
		break;
	default:
		errlog("SMAPIDecryptPinX98A() nAlgo is invalid");
		return ERR_ALGO_FLAG;
	}

#ifdef DEBUG_ON
	int i;
	nhLog(" iMsgLen:%d:\n", iMsgLen);
	nhLog("%s() send:\n", __func__);
	for(i=0;i<iMsgLen;i++)
	{
		nhLog("%02X", secbuf_in[i]);
	}
	nhLog("\n");
#endif

	if ((retval = HSM_LINK(nSock, iMsgLen, secbuf_in, secbuf_out)) != 0)
	{
		errlog("SMAPIDecryptPinX98A() call failed, errno=%d", retval);
		return retval;
	}
	else
	{
#ifdef DEBUG

	data_dump("secbuf_out", secbuf_out, 20);

#endif
		u8 pinlen , buf[32];
		pinlen = secbuf_out[8];

		if(pinlen <4 || pinlen > 12){
			errlog("SMAPIDecryptPinX98A() call ok, pinlen=%d", pinlen);
			return ERR_PINLEN;
		}

		tmpp = szPlainPin;
		hex2str(&secbuf_out[9], &tmpp, 6);
		szPlainPin[pinlen] = '\0';
	#ifdef DUMP
		printf("szPlainPin=%s\n",szPlainPin);
	#endif
	}

	return 0;
}

/**************************************************************************************
 * 4.8 无主账号的ANSI X9.8 PIN解密__国密版 (V2)
 *功能描述: 用ANSI X9.8 标准对PIN 密文解密，主帐号不参与计算（7.3.6 数据加解密）
 *输入参数:
 *          UINT nSock：连接的socket句柄
 *          int nAlgo：算法类型。1Des=1; 2Des=2; 3Des=3;SM4=4
 *          char *pbPinKey: 经HMK 加密的Pik 的密文值，二进制数;nAlgo=1时，8字节长,nAlgo=2时，16字节长,nAlgo=3时，24字节长, nAlgo=4 时，16 字节长
 *          byte *pbCryptPin：Pin 的密文，nAlgo=1/2/3 时, 8 字节长的二进制数, nAlgo=4 时：16 字节长的二进制数
 *
 *输出参数:
 *          byte szPlainPin[13]：buffer 长度：13 字节长。数字字符型
 *返回值:
 *          0--成功;
 *          1：输入参数验证失败
 *          2：无效的密钥（PIK）
 *          3：向加密机发送数据失败
 *          4：接收加密机数据超时
 *          5：接收到的数据格式错
 *          6：明文数据格式错(Pin)
 *          9:其他错误
 *
***************************************************************************************/
int SMAPIDecryptPinX98A_GM(int nSock,int nAlgo,u8 *pbPinKey,u8 *pbCryptPin,
                           char szPlainPin[13])
{
	int iMsgLen = -1, retval = -1;

	u8 secbuf_in[HSM_MAX_BUFFER_SIZE]= {0};
	u8 secbuf_out[HSM_MAX_BUFFER_SIZE]= {0};
	u8 *tmpp;
	int dlen;
	int nkeylen = 0;

	nkeylen = strlen(pbPinKey);
#ifdef DUMP
	int_dump("nAlgo",nAlgo);
	int_dump("nkeylen",nkeylen);
	data_dump("pbPinKey",pbPinKey,nkeylen);
#endif
	if((nAlgo == 1 && nkeylen != 8)|| ((nAlgo == 2|| nAlgo == 4)&& nkeylen != 16)||(nAlgo == 3 && nkeylen != 24))
	{
		errlog("SMAPIDecryptPinX98A_GM() failed, pbPinKey length is wrong");
		return ERR_KEY_LEN;
	}

	memset(secbuf_in, 0x00, sizeof(secbuf_in));
	memset(secbuf_out, 0x00, sizeof(secbuf_out));

	strcpy(secbuf_in , "V2");
	iMsgLen = 2;
	switch (nAlgo)
	{
	case 0x01:
	case 0x02:
	case 0x03:
		secbuf_in[iMsgLen ++] = DES3;
//		strncpy(&secbuf_in[iMsgLen], TAG3,3);
//		iMsgLen +=3;
		//PIK
		if(nAlgo ==1)
			retval = key_hex2str(pbPinKey , DES1 , &secbuf_in[iMsgLen]);
		else if(nAlgo ==2)
			retval = key_hex2str(pbPinKey , DES2 , &secbuf_in[iMsgLen]);
		else
			retval = key_hex2str(pbPinKey , DES3 , &secbuf_in[iMsgLen]);
		if(retval <0){
			errlog("SMAPIEncryptPinX98A_GM() failed, pbPinKey is wrong");
			return ERR_INPUT;
		}
		iMsgLen += retval;
		//div num
		secbuf_in[iMsgLen ++] = '0';
		//enc or dec
		secbuf_in[iMsgLen ++] = DEC; //enc
		//
		secbuf_in[iMsgLen ++] = ECB; //ECB
		//
		secbuf_in[iMsgLen ++] = FILL_80_N;
		//datalen
		sprintf(&secbuf_in[iMsgLen] , "%04d" , 8);
		iMsgLen +=4;
		//data
		//tmpp = &secbuf_in[iMsgLen];
		//hex2str(pbCryptPin, &tmpp, 8);
		//iMsgLen +=8;
		memcpy(&secbuf_in[iMsgLen] , pbCryptPin , 8);
		iMsgLen +=8;
		break;
	case 0x04:
		secbuf_in[iMsgLen ++] = SM4;
//		strncpy(&secbuf_in[iMsgLen], TAG3,3);
//		iMsgLen +=3;
		//PIK
		retval = key_hex2str(pbPinKey , SM4 , &secbuf_in[iMsgLen]);
		if(retval <0){
			errlog("SMAPIDecryptPinX98A_GM() failed, pbPinKey is wrong");
			return ERR_INPUT;
		}
		iMsgLen += retval;
		//div num
		secbuf_in[iMsgLen ++] = '0';
		//enc or dec
		secbuf_in[iMsgLen ++] = DEC; //enc
		//
		secbuf_in[iMsgLen ++] = ECB; //ECB
		//
		secbuf_in[iMsgLen ++] = FILL_80_N;
		//datalen
		sprintf(&secbuf_in[iMsgLen] , "%04d" , 16);
		iMsgLen +=4;
		//data
		//tmpp = &secbuf_in[iMsgLen];
		//hex2str(pbCryptPin, &tmpp, 16);
		//iMsgLen +=32;
		memcpy(&secbuf_in[iMsgLen] , pbCryptPin , 16);
		iMsgLen +=16;
		break;
	default:
		errlog("SMAPIDecryptPinX98A_GM() nAlgo is invalid");
		return ERR_ALGO_FLAG;
	}

#ifdef DEBUG_ON
	int i;
	nhLog(" iMsgLen:%d:\n", iMsgLen);
	nhLog("%s() send:\n", __func__);
	for(i=0;i<iMsgLen;i++)
	{
		nhLog("%02X", secbuf_in[i]);
	}
	nhLog("\n");
#endif

	if ((retval = HSM_LINK(nSock, iMsgLen, secbuf_in, secbuf_out)) != 0)
	{
		errlog("SMAPIDecryptPinX98A_GM() call failed, errno=%d", retval);
		return retval;
	}
	else
	{
		u8 pinlen , buf[32];
		pinlen = secbuf_out[8];

		if(pinlen <4 || pinlen > 12){
			errlog("SMAPIDecryptPinX98A_GM() call ok, pinlen=%d", pinlen);
			return ERR_PINLEN;
		}

		tmpp = szPlainPin;
		hex2str(&secbuf_out[9], &tmpp, 6);
		szPlainPin[pinlen] = '\0';
	#ifdef DUMP
		printf("szPlainPin=%s\n",szPlainPin);
	#endif
	}

	return 0;
}

/**************************************************************************************
 * 4.9 带主账号的ANSI X9.8 PIN解密  (BC)
 *功能描述: 用ANSI X9.8 标准对PIN 密文解密，主帐号参与计算（7.6.2 解密PIN）
 *输入参数:
 *          UINT nSock：连接的socket句柄
 *          int nAlgo：算法类型。1Des=1; 2Des=2; 3Des=3;
 *          char *pbPinKey: 经HMK 加密的Pik 的密文值，二进制数;nAlgo=1时，8字节长,nAlgo=2时，16字节长,nAlgo=3时，24字节长,
 *          byte *pbCryptPin：Pin 的密文，nAlgo=1/2/3 时, 8 字节长的二进制数,
 *
 *输出参数:
 *          byte szPlainPin[13]：buffer 长度：13 字节长。数字字符型
 *返回值:
 *          0--成功;
 *          1：输入参数验证失败
 *          2：无效的密钥（PIK）
 *          3：向加密机发送数据失败
 *          4：接收加密机数据超时
 *          5：接收到的数据格式错
 *          6：明文数据格式错(Pin)
 *          9:其他错误
 *
***************************************************************************************/
int SMAPIDecryptPinX98B(int nSock,int nAlgo,char *pszPan,int nPanLen,u8 *pbPinKey,u8 *pbCryptPin,
                        char szPlainPin[13])
{
	int iMsgLen = -1, retval = -1, i = 0;

	u8 secbuf_in[HSM_MAX_BUFFER_SIZE]= {0};
	u8 secbuf_out[HSM_MAX_BUFFER_SIZE]= {0};
	u8 *tmpp;
	int pinlen = 0;
	u8 plainpinwithpad[13];
	int nkeylen = 0;

	nkeylen = strlen(pbPinKey);
#ifdef DUMP
	int_dump("nAlgo",nAlgo);
	int_dump("nkeylen",nkeylen);
	data_dump("pbPinKey",pbPinKey,nkeylen);
#endif
	if((nAlgo == 1 && nkeylen != 8)|| ((nAlgo == 2 || nAlgo == 4)&& nkeylen != 16)||(nAlgo == 3 && nkeylen != 24))
	{
		errlog("SMAPIDecryptPinX98B() failed, pbPinKey length is wrong");
		return ERR_KEY_LEN;
	}

	memset(secbuf_in, 0x00, sizeof(secbuf_in));
	memset(secbuf_out, 0x00, sizeof(secbuf_out));

	strcpy(secbuf_in , "BC");
	iMsgLen = 2;
	switch (nAlgo)
	{
	case 0x01:
	case 0x02:
	case 0x03:
		secbuf_in[iMsgLen ++] = DES3;
		//PIK
		if(nAlgo ==1)
			retval = key_hex2str(pbPinKey , DES1 , &secbuf_in[iMsgLen]);
		else if(nAlgo ==2)
			retval = key_hex2str(pbPinKey , DES2 , &secbuf_in[iMsgLen]);
		else
			retval = key_hex2str(pbPinKey , DES3 , &secbuf_in[iMsgLen]);
		if(retval <0){
			errlog("SMAPIDecryptPinX98B() failed, pbPinKey is wrong");
			return ERR_INPUT;
		}
		iMsgLen += retval;
		//PIN cipher
		tmpp =  &secbuf_in[iMsgLen];
		hex2str(pbCryptPin, &tmpp, 8);
		iMsgLen += 16;

		//PAN

		if ((nPanLen < 13) || (nPanLen > 19)|| (nPanLen != strlen(pszPan)))
		{
			errlog("SMAPIDecryptPinX98B() parameter nPanLen is invalid");
			return ERR_PAN_LEN;
		}
		memcpy(&secbuf_in[iMsgLen], pszPan+nPanLen-13, 12);
		iMsgLen += 12;
		break;
	default:
		errlog("SMAPIDecryptPINX98B() parameter nAlgo is invalid");
		return ERR_ALGO_FLAG;
	}

	for (i = 0; i < nPanLen; i++)
	{
		if (!isdigit(pszPan[i]))
		{
			errlog("SMAPIDecryptPINX98B() failed, pszPan is wrong");
			return ERR_PAN_INVALID;
		}
	}

#ifdef DEBUG_ON
	nhLog(" iMsgLen:%d:\n", iMsgLen);
	nhLog("%s() send:\n", __func__);
	for(i=0;i<iMsgLen;i++)
	{
		nhLog("%02X", secbuf_in[i]);
	}
	nhLog("\n");
#endif

	if ((retval = HSM_LINK(nSock, iMsgLen, secbuf_in, secbuf_out)) != 0)
	{
		errlog("SMAPIDecryptPINX98B() call failed, errno=%d", retval);
		return retval;
	}
	else
	{
		memcpy(plainpinwithpad, &secbuf_out[4], 13);

	#ifdef DUMP
		data_dump("plainpinwithpad", plainpinwithpad, 13);
	#endif

		for (i = 0; i < 13; i++)
	    {
	        if ( plainpinwithpad[i] == 'F')
	            break;
	        if (isdigit(plainpinwithpad[i]) == 0)
	        {
	          	 errlog("SMAPIDecryptPINX98B() failed, plain pin is wrong");
	            return;
	        }
	    }
		pinlen = i;

	#ifdef DUMP
		int_dump("pin len", pinlen);
	#endif

		if(pinlen < 4  || pinlen > 12){
				errlog("SMAPIDecryptPINX98B() failed, call ok   pinlen=%d" , pinlen);
				return ERR_PINLEN;
			}
		memcpy(szPlainPin, plainpinwithpad, pinlen);

		szPlainPin[pinlen] = '\0';
	#ifdef DUMP
		printf("szPlainPin=%s\n",szPlainPin);
	#endif
	}

	return 0;
}

/**************************************************************************************
 * 4.10 带主账号的ANSI X9.8 PIN解密__国密版 (BC)
 *功能描述: 用ANSI X9.8 标准对PIN 密文解密，主帐号参与计算（7.6.2 解密PIN）
 *输入参数:
 *          UINT nSock：连接的socket句柄
 *          int nAlgo：算法类型。1Des=1; 2Des=2; 3Des=3;SM4=4
 *          char *pbPinKey: 经HMK 加密的Pik 的密文值，二进制数;nAlgo=1时，8字节长,nAlgo=2时，16字节长,nAlgo=3时，24字节长, nAlgo=4 时，16 字节长
 *          byte *pbCryptPin：Pin 的密文，nAlgo=1/2/3 时, 8 字节长的二进制数, nAlgo=4 时：16 字节长的二进制数
 *
 *输出参数:
 *          byte szPlainPin[13]：buffer 长度：13 字节长。数字字符型
 *返回值:
 *          0--成功;
 *          1：输入参数验证失败
 *          2：无效的密钥（PIK）
 *          3：向加密机发送数据失败
 *          4：接收加密机数据超时
 *          5：接收到的数据格式错
 *          6：明文数据格式错(Pin)
 *          9:其他错误
 *
***************************************************************************************/
int SMAPIDecryptPinX98B_GM(int nSock,int nAlgo,char *pszPan,int nPanLen,u8 *pbPinKey,u8 *pbCryptPin,
                           char szPlainPin[13])
{
	int iMsgLen = -1, retval = -1, i = 0;

	u8 secbuf_in[HSM_MAX_BUFFER_SIZE]= {0};
	u8 secbuf_out[HSM_MAX_BUFFER_SIZE]= {0};
	u8 *tmpp;
	int pinlen = 0;
	u8 plainpinwithpad[13];
	int nkeylen = 0;

	nkeylen = strlen(pbPinKey);
#ifdef DUMP
	int_dump("nAlgo",nAlgo);
	int_dump("nkeylen",nkeylen);
	data_dump("pbPinKey",pbPinKey,nkeylen);
#endif
	if((nAlgo == 1 && nkeylen != 8)|| ((nAlgo == 2 || nAlgo == 4)&& nkeylen != 16)||(nAlgo == 3 && nkeylen != 24))
	{
		errlog("SMAPIDecryptPinX98B_GM() failed, pbPinKey length is wrong");
		return ERR_KEY_LEN;
	}

	memset(secbuf_in, 0x00, sizeof(secbuf_in));
	memset(secbuf_out, 0x00, sizeof(secbuf_out));

	strcpy(secbuf_in , "BC");
	iMsgLen = 2;
	switch (nAlgo)
	{
	case 0x01:
	case 0x02:
	case 0x03:
		secbuf_in[iMsgLen ++] = DES3;
		//PIK
		if(nAlgo ==1)
			retval = key_hex2str(pbPinKey , DES1 , &secbuf_in[iMsgLen]);
		else if(nAlgo ==2)
			retval = key_hex2str(pbPinKey , DES2 , &secbuf_in[iMsgLen]);
		else
			retval = key_hex2str(pbPinKey , DES3 , &secbuf_in[iMsgLen]);
		if(retval <0){
			errlog("SMAPIDecryptPinX98B_GM() failed, pbPinKey is wrong");
			return ERR_INPUT;
		}
		iMsgLen += retval;
		//PIN cipher
		tmpp =  &secbuf_in[iMsgLen];
		hex2str(pbCryptPin, &tmpp, 8);
		iMsgLen += 16;

		//PAN

		if ((nPanLen < 13) || (nPanLen > 19) || (nPanLen != strlen(pszPan)))
		{
			errlog("SMAPIDecryptPinX98B_GM() parameter nPanLen is invalid");
			return ERR_PAN_LEN;
		}
		memcpy(&secbuf_in[iMsgLen], pszPan+nPanLen-13, 12);
		iMsgLen += 12;
		break;
	case 0x04:
		secbuf_in[iMsgLen ++] = SM4;
		//PIK
		retval = key_hex2str(pbPinKey , SM4 , &secbuf_in[iMsgLen]);
		if(retval <0){
			errlog("SMAPIDecryptPinX98B_GM() failed, pbPinKey is wrong");
			return ERR_INPUT;
		}
		iMsgLen += retval;
		//PIN cipher
		tmpp =  &secbuf_in[iMsgLen];
		hex2str(pbCryptPin, &tmpp, 16);
		iMsgLen += 32;

		//PAN

		if ((nPanLen < 13) || (nPanLen > 19)|| ( nPanLen != strlen(pszPan)))
		{
			errlog("SMAPIDecryptPinX98B_GM() parameter nPanLen is invalid");
			return ERR_PAN_LEN;
		}
		memcpy(&secbuf_in[iMsgLen], pszPan+nPanLen-13, 12);
		iMsgLen += 12;
		break;

	default:
		errlog("SMAPIDecryptPinX98B_GM() parameter nAlgo is invalid");
		return ERR_ALGO_FLAG;
	}

	for (i = 0; i < nPanLen; i++)
	{
		if (!isdigit(pszPan[i]))
		{
			errlog("SMAPIDecryptPinX98B_GM() failed, pszPan is wrong");
			return ERR_PAN_INVALID;
		}
	}

#ifdef DEBUG_ON
	nhLog(" iMsgLen:%d:\n", iMsgLen);
	nhLog("%s() send:\n", __func__);
	for(i=0;i<iMsgLen;i++)
	{
		nhLog("%02X", secbuf_in[i]);
	}
	nhLog("\n");
#endif

	if ((retval = HSM_LINK(nSock, iMsgLen, secbuf_in, secbuf_out)) != 0)
	{
		errlog("SMAPIDecryptPinX98B_GM() call failed, errno=%d", retval);
		return retval;
	}
	else
	{
		memcpy(plainpinwithpad, &secbuf_out[4], 13);

	#ifdef DUMP
		data_dump("plainpinwithpad", plainpinwithpad, 13);
	#endif

		for (i = 0; i < 13; i++)
	    {
	        if ( plainpinwithpad[i] == 'F')
	            break;
	        if (isdigit(plainpinwithpad[i]) == 0)
	        {
	          	 errlog("SMAPIDecryptPINX98B() failed, plain pin is wrong");
	            return;
	        }
	    }
		pinlen = i;

	#ifdef DUMP
		int_dump("pin len", pinlen);
	#endif

		if(pinlen < 4  || pinlen > 12){
				errlog("SMAPIDecryptPINX98B() failed, call ok   pinlen=%d" , pinlen);
				return ERR_PINLEN;
			}
		memcpy(szPlainPin, plainpinwithpad, pinlen);

		szPlainPin[pinlen] = '\0';
	#ifdef DUMP
		printf("szPlainPin=%s\n",szPlainPin);
	#endif

	}
	return 0;
}


/**************************************************************************************
 * 4.11 MAC计算  (V4)
 * 功能描述: 用指定的MacKey计算一段报文数据的MAC值(7.3.7 计算MAC)
 * 填充方式：若报文数据不够8 字节的整数倍，后面填充0x00 直到长度为8 的整数倍；
 *     		 如果报文数据长度为8 的整数倍，不填充
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          nAlgo:  算法类型: ECB = 1; X9.9 = 2; x9.19 = 3
 *          pbMacKey: 经HMK(LMK)加密的Mak的密文值,二进制数
 *          nMakLen: Mak长度, 即pbMacKey的buffer长度
 *                   nAlgo = 1和nAlgo = 2时, nMakLen应为8
 *                   nAlgo = 3时, nMakLen应为16
 *          pbMsgBuf: 需要计算MAC的数据buffer,二进制数
 *          nMsgLen:  数据buffer的长度, 范围: 8--2048
 *
 * 输出参数:
 *          bMAC: 计算所得的数据报文的MAC
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          2: 无效的密钥(MAK);
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9 -- 其它错误
 *
 ***************************************************************************************/
int SMAPICalcMac(int nSock,int nAlgo,u8 *pbMacKey,int nMakLen,u8 *pbMsgBuf,int nMsgLen,
                 u8 bMAC[8])
{
	int iMsgLen = -1, retval = -1;

	u8 secbuf_in[HSM_MAX_BUFFER_SIZE]= {0};
	u8 secbuf_out[HSM_MAX_BUFFER_SIZE]= {0};

	if((NULL == pbMacKey) || (NULL == pbMsgBuf) || (NULL == bMAC))
	{
		errlog("SMAPICalcMac() failed, the pointer is NULL");
		return ERR_INPUT;
	}

	memset(secbuf_in, 0x00, sizeof(secbuf_in));
	memset(secbuf_out, 0x00, sizeof(secbuf_out));
	strcpy(secbuf_in , "V4");
	iMsgLen = 2;
	//
	secbuf_in[iMsgLen ++] = DES3;

	//tag
//	strncpy(&secbuf_in[iMsgLen], TAG3,3);
//	iMsgLen +=3;
	//mak
	/* 算法类型 */
	if((1 != nAlgo) && (2 != nAlgo) && (3 != nAlgo))
	{
		errlog("SMAPICalcMac() failed, nAlgo is wrong %d", nAlgo);
		return ERR_INPUT;
	}
	/* 密钥长度 */
	if((1 == nAlgo) || (2 == nAlgo))
	{
		if(8 != nMakLen)
		{
			errlog("SMAPICalcMac() failed, nMakLen is wrong %d", nMakLen);
			return ERR_INPUT;
		}
		retval = key_hex2str(pbMacKey , DES1 , &secbuf_in[iMsgLen]);
		if(retval <0){
			errlog("SMAPICalcMac() failed, pbMacKey is wrong");
			return ERR_INPUT;
		}
		iMsgLen += retval;
	}
	else
	{
		if(16 != nMakLen)
		{
			errlog("SMAPICalcMac() failed, nMakLen is wrong %d", nMakLen);
			return ERR_INPUT;
		}
		retval = key_hex2str(pbMacKey , DES2 , &secbuf_in[iMsgLen]);
		if(retval <0){
			errlog("SMAPICalcMac() failed, pbMacKey is wrong");
			return ERR_INPUT;
		}
		iMsgLen += retval;
	}
	if(nAlgo == 1)	//xor
		secbuf_in[iMsgLen ++] = '2';
	else if(nAlgo == 2)	//x9.9
		secbuf_in[iMsgLen ++] = '6';
	else if(nAlgo == 3)	//x9.19
		secbuf_in[iMsgLen ++] = '1';

	//div num
	secbuf_in[iMsgLen ++] = '0';

	//iv
	memset(&secbuf_in[iMsgLen], 0, 16);
	iMsgLen += 16;

	//datalen
	if(nMsgLen > 2048){
		errlog("SMAPICalcMac() failed, pbMacKey is wrong");
		return ERR_DATA_LEN;
	}
	sprintf(&secbuf_in[iMsgLen] , "%04d" ,nMsgLen);
	iMsgLen +=4;
	//data
	u8 *tmpp;
	//tmpp = &secbuf_in[iMsgLen] ;
	//hex2str(pbMsgBuf, &tmpp, nMsgLen);
	memcpy(&secbuf_in[iMsgLen] , pbMsgBuf, nMsgLen);
	iMsgLen += nMsgLen;

	//data_dump("send data", secbuf_in, iMsgLen);

#ifdef DEBUG_ON
	int i;
	nhLog(" iMsgLen:%d:\n", iMsgLen);
	nhLog("%s() send:\n", __func__);
	for(i=0;i<iMsgLen;i++)
	{
		nhLog("%02X", secbuf_in[i]);
	}
	nhLog("\n");
#endif

	if ((retval = HSM_LINK(nSock, iMsgLen, secbuf_in, secbuf_out)) != 0)
	{
		errlog("SMAPICalcMac() call failed, errno=%d", retval);
		return retval;
	}
	else
	{
		str2hex(&secbuf_out[4], bMAC, 16);
	}

	return 0;
}

/**************************************************************************************
 * 4.12 MAC计算_国密版 (V4)
 * 功能描述: 用指定的MacKey计算一段报文数据的MAC值(7.3.7 计算MAC)
 * 填充方式：nMode=1/2/3 时，若报文数据不够8 字节的整数倍，后面填充0x00 直
 *           到长度为8 的整数倍；如果报文数据长度为8 的整数倍，不填充。
 *           nMode=4/5 时，若报文数据不够16 字节的整数倍，后面填充0x00 直
 *           到长度为16 的整数倍；如果报文数据长度为16 的整数倍，不填充。
 *           nMode=6/7 时，强制填充0x80，若报文数据不够16 字节的整数倍，填
 *           充x00 直到长度为16 的整数倍。
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          nMode:  加密模式: ECB = 1; X9.9 = 2; x9.19 = 3;
 *			     ECB_SM4 = 4; X9.9_SM4 = 5;
 *			     ECB_SM4_PBOC = 6; X9.9_SM4_PBOC = 7;
 *
 *          pbKey: 经HMK(LMK)加密的Mak的密文值,二进制数
 *				   nMode=1/2时，MAK长度为8字节，
 *                 nMode=3/4/5/6/7时，MAK长度为16字节
 *          pbInData: 需要计算MAC的数据data,二进制数
 *          nDataLen:  数据data的长度, 范围: 1--2048
 *			pbIV: 初始化向量，二进制数，16字节长，全0x00
 *
 * 输出参数:
 *          pbMAC: 计算所得的数据报文的MAC，16字节长
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          2: 无效的密钥(MAK);
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9  其它错误
 *
 ***************************************************************************************/
int SMAPICalcMac_GM(int nSock,int nMode,u8 *pbKey,u8 *pbInData,int nDataLen,u8 *pbIV,
		    u8 *pbMAC)
{
	int iMsgLen = -1, retval = -1;

	u8 secbuf_in[HSM_MAX_BUFFER_SIZE]= {0};
	u8 secbuf_out[HSM_MAX_BUFFER_SIZE]= {0};

	u8 *tp;
	int nMakLen = 0;

	int i = 0;

	if((NULL == pbKey) || (NULL == pbInData) || (NULL == pbIV) || (NULL == pbMAC))
	{
		errlog("SMAPICalcMac_GM() failed, the pointer is NULL");
		return ERR_INPUT;
	}
	if((nMode<1) || (nMode>7))
	{
		errlog("SMAPICalcMac_GM() failed, nMode is wrong %d", nMode);
		return ERR_INPUT;
	}

	memset(secbuf_in, 0x00, sizeof(secbuf_in));
	memset(secbuf_out, 0x00, sizeof(secbuf_out));

	strcpy(secbuf_in , "V4");
	iMsgLen = 2;


	//
	if(nMode < 4){
		secbuf_in[iMsgLen ++] = DES3;
		nMakLen = 8;
	}
	else{
		secbuf_in[iMsgLen ++] = SM4;
		nMakLen = 16;
	}

	//tag
//	strncpy(&secbuf_in[iMsgLen], TAG3,3);
//	iMsgLen +=3;

	/* 密钥长度 */
	if((1 == nMode) || (2 == nMode))
	{
		retval = key_hex2str(pbKey , DES1 , &secbuf_in[iMsgLen]);
		if(retval <0){
			errlog("SMAPICalcMac_GM() failed, pbMacKey is wrong");
			return ERR_INPUT;
		}
		iMsgLen += retval;
	}
	else if(3 == nMode)
	{
		retval = key_hex2str(pbKey , DES2 , &secbuf_in[iMsgLen]);
		if(retval <0){
			errlog("SMAPICalcMac_GM() failed, pbMacKey is wrong");
			return ERR_INPUT;
		}
		iMsgLen += retval;
	}else{//sm4
		retval = key_hex2str(pbKey , SM4 , &secbuf_in[iMsgLen]);
		if(retval <0){
			errlog("SMAPICalcMac_GM() failed, pbMacKey is wrong");
			return ERR_INPUT;
		}
		iMsgLen += retval;

	}

	//1= 9.19(fill00) des ; 2= xor(des sm4); 3 =posmac;  4 =pboc(fill80 9.9)des sm4 ;  5 = pboc(fill80) 99 des ; 6=9.9 (fill00 des sm4)
	//secbuf_in[iMsgLen ++] = (nMode&0xff) +'0';
	if(nMode == 1) //ECB  XOR
		secbuf_in[iMsgLen ++] = '2';
	else if( nMode== 2) //9.9
		secbuf_in[iMsgLen ++] = '6';
	else  if(nMode == 3)//9.19
		secbuf_in[iMsgLen ++] = '1';
	else  if(nMode == 4)//ecb cup sm4  = xor sm4
		secbuf_in[iMsgLen ++] = '2';
	else  if(nMode == 5)//fill00 9.9 sm4
		secbuf_in[iMsgLen ++] = '6';
	else  if(nMode == 6)//pboc cup sm4 = fill80 xor sm4   not eq
		secbuf_in[iMsgLen ++] = '2';
	else  if(nMode == 7)//pboc 9.9 sm4 = fill80 9.9 sm4
		secbuf_in[iMsgLen ++] = '4';

	//div num
	secbuf_in[iMsgLen ++] = '0';

	//iv
	tp = &secbuf_in[iMsgLen];
	if(nMode < 4)
	{
		hex2str(pbIV, &tp, 8);
		iMsgLen += 16;
	}
	else
	{
		hex2str(pbIV, &tp, 16);
		iMsgLen += 32;
	}

	//nMode=6 pad_80
	if(nMode == 6 )
	{
		//强填80
		memset(pbInData+nDataLen, 0x80, 1);
		memset(pbInData+nDataLen+1, 0x00, 16-nDataLen%16-1);
		nDataLen = ((nDataLen >> 4) +1) << 4;
	}

	//datalen
	if(nDataLen > 4000){
		errlog("SMAPICalcMac_GM() failed, pbMacKey is wrong");
		return ERR_DATA_LEN;
	}
	sprintf(&secbuf_in[iMsgLen] , "%04d" ,nDataLen);
	iMsgLen +=4;
	//data

	//tmpp = &secbuf_in[iMsgLen] ;
	//hex2str(pbInData, &tmpp, nDataLen);
	memcpy(&secbuf_in[iMsgLen]  ,pbInData , nDataLen );
	iMsgLen += nDataLen;


#ifdef DEBUG_ON
	errlog(" iMsgLen:%d:\n", iMsgLen);
	errlog("%s() send:\n", __func__);
	for(i=0;i<iMsgLen;i++)
	{
		printf("%02X", secbuf_in[i]);
	}
	errlog("\n");
#endif

	if ((retval = HSM_LINK(nSock, iMsgLen, secbuf_in, secbuf_out)) != 0)
	{
		errlog("SMAPICalcMac_GM() call failed, errno=%d", retval);
		return retval;
	}
	else
	{
		str2hex(&secbuf_out[4], pbMAC, 32);
	}

	return 0;
}

/**************************************************************************************
 * 4.13 数据转加密 (VS)
 * 功能描述: 将被密钥1加密的密文,转换为被密钥2加密的密文,其中密钥1和密钥2
 *           已分别提交到加密模块的两个密钥寄存器中（7.3.5 数据转加密）.
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          nAlgo1:  使用密钥1加密时采用的加密算法的标识
 *                   (Single_Des = 1; Double_Des = 2; Triple_Des = 3)
 *          pbKey1: 经HMK加密的密钥1的密文值,二进制数
 *                  当nAlgo1 = 1时, 8字节长;
 *                  当nAlgo1 = 2时, 16字节长;
 *                  当nAlgo1 = 3时, 24字节长
 *          nAlgo2:  使用密钥2加密时采用的加密算法的标识
 *                   (Single_Des = 1; Double_Des = 2; Triple_Des = 3)
 *          pbKey2: 经HMK加密的密钥2的密文值,二进制数
 *                  当nAlgo2 = 1时, 8字节长;
 *                  当nAlgo2 = 2时, 16字节长;
 *                  当nAlgo2 = 3时, 24字节长
 *          pbSrcBlock: 被密钥1加密的密文数据,二进制数,8字节长
 *
 * 输出参数:
 *          bDestBlock: 被密钥2加密的密文数据,二进制数,8字节长
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          2: 无效的密钥(密钥1或密钥2);
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9  其它错误
 *
 ***************************************************************************************/
int SMAPITranslateBlock(int nSock,int nAlgo1,u8 *pbKey1,int nAlgo2,u8 *pbKey2,u8 *pbSrcBlock,
                        u8 bDestBlock[8])
{
	int iMsgLen = -1, retval = -1;

	u8 secbuf_in[HSM_MAX_BUFFER_SIZE]= {0};
	u8 secbuf_out[HSM_MAX_BUFFER_SIZE]= {0};

	memset(secbuf_in, 0x00, sizeof(secbuf_in));
	memset(secbuf_out, 0x00, sizeof(secbuf_out));

	strcpy(secbuf_in , "VS");
	iMsgLen = 2;
	//src alg
	secbuf_in[iMsgLen ++] = DES3;
	//src tag
//	strncpy(&secbuf_in[iMsgLen], TAG3,3);
//	iMsgLen +=3;
	//src key
	if(nAlgo1 ==1)
		retval = key_hex2str(pbKey1, DES1, &secbuf_in[iMsgLen]);
	else if(nAlgo1 ==2)
		retval = key_hex2str(pbKey1, DES2, &secbuf_in[iMsgLen]);
	else if(nAlgo1 ==3)
		retval = key_hex2str(pbKey1, DES3, &secbuf_in[iMsgLen]);
	else{
		errlog("SMAPITranslateBlock() nAlgo1 is invalid");
		return ERR_ALGO_FLAG;
	}
	if(retval <0){
		errlog("SMAPITranslateBlock() failed, pbKey1 is wrong");
		return ERR_INPUT;
	}
	iMsgLen += retval;

	//src type
	secbuf_in[iMsgLen ++] = ECB;


	//dst alg
	secbuf_in[iMsgLen ++] = DES3;
	//dst tag
//	strncpy(&secbuf_in[iMsgLen], TAG3,3);
//	iMsgLen +=3;
	//dst key
	if(nAlgo2 ==1)
		retval = key_hex2str(pbKey2, DES1, &secbuf_in[iMsgLen]);
	else if(nAlgo2 ==2)
		retval = key_hex2str(pbKey2, DES2, &secbuf_in[iMsgLen]);
	else if(nAlgo2 ==3)
		retval = key_hex2str(pbKey2, DES3, &secbuf_in[iMsgLen]);
	else{
		errlog("SMAPITranslateBlock() nAlgo2 is invalid");
		return ERR_ALGO_FLAG;
	}
	if(retval <0){
		errlog("SMAPITranslateBlock() failed, pbKey2 is wrong");
		return ERR_INPUT;
	}
	iMsgLen += retval;

	//dst type
	secbuf_in[iMsgLen ++] = ECB;

	//datalen
	sprintf(&secbuf_in[iMsgLen] , "%04d" ,8);
	iMsgLen +=4;
	//data
	u8 *tmpp;
	//tmpp = &secbuf_in[iMsgLen] ;
	//hex2str(pbSrcBlock, &tmpp, 8);
	memcpy(&secbuf_in[iMsgLen]  ,pbSrcBlock , 8 );
	iMsgLen += 8;

#ifdef DEBUG_ON
	int i;
	nhLog(" iMsgLen:%d:\n", iMsgLen);
	nhLog("%s() send:\n", __func__);
	for(i=0;i<iMsgLen;i++)
	{
		nhLog("%02X", secbuf_in[i]);
	}
	nhLog("\n");
#endif

	if ((retval = HSM_LINK(nSock, iMsgLen, secbuf_in, secbuf_out)) != 0)
	{
		errlog("SMAPITranslateBlock() call failed, errno=%d", retval);
		return retval;
	}
	else
	{
		//str2hex(&secbuf_out[8], bDestBlock, 16);
		memcpy(bDestBlock  ,&secbuf_out[8] , 8 );
	}

	return 0;
}

/**************************************************************************************
 * 4.14 PIN转加密-不带主账号_国密版  (VS)
 * 功能描述: PIN 转加密-不带主账号_国密版,（7.3.5 数据转加密）.
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          Int nMode ： 转换类型. 1.2DES-->2DES,2.2DES-->SM4,3.SM4-->2DES,4.SM4-->SM4
 *          byte *pbSrcPinKey：经HMK 加密的源Pik 的密文值，二进制数
 *          int nSrcPinKeyLen：pbSrcPinKey 的长度，字节数
 *          byte *pbDestPinKey：经HMK 加密的目的Pik 的密文值，二进制数
 *          int nDestPinKeyLen：pbDestPinKey 的长度，字节数
 *          byte *pszSrcPinCipher 源Pin 密文，长度与源算法分组长度相等
 *
 * 输出参数:
 *          pbDestPinCipher: 目的Pin 密文,目的算法为DES 时长度为8 字节，目的算法为SM4 时长度为16 字节
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          2: 无效的密钥(密钥1或密钥2);
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9 -- 其它错误
 *
 ***************************************************************************************/
int SMAPIConvertPinX98A (int nSock,int nMode,u8 *pbSrcPinKey,int nSrcPinKeyLen,	u8 *pbDestPinKey,
	                 int nDestPinKeyLen, u8 *pszSrcPinCipher,
	                 u8 pbDestPinCipher[16])
{
	int iMsgLen = -1, retval = -1, i = 0;
	int nlen=0;

	u8 secbuf_in[HSM_MAX_BUFFER_SIZE]= {0};
	u8 secbuf_out[HSM_MAX_BUFFER_SIZE]= {0};

	memset(secbuf_in, 0x00, sizeof(secbuf_in));
	memset(secbuf_out, 0x00, sizeof(secbuf_out));

	if(nSock <= 0){
		errlog("SMAPIConvertPinX98A() parameter nSock is invalid");
		return ERR_SOCK_INVALID;
	}

	if(nMode!=1 && nMode!=2 && nMode!=3 && nMode!=4){
		errlog("SMAPIConvertPinX98A() parameter nMode is invalid");
		return ERR_INPUT;
	}
	if(pbDestPinCipher==NULL || pszSrcPinCipher==NULL || pbSrcPinKey==NULL || pbDestPinKey==NULL){
		errlog("SMAPIConvertPinX98A() buffer is NULL");
		return ERR_INPUT;
	}
	if(nSrcPinKeyLen!=8 && nSrcPinKeyLen!=16 && nSrcPinKeyLen!=24){
		errlog("SMAPIConvertPinX98A() parameter nSrcPinKeyLen is invalid");
		return ERR_INPUT;
	}

	if(nDestPinKeyLen!=8 && nDestPinKeyLen!=16 && nDestPinKeyLen!=24){
		errlog("SMAPIConvertPinX98A() parameter nDestPinKeyLen is invalid");
		return ERR_INPUT;
	}

	if(nMode==2 && nDestPinKeyLen!=16){
		errlog("SMAPIConvertPinX98A() parameter nDestPinKeyLen is invalid");
		return ERR_INPUT;
	}

	if(nMode==3 && nSrcPinKeyLen!=16){
		errlog("SMAPIConvertPinX98A() parameter nSrcPinKeyLen is invalid");
		return ERR_INPUT;
	}

	if(nMode==4 && (nSrcPinKeyLen!=16 || nDestPinKeyLen!=16)){
		errlog("SMAPIConvertPinX98A() parameter nPinKeyLen is invalid");
		return ERR_INPUT;
	}

	strcpy(secbuf_in , "EN");
	iMsgLen = 2;

	/*算法转换类型*/
	secbuf_in[iMsgLen++] = (nMode&0XFF)+'0';

	if(nMode ==1 || nMode==2){
		if(nSrcPinKeyLen == 8)
			retval = key_hex2str(pbSrcPinKey, DES1, &secbuf_in[iMsgLen]);
		else if(nSrcPinKeyLen == 16)
			retval = key_hex2str(pbSrcPinKey, DES2, &secbuf_in[iMsgLen]);
		else
			retval = key_hex2str(pbSrcPinKey, DES3, &secbuf_in[iMsgLen]);
	}
	else
		retval = key_hex2str(pbSrcPinKey, SM4, &secbuf_in[iMsgLen]);
	if(retval < 0){
		errlog("SMAPIConvertPinX98A() failed, pbSrcPinKey is wrong");
		return ERR_INPUT;
	}
	iMsgLen += retval;

	//div num
	secbuf_in[iMsgLen++] = '0';

	//dst key
	if(nMode ==1 || nMode==3){
		if(nDestPinKeyLen == 8)
			retval = key_hex2str(pbDestPinKey, DES1, &secbuf_in[iMsgLen]);
		else if(nDestPinKeyLen == 16)
			retval = key_hex2str(pbDestPinKey, DES2, &secbuf_in[iMsgLen]);
		else
			retval = key_hex2str(pbDestPinKey, DES3, &secbuf_in[iMsgLen]);
	}
	else
		retval = key_hex2str(pbDestPinKey, SM4, &secbuf_in[iMsgLen]);
	if(retval < 0){
		errlog("SMAPIConvertPinX98A() failed, pbDestPinKey is wrong");
		return ERR_INPUT;
	}
	iMsgLen += retval;
	//div num
	secbuf_in[iMsgLen ++] = '0';
	//src format
	sprintf(&secbuf_in[iMsgLen], "%02d", 7);
	iMsgLen += 2;

	//dst format
	sprintf(&secbuf_in[iMsgLen], "%02d", 7);
	iMsgLen += 2;
	//pin cipher
	//pinblock len
	if(nMode == 1 || nMode ==2)
		nlen = 8;
	else nlen = 16;
	//pinblock
	u8 *tmpp;
	tmpp = &secbuf_in[iMsgLen];
	data_dump("pszSrcPinCipher", pszSrcPinCipher,nlen);
	hex2str(pszSrcPinCipher, &tmpp, nlen);
	iMsgLen += nlen*2;
	secbuf_in[iMsgLen++] = '0';


#ifdef DEBUG_ON
	nhLog(" iMsgLen:%d:\n", iMsgLen);
	nhLog("%s() send:\n", __func__);
	for(i=0;i<iMsgLen;i++)
	{
		nhLog("%02X", secbuf_in[i]);
	}
	nhLog("\n");
#endif

	if ((retval = HSM_LINK(nSock, iMsgLen, secbuf_in, secbuf_out)) != 0)
	{
		errlog("SMAPIConvertPinX98A call failed, errno=%d", retval);
		return retval;
	}
	else
	{
		if(nMode==1 || nMode ==3){
			//memcpy(pbDestPinCipher , &secbuf_out[8], 8);
			str2hex(&secbuf_out[4], pbDestPinCipher,16);
		}
		else{
			//memcpy(pbDestPinCipher , &secbuf_out[8], 16);
			str2hex(&secbuf_out[4], pbDestPinCipher,32);
		}
	}

	return 0;

}

/**************************************************************************************
 * 4.14 PIN转加密-带主账号,支持DES和Sm4算法  CC
 * 功能描述: PIN 转加密-带主账号_国密版,（7.2.12 PIN 块从PIK1 到PIK2）.
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          Int nMode ： 转换类型. 1.2DES-->2DES,2.2DES-->SM4,3.SM4-->2DES,4.SM4-->SM4
 *			char *pszPan: 主帐号，ASCII 字符串，去掉校验位的最右12 个字符
 *			int nPanLen：主帐号长度（字符数），13-19 位
 *          byte *pbSrcPinKey：经HMK 加密的源Pik 的密文值，二进制数
 *          int nSrcPinKeyLen：pbSrcPinKey 的长度，字节数
 *          byte *pbDestPinKey：经HMK 加密的目的Pik 的密文值，二进制数
 *          int nDestPinKeyLen：pbDestPinKey 的长度，字节数
 *          byte *pszSrcPinCipher 源Pin 密文，长度与源算法分组长度相等
 *
 * 输出参数:
 *          pbDestPinCipher: 目的Pin 密文,目的算法为DES 时长度为8 字节，目的算法为SM4 时长度为16 字节
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          2: 无效的密钥(密钥1或密钥2);
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9  其它错误
 *
 ***************************************************************************************/
int SMAPIConvertPinX98B (int nSock,int nMode,char *pszPan,int nPanLen,u8 *pbSrcPinKey,
	                 int nSrcPinKeyLen,u8 *pbDestPinKey,int nDestPinKeyLen,	u8 *pszSrcPinCipher,
	                 u8 pbDestPinCipher[16])
{
	int iMsgLen = -1, retval = -1, i = 0;
	int nlen=0;

	u8 secbuf_in[HSM_MAX_BUFFER_SIZE]= {0};
	u8 secbuf_out[HSM_MAX_BUFFER_SIZE]= {0};

	memset(secbuf_in, 0x00, sizeof(secbuf_in));
	memset(secbuf_out, 0x00, sizeof(secbuf_out));

	if(nSock <= 0){
		errlog("SMAPIConvertPinX98B() parameter nSock is invalid");
		return ERR_SOCK_INVALID;
	}

	if(nMode!=1 && nMode!=2 && nMode!=3 && nMode!=4){
		errlog("SMAPIConvertPinX98B() parameter nMode is invalid");
		return ERR_INPUT;
	}

	for (i = 0; i < nPanLen; i++)
	{
		if (!isdigit(pszPan[i]))
		{
			errlog("SMAPIConvertPinX98B() failed, pszPan is wrong");
			return ERR_INPUT;
		}
	}

	if(nPanLen<13 || nPanLen > 19){
		errlog("SMAPIConvertPinX98B() parameter nPanlen is invalid");
		return ERR_INPUT;
	}

	if(pbDestPinCipher==NULL || pszSrcPinCipher==NULL || pbSrcPinKey==NULL || pbDestPinKey==NULL){
		errlog("SMAPIConvertPinX98B() buffer is NULL");
		return ERR_INPUT;
	}
	if(nSrcPinKeyLen!=8 && nSrcPinKeyLen!=16 && nSrcPinKeyLen!=24){
		errlog("SMAPIConvertPinX98B() parameter nSrcPinKeyLen is invalid");
		return ERR_INPUT;
	}

	if(nDestPinKeyLen!=8 && nDestPinKeyLen!=16 && nDestPinKeyLen!=24){
		errlog("SMAPIConvertPinX98B() parameter nDestPinKeyLen is invalid");
		return ERR_INPUT;
	}

	if(nMode==2 && (nDestPinKeyLen!=16)){
		errlog("SMAPIConvertPinX98B() parameter nDestPinKeyLen is invalid");
		return ERR_INPUT;
	}

	if(nMode==3 && nSrcPinKeyLen!=16){
		errlog("SMAPIConvertPinX98B() parameter nSrcPinKeyLen is invalid");
		return ERR_INPUT;
	}

	if(nMode==4 && (nSrcPinKeyLen!=16 || nDestPinKeyLen!=16)){
		errlog("SMAPIConvertPinX98B() parameter nPinKeyLen is invalid");
		return ERR_INPUT;
	}

	strcpy(secbuf_in , "CC");
	iMsgLen = 2;
	//src alg
	if(nMode ==1 || nMode==2)
		secbuf_in[iMsgLen ++] = DES3;
	else
		secbuf_in[iMsgLen ++] = SM4;
	//dst alg
	if(nMode ==1 || nMode==3)
		secbuf_in[iMsgLen ++] = DES3;
	else
		secbuf_in[iMsgLen ++] = SM4;

	//src key
	if(nMode ==1 || nMode==2){
		if(nSrcPinKeyLen == 8)
			retval = key_hex2str(pbSrcPinKey, DES1, &secbuf_in[iMsgLen]);
		else if(nSrcPinKeyLen == 16)
			retval = key_hex2str(pbSrcPinKey, DES2, &secbuf_in[iMsgLen]);
		else
			retval = key_hex2str(pbSrcPinKey, DES3, &secbuf_in[iMsgLen]);
	}
	else
		retval = key_hex2str(pbSrcPinKey, SM4, &secbuf_in[iMsgLen]);
	if(retval < 0){
		errlog("SMAPIConvertPinX98B() failed, pbSrcPinKey is wrong");
		return ERR_INPUT;
	}
	iMsgLen += retval;

	//dst key
	if(nMode ==1 || nMode==3){
		if(nDestPinKeyLen == 8)
			retval = key_hex2str(pbDestPinKey, DES1, &secbuf_in[iMsgLen]);
		else if(nDestPinKeyLen == 16)
			retval = key_hex2str(pbDestPinKey, DES2, &secbuf_in[iMsgLen]);
		else
			retval = key_hex2str(pbDestPinKey, DES3, &secbuf_in[iMsgLen]);
	}
	else
		retval = key_hex2str(pbDestPinKey, SM4, &secbuf_in[iMsgLen]);
	if(retval < 0){
		errlog("SMAPIConvertPinX98B() failed, pbDestPinKey is wrong");
		return ERR_INPUT;
	}
	iMsgLen += retval;
	//max pin len
	sprintf(&secbuf_in[iMsgLen] , "%02d" , 12);
	iMsgLen +=2;

	if(nMode == 1 || nMode ==2)
		nlen = 8;
	else nlen = 16;

	//pinblock
	u8 *tmpp;
	tmpp = &secbuf_in[iMsgLen];
	hex2str(pszSrcPinCipher, &tmpp, nlen);
	iMsgLen += (nlen*2);
	//src format
	strcpy(&secbuf_in[iMsgLen] , "01");
	iMsgLen +=2;
	//dst format
	strcpy(&secbuf_in[iMsgLen] , "01");
	iMsgLen +=2;
	//pan
	memcpy(&secbuf_in[iMsgLen] , pszPan+nPanLen-13 , 12);
	iMsgLen +=12;

#ifdef DEBUG_ON
	nhLog(" iMsgLen:%d:\n", iMsgLen);
	nhLog("%s() send:\n", __func__);
	for(i=0;i<iMsgLen;i++)
	{
		nhLog("%02X", secbuf_in[i]);
	}
	nhLog("\n");
#endif

	if ((retval = HSM_LINK(nSock, iMsgLen, secbuf_in, secbuf_out)) != 0)
	{
		errlog("SMAPIConvertPinX98B call failed, errno=%d", retval);
		return retval;
	}
	else
	{
		if(nMode==1 || nMode ==3)
			str2hex(&secbuf_out[4], pbDestPinCipher, 16);
		else
			str2hex(&secbuf_out[4], pbDestPinCipher, 32);
	}

	return 0;
}

/*PIN转加密-带双主账号,支持DES和Sm4算法*/
/**************************************************************************************
 *
 * 功能描述: PIN 转加密-带主账号_国密版,（7.2.12 PIN 块从PIK1 到PIK2）.
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          Int nMode ： 转换类型. 1.2DES-->2DES,2.2DES-->SM4,3.SM4-->2DES,4.SM4-->SM4
 *			char *pszSrcPan:: 主帐号，ASCII 字符串，去掉校验位的最右12 个字符
 *			int nSrcPanLen：主帐号长度（字符数），13-19 位
 *			char *pszDstPan:: 主帐号，ASCII 字符串，去掉校验位的最右12 个字符
 *			int nDstPanLen：主帐号长度（字符数），13-19 位
 *          byte *pbSrcPinKey：经HMK 加密的源Pik 的密文值，二进制数
 *          int nSrcPinKeyLen：pbSrcPinKey 的长度，字节数
 *          byte *pbDestPinKey：经HMK 加密的目的Pik 的密文值，二进制数
 *          int nDestPinKeyLen：pbDestPinKey 的长度，字节数
 *          byte *pszSrcPinCipher 源Pin 密文，长度与源算法分组长度相等
 *
 * 输出参数:
 *          pbDestPinCipher: 目的Pin 密文,目的算法为DES 时长度为8 字节，目的算法为SM4 时长度为16 字节
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          2: 无效的密钥(密钥1或密钥2);
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9 -- 其它错误
 *
 ***************************************************************************************/
/*int SMAPIConvertPinX98B_DoublePan(
	int nSock,
	int nMode,
	char *pszSrcPan,
	int nSrcPanLen,
	char *pszDstPan,
	int nDstPanLen,
	u8 *pbSrcPinKey,
	int nSrcPinKeyLen,
	u8 *pbDestPinKey,
	int nDestPinKeyLen,
	u8 *pszSrcPinCipher,
	u8 pbDestPinCipher[16])
{
	int iMsgLen = -1, retval = -1, i = 0;
	int nlen=0;

	u8 secbuf_in[HSM_MAX_BUFFER_SIZE]= {0};
	u8 secbuf_out[HSM_MAX_BUFFER_SIZE]= {0};

	memset(secbuf_in, 0x00, sizeof(secbuf_in));
	memset(secbuf_out, 0x00, sizeof(secbuf_out));

	if(nSock <= 0){
		errlog("SMAPIConvertPinX98B_DoublePan() parameter nSock is invalid");
		return ERR_SOCK_INVALID;
	}

	if(nMode!=1 && nMode!=2 && nMode!=3 && nMode!=4){
		errlog("SMAPIConvertPinX98B_DoublePan() parameter nMode is invalid");
		return ERR_INPUT;
	}

	for (i = 0; i < nSrcPanLen; i++)
	{
		if (!isdigit(pszSrcPan[i]))
		{
			errlog("SMAPIConvertPinX98B_DoublePan() failed, pszSrcPan is wrong");
			return ERR_INPUT;
		}
	}

	if(nSrcPanLen<13 || nSrcPanLen > 19){
		errlog("SMAPIConvertPinX98B_DoublePan() parameter nSrcPanLen is invalid");
		return ERR_INPUT;
	}

	for (i = 0; i < nDstPanLen; i++)
	{
		if (!isdigit(pszDstPan[i]))
		{
			errlog("SMAPIConvertPinX98B_DoublePan() failed, pszDstPan is wrong");
			return ERR_INPUT;
		}
	}

	if(nDstPanLen<13 || nDstPanLen > 19){
		errlog("SMAPIConvertPinX98B_DoublePan() parameter nDstPanLen is invalid");
		return ERR_INPUT;
	}

	if(pbDestPinCipher==NULL || pszSrcPinCipher==NULL || pbSrcPinKey==NULL || pbDestPinKey==NULL){
		errlog("SMAPIConvertPinX98B_DoublePan() buffer is NULL");
		return ERR_INPUT;
	}
	if(nSrcPinKeyLen!=8 && nSrcPinKeyLen!=16 && nSrcPinKeyLen!=24){
		errlog("SMAPIConvertPinX98B_DoublePan() parameter nSrcPinKeyLen is invalid");
		return ERR_INPUT;
	}

	if(nDestPinKeyLen!=8 && nDestPinKeyLen!=16 && nDestPinKeyLen!=24){
		errlog("SMAPIConvertPinX98B_DoublePan() parameter nDestPinKeyLen is invalid");
		return ERR_INPUT;
	}

	if(nMode==2 && nDestPinKeyLen!=16){
		errlog("SMAPIConvertPinX98B_DoublePan() parameter nDestPinKeyLen is invalid");
		return ERR_INPUT;
	}

	if(nMode==3 && nSrcPinKeyLen!=16){
		errlog("SMAPIConvertPinX98B_DoublePan() parameter nSrcPinKeyLen is invalid");
		return ERR_INPUT;
	}

	if(nMode==4 && (nSrcPinKeyLen!=16 || nDestPinKeyLen!=16)){
		errlog("SMAPIConvertPinX98B_DoublePan() parameter nPinKeyLen is invalid");
		return ERR_INPUT;
	}

	strcpy(secbuf_in , "EN");
	iMsgLen = 2;
	//mode
	secbuf_in[iMsgLen++] = (nMode&0XFF)+'0';

	//src tag
//	strncpy(&secbuf_in[iMsgLen], TAG3,3);
//	iMsgLen +=3;

	//src key
	if(nMode ==1 || nMode==2){
		if(nSrcPinKeyLen == 8)
			retval = key_hex2str(pbSrcPinKey, DES1, &secbuf_in[iMsgLen]);
		else if(nSrcPinKeyLen == 16)
			retval = key_hex2str(pbSrcPinKey, DES2, &secbuf_in[iMsgLen]);
		else
			retval = key_hex2str(pbSrcPinKey, DES3, &secbuf_in[iMsgLen]);
	}
	else
		retval = key_hex2str(pbSrcPinKey, SM4, &secbuf_in[iMsgLen]);
	if(retval < 0){
		errlog("SMAPIConvertPinX98B_DoublePan() failed, pbSrcPinKey is wrong");
		return ERR_INPUT;
	}
	iMsgLen += retval;

	//div num
	secbuf_in[iMsgLen++] = '0';

	//dst tag
//	strncpy(&secbuf_in[iMsgLen], TAG3,3);
//	iMsgLen +=3;

	//dst key
	if(nMode ==1 || nMode==3){
		if(nDestPinKeyLen == 8)
			retval = key_hex2str(pbDestPinKey, DES1, &secbuf_in[iMsgLen]);
		else if(nDestPinKeyLen == 16)
			retval = key_hex2str(pbDestPinKey, DES2, &secbuf_in[iMsgLen]);
		else
			retval = key_hex2str(pbDestPinKey, DES3, &secbuf_in[iMsgLen]);
	}
	else
		retval = key_hex2str(pbDestPinKey, SM4, &secbuf_in[iMsgLen]);
	if(retval < 0){
		errlog("SMAPIConvertPinX98B_DoublePan() failed, pbDestPinKey is wrong");
		return ERR_INPUT;
	}
	iMsgLen += retval;
	//divnum
	secbuf_in[iMsgLen++] = '0';

	//src format
	strcpy(&secbuf_in[iMsgLen] , "01");
	iMsgLen += 2;

	//dst format
	strcpy(&secbuf_in[iMsgLen] , "01");
	iMsgLen += 2;

	//pin cipher
	//pinblock len
	if(nMode == 1 || nMode ==2)
		nlen = 8;
	else nlen = 16;
	//pinblock
	u8 *tmpp;
	tmpp = &secbuf_in[iMsgLen];
	data_dump("pszSrcPinCipher", pszSrcPinCipher,nlen);
	hex2str(pszSrcPinCipher, &tmpp, nlen);

	iMsgLen += (nlen*2);

	//src pan
	memcpy( &secbuf_in[iMsgLen] , pszSrcPan + nSrcPanLen -13 , 12);
	iMsgLen +=12;
	//
	secbuf_in[iMsgLen++] = '1';
	memcpy( &secbuf_in[iMsgLen] , pszDstPan + nDstPanLen -13 , 12);
	iMsgLen +=12;

#ifdef DEBUG_ON
	nhLog(" iMsgLen:%d:\n", iMsgLen);
	nhLog("%s() send:\n", __func__);
	for(i=0;i<iMsgLen;i++)
	{
		nhLog("%02X", secbuf_in[i]);
	}
	nhLog("\n");
#endif

	if ((retval = HSM_LINK(nSock, iMsgLen, secbuf_in, secbuf_out)) != 0)
	{
		errlog("SMAPIConvertPinX98B_DoublePan call failed, errno=%d", retval);
		return retval;
	}
	else
	{
		if(nMode==1 || nMode ==3)
			str2hex(&secbuf_out[4], pbDestPinCipher, 16);
		else
			str2hex(&secbuf_out[4], pbDestPinCipher, 32);
	}

	return 0;


}*/

/**************************************************************************************
 *
 * 功能描述: PIN 转加密_X98 到IBM3624（7.6.3 转加密PIN-双主账号）.
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          Int nMode ： 转换类型. 1: DES->IBM3624 2: 2DES->IBM3624 3: 3DES->IBM3624 4: SM4->IBM3624
 *			int nX98Algo：X98 算法类型。1: X98A 2: X98B
 *			char *pszSrcPan:: 当nX98Algo=1 时，pszPan = NULL, 当nX98Algo=2 时，源主帐号，ASCII 字符串，上层调用时传入
 *								全部的PAN 号，计算时使用PAN 号最右边的16 位
 *			int nSrcPanLen：主帐号长度（字符数），13-19 位
 *			char *pszDstPan:: 当nX98Algo=1 时，pszPan = NULL, 当nX98Algo=2 时，源主帐号，ASCII 字符串，上层调用时传入
 *								全部的PAN 号，计算时使用PAN 号最右边的16 位
 *			int nDstPanLen：主帐号长度（字符数），13-19 位
 *          byte *pbSrcPinKey：经HMK 加密的源Pik 的密文值，二进制数
 *          int nSrcPinKeyLen：pbSrcPinKey 的长度，字节数
 *          byte *pbDestPinKey：经HMK 加密的目的Pik 的密文值，二进制数
 *          int nDestPinKeyLen：pbDestPinKey 的长度，字节数
 *          byte *pszSrcPinCipher 源Pin密文，长度与nMode 定义的算法分组长度相等
 *
 * 输出参数:
 *          pbDestPinCipher: 目的Pin 密文,IBM3624 格式的Pin Offset，长度范围[1~12]
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          2: 无效的密钥(密钥1或密钥2);
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9 -- 其它错误
 *
 ***************************************************************************************/
/*int SMAPIConvertPinX98ToIBM3624(
	int nSock,
	int nMode,
	int nX98Algo,
	char *pszSrcPan,
	int nSrcPanLen,
	char *pszDstPan,
	int nDstPanLen,
	u8 *pbSrcPinKey,
	int nSrcPinKeyLen,
	u8 *pbDstPinKey,
	int nDstPinKeyLen,
	u8 *pszSrcPinCipher,
	u8 pbDestPinCipher[13])
{
	int iMsgLen = -1, retval = -1, i = 0;
	int nlen=0;
	char plainPin[13] = {0};
	int pinlen=0;

	u8 secbuf_in[HSM_MAX_BUFFER_SIZE]= {0};
	u8 secbuf_out[HSM_MAX_BUFFER_SIZE]= {0};

	memset(secbuf_in, 0x00, sizeof(secbuf_in));
	memset(secbuf_out, 0x00, sizeof(secbuf_out));

	if(nSock <= 0){
		errlog("SMAPIConvertPinX98ToIBM3624() parameter nSock is invalid");
		return ERR_SOCK_INVALID;
	}

    if(nMode!=1 && nMode!=2 && nMode!=3 && nMode!=4){
		errlog("SMAPIConvertPinX98ToIBM3624() parameter nMode is invalid");
		return ERR_INPUT;
	}
	if(nX98Algo!=1 && nX98Algo !=2){
		errlog("SMAPIConvertPinX98ToIBM3624() parameter nX98Algo is invalid");
		return ERR_INPUT;
	}

	if(nX98Algo==2){

		if(nSrcPanLen != strlen(pszSrcPan)){
			errlog("SMAPIConvertPinX98ToIBM3624() failed, pszSrcPan length is invalid");
		       return ERR_INPUT;
		}
		for (i = 0; i < nSrcPanLen; i++)
		{
			if (!isdigit(pszSrcPan[i]))
			{
				errlog("SMAPIConvertPinX98ToIBM3624() failed, pszSrcPan is wrong");
				return ERR_INPUT;
			}
		}

		if(nSrcPanLen<13 || nSrcPanLen > 19){
			errlog("SMAPIConvertPinX98ToIBM3624() parameter nSrcPanLen is invalid");
			return ERR_INPUT;
		}
	}

	for (i = 0; i < nDstPanLen; i++)
	{
		if (!isdigit(pszDstPan[i]))
		{
			errlog("SMAPIConvertPinX98ToIBM3624() failed, pszDstPan is wrong");
			return ERR_INPUT;
		}
	}

	if((nDstPanLen!=16 && nDstPanLen != 19) || (nDstPanLen != strlen(pszDstPan))){
		errlog("SMAPIConvertPinX98ToIBM3624() parameter nDstPanLen is invalid");
		return ERR_INPUT;
	}

	if(pbDstPinKey==NULL || pbSrcPinKey==NULL || pbDestPinCipher==NULL){
		errlog("SMAPIConvertPinX98ToIBM3624() buffer  is NULL");
		return ERR_INPUT;
	}

	if(nSrcPinKeyLen!=8 && nSrcPinKeyLen!=16 && nSrcPinKeyLen!=24){
		errlog("SMAPIConvertPinX98ToIBM3624() parameter nSrcPinKeyLen is invalid");
		return ERR_INPUT;
	}

	if(nDstPinKeyLen!=8 && nDstPinKeyLen!=16 && nDstPinKeyLen!=24){
		errlog("SMAPIConvertPinX98ToIBM3624() parameter nDstPinKeyLen is invalid");
		return ERR_INPUT;
	}

	if(nMode==4){
		if(nSrcPinKeyLen!=16){
			errlog("SMAPIConvertPinX98ToIBM3624() parameter nSrcPinKeyLen is invalid");
			return ERR_INPUT;
		}
	}

	strcpy(secbuf_in , "EN");
	iMsgLen = 2;
	//mode
	if(nMode ==4)
		secbuf_in[iMsgLen++] = '3';
	else
		secbuf_in[iMsgLen++] = '1';

	//src tag
//	strncpy(&secbuf_in[iMsgLen], TAG3,3);
//	iMsgLen +=3;

	//src key
	if(nMode ==1 || nMode==2 || nMode==3){
		if(nSrcPinKeyLen == 8)
			retval = key_hex2str(pbSrcPinKey, DES1, &secbuf_in[iMsgLen]);
		else if(nSrcPinKeyLen == 16)
			retval = key_hex2str(pbSrcPinKey, DES2, &secbuf_in[iMsgLen]);
		else
			retval = key_hex2str(pbSrcPinKey, DES3, &secbuf_in[iMsgLen]);
	}
	else
		retval = key_hex2str(pbSrcPinKey, SM4, &secbuf_in[iMsgLen]);
	if(retval < 0){
		errlog("SMAPIConvertPinX98ToIBM3624() failed, pbSrcPinKey is wrong");
		return ERR_INPUT;
	}
	iMsgLen += retval;

	//div num
	secbuf_in[iMsgLen++] = '0';

	//dst tag
//	strncpy(&secbuf_in[iMsgLen], TAG3,3);
//	iMsgLen +=3;

	//dst key
	if(nDstPinKeyLen == 8)
		retval = key_hex2str(pbDstPinKey, DES1, &secbuf_in[iMsgLen]);
	else if(nDstPinKeyLen == 16)
		retval = key_hex2str(pbDstPinKey, DES2, &secbuf_in[iMsgLen]);
	else
		retval = key_hex2str(pbDstPinKey, DES3, &secbuf_in[iMsgLen]);

	if(retval < 0){
		errlog("SMAPIConvertPinX98ToIBM3624() failed, pbDestPinKey is wrong");
		return ERR_INPUT;
	}
	iMsgLen += retval;

	//divnum
	secbuf_in[iMsgLen++] = '0';

	//src format
	if(nX98Algo ==1) //98A
		strcpy(&secbuf_in[iMsgLen] , "07");
	else
		strcpy(&secbuf_in[iMsgLen] , "01");
	iMsgLen += 2;

	//dst format
	strcpy(&secbuf_in[iMsgLen] , "50");
	iMsgLen += 2;

	//pin cipher
	//pinblock len
	if(nMode == 1 || nMode ==2 || nMode ==3)
		nlen = 8;
	else
		nlen = 16;
	//pinblock
	u8 *tmpp;
	tmpp = &secbuf_in[iMsgLen];
	hex2str(pszSrcPinCipher, &tmpp, nlen);
	iMsgLen += (nlen*2);

	//src pan
	if(nX98Algo ==2){
		memcpy( &secbuf_in[iMsgLen] , pszSrcPan + nSrcPanLen -13 , 12);
		iMsgLen +=12;
	}

	secbuf_in[iMsgLen++] = '1';
	memcpy( &secbuf_in[iMsgLen] , pszDstPan + nDstPanLen -16 , 16);
	iMsgLen +=16;


#ifdef DEBUG_ON
	nhLog(" iMsgLen2:%d:\n", iMsgLen);
	nhLog("%s() send:\n", __func__);
	for(i=0;i<iMsgLen;i++)
	{
		nhLog("%02X", secbuf_in[i]);
	}
	nhLog("\n");
#endif

	if ((retval = HSM_LINK(nSock, iMsgLen, secbuf_in, secbuf_out)) != 0)
	{
		errlog("SMAPIConvertPinX98ToIBM3624 call failed, errno=%d", retval);
		return retval;
	}
	else
	{
		for(i = 0 ; i < 13 ; i ++){

			if(secbuf_out[4+i] == 'F'){
				pbDestPinCipher[i] = 0;
				break;
			}else
				pbDestPinCipher[i] = secbuf_out[4+i];
		}
	}

    return 0;
}  */


/**************************************************************************************
 * 4.18 HMK到KEK的转加密 (A8)
 * 功能描述: 将被HMK加密的密钥的密文, 转换为以KEK加密的密文(7.2.3 导出密钥)
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          nAlgo:  KEK加密算法类型
 *                   (Single_Des = 1; Double_Des = 2; Triple_Des = 3)
 *          pbKEK: 经HMK加密的KEK的密文值, 二进制数
 *                  当nAlgo1 = 1时, 8字节长;
 *                  当nAlgo1 = 2时, 16字节长;
 *                  当nAlgo1 = 3时, 24字节长
 *          pbKeyUnderLMK:  被HMK(LMK)加密的密钥的密文, 二进制数, 长度由nKeyLen指定
 *          nKeyLen: 被加密密钥的长度, 取值范围: {8, 16, 24}
 *
 * 输出参数:
 *          pbKeyUnderKEK: 被KEK加密的密钥的密文, 二进制数, 长度由nKeyLen指定
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          2: 无效的密钥(KEK);
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9  其它错误
 *
 ***************************************************************************************/
int SMAPITranslateKeyOutOf(int nSock,int nAlgo,u8 *pbKEK,u8 *pbKeyUnderHMK,int nKeyLen,
                           u8 *pbKeyUnderKEK)
{
	int iMsgLen = -1, retval = -1;

	u8 secbuf_in[HSM_MAX_BUFFER_SIZE]= {0};
	u8 secbuf_out[HSM_MAX_BUFFER_SIZE]= {0};

	memset(secbuf_in, 0x00, sizeof(secbuf_in));
	memset(secbuf_out, 0x00, sizeof(secbuf_out));

	strcpy(secbuf_in , "A8");
	iMsgLen = 2;
	// tag
//	strncpy(&secbuf_in[iMsgLen], TAG3,3);
//	iMsgLen +=3;

	//
	secbuf_in[iMsgLen++] = DES3;
	//kek
	if(nAlgo ==1)
		retval = key_hex2str(pbKEK, DES1, &secbuf_in[iMsgLen]);
	else if(nAlgo ==2)
		retval = key_hex2str(pbKEK, DES2, &secbuf_in[iMsgLen]);
	else if(nAlgo ==3)
		retval = key_hex2str(pbKEK, DES3, &secbuf_in[iMsgLen]);
	else{
		errlog("SMAPITranslateKeyOutOf() nAlgo is invalid");
		return ERR_ALGO_FLAG;
	}
	if(retval <0){
		errlog("SMAPITranslateKeyOutOf() failed, pbKEK is wrong");
		return ERR_INPUT;
	}
	iMsgLen += retval;
	//key
	if(nKeyLen ==8)
		retval = key_hex2str(pbKeyUnderHMK, DES1, &secbuf_in[iMsgLen]);
	else if(nKeyLen ==16)
		retval = key_hex2str(pbKeyUnderHMK, DES2, &secbuf_in[iMsgLen]);
	else if(nKeyLen ==24)
		retval = key_hex2str(pbKeyUnderHMK, DES3, &secbuf_in[iMsgLen]);
	else{
		errlog("SMAPITranslateKeyOutOf() nKeyLen is invalid");
		return ERR_ALGO_FLAG;
	}
	if(retval <0){
		errlog("SMAPITranslateKeyOutOf() failed, pbKeyUnderLMK is wrong");
		return ERR_INPUT;
	}
	iMsgLen += retval;
	//kek
	if(nKeyLen ==8)
		secbuf_in[iMsgLen++] = 'Z';
	else if(nKeyLen ==16)
		secbuf_in[iMsgLen++] = 'X';
	else
		secbuf_in[iMsgLen++] = 'Y';

#ifdef DEBUG_ON
	int i;
	nhLog(" iMsgLen:%d:\n", iMsgLen);
	nhLog("%s() send:\n", __func__);
	for(i=0;i<iMsgLen;i++)
	{
		nhLog("%02X", secbuf_in[i]);
	}
	nhLog("\n");
#endif

	if ((retval = HSM_LINK(nSock, iMsgLen, secbuf_in, secbuf_out)) != 0)
	{
		errlog("SMAPITranslateKeyOutOf() call failed, errno=%d", retval);
		return retval;
	}
	else
	{
		if(nKeyLen ==8)
			str2hex(&secbuf_out[4], pbKeyUnderKEK, 16);
		else if(nKeyLen ==16)
			str2hex(&secbuf_out[5], pbKeyUnderKEK, 32);
		else
			str2hex(&secbuf_out[5], pbKeyUnderKEK, 48);
	}

 	return 0;
}

/*****************************************************************************************************
1. 4.19 HMK 到KEK 的转加密_国密版（7.2.3 导出密钥） (A8)
2. 函数功能：将被HMK 加密的密钥的密文，转换为以KEK 加密的密文。
3. 输入参数：
	UINT nSock：连接的socket 句柄
	int nAlgo：KEK 加密算法类型。Single_Des = 1, Double_Des = 2, Triple_Des = 3,
	SM4=4
	byte *pbKEK：经HMK 加密的KEK 的密文值，二进制数
	byte *pbKeyUnderHMK：被HMK 加密的密钥的密文，二进制数，长度由nKeyLen
	指定
	int nKeyLen：被加密密钥的长度，取值范围：{8, 16, 24}
4. 输出参数：
	byte *pbKeyUnderKEK：被KEK 加密的密钥的密文，二进制数，长度由nKeyLen指定
5. 返回值： 
	0：成功
	1： 输入参数验证失败
	2： 无效的密钥（KEK）
	3： 向加密机发送数据失败
	4： 接收加密机数据超时
	5： 接收到的数据格式错
	9:  其他错误
****************************************************************************************************/
int SMAPITranslateKeyOutOf_GM(int nSock,int nAlgo,u8 *pbKEK,u8 *pbKeyUnderHMK,int nKeyLen,
	                      u8 *pbKeyUnderKEK)
{
	int iMsgLen = -1, retval = -1;

	u8 secbuf_in[HSM_MAX_BUFFER_SIZE]= {0};
	u8 secbuf_out[HSM_MAX_BUFFER_SIZE]= {0};

	memset(secbuf_in, 0x00, sizeof(secbuf_in));
	memset(secbuf_out, 0x00, sizeof(secbuf_out));

	if(nSock <= 0){
		errlog("SMAPITranslateKeyOutOf_GM() parameter nSock is invalid");
		return ERR_SOCK_INVALID;
	}

	if(nAlgo!=1 && nAlgo!=2 && nAlgo!=3 && nAlgo!=4){
		errlog("SMAPITranslateKeyOutOf_GM() parameter nAlgo is invalid");
		return ERR_INPUT;
	}
	if(pbKEK==NULL || pbKeyUnderHMK==NULL || pbKeyUnderKEK==NULL){
		errlog("SMAPITranslateKeyOutOf_GM() buffer is NULL");
		return ERR_INPUT;
	}

	if(nAlgo==4){
		if(nKeyLen!=16){
			errlog("SMAPITranslateKeyOutOf_GM() parameter nAlgo is invalid");
			return ERR_INPUT;
		}
	}

	strcpy(secbuf_in , "A8");
	iMsgLen = 2;
	// tag
//	strncpy(&secbuf_in[iMsgLen], TAG3,3);
//	iMsgLen +=3;

	//
	if(nAlgo==4)
		secbuf_in[iMsgLen++] = SM4;
	else
		secbuf_in[iMsgLen++] = DES3;
	//kek
	if(nAlgo ==1)
		retval = key_hex2str(pbKEK, DES1, &secbuf_in[iMsgLen]);
	else if(nAlgo ==2)
		retval = key_hex2str(pbKEK, DES2, &secbuf_in[iMsgLen]);
	else if(nAlgo ==3)
		retval = key_hex2str(pbKEK, DES3, &secbuf_in[iMsgLen]);
	else if(nAlgo ==4)
		retval = key_hex2str(pbKEK, SM4, &secbuf_in[iMsgLen]);
	else{
		errlog("SMAPITranslateKeyOutOf_GM() nAlgo is invalid");
		return ERR_ALGO_FLAG;
	}
	if(retval <0){
		errlog("SMAPITranslateKeyOutOf_GM() failed, pbKEK is wrong");
		return ERR_INPUT;
	}
	iMsgLen += retval;
	//key
	if(nKeyLen ==8)
		retval = key_hex2str(pbKeyUnderHMK, DES1, &secbuf_in[iMsgLen]);
	else if(nKeyLen ==16){
		if(nAlgo == 4)
			retval = key_hex2str(pbKeyUnderHMK, SM4, &secbuf_in[iMsgLen]);
		else
			retval = key_hex2str(pbKeyUnderHMK, DES2, &secbuf_in[iMsgLen]);
	}
	else if(nKeyLen ==24)
		retval = key_hex2str(pbKeyUnderHMK, DES3, &secbuf_in[iMsgLen]);
	else{
		errlog("SMAPITranslateKeyOutOf_GM() nKeyLen is invalid");
		return ERR_ALGO_FLAG;
	}
	if(retval <0){
		errlog("SMAPITranslateKeyOutOf_GM() failed, pbKeyUnderLMK is wrong");
		return ERR_INPUT;
	}
	iMsgLen += retval;
	//kek
	if(nKeyLen ==8)
		secbuf_in[iMsgLen++] = 'Z';
	else if(nKeyLen ==16){
		if(nAlgo == 4)
			secbuf_in[iMsgLen++] = 'S';
		else
			secbuf_in[iMsgLen++] = 'X';
	}
	else
		secbuf_in[iMsgLen++] = 'Y';

#ifdef DEBUG_ON
	int i;
	nhLog(" iMsgLen:%d:\n", iMsgLen);
	nhLog("%s() send:\n", __func__);
	for(i=0;i<iMsgLen;i++)
	{
		nhLog("%02X", secbuf_in[i]);
	}
	nhLog("\n");
#endif

	if ((retval = HSM_LINK(nSock, iMsgLen, secbuf_in, secbuf_out)) != 0)
	{
		errlog("SMAPITranslateKeyOutOf() call failed, errno=%d", retval);
		return retval;
	}
	else
	{
		if(nKeyLen ==8)
			str2hex(&secbuf_out[4], pbKeyUnderKEK, 16);
		else if(nKeyLen ==16)
			str2hex(&secbuf_out[5], pbKeyUnderKEK, 32);
		else
			str2hex(&secbuf_out[5], pbKeyUnderKEK, 48);
	}

 	return 0;

}

/**************************************************************************************
 * (A6)
 * 功能描述: 将被KEK加密的密钥的密文, 转换为以HMK加密的密文(导入密钥: 指令D002)
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          nAlgo:  KEK加密算法类型
 *                   (Single_Des = 1; Double_Des = 2; Triple_Des = 3)
 *          pbKEK: 经HMK加密的KEK的密文值, 二进制数
 *                  当nAlgo1 = 1时, 8字节长;
 *                  当nAlgo1 = 2时, 16字节长;
 *                  当nAlgo1 = 3时, 24字节长
 *          pbKeyUnderKEK:  被KEK加密的密钥的密文, 二进制数, 长度由nKeyLen指定
 *          nKeyLen: 被加密密钥的长度, 取值范围: {8, 16, 24}
 *
 * 输出参数:
 *          pbKeyUnderHMK: 被HMK加密的密钥的密文, 二进制数, 长度由nKeyLen指定
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          2: 无效的密钥(KEK);
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9 -- 其它错误
 *
 ***************************************************************************************/
int SMAPITranslateKeyInTo(int nSock,int nAlgo,u8 *pbKEK,u8 *pbKeyUnderKEK,int nKeyLen,
                          u8 *pbKeyUnderHMK)
{
	int iMsgLen = -1, retval = -1;

	u8 secbuf_in[HSM_MAX_BUFFER_SIZE]= {0};
	u8 secbuf_out[HSM_MAX_BUFFER_SIZE]= {0};

	memset(secbuf_in, 0x00, sizeof(secbuf_in));
	memset(secbuf_out, 0x00, sizeof(secbuf_out));

	strcpy(secbuf_in , "A6");
	iMsgLen = 2;
	// tag
//	strncpy(&secbuf_in[iMsgLen], TAG3,3);
//	iMsgLen +=3;
//
	secbuf_in[iMsgLen++] = DES3;
	//kek
	if(nAlgo ==1)
		retval = key_hex2str(pbKEK, DES1, &secbuf_in[iMsgLen]);
	else if(nAlgo ==2)
		retval = key_hex2str(pbKEK, DES2, &secbuf_in[iMsgLen]);
	else if(nAlgo ==3)
		retval = key_hex2str(pbKEK, DES3, &secbuf_in[iMsgLen]);
	else{
		errlog("SMAPITranslateKeyInTo() nAlgo is invalid");
		return ERR_ALGO_FLAG;
	}
	if(retval <0){
		errlog("SMAPITranslateKeyInTo() failed, pbKEK is wrong");
		return ERR_INPUT;
	}
	iMsgLen += retval;
	//key
	if(nKeyLen ==8)
		retval = key_hex2str(pbKeyUnderKEK, DES1, &secbuf_in[iMsgLen]);
	else if(nKeyLen ==16)
		retval = key_hex2str(pbKeyUnderKEK, DES2, &secbuf_in[iMsgLen]);
	else if(nKeyLen ==24)
		retval = key_hex2str(pbKeyUnderKEK, DES3, &secbuf_in[iMsgLen]);
	else{
		errlog("SMAPITranslateKeyInTo() nKeyLen is invalid");
		return ERR_ALGO_FLAG;
	}
	if(retval <0){
		errlog("SMAPITranslateKeyInTo() failed, pbKeyUnderKEK is wrong");
		return ERR_INPUT;
	}
	iMsgLen += retval;
	//kek
	if(nKeyLen ==8)
		secbuf_in[iMsgLen++] = 'Z';
	else if(nKeyLen ==16)
		secbuf_in[iMsgLen++] = 'X';
	else
		secbuf_in[iMsgLen++] = 'Y';


#ifdef DEBUG_ON
	int i;
	nhLog(" iMsgLen:%d:\n", iMsgLen);
	nhLog("%s() send:\n", __func__);
	for(i=0;i<iMsgLen;i++)
	{
		nhLog("%02X", secbuf_in[i]);
	}
	nhLog("\n");
#endif

	if ((retval = HSM_LINK(nSock, iMsgLen, secbuf_in, secbuf_out)) != 0)
	{
		errlog("SMAPITranslateKeyInTo() call failed, errno=%d", retval);
		return retval;
	}
	else
	{
		if(nKeyLen ==8)
			str2hex(&secbuf_out[4], pbKeyUnderHMK, 16);
		else if(nKeyLen ==16)
			str2hex(&secbuf_out[5], pbKeyUnderHMK, 32);
		else
			str2hex(&secbuf_out[5], pbKeyUnderHMK, 48);
	}

	return 0;
}

/*************************************************************************************************
1. 4.21 KEK 到HMK 的转加密_国密版（7.2.2 导入密钥）  (A6)
2. 函数功能：将被KEK 加密的密钥的密文，转换为以HMK 加密的密文。
3. 输入参数：
	UINT nSock：连接的socket 句柄
	int nAlgo：KEK 加密算法类型。Single_Des = 1,Double_Des = 2 ,Triple_Des = 3, SM4= 4
	byte *pbKEK：经HMK 加密的KEK 的密文值，二进制数
	byte *pbKeyUnderKEK：被KEK 加密的密钥的密文，二进制数，长度由nKeyLen指定
	int nKeyLen：被加密密钥的长度，取值范围：{8, 16, 24}
4. 输出参数：
	byte *pbKeyUnderHMK：被HMK 加密的密钥的密文，二进制数，长度由nKeyLen指定
5. 返回值：
	0： 执行成功
	1： 输入参数验证失败
	2： 无效的索引值
	3： 向加密机发送数据失败
	4： 接收加密机数据超时
	5： 接收到的数据格式错
	9:  其他错误
***************************************************************************************************/
int SMAPITranslateKeyInTo_GM(int nSock,int nAlgo,u8 *pbKEK,u8 *pbKeyUnderKEK,int nKeyLen,
	                     u8 *pbKeyUnderHMK)
{
	int iMsgLen = -1, retval = -1;

	u8 secbuf_in[HSM_MAX_BUFFER_SIZE]= {0};
	u8 secbuf_out[HSM_MAX_BUFFER_SIZE]= {0};

	memset(secbuf_in, 0x00, sizeof(secbuf_in));
	memset(secbuf_out, 0x00, sizeof(secbuf_out));

	if(nSock <= 0){
		errlog("SMAPITranslateKeyInTo_GM() parameter nSock is invalid");
		return ERR_SOCK_INVALID;
	}

	if(nAlgo!=1 && nAlgo!=2 && nAlgo!=3 && nAlgo!=4){
		errlog("SMAPITranslateKeyInTo_GM() parameter nAlgo is invalid");
		return ERR_INPUT;
	}
	if(pbKEK==NULL || pbKeyUnderHMK==NULL || pbKeyUnderKEK==NULL){
		errlog("SMAPITranslateKeyInTo_GM() buffer is NULL");
		return ERR_INPUT;
	}

	if(nAlgo==4){
		if(nKeyLen!=16){
			errlog("SMAPITranslateKeyInTo_GM() parameter nAlgo is invalid");
			return ERR_INPUT;
		}
	}

	strcpy(secbuf_in , "A6");
	iMsgLen = 2;
	// tag
//	strncpy(&secbuf_in[iMsgLen], TAG3,3);
//	iMsgLen +=3;
//
	if(nAlgo ==4)
		secbuf_in[iMsgLen++] = SM4;
	else
		secbuf_in[iMsgLen++] = DES3;
	//kek
	if(nAlgo ==1)
		retval = key_hex2str(pbKEK, DES1, &secbuf_in[iMsgLen]);
	else if(nAlgo ==2)
		retval = key_hex2str(pbKEK, DES2, &secbuf_in[iMsgLen]);
	else if(nAlgo ==3)
		retval = key_hex2str(pbKEK, DES3, &secbuf_in[iMsgLen]);
	else if(nAlgo ==4)
		retval = key_hex2str(pbKEK, SM4, &secbuf_in[iMsgLen]);
	else{
		errlog("SMAPITranslateKeyInTo_GM() nAlgo is invalid");
		return ERR_ALGO_FLAG;
	}
	if(retval <0){
		errlog("SMAPITranslateKeyInTo_GM() failed, pbKEK is wrong");
		return ERR_INPUT;
	}
	iMsgLen += retval;
	//key
	if(nKeyLen ==8)
		retval = key_hex2str(pbKeyUnderKEK, DES1, &secbuf_in[iMsgLen]);
	else if(nKeyLen ==16){
		if(nAlgo ==4)
			retval = key_hex2str(pbKeyUnderKEK, SM4, &secbuf_in[iMsgLen]);
		else
			retval = key_hex2str(pbKeyUnderKEK, DES2, &secbuf_in[iMsgLen]);
	}
	else if(nKeyLen ==24)
		retval = key_hex2str(pbKeyUnderKEK, DES3, &secbuf_in[iMsgLen]);
	else{
		errlog("SMAPITranslateKeyInTo_GM() nKeyLen is invalid");
		return ERR_ALGO_FLAG;
	}
	if(retval <0){
		errlog("SMAPITranslateKeyInTo_GM() failed, pbKeyUnderKEK is wrong");
		return ERR_INPUT;
	}
	iMsgLen += retval;
	//kek
	if(nKeyLen ==8)
		secbuf_in[iMsgLen++] = 'Z';
	else if(nKeyLen ==16)
		secbuf_in[iMsgLen++] = 'X';
	else
		secbuf_in[iMsgLen++] = 'Y';

#ifdef DEBUG_ON
	int i;
	nhLog(" iMsgLen:%d:\n", iMsgLen);
	nhLog("%s() send:\n", __func__);
	for(i=0;i<iMsgLen;i++)
	{
		nhLog("%02X", secbuf_in[i]);
	}
	nhLog("\n");
#endif

	if ((retval = HSM_LINK(nSock, iMsgLen, secbuf_in, secbuf_out)) != 0)
	{
		errlog("SMAPITranslateKeyInTo_GM() call failed, errno=%d", retval);
		return retval;
	}
	else
	{
		if(nKeyLen ==8)
			str2hex(&secbuf_out[4], pbKeyUnderHMK, 16);
		else if(nKeyLen ==16)
			str2hex(&secbuf_out[5], pbKeyUnderHMK, 32);
		else
			str2hex(&secbuf_out[5], pbKeyUnderHMK, 48);
	}

	return 0;

}

/**************************************************************************************
 *
 * 功能描述: 定义密钥信封打印格式
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          pszPrintFormat:  打印格式控制符,长度小于255
 *
 * 输出参数:
 *          无
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9 -- 其它错误
 *
 ***************************************************************************************/
int SMAPIDefinePrintFormat(int nSock, const char *pszPrintFormat)
{
	int iMsgLen = -1, retval = -1;

	u8 secbuf_in[HSM_MAX_BUFFER_SIZE]= {0};
	u8 secbuf_out[HSM_MAX_BUFFER_SIZE]= {0};

	memset(secbuf_in, 0x00, sizeof(secbuf_in));
	memset(secbuf_out, 0x00, sizeof(secbuf_out));
	secbuf_in[0] = 'P';
	secbuf_in[1] = 'A';
	memcpy(&secbuf_in[2], pszPrintFormat, strlen(pszPrintFormat));

	iMsgLen = (2 + strlen(pszPrintFormat));

#ifdef DEBUG_ON
	int i;
	nhLog(" iMsgLen:%d:\n", iMsgLen);
	nhLog("%s() send:\n", __func__);
	for(i=0;i<iMsgLen;i++)
	{
		nhLog("%02X", secbuf_in[i]);
	}
	nhLog("\n");
#endif

	if ((retval = HSM_LINK(nSock, iMsgLen, secbuf_in, secbuf_out)) != 0)
	{
		errlog("SMAPIDefinePrintFormat() call failed, errno=%d", retval);
		return retval;
	}

	return 0;
}


/**************************************************************************************
 * 4.22 产生随机密钥 (X0)
 * 功能描述: 根据指定长度随机生成一个密钥, 并返回密钥的效验值; 并根据nIndex选择是否将
 *           产生的密钥保存到加密机的某个索引位上(指令D006、D052、D054、D00C).
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          nKeyLen:  要生成的随机密钥的长度, 取值范围: {8, 16, 24}
 *          pszServId: 打印在密码信封上的终端编号, ASCII字符, 长度由nServIdLen指定
 *          nServIdLen: pszServId的长度
 *          nMode: 密钥被保存的方式
 *                 	0: 不保存;
 *                 	1: 打印密码信封;
 *                 	2: 保存到IC卡上.
 *          nIndex: 索引号, 值为 0: 不保存到加密机上
 *                               1 -- 255: 密钥存储到加密机上相应的索引值
 *
 * 输出参数:
 *          pbKey: 随机产生的密钥(被HMK加密), 二进制数, 调用函数应分配24字节
 *                 的存储空间, 返回数据实际长度由nKeyLen指定
 *          szCheckValue: 产生密钥的效验值, 是将CheckValue的前四个字节进行扩展而
 *                        得到的8个十六进制字符
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          8: 打印密钥信封
 *          9 -- 其它错误
 *
 * 密钥信封格式: 由程序执行目录下的XXXX.fmt文件指定, 其中: 格尔为GeEr.fmt;
 *               卫士通为: WeiShiTong.fmt; 歌盟为: GeMeng.fmt
 ***************************************************************************************/
int SMAPIGenerateKey(int nSock,int nKeyLen,char *pszServId,int nServIdLen,int nMode,int nIndex,
                     u8 *pbKey,u8 szCheckValue[8])
{
	FILE *fp = NULL;
	char fmt1[256] = {'\0'};
	int retval = -1;
	u8 bTmpKey1[25] = {'\0'}, bTmpKey2[25] = {'\0'}, bTmpKey3[25] = {'\0'};
	u8 tmpbuf[512] = {'\0'};
	int iMsgLen = -1;

	u8 secbuf_in[HSM_MAX_BUFFER_SIZE]= {0};
	u8 secbuf_out[HSM_MAX_BUFFER_SIZE]= {0};
	u8 ApdexInfo[512]={0} , sServId[256]={0};

	memset(secbuf_in, 0x00, sizeof(secbuf_in));
	memset(secbuf_out, 0x00, sizeof(secbuf_out));



	/* 从文件中读取密钥信封打印格式... */
	if (nMode == 1)
	{
		fp = fopen("./WeiShiTong.fmt", "r");
		if (fp == NULL)
			return ERR_READ_FILE;
		else
		{
			fscanf(fp, "%s", fmt1);
			fclose(fp);
			fp = NULL;
		}
		/* 定义打印格式 */
		if ((retval = SMAPIDefinePrintFormat(nSock, fmt1)) != 0)
		{
			errlog("SMAPIGenerateKey() define print format failed.");
			return ERR_DEFINE_PRINTFORMAT;
		}
	}

	strcpy(secbuf_in , "X0");
	iMsgLen = 2;
	secbuf_in[iMsgLen++] = '0';//random key
	if(nMode==0){
		strcpy(&secbuf_in[iMsgLen] , "00");
	}else if(nMode==1){
		strcpy(&secbuf_in[iMsgLen] , "10");
	}else if(nMode==2){
		strcpy(&secbuf_in[iMsgLen] , "00");
	}else{
		errlog("SMAPIGenerateKey() invalid nMode");
		return ERR_INPUT;
	}
	iMsgLen +=2;
	// tag
//	strncpy(&secbuf_in[iMsgLen], TAG3,3);
//	iMsgLen +=3;
//
	secbuf_in[iMsgLen++] = DES3;
	//compment num
	secbuf_in[iMsgLen++] = '3';
	//keylen
	sprintf(&secbuf_in[iMsgLen]  , "%04d" , nKeyLen);
	iMsgLen +=4;
	//key or index
	if(nMode ==2){//
		sprintf(&secbuf_in[iMsgLen] , "K3%03d" , nIndex);
		iMsgLen +=5;
	}
	//dayin fen shu
	if(nMode ==1){
		secbuf_in[iMsgLen++] = '1';

		memset(ApdexInfo , 0 , sizeof(ApdexInfo));
		strncpy(sServId, pszServId,nServIdLen);
		strcat(ApdexInfo, sServId);
		strcat(ApdexInfo, ";CheckValue");
		strcat(ApdexInfo, ";Component");
		//strcat(ApdexInfo, ";Component 1;;");
		//strcat(ApdexInfo, sServId);
		//strcat(ApdexInfo, ";CheckValue");
		//strcat(ApdexInfo, ";Component 2;;");
		//strcat(ApdexInfo, sServId);
		//strcat(ApdexInfo, ";CheckValue");
		//strcat(ApdexInfo, ";Component 3");
		memcpy(&secbuf_in[iMsgLen],ApdexInfo,strlen(ApdexInfo));
		iMsgLen +=strlen(ApdexInfo);
	}

	if ((retval = HSM_LINK(nSock, iMsgLen, secbuf_in, secbuf_out)) != 0)
	{
		errlog("SMAPIGenerateKey() call failed, errno=%d", retval);
		return retval;
	}

	if(nKeyLen ==8){
		str2hex(&secbuf_out[4], pbKey, 16);
		str2hex(&secbuf_out[4+8], szCheckValue, 16);
	}
	else if(nKeyLen ==16){
		str2hex(&secbuf_out[5], pbKey, 32);
		str2hex(&secbuf_out[5+16], szCheckValue, 16);
	}
	else {
		str2hex(&secbuf_out[5], pbKey, 48);
		str2hex(&secbuf_out[5+24], szCheckValue, 16);
	}
	return 0;
}



/**************************************************************************************
 * 4.23 数据掩盖 (KE)
 * 功能描述: 采用内部算法对一段数据进行"掩盖", 输出密文(指令KE)
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          pszPlainText:  明文数据段, ASCII字符, 长度由nTextLen指定
 *          nTextLen: pszPlainText的字节长度
 *
 * 输出参数:
 *          pszHiddenText: 掩盖之后的密文数据,ASCII字符, 长度由nTextLen指定
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9  其它错误
 *
 ***************************************************************************************/
int SMAPIHideBlock(int nSock,char *pszPlainText,int nTextLen,
                   char *pszHiddenText)
{
	int iMsgLen = -1, retval = -1;

	u8 secbuf_in[HSM_MAX_BUFFER_SIZE]= {0};
	u8 secbuf_out[HSM_MAX_BUFFER_SIZE]= {0};

	if(nSock<0){
		errlog("SMAPIHideBlock() failed, the socket is invalid");
		return ERR_SOCK_INVALID;
	}

	if(nTextLen<0 || nTextLen>256){
		errlog("SMAPIHideBlock() failed, the nTextLen is invalid");
		return ERR_DATA_LEN;
	}

	if((NULL == pszPlainText) || (NULL == pszHiddenText))
	{
		errlog("SMAPIHideBlock() failed, the pointer is NULL");
		return ERR_INVALID_PARA;
	}

	if(nTextLen != strlen(pszPlainText)){
		errlog("SMAPIHideBlock() failed, pszPlainText is not equal to nTextLen");
		return ERR_DATA_LEN;
	}

	secbuf_in[0] = 'K';
	secbuf_in[1] = 'E';
	secbuf_in[2] = '1';
	iMsgLen = 3;
	sprintf((char *)secbuf_in+iMsgLen, "%04d", nTextLen);
	iMsgLen += 4;

	memcpy(secbuf_in+iMsgLen, pszPlainText, nTextLen);
	iMsgLen += nTextLen;

#ifdef DEBUG_ON
	int i;
	nhLog(" iMsgLen:%d:\n", iMsgLen);
	nhLog("%s() send:\n", __func__);
	for(i=0;i<iMsgLen;i++)
	{
		nhLog("%02X", secbuf_in[i]);
	}
	nhLog("\n");
#endif

	if ((retval = HSM_LINK(nSock, iMsgLen, secbuf_in, secbuf_out)) != 0)
	{
		errlog("SMAPIHideBlock() call failed, errno=%d", retval);
		return retval;
	}
	else
	{
		memcpy(pszHiddenText,secbuf_out+8, nTextLen);
		pszHiddenText[nTextLen]='\0';
	}

	return 0;
}

/**************************************************************************************
 *
 * 功能描述: 采用内部算法对一段经过"掩盖"的数据进行还原, 输出明文(指令KE)
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          pszHiddenText:  被掩盖密文数据, ASCII字符, 长度由nTextLen指定
 *          nTextLen: pszHiddenText的字节长度
 *
 * 输出参数:
 *          pszPlainText: 被还原的明文数据, ASCII字符, 长度由nTextLen指定
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9  其它错误
 *
 ***************************************************************************************/
int SMAPIRevalBlock(int nSock, char *pszHiddenText, int nTextLen, char *pszPlainText)
{
	int iMsgLen = -1, retval = -1;

	u8 secbuf_in[HSM_MAX_BUFFER_SIZE]= {0};
	u8 secbuf_out[HSM_MAX_BUFFER_SIZE]= {0};

	if(nSock<0){
		errlog("SMAPIHideBlock() failed, the socket is invalid");
		return ERR_SOCK_INVALID;
	}

	if(nTextLen<0 || nTextLen>256){
		errlog("SMAPIHideBlock() failed, the nTextLen is invalid");
		return ERR_DATA_LEN;
	}

	if((NULL == pszHiddenText) || (NULL == pszPlainText))
	{
		errlog("SMAPIRevalBlock() failed, the pointer is NULL");
		return ERR_INVALID_PARA;
	}

	if(nTextLen != strlen(pszHiddenText)){
		errlog("SMAPIHideBlock() failed, pszPlainText is not equal to nTextLen");
		return ERR_DATA_LEN;
	}

	secbuf_in[0] = 'K';
	secbuf_in[1] = 'E';
	secbuf_in[2] = '0';
	iMsgLen = 3;
	sprintf((char *)secbuf_in+iMsgLen, "%04d", nTextLen);
	iMsgLen += 4;

	memcpy(secbuf_in+iMsgLen, pszHiddenText, nTextLen);
	iMsgLen += nTextLen;

#ifdef DEBUG_ON
	int i;
	nhLog(" iMsgLen:%d:\n", iMsgLen);
	nhLog("%s() send:\n", __func__);
	for(i=0;i<iMsgLen;i++)
	{
		nhLog("%02X", secbuf_in[i]);
	}
	nhLog("\n");
#endif

	/* 发送指令 */
	if ((retval = HSM_LINK(nSock, iMsgLen, secbuf_in, secbuf_out)) != 0)
	{
		errlog("SMAPIRevalBlock() call failed, errno=%d", retval);
		return retval;
	}
	else
	{
		memcpy(pszPlainText, &secbuf_out[8], nTextLen);
		pszPlainText[nTextLen]='\0';
	}

	return 0;
}

/**************************************************************************************
 * 功能描述: 将密钥的明文, 以HMK(LMK)加密, 输出密文(根据HMK的长度,选择加密算法),指令UX
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          pbPlainKey:  密钥的明文, 二进制数, 长度由nKeyLen指定
 *          nKeyLen: pbPlainKey的字节长度, 取值范围: {8, 16, 24}
 *
 * 输出参数:
 *          pbKeyUnderLMK: 被HMK(LMK)加密的密钥的密文
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9  其它错误
 *
 ***************************************************************************************/
int SMAPIEncryptKey(int nSock, u8 *pbPlainKey, int nKeyLen, u8 *pbKeyUnderLMK)
{
	int iMsgLen = -1, retval = -1;

	u8 secbuf_in[HSM_MAX_BUFFER_SIZE]= {0};
	u8 secbuf_out[HSM_MAX_BUFFER_SIZE]= {0};

	if(nSock<0){
		errlog("SMAPIEncryptKey() failed, the socket is invalid");
		return ERR_SOCK_INVALID;
	}

	if (pbPlainKey == NULL || pbKeyUnderLMK == NULL){
		errlog("SMAPIEncryptKey() failed, the pointer is NULL");
		return ERR_INVALID_PARA;
	}

	/*if (nKeyLen != 8 && nKeyLen != 16 && nKeyLen != 24)
		return ERR_INVALID_PARA;*/

	secbuf_in[0] = 'U';
	secbuf_in[1] = 'X';
	secbuf_in[2] = '0';
	secbuf_in[3] = '1';

	iMsgLen = 4;

	secbuf_in[iMsgLen++] = '0';
	secbuf_in[iMsgLen++] = '1';

	if((nKeyLen !=8) &&(nKeyLen !=16)&&(nKeyLen !=24)){
		errlog("SMAPIEncryptKey() nKeyLen is invalid");
		return ERR_ALGO_FLAG;
	}
	sprintf(&secbuf_in[iMsgLen] , "%02d" , nKeyLen);
	iMsgLen +=2;
	memcpy(&secbuf_in[iMsgLen]  , pbPlainKey , nKeyLen);
	iMsgLen +=nKeyLen;


	if ((retval = HSM_LINK(nSock, iMsgLen, secbuf_in, secbuf_out)) != 0)
	{
		errlog("SMAPIEncryptKey() call failed, errno=%d", retval);
		return retval;
	}
	else
	{
		memcpy(pbKeyUnderLMK , &secbuf_out[6] , nKeyLen);
	}

	return 0;
}


/**************************************************************************************
 *
 * 功能描述: 用DES类算法以ECB模式对明文数据进行加密(指令D012)
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          nAlgo:  算法类型(Single_Des = 1; Double_Des = 2; Triple_Des = 3)
 *          pbKey:  DES密钥的密文(由HMK/LMK加密), 二进制数
 *                  当nAlgo = 1时, 长度为8字节
 *                  当nAlgo = 2时, 长度为16字节
 *                  当nAlgo = 3时, 长度为24字节
 *          pbPlainBlock: 需要加密的明文, 二进制数, 长度由nBlockLen指定
 *          nBlockLen: pbPlainBlock的长度, 取值范围: 8的整数倍, 小于等于1024
 *
 * 输出参数:
 *          pbCryptBlock: 加密之后的密文, 二进制数, 长度由nBlockLen指定
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          2: 无效的密钥(KEK)
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9  其它错误
 ***************************************************************************************/
int SMAPIEncryptBlock(int nSock,int nAlgo,u8 *pbKey,u8 *pbPlainBlock,int nBlockLen,
                      u8 *pbCryptBlock)
{
	int iMsgLen = -1, retval = -1 ,tlen;
	u8 *temp;
	char lenbuf[5] = {0};

	u8 secbuf_in[HSM_MAX_BUFFER_SIZE]= {0};
	u8 secbuf_out[HSM_MAX_BUFFER_SIZE]= {0};

	if(nSock<0){
		errlog("SMAPIEncryptBlock() failed, the socket is invalid");
		return ERR_SOCK_INVALID;
	}
	if(nAlgo!=1 && nAlgo!=2 && nAlgo!=3){
		errlog("SMAPIEncryptBlock() failed, the nAlgo is invalid");
		return ERR_INVALID_PARA;
	}

	if(nBlockLen<0 || nBlockLen>4096 || nBlockLen%8!=0){
		errlog("SMAPIEncryptBlock() failed, the nBlockLen is invalid");
		return ERR_DATA_LEN;
	}

	if((NULL == pbKey) || (NULL == pbPlainBlock) || (NULL == pbCryptBlock))
	{
		errlog("SMAPIEncryptBlock() failed, the pointer is NULL");
		return ERR_INVALID_PARA;
	}

	secbuf_in[0] = 'V';
	secbuf_in[1] = '2';
	iMsgLen = 2;

	/* 算法应用模式: ECB = 0; CBC = 1 */
	secbuf_in[iMsgLen++] = DES3;
//	memcpy(secbuf_in+iMsgLen, TAG3, 3);
//	iMsgLen += 3;

	/* 算法类型: Single_Des = 1; Double_Des = 2; Triple_Des = 3 */
	if(nAlgo==1){
		retval = key_hex2str(pbKey, DES1, &secbuf_in[iMsgLen]);
		//iMsgLen += retval;
	}
	else if(nAlgo==2){
		retval = key_hex2str(pbKey, DES2, &secbuf_in[iMsgLen]);
		//iMsgLen += retval;
	}
	else if(nAlgo==3){
		retval = key_hex2str(pbKey, DES3, &secbuf_in[iMsgLen]);
		//iMsgLen += retval;
	}
	else{
		errlog("SMAPIEncryptBlock() nKeyLen is invalid");
		return ERR_ALGO_FLAG;
	}
	if(retval < 0)
	{
		errlog("SMAPIEncryptBlock() failed, pbKey is wrong");
		return ERR_INPUT;
	}
	iMsgLen += retval;

	/*分散次数*/
	secbuf_in[iMsgLen++] = '0';
	/*加解密标识*/
	secbuf_in[iMsgLen++] = ENC;
	/*算法模式*/
	secbuf_in[iMsgLen++] = ECB;
	/*填充模式*/
	secbuf_in[iMsgLen++] = FILL_80_N;
	/*数据长度*/
	sprintf((char *)secbuf_in+iMsgLen, "%04d", nBlockLen);
	iMsgLen += 4;
	/*数据*/
	//temp = secbuf_in+iMsgLen;
	//hex2str(pbPlainBlock,  &temp,  nBlockLen);
	memcpy(secbuf_in+iMsgLen , pbPlainBlock , nBlockLen);
	iMsgLen += nBlockLen;

#ifdef DEBUG_ON
	int i;
	nhLog(" iMsgLen:%d:\n", iMsgLen);
	nhLog("%s() send:\n", __func__);
	for(i=0;i<iMsgLen;i++)
	{
		nhLog("%02X", secbuf_in[i]);
	}
	nhLog("\n");
#endif

	if ((retval = HSM_LINK(nSock, iMsgLen, secbuf_in, secbuf_out)) != 0)
	{
		errlog("SMAPIEncryptBlock() call failed, errno=%d", retval);
		return retval;
	}
	else
	{
		//memcpy(lenbuf, secbuf_out+4, 4);
		tlen = (secbuf_out[4]-'0')*1000 + (secbuf_out[5]-'0')*100+ (secbuf_out[6]-'0')*10+ (secbuf_out[7]-'0');
		memcpy(pbCryptBlock, &secbuf_out[8], tlen);
		//str2hex(secbuf_out+4+4, pbCryptBlock, 2*nBlockLen);
	}

	return 0;
}

/**************************************************************************************
 *
 * 功能描述: 用DES类算法以ECB模式对密文数据进行解密(指令D014)
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          nAlgo:  算法类型(Single_Des = 1; Double_Des = 2; Triple_Des = 3)
 *          pbKey:  DES密钥的密文(由HMK/LMK加密), 二进制数
 *                  当nAlgo = 1时, 长度为8字节
 *                  当nAlgo = 2时, 长度为16字节
 *                  当nAlgo = 3时, 长度为24字节
 *          pbCryptBlock: 需要解密的密文, 二进制数, 长度由nBlockLen指定
 *          nBlockLen: pbCryptBlock的长度, 取值范围: 8的整数倍, 小于等于1024
 *
 * 输出参数:
 *          pbPlainBlock: 解密之后的明文, 二进制数, 长度由nBlockLen指定
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          2: 无效的密钥(KEK)
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9 -- 其它错误
 *
 ***************************************************************************************/
int SMAPIDecryptBlock(int nSock,int nAlgo,u8 *pbKey,u8 *pbCryptBlock,int nBlockLen,
                      u8 *pbPlainBlock)
{
	int iMsgLen = -1, retval = -1;

	u8 secbuf_in[HSM_MAX_BUFFER_SIZE]= {0};
	u8 secbuf_out[HSM_MAX_BUFFER_SIZE]= {0};
	u8 *temp;

	if(nSock<0){
		errlog("SMAPIDecryptBlock() failed, the socket is invalid");
		return ERR_SOCK_INVALID;
	}
	if(nAlgo!=1 && nAlgo!=2 && nAlgo!=3){
		errlog("SMAPIDecryptBlock() failed, the nAlgo is invalid");
		return ERR_INVALID_PARA;
	}

	if(nBlockLen<0 || nBlockLen>4096 || nBlockLen%8!=0){
		errlog("SMAPIDecryptBlock() failed, the nBlockLen is invalid");
		return ERR_DATA_LEN;
	}

	if((NULL == pbKey) || (NULL == pbCryptBlock) || (NULL == pbPlainBlock))
	{
		errlog("SMAPIDecryptBlock() failed, the pointer is NULL");
		return ERR_INVALID_PARA;
	}

	secbuf_in[0] = 'V';
	secbuf_in[1] = '2';
	iMsgLen = 2;

	/* 算法应用模式: ECB = 0; CBC = 1 */
	secbuf_in[iMsgLen++] = DES3;
//	memcpy(secbuf_in+iMsgLen, TAG3, 3);
//	iMsgLen += 3;

	/* 算法类型: Single_Des = 1; Double_Des = 2; Triple_Des = 3 */
	if(nAlgo==1){
		retval = key_hex2str(pbKey, DES1, &secbuf_in[iMsgLen]);
		//iMsgLen += retval;
	}
	else if(nAlgo==2){
		retval = key_hex2str(pbKey, DES2, &secbuf_in[iMsgLen]);
		//iMsgLen += retval;
	}
	else if(nAlgo==3){
		retval = key_hex2str(pbKey, DES3, &secbuf_in[iMsgLen]);
		//iMsgLen += retval;
	}
	else{
		errlog("SMAPIDecryptBlock() nKeyLen is invalid");
		return ERR_ALGO_FLAG;
	}
	if(retval < 0)
	{
		errlog("SMAPIDecryptBlock() failed, pbKey is wrong");
		return ERR_INPUT;
	}
	iMsgLen += retval;

	/*分散次数*/
	secbuf_in[iMsgLen++] = '0';
	/*加解密标识*/
	secbuf_in[iMsgLen++] = DEC;
	/*算法模式*/
	secbuf_in[iMsgLen++] = ECB;
	/*填充模式*/
	secbuf_in[iMsgLen++] = FILL_80_N;
	/*数据长度*/
	sprintf((char *)secbuf_in+iMsgLen, "%04d", nBlockLen);
	iMsgLen += 4;
	/*数据*/
	//temp = secbuf_in+iMsgLen;
	//hex2str(pbCryptBlock,  &temp,  nBlockLen);
	memcpy(secbuf_in+iMsgLen ,pbCryptBlock,  nBlockLen);
	iMsgLen += nBlockLen;

#ifdef DEBUG_ON
	int i=0;

	nhLog("SMAPIDecryptBlock() send:\n");
	for(i=0;i<iMsgLen;i++)
	{
		nhLog("%02X", secbuf_in[i]);
	}
	nhLog("\n");
#endif


	if ((retval = HSM_LINK(nSock, iMsgLen, secbuf_in, secbuf_out)) != 0)
	{
		errlog("SMAPIDecryptBlock() call failed, errno=%d", retval);
		return retval;
	}
	else
	{
		memcpy(pbPlainBlock, secbuf_out+4+4, nBlockLen);
		//str2hex(secbuf_out+4+4, pbPlainBlock, nBlockLen*2);
	}

	return 0;
}


/**************************************************************************************
 *
 * 功能描述: 用DES类算法以CBC模式对明文数据进行加密
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          nAlgo:  算法类型(Single_Des = 1; Double_Des = 2; Triple_Des = 3)
 *          pbKey:  DES密钥的密文(由HMK/LMK加密), 二进制数
 *                  当nAlgo = 1时, 长度为8字节
 *                  当nAlgo = 2时, 长度为16字节
 *                  当nAlgo = 3时, 长度为24字节
 *          pbPlainBlock: 需要加密的明文, 二进制数, 长度由nBlockLen指定
 *          nBlockLen: pbPlainBlock的长度, 取值范围: 8的整数倍, 小于等于1024
 *          pbIV: 初始化向量, 二进制数, 长度为8字节
 *
 * 输出参数:
 *          pbCryptBlock: 加密之后的密文, 二进制数, 长度由nBlockLen指定
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          2: 无效的密钥(KEK)
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9 -- 其它错误
 *
 ***************************************************************************************/
int SMAPIEncryptCBC(int nSock,int nAlgo,u8 *pbKey,u8 *pbPlainBlock,int nBlockLen,u8 *pbIV,
                    u8 *pbCryptBlock)
{
	int iMsgLen = 0, retval = -1 ,tlen;

	u8 secbuf_in[HSM_MAX_BUFFER_SIZE]= {0};
	u8 secbuf_out[HSM_MAX_BUFFER_SIZE]= {0};
	u8 *temp;

	if(nSock<0){
		errlog("SMAPIEncryptCBC() failed, the socket is invalid");
		return ERR_SOCK_INVALID;
	}
	if(nAlgo!=1 && nAlgo!=2 && nAlgo!=3){
		errlog("SMAPIEncryptCBC() failed, the nAlgo is invalid");
		return ERR_INVALID_PARA;
	}

	if(nBlockLen<0 || nBlockLen>4096 || nBlockLen%8!=0){
		errlog("SMAPIEncryptCBC() failed, the nBlockLen is invalid");
		return ERR_DATA_LEN;
	}

	if((NULL == pbKey) || (NULL == pbPlainBlock) || (NULL == pbIV) || (NULL== pbCryptBlock))
	{
		errlog("SMAPIEncryptCBC() failed, the pointer is NULL");
		return ERR_INVALID_PARA;
	}

	secbuf_in[0] = 'V';
	secbuf_in[1] = '2';
	iMsgLen = 2;

	/* 算法应用模式: ECB = 0; CBC = 1 */
	secbuf_in[iMsgLen++] = DES3;
//	memcpy(secbuf_in+iMsgLen, TAG3, 3);
//	iMsgLen += 3;

	/* 算法类型: Single_Des = 1; Double_Des = 2; Triple_Des = 3 */
	if(nAlgo==1){
		retval = key_hex2str(pbKey, DES1, &secbuf_in[iMsgLen]);
		//iMsgLen += retval;
	}
	else if(nAlgo==2){
		retval = key_hex2str(pbKey, DES2, &secbuf_in[iMsgLen]);
		//iMsgLen += retval;
	}
	else if(nAlgo==3){
		retval = key_hex2str(pbKey, DES3, &secbuf_in[iMsgLen]);
		//iMsgLen += retval;
	}
	else{
		errlog("SMAPIEncryptCBC() nKeyLen is invalid");
		return ERR_ALGO_FLAG;
	}
	if(retval < 0)
	{
		errlog("SMAPIEncryptCBC() failed, pbKey is wrong");
		return ERR_INPUT;
	}
	iMsgLen += retval;

	/*分散次数*/
	secbuf_in[iMsgLen++] = '0';
	/*加解密标识*/
	secbuf_in[iMsgLen++] = ENC;
	/*算法模式*/
	secbuf_in[iMsgLen++] = CBC;
	/*IV*/
	temp = secbuf_in+iMsgLen;
	hex2str(pbIV,  &temp,  8);
	iMsgLen += 16;
	/*填充模式*/
	secbuf_in[iMsgLen++] = FILL_00_N;
	/*数据长度*/
	sprintf((char *)secbuf_in+iMsgLen, "%04d", nBlockLen);
	iMsgLen += 4;
	/*数据*/
	//temp = secbuf_in+iMsgLen;
	//hex2str(pbPlainBlock,  &temp,  nBlockLen);
	memcpy(secbuf_in+iMsgLen  , pbPlainBlock,  nBlockLen);
	iMsgLen += nBlockLen;

#ifdef DEBUG_ON
	int i=0;

	nhLog("SMAPIEncryptCBC() send:\n");
	for(i=0;i<iMsgLen;i++)
	{
		nhLog("%02X", secbuf_in[i]);
	}
	nhLog("\n");
#endif
	if ((retval = HSM_LINK(nSock, iMsgLen, secbuf_in, secbuf_out)) != 0)
	{
		errlog("SMAPIEncryptCBC() call failed, errno=%d", retval);
		return retval;
	}
	else
	{
		tlen = (secbuf_out[4]-'0')*1000 + (secbuf_out[5]-'0')*100+ (secbuf_out[6]-'0')*10+ (secbuf_out[7]-'0');
		memcpy(pbCryptBlock, &secbuf_out[8], tlen);
	      //str2hex(secbuf_out+4+4, pbCryptBlock, nBlockLen*2);
	}

	return 0;
}

/**************************************************************************************
 *
 * 功能描述: 用DES类算法以CBC模式对明文数据进行加密
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          nAlgo:  算法类型(Single_Des = 1; Double_Des = 2; Triple_Des = 3)
 *          pbKey:  DES密钥的密文(由HMK/LMK加密), 二进制数
 *                  当nAlgo = 1时, 长度为8字节
 *                  当nAlgo = 2时, 长度为16字节
 *                  当nAlgo = 3时, 长度为24字节
 *          pbCryptBlock: 需要解密的密文, 二进制数, 长度由nBlockLen指定
 *          nBlockLen: pbPlainBlock的长度, 取值范围: 8的整数倍, 小于等于1024
 *          pbIV: 初始化向量, 二进制数, 长度为8字节
 *
 * 输出参数:
 *          pbPlainBlock: 解密之后的明文, 二进制数, 长度由nBlockLen指定
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          2: 无效的密钥(KEK)
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9 -- 其它错误
 *
 ***************************************************************************************/
int SMAPIDecryptCBC(int nSock,int nAlgo,u8 *pbKey,u8 *pbCryptBlock,int nBlockLen,u8 *pbIV,
                    u8 *pbPlainBlock)
{
	int iMsgLen = 0, retval = -1;

	u8 secbuf_in[HSM_MAX_BUFFER_SIZE]= {0};
	u8 secbuf_out[HSM_MAX_BUFFER_SIZE]= {0};
	u8 *temp;

	if(nSock<0){
		errlog("SMAPIDecryptCBC() failed, the socket is invalid");
		return ERR_SOCK_INVALID;
	}
	if(nAlgo!=1 && nAlgo!=2 && nAlgo!=3){
		errlog("SMAPIDecryptCBC() failed, the nAlgo is invalid");
		return ERR_INVALID_PARA;
	}

	if(nBlockLen<0 || nBlockLen>4096 || nBlockLen%8!=0){
		errlog("SMAPIDecryptCBC() failed, the nBlockLen is invalid");
		return ERR_DATA_LEN;
	}

	if((NULL == pbKey) || (NULL == pbCryptBlock) || (NULL == pbIV) || (NULL== pbPlainBlock))
	{
		errlog("SMAPIDecryptCBC() failed, the pointer is NULL");
		return ERR_INVALID_PARA;
	}

	secbuf_in[0] = 'V';
	secbuf_in[1] = '2';
	iMsgLen = 2;

	/* 算法应用模式: ECB = 0; CBC = 1 */
	secbuf_in[iMsgLen++] = DES3;
//	memcpy(secbuf_in+iMsgLen, TAG3, 3);
//	iMsgLen += 3;

	/* 算法类型: Single_Des = 1; Double_Des = 2; Triple_Des = 3 */
	if(nAlgo==1){
		retval = key_hex2str(pbKey, DES1, &secbuf_in[iMsgLen]);
		//iMsgLen += retval;
	}
	else if(nAlgo==2){
		retval = key_hex2str(pbKey, DES2, &secbuf_in[iMsgLen]);
		//iMsgLen += retval;
	}
	else if(nAlgo==3){
		retval = key_hex2str(pbKey, DES3, &secbuf_in[iMsgLen]);
		//iMsgLen += retval;
	}
	else{
		errlog("SMAPIDecryptCBC() nKeyLen is invalid");
		return ERR_ALGO_FLAG;
	}
	if(retval < 0)
	{
		errlog("SMAPIDecryptCBC() failed, pbKey is wrong");
		return ERR_INPUT;
	}
	iMsgLen += retval;
	/*分散次数*/
	secbuf_in[iMsgLen++] = '0';
	/*加解密标识*/
	secbuf_in[iMsgLen++] = DEC;
	/*算法模式*/
	secbuf_in[iMsgLen++] = CBC;
	/*IV*/
	temp = secbuf_in+iMsgLen;
	hex2str(pbIV,  &temp,  8);
	iMsgLen += 16;
	/*填充模式*/
	secbuf_in[iMsgLen++] = FILL_00_N;
	/*数据长度*/
	sprintf((char *)secbuf_in+iMsgLen, "%04d", nBlockLen);
	iMsgLen += 4;
	/*数据*/
	//temp = secbuf_in+iMsgLen;
	//hex2str(pbCryptBlock,  &temp,  nBlockLen);
	memcpy(secbuf_in+iMsgLen , pbCryptBlock,nBlockLen);
	iMsgLen += nBlockLen;


#ifdef DEBUG_ON
	int i=0;

	nhLog("SMAPIDecryptCBC() send:\n");
	for(i=0;i<iMsgLen;i++)
	{
		nhLog("%02X", secbuf_in[i]);
	}
	nhLog("\n");
#endif

	if ((retval = HSM_LINK(nSock, iMsgLen, secbuf_in, secbuf_out)) != 0)
	{
		errlog("SMAPIDecryptCBC() call failed, errno=%d", retval);
		return retval;
	}
	else
	{
		memcpy(pbPlainBlock,secbuf_out+4+4, nBlockLen);
		//str2hex(secbuf_out+4+4, pbPlainBlock, nBlockLen*2);
	}

	return 0;
}


/***************************************************************************************************
 *
 * 功能描述: 根据输入参数计算CVV
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          pbCVK:  CVK的密文(LMK加密), 二进制数, 16字节长
 *          pszPan: 主账号, ASCII字符, 长度由nPanLen指定
 *          nPanLen: pszPan的长度, 取值范围: {16, 19}
 *          pszExpireDate: 卡有效期, 格式为YYMM, ASCII字符, 4字节长
 *          pszServiceCode: 服务代码, ASCII字符, 3字节长
 *
 * 输出参数:
 *          szCVV: CVV值, ASCII字符, 3字节长
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          2: 无效的密钥(CVK)
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9 -- 其它错误
 *
 ******************************************************************************************************/
int SMAPICalCVV(int nSock,u8 *pbCVK,char *pszPan,int nPanLen,char *pszExpireDate,char *pszServiceCode,
                char szCVV[3])
{
	int iMsgLen = -1, retval = -1, tmplen = -1, i = 0;

	u8 secbuf_in[HSM_MAX_BUFFER_SIZE]= {0};
	u8 secbuf_out[HSM_MAX_BUFFER_SIZE]= {0};

	if(nSock<0){
		errlog("SMAPICalCVV() failed, the socket is invalid");
		return ERR_SOCK_INVALID;
	}

	if(nPanLen<16 || nPanLen>19 || nPanLen!=strlen(pszPan)){
		errlog("SMAPICalCVV() failed, the nPanLen is invalid");
		return ERR_INVALID_PARA;
	}

	for (i = 0; i < nPanLen; i++)
	{
		if (!isdigit(pszPan[i]))
		{
			errlog("SMAPICalCVV() failed, pszPan is wrong");
			return ERR_INVALID_PARA;
		}
	}

	if((NULL == pbCVK) || (NULL == pszPan) || (NULL == pszExpireDate) || (NULL == pszServiceCode) || (NULL == szCVV))
	{
		errlog("SMAPICalCVV() failed, the pointer is NULL");
		return ERR_INVALID_PARA;
	}

	/* 指令 */
	secbuf_in[0] = 'C';
	secbuf_in[1] = 'W';
	iMsgLen = 2;

	/*CVK*/
	secbuf_in[iMsgLen++] = DES3;
	retval = key_hex2str(pbCVK, DES2, &secbuf_in[iMsgLen]);
	if(retval < 0)
	{
		errlog("SMAPICalCVV() failed, pbCVK is wrong");
		return ERR_INPUT;
	}
	iMsgLen += retval;

	/* 账号 */
	memcpy(secbuf_in+iMsgLen, pszPan, nPanLen);
	iMsgLen += nPanLen;

	/* 分隔符 */
	secbuf_in[iMsgLen] = ';';
	iMsgLen += 1;

	/* 卡有效期 */
	tmplen = strlen(pszExpireDate);
	if (tmplen != 4)
	{
		errlog("SMAPICalCVV() failed, pszExpireDate length is wrong");
		return ERR_INVALID_PARA;
	}

	for (i = 0; i < 4; i++)
	{
		if (!isdigit(pszExpireDate[i]))
		{
			errlog("SMAPICalCVV() failed, pszExpireDate is wrong");
			return ERR_INVALID_PARA;
		}
	}

	memcpy(&secbuf_in[iMsgLen], pszExpireDate, 4);
	iMsgLen += 4;

	/* 服务代码 */
	tmplen = strlen(pszServiceCode);
	if (tmplen != 3)
	{
		errlog("SMAPICalCVV() failed, pszServiceCode length is wrong");
		return ERR_INVALID_PARA;
	}

	for (i = 0; i < 3; i++)
	{
		if (!isdigit(pszServiceCode[i]))
		{
			errlog("SMAPICalCVV() failed, pszServiceCode is wrong");
			return ERR_INVALID_PARA;
		}
	}

	memcpy(&secbuf_in[iMsgLen], pszServiceCode, 3);
	iMsgLen += 3;

#ifdef DEBUG_ON
	nhLog(" iMsgLen:%d:\n", iMsgLen);
	nhLog("%s() send:\n", __func__);
	for(i=0;i<iMsgLen;i++)
	{
		nhLog("%02X", secbuf_in[i]);
	}
	nhLog("\n");
#endif

	if ((retval = HSM_LINK(nSock, iMsgLen, secbuf_in, secbuf_out)) != 0)
	{
		errlog("SMAPICalCVV() call failed, errno=%d", retval);
		return retval;
	}
	else
	{
		memcpy(szCVV, &secbuf_out[4], 3);
	}

	return 0;
}


/**************************************************************************************
 *
 * 功能描述: 根据输入参数计算PVV
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          pbPVK:  PVK的密文(LMK加密), 二进制数, 16字节长
 *          pszPan: 主账号, ASCII字符, 长度由nPanLen指定
 *          nPanLen: pszPan的长度, 取值范围: {16, 19}
 *          pszPlainPin: 个人密码的明文, ASCII字符, 12字节长
 *          nPVKIndex: PVK索引代号
 *
 * 输出参数:
 *          szPVV: PVV值, ASCII字符, 4字节长
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          2: 无效的密钥(PVK)
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9 -- 其它错误
 *
 ***************************************************************************************/
int SMAPICalPVV(int nSock,u8 *pbPVK,char *pszPan,int nPanLen,char *pszPlainPin,int nPVKIndex,
                char szPVV[4])
{
	int iMsgLen = -1, retval = -1, pinlen = -1, i = 0;

	u8 secbuf_in[HSM_MAX_BUFFER_SIZE]= {0};
	u8 secbuf_out[HSM_MAX_BUFFER_SIZE]= {0};


	if(nSock<0){
		errlog("SMAPICalPVV() failed, the socket is invalid");
		return ERR_SOCK_INVALID;
	}

	if(nPanLen<16 || nPanLen>19 || nPanLen!=strlen(pszPan)){
		errlog("SMAPICalPVV() failed, the nPanLen is invalid");
		return ERR_INVALID_PARA;
	}

	for (i = 0; i < nPanLen; i++)
	{
		if (!isdigit(pszPan[i]))
		{
			errlog("SMAPICalPVV() failed, pszPan is wrong");
			return ERR_INVALID_PARA;
		}
	}

	if((NULL == pbPVK) || (NULL == pszPan) || (NULL == pszPlainPin) || (NULL == szPVV))
	{
		errlog("SMAPICalPVV() failed, the pointer is NULL");
		return ERR_INVALID_PARA;
	}

	/* 指令 */
	secbuf_in[0] = 'D';
	secbuf_in[1] = 'G';
	iMsgLen = 2;

	/* 密钥 */
	retval = key_hex2str(pbPVK, DES2, &secbuf_in[iMsgLen]);
	if(retval < 0)
	{
		errlog("SMAPICalPVV() failed, pbPVK is wrong");
		return ERR_INPUT;
	}

	iMsgLen += retval;

	/*标识位*/
	secbuf_in[iMsgLen++] = 'X';

	/*PIN length*/
	pinlen = strlen(pszPlainPin);
	sprintf((char *)secbuf_in+iMsgLen, "%02d", pinlen);
	iMsgLen += 2;

	/*PIN*/
	for (i = 0; i < pinlen; i++)
	{
		if (!isdigit(pszPlainPin[i]))
		{
			errlog("SMAPICalPVV() failed, pszPlainPin is wrong");
			return ERR_INVALID_PARA;
		}
	}
	memcpy(secbuf_in+iMsgLen, pszPlainPin, pinlen);
	iMsgLen += pinlen;


	for (i = 0; i < nPanLen; i++)
	{
		if (!isdigit(pszPan[i]))
		{
			errlog("SMAPICalPVV() failed, pszPan is wrong");
			return ERR_INVALID_PARA;
		}
	}

	memcpy(&secbuf_in[iMsgLen], &pszPan[strlen(pszPan)-13], 12);
	iMsgLen += 12;

	/* PVK索引代号 */
	if((nPVKIndex >= 0) && (nPVKIndex <= 9))
	{
		secbuf_in[iMsgLen] = nPVKIndex + '0';
	}
	else if((nPVKIndex >= 0x0A) && (nPVKIndex <= 0x0F))
	{
		secbuf_in[iMsgLen] = nPVKIndex - 10 + 'A';
	}
	else
	{
		errlog("SMAPICalPVV() failed, nPVKIndex is wrong");
		return ERR_INVALID_PARA;
	}
	iMsgLen += 1;

#ifdef DEBUG_ON
	nhLog(" iMsgLen:%d:\n", iMsgLen);
	nhLog("%s() send:\n", __func__);
	for(i=0;i<iMsgLen;i++)
	{
		nhLog("%02X", secbuf_in[i]);
	}
	nhLog("\n");
#endif

	if ((retval = HSM_LINK(nSock, iMsgLen, secbuf_in, secbuf_out)) != 0)
	{
		errlog("SMAPICalPVV() call failed, errno=%d", retval);
		return retval;
	}
	else
	{
		memcpy(szPVV, &secbuf_out[4], 4);
		szPVV[4] = '\0';
	}

	return 0;
}

/**************************************************************************************
 *
 * 功能描述: 根据输入参数用IBM3624方法生成PIN OFFSET
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          pbKey:  用HMK(LMK)加密的密文密钥, 二进制数, 8字节长
 *          pszPan: 主账号, ASCII字符, 长度由nPanLen指定
 *          nPanLen: pszPan的长度, 取值范围: {16, 19}
 *          pszPlainPin: 个人密码的明文, ASCII字符, 12字节长
 *
 * 输出参数:
 *          szOffset: PIN OFFSET, ASCII字符, 12字节长
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          2: 无效的密钥(KEY)
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9  其它错误
 *
 ***************************************************************************************/
int SMAPIIBM3624(int nSock,u8 *pbKey,char *pszPan,int nPanLen,char *pszPlainPin,
                 char szOffset[12])
{
	int iMsgLen = -1, retval = -1, i = 0;
	u8 strbuf[17] = {'\0'};
	int pinlen = strlen(pszPlainPin);

	u8 secbuf_in[HSM_MAX_BUFFER_SIZE]= {0};
	u8 secbuf_out[HSM_MAX_BUFFER_SIZE]= {0};

	if(nSock<0){
		errlog("SMAPIIBM3624() failed, the socket is invalid");
		return ERR_SOCK_INVALID;
	}

	/* 账号 */
	if (((nPanLen != 16) && (nPanLen != 19)) || nPanLen != strlen(pszPan))
	{
		errlog("SMAPIIBM3624() parameter nPanLen is invalid");
		return ERR_INVALID_PARA;
	}

	for (i = 0; i < nPanLen; i++)
	{
		if (!isdigit(pszPan[i]))
		{
			errlog("SMAPIIBM3624() failed, pszPan is wrong");
			return ERR_ASC_INVALID;
		}
	}


	if ((pinlen < 4) || (pinlen > 12))
	{
		errlog("SMAPIIBM3624() parameter plain PIN length is invalid");
		return ERR_INVALID_PARA;
	}

	/*pin 明文*/
	for(i=0; i<pinlen; i++)
	{
		if(!isdigit(pszPlainPin[i]))
		{
			errlog("SMAPIIBM3624() failed, pszPlainPin is wrong");
			return ERR_ASC_INVALID;
		}
	}

	if((NULL == pbKey) || (NULL == pszPan) || (NULL == pszPlainPin) || (NULL == szOffset))
	{
		errlog("SMAPIIBM3624() failed, the pointer is NULL");
		return ERR_INVALID_PARA;
	}

	/* 指令 */
	secbuf_in[0] = 'D';
	secbuf_in[1] = 'E';
	iMsgLen = 2;

	/* 密钥 */
	retval = key_hex2str(pbKey, DES1, &secbuf_in[iMsgLen]);
	if(retval < 0)
	{
		errlog("SMAPIIBM3624() failed, pbKey is wrong");
		return ERR_INPUT;
	}
	iMsgLen += retval;

	/*标识位*/
	secbuf_in[iMsgLen++] = 'X';

	/*pin明文长度*/
	sprintf((char *)secbuf_in+iMsgLen, "%02d", pinlen);
	iMsgLen += 2;

	/* 密码 */
	memcpy(&secbuf_in[iMsgLen], pszPlainPin, pinlen);
	iMsgLen += pinlen;
	//checklen
	sprintf((char *)secbuf_in+iMsgLen, "%02d", pinlen);
	iMsgLen += 2;

	/* 账号 */
	memcpy(&secbuf_in[iMsgLen], (u8 *)&pszPan[nPanLen - 16], 16);
	iMsgLen += 16;

	/* 十进制表 */
	memcpy(&secbuf_in[iMsgLen], "0123456789012345", 16);
	iMsgLen += 16;

	/*pin校验数据*/
	memcpy(&secbuf_in[iMsgLen], "0123456N2222", 12);
	iMsgLen += 12;


#ifdef DEBUG_ON
	nhLog(" iMsgLen:%d:\n", iMsgLen);
	nhLog("%s() send:\n", __func__);
	for(i=0;i<iMsgLen;i++)
	{
		nhLog("%02X", secbuf_in[i]);
	}
	nhLog("\n");
#endif

	/* 发送指令 */
	if ((retval = HSM_LINK(nSock, iMsgLen, secbuf_in, secbuf_out)) != 0)
	{
		errlog("SMAPIIBM3624() call failed, errno=%d", retval);
		return retval;
	}
	else
	{
		memcpy(szOffset, &secbuf_out[4], pinlen);
		szOffset[pinlen] = '\0';
	}

	return 0;
}


/**************************************************************************************
 *
 * 功能描述: 产生指定位数的十进制随机数字串
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          nDigitNum:  数字的位数
 *
 * 输出参数:
 *          pszDigits: 产生的随机数字串, ASCII字符, 长度为(nDigitNum + 1)
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9 -- 其它错误
 *
 ***************************************************************************************/
int SMAPIGenRandDigits(int nSock, int nDigitNum, char *pszDigits)
{
	int  retval = -1;

	u8 secbuf_in[HSM_MAX_BUFFER_SIZE]= {0};
	u8 secbuf_out[HSM_MAX_BUFFER_SIZE]= {0};
	u8 *tmpp;

	if(nSock<0){
		errlog("SMAPIGenerateRandomDigits() failed, the socket is invalid");
		return ERR_SOCK_INVALID;
	}

	if(nDigitNum<1 || nDigitNum>1024){
		errlog("SMAPIGenerateRandomDigits() failed, the nDigitNum is invalid");
		return ERR_DATA_LEN;
	}

	if(NULL == pszDigits)
	{
		errlog("SMAPIGenerateRandomDigits() failed, the pointer is NULL");
		return ERR_INVALID_PARA;
	}

	/* 指令 */
	secbuf_in[0] = 'T';
	secbuf_in[1] = 'E';

	/* 随机数长度 */
	sprintf((char *)secbuf_in+2, "%04d", (nDigitNum+1)/2);

#ifdef DEBUG_ON
	int i;
	nhLog(" iMsgLen:%d:\n", 4);
	nhLog("%s() send:\n", __func__);
	for(i=0;i<4;i++)
	{
		nhLog("%02X", secbuf_in[i]);
	}
	nhLog("\n");
#endif

	if ((retval = HSM_LINK(nSock, 6, secbuf_in, secbuf_out)) != 0)
	{
		errlog("SMAPIGenerateRandomDigits() call failed, errno=%d", retval);
		return retval;
	}
	else
	{
		tmpp = pszDigits;
		hex2str(&secbuf_out[4], &tmpp, (nDigitNum+1)/2);
		pszDigits[((nDigitNum+1)/2)*2] = '\0';
	}

	return 0;
}


/**************************************************************************************
 *
 * 功能描述: 检验指定密钥的CheckValue
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          pbKey:  待校验的密钥(由HMK加密), 可能是KEK, 也可能是WK,二进制数,长度由nKeyLen指定
 *          nKeyLen: 密钥长度
 *          pszCheckValue: 待验证的CheckValue值, 8位十六进制字符
 *
 * 输出参数:
 *          无
 *
 * 返回值:
 *          0: 验证成功;
 *          1: 输入参数验证失败;
 *          2: 无效的密钥(KEY)
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9 -- 其它错误
 *          10: 验证失败
 *
 ***************************************************************************************/
int SMAPIVerifyCheckValue(int nSock, u8 *pbKey, int nKeyLen, char *pszCheckValue)
{
	int iMsgLen = -1, retval = -1;

	u8 secbuf_in[HSM_MAX_BUFFER_SIZE]= {0};
	u8 secbuf_out[HSM_MAX_BUFFER_SIZE]= {0};
	u8 tmpbuf[16] = {0};

	if(nSock<0){
		errlog("SMAPIVerifyCheckValue() failed, the socket is NULL");
		return ERR_SOCK_INVALID;
	}

	if((8 != nKeyLen) && (16 != nKeyLen) && (24 != nKeyLen))
	{
		errlog("SMAPIVerifyCheckValue() failed, nKeyLen is wrong %d", nKeyLen);
		return ERR_KEY_LEN;
	}

	if((NULL == pbKey) || (NULL == pszCheckValue))
	{
		errlog("SMAPIVerifyCheckValue() failed, the pointer is NULL");
		return ERR_INVALID_PARA;
	}

	/* 指令 */
	secbuf_in[0] = 'K';
	secbuf_in[1] = 'A';
	iMsgLen = 2;

	/*算法标识*/
	secbuf_in[iMsgLen++] = DES3;

	/* 密钥 */
	if(nKeyLen==8){
		retval = key_hex2str(pbKey, DES1, &secbuf_in[iMsgLen]);
		//iMsgLen += retval;
	}
	else if(nKeyLen==16){
		retval = key_hex2str(pbKey, DES2, &secbuf_in[iMsgLen]);
		//iMsgLen += retval;
	}
	else if(nKeyLen==24){
		retval = key_hex2str(pbKey, DES3, &secbuf_in[iMsgLen]);
		//iMsgLen += retval;
	}
	else{
		errlog("SMAPIVerifyCheckValue() nKeyLen is invalid");
		return ERR_KEY_LEN;
	}
	if(retval < 0)
	{
		errlog("SMAPIVerifyCheckValue() failed, pbKey is wrong");
		return ERR_INPUT;
	}
	iMsgLen += retval;
	strcpy(&secbuf_in[iMsgLen]  , ";0");
	iMsgLen+=2;

#ifdef DEBUG_ON
	int i;
	nhLog(" iMsgLen:%d:\n", iMsgLen);
	nhLog("%s() send:\n", __func__);
	for(i=0;i<iMsgLen;i++)
	{
		nhLog("%02X", secbuf_in[i]);
	}
	nhLog("\n");
#endif

	if ((retval = HSM_LINK(nSock, iMsgLen, secbuf_in, secbuf_out)) != 0)
	{
		errlog("SMAPIVerifyCheckValue() call failed, errno=%d", retval);
		return retval;
	}
	else{
		memcpy(tmpbuf, &secbuf_out[4], 16);
	}

	data_dump("pszCheckValue tmpbuf", tmpbuf, 8);
	data_dump("pszCheckValue ", pszCheckValue, 8);

	if(memcmp(pszCheckValue, tmpbuf, 8)==0)
		return 0;
	else
		return 1;
}




/**************************************************************************************
 *
 * 功能描述: 获取加密机状态码及状态信息
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *
 * 输出参数:
 *          szStatusCode: 加密机状态码 -- "00"表示正常, 其它状态码个厂商可以自己定义
 *          szStatusMsg: 加密机状态信息, 应包括线程数量等加密机状态信息, 供调试用
 *
 * 返回值:
 *          0: 验证成功;
 *          1: 输入参数验证失败;
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9 -- 其它错误
 *          10: 执行失败
 *
 ***************************************************************************************/
/*int SMAPIGetHsmStatus(int nSock, char szStatusCode[2], char szStatusMsg[200])
{
	int retval = -1;
	u8 errcode[1] = {'\0'};
	u8 *tmp = NULL;

	u8 secbuf_in[HSM_MAX_BUFFER_SIZE]= {0};
	u8 secbuf_out[HSM_MAX_BUFFER_SIZE]= {0};

	if(nSock<0){
		errlog("SMAPIGetHsmStatus() failed, the socket is invalid");
		return ERR_SOCK_INVALID;
	}

	if((NULL == szStatusCode) || (NULL == szStatusMsg))
	{
		errlog("SMAPIGetHsmStatus() failed, the pointer is NULL");
		return ERR_INVALID_PARA;
	}

	secbuf_in[0] = 'N';
	secbuf_in[1] = 'C';
	if ((retval = HSM_LINK(nSock, 2, secbuf_in, secbuf_out)) != 0)
	{
		//errcode[0] = retval & 0xff;
		//tmp = szStatusCode;
		//hex2str(errcode, &tmp, 1);
		
		memcpy(szStatusCode, secbuf_out+2, 2);

		errlog("SMAPIGetHsmStatus() call failed, errno=%d", retval);
		return retval;
	}

	memcpy(szStatusCode, "00", 2);
	memcpy(szStatusMsg, &secbuf_out[4], strlen(secbuf_out)-4);

	return 0;
}*/




/**************************************************************************************
 *
 * 功能描述: 计算大数的指数模运算, 即 Out = (Base^Exp) mod Module
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          pbBase:  指数模运算中的底数, 二进制数, 长度由nBaseLen指定
 *          nBaseLen: bpBase的字节长度
 *          pbExp: 指数模运算中的指数, 二进制数, 长度由nExpLen指定
 *          nExpLen: bpExp的字节长度
 *          pbModule: 指数模运算中的模, 二进制数, 长度由nModuleLen指定
 *          nModuleLen: pbModule的字节长度
 *
 * 输出参数:
 *          pbOut: 指数模运算的结果, 二进制数, 长度由npOutLen指定
 *          pnOutLen: bpOut的长度
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9 -- 其它错误
 *          10: 执行失败
 *
 ***************************************************************************************/
int SMAPIExpMod(int  nSock,u8 *pbBase, int nBaseLen, u8 *pbExp,int nExpLen,u8 *pbModule,int nModuleLen,
                u8 *pbOut, int *pnOutLen)
{
	int iMsgLen = -1, retval = -1;

	u8 secbuf_in[HSM_MAX_BUFFER_SIZE]= {0};
	u8 secbuf_out[HSM_MAX_BUFFER_SIZE]= {0};
	char lenbuf[5] = {0};

	if(nSock<0){
		errlog("SMAPIExpMod() failed, the socket is invalid");
		return ERR_SOCK_INVALID;
	}

	if((NULL == pbBase) || (NULL == pbExp) || (NULL == pbModule) || (NULL == pbOut) || (NULL == pnOutLen))
	{
		errlog("SMAPIExpMod() failed, the pointer is NULL");
		return ERR_INVALID_PARA;
	}

	memset(secbuf_in, 0x00, sizeof(secbuf_in));
	memset(secbuf_out, 0x00, sizeof(secbuf_out));

	secbuf_in[0] = 'E';
	secbuf_in[1] = 'D';
	iMsgLen = 2;

	/*底数长度*/
	sprintf((char *)secbuf_in+iMsgLen, "%04d", nBaseLen);
	iMsgLen += 4;

	/*底数*/
	memcpy(secbuf_in+iMsgLen, pbBase, nBaseLen);
	iMsgLen += nBaseLen;

	/*指数长度*/
	sprintf((char *)secbuf_in+iMsgLen, "%04d", nExpLen);
	iMsgLen += 4;
	/*指数*/
	memcpy(secbuf_in+iMsgLen, pbExp, nExpLen);
	iMsgLen += nExpLen;

	/*模长度*/
	sprintf((char *)secbuf_in+iMsgLen, "%04d", nModuleLen);
	iMsgLen += 4;

	/*模*/
	memcpy(secbuf_in+iMsgLen, pbModule, nModuleLen);
	iMsgLen += nModuleLen;

#ifdef DEBUG_ON
	int i;
	nhLog(" iMsgLen:%d:\n", iMsgLen);
	nhLog("%s() send:\n", __func__);
	for(i=0;i<iMsgLen;i++)
	{
		nhLog("%02X", secbuf_in[i]);
	}
	nhLog("\n");
#endif

	if ((retval = HSM_LINK(nSock, iMsgLen, secbuf_in, secbuf_out)) != 0)
	{
		errlog("SMAPIExpMod() call failed, errno=%d", retval);
		return retval;
	}
	else{
		memcpy(lenbuf, &secbuf_out[4], 4);
		*pnOutLen = atoi(lenbuf);

		memcpy(pbOut, &secbuf_out[8], *pnOutLen);
	}


	return 0;
}



/**************************************************************************************
 *
 * 功能描述: 随机产生大的素数
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          nPrimeBit:  需要随机产生大素数的bit长度, 取值范围为[1, 2048]
 *
 * 输出参数:
 *          pbPrime: 产生的大素数, 二进制数, 字节长度为(nPrimeBit/8/2)
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9 -- 其它错误
 *          10: 执行失败
 *
 ***************************************************************************************/
int SMAPIGenBigPrime(int nSock, int nPrimeBit, u8 *pbPrime)
{
	int iMsgLen = -1, retval = -1, outlen = -1;
	u8 secbuf_in[HSM_MAX_BUFFER_SIZE]= {0};
	u8 secbuf_out[HSM_MAX_BUFFER_SIZE]= {0};
	char lenbuf[5] = {0};

	if(nSock<0){
		errlog("SMAPIGenBigPrime() failed, the socket is invalid");
		return ERR_SOCK_INVALID;
	}

	if(nPrimeBit<1 || nPrimeBit>2048){
		errlog("SMAPIGenBigPrime() failed, the socket is invalid");
		return ERR_DATA_LEN;
	}

	if((NULL == pbPrime))
	{
		errlog("SMAPIGenBigPrime() failed, the pointer is NULL");
		return ERR_INVALID_PARA;
	}

	memset(secbuf_in, 0x00, sizeof(secbuf_in));
	memset(secbuf_out, 0x00, sizeof(secbuf_out));


	secbuf_in[0] = 'E';
	secbuf_in[1] = 'F';

	sprintf((char *)secbuf_in+2, "%04d", nPrimeBit);

	iMsgLen = 6;

#ifdef DEBUG_ON
	int i;
	nhLog(" iMsgLen:%d:\n", iMsgLen);
	nhLog("%s() send:\n", __func__);
	for(i=0;i<iMsgLen;i++)
	{
		nhLog("%02X", secbuf_in[i]);
	}
	nhLog("\n");
#endif

	if ((retval = HSM_LINK(nSock, iMsgLen, secbuf_in, secbuf_out)) != 0)
	{
		errlog("SMAPIGenBigPrime() call failed, errno=%d", retval);
		return retval;
	}

      memcpy(lenbuf, secbuf_out+4, 4);
      outlen = atoi(lenbuf);
      memcpy(pbPrime, &secbuf_out[8], outlen);

      return 0;
}

/********************************************** 天安   *********************************************************/






/******************************************     江南科友   *****************************************************/

/***************************************************************************************************************/
/* 函数名称：SMAPIGenRsaKey                                                                                    */
/*          5.1 产生RSA 公私钥对（7.5.1 产生RSA 密钥对）  农行    "EI"                                          */
/* 功能说明：                                                                                                  */
/*	    产生RSA 密钥对。                                                                                   */
/* 输入参数：												      */	
/*	    UINT nSock：   连接的socket 句柄                                                                   */
/*	    int nIndex：   索引位，0：不保存在索引位上；1—50：相应索引位的值                                     */
/*	    int nModLen：  公钥模长，取值范围： 512—2048                                                       */
/*	    char *pszExp： 公钥指数标志，ASCII 码，10 字节长                                                   */
/* 输出参数：                                                                                                 */
/*	    byte *pbPK：   产生的公钥的明文，二进制数，DER 编码格式，调用函数应分配                              */ 
/*		           1.5 * nModLen 的存储空间，实际返回的数据长度由pnPKLen 指定。                         */
/*    	    int *pnPKLen： 返回的公钥数据长度                                                                  */
/*	    byte *pbSK：   私钥密文值，二进制数，DER 编码格式，被HMK 加密，调用函数                             */ 
/*		           应分配3*nModLen 的存储空间，实际返回的数据长度由pnSKLen 指定                         */
/*	    int * pnSKLen：返回的私钥数据长度                                                                  */ 
/* 返回说明：                                                                                                 */
/*          0： 生成成功                                                                                      */
/*	    1： 输入参数验证失败                                                                               */
/*	    3： 向加密机发送数据失败                                                                           */
/*	    4： 接收加密机数据超时                                                                             */
/*	    5： 接收到的数据格式错                                                                             */
/*	    9:  其他错误                                                                                      */
/* 维护记录：                                                                                                 */
/*          2017-03-07 by zhaomx                                                                              */
/**************************************************************************************************************/

int SMAPIGenRsaKey(UINT nSock, int nIndex,int nModLen,char *pszExp, 
		   byte * pbPK,int *pnPKLen,byte * pbSK,int *pnSKLen)
{
    int retCode = 0;
    int nCmd_len;
    int rst_len;
    int offset;
    int prnKeyLen;
    int pubKeyDerLen;
    int pubKeyLen;
    int expLen;
    int modLen;
    int iCmdLen = 0;
    char pszExp_char[12];
    char cprnKeyLen[4 + 1];
    char cCmd_info[128 + 1];
    char mod[2048 + 1];
    char exp[2048 + 1];
    char pubKeyDer[4096 + 2];
    char cRst_info[40960];
    unsigned int nExp = 0;
    char nExp_buf[20];
    char cTmpBuf[24];
    char *p = NULL;

    if( !pszExp )
    {
	union_err_log("In SMAPIGenRsaKey::Point is NULL");
	return CKR_PARAMETER_ERR;
    }	

    nExp = atoi(pszExp);
    if(nExp<1 || nExp>65537)
    {
	union_err_log("In SMAPIGenRsaKey::Parameter[nExp] error nExp=[%d]",nExp);
	return CKR_PARAMETER_ERR;
    }

    if(UnionIsSocket(nSock)<1)
    {
	union_err_log("In SMAPIGenRsaKey::Parameter[Nsock] error socket=[%d]\n",nSock);
	return CKR_SENDFAIL_ERR;
    }

    if(nIndex<0||nIndex>50)
    {
	union_err_log("In SMAPIGenRsaKey::Parameter[nIndex] error nIndex=[%d]\n",nIndex);
	return CKR_PARAMETER_ERR;
    }
    if(nModLen<512||nModLen>2048)
    {
	union_err_log("In SMAPIGenRsaKey::Parameter[nModLen] error ModeLen=[%d]\n",nModLen);
	return CKR_PARAMETER_ERR;
    }

#ifdef	_DEBUG
    unsigned char debugBuff[8192];
#endif

    memset(cCmd_info, 0x00, sizeof(cCmd_info));
    memset(cRst_info, 0x00, sizeof(cRst_info));
    memset(pubKeyDer, 0x00, sizeof(pubKeyDer));
    memset(mod, 0x00, sizeof(mod));
    memset(exp, 0x00, sizeof(exp));
    offset = 0;

    /* command */
    memcpy(cCmd_info+iCmdLen, "EI", 2);
    iCmdLen += 2;

    //模式   1
    memcpy(cCmd_info+iCmdLen, "1", 1);
    iCmdLen += 1;

    /* length of RSA key */
    if ((!(nModLen % 8)) && (nModLen >= 512 && nModLen <= 2048) ) 
    {
	sprintf(cCmd_info+iCmdLen, "%04d", nModLen);
	iCmdLen += 4;
    }
    else
    {
	union_err_log("In SMAPIGenRsaKey::Parameter error,[nModLen] " \
			"is not multiples of 8! nModLen= [%04d]", nModLen);
	return CKR_PARAMETER_ERR;
    }

    //公私钥编码 01:DER编码
    sprintf(cCmd_info+iCmdLen, "%02d", 1);
    iCmdLen += 2;

    //密钥索引
    if (nIndex > 0 && nIndex < 50) 
    {
	sprintf(cCmd_info+iCmdLen, "%02d", nIndex);
	iCmdLen += 2;
	//密钥口令    索引不等于"00"时存在
	memcpy(cCmd_info+iCmdLen, "12345678", 8);
        iCmdLen += 8;
    }
    else if(nIndex == 0)
    {
	sprintf(cCmd_info+iCmdLen, "%02d", 0);
	iCmdLen += 2;
    }
    else
    {
	union_err_log("In SMAPIGenRsaKey::Parameter error,[nIndex] must between [0,50] or equal 99! nLmkId= [%02d]", nIndex);
	return CKR_PARAMETER_ERR;
    }

    //密钥用途   '1'-签名   '2'-加密   '3'-签名和加密
    sprintf(cCmd_info+iCmdLen, "%d", 3);
    iCmdLen += 1;

    //KEK 导出标识  ‘0’: 不使用 KEK 加密导出私钥
    sprintf(cCmd_info+iCmdLen, "%d", 0);
    iCmdLen += 1;    

    //分隔符
    memcpy(cCmd_info+iCmdLen, ";", 1);
    iCmdLen += 1;
    /* NOTE: Cautiously Use!!!!! don't open if 0=1 effect performance!!!!! */
    if(nExp == 65537  || nExp == 3)
    {   
        //指数长度
	nExp=atoi(pszExp);
        memset(nExp_buf, 0x00, sizeof(nExp_buf));
        sprintf(nExp_buf,"%d",nExp);
        
	sprintf(cCmd_info+iCmdLen,"%04d", strlen(nExp_buf));
        iCmdLen += 4;    
         
        //指数  
	memcpy(cCmd_info+iCmdLen,(unsigned char*)nExp_buf,strlen(nExp_buf));
	iCmdLen += strlen(nExp_buf);
    }

    cCmd_info[iCmdLen++] = '\0';
    nCmd_len = iCmdLen - 1;	
	
#ifdef	_DEBUG
    memset(debugBuff, 0x00, sizeof(debugBuff));
    UnpackBCD(cCmd_info, (char *) debugBuff, nCmd_len*2);
    union_log("In SMAPIGenRsaKey::[REQUEST]=[%d][%s]", nCmd_len, debugBuff);
#endif
    rst_len = UnionHSMCmd(nSock, cCmd_info, nCmd_len, cRst_info, gUnionTimeout, &retCode);

#ifdef _DEBUG
    memset(debugBuff, 0x00, sizeof(debugBuff));
    UnpackBCD(cRst_info, (char *)debugBuff, rst_len*2);
    union_log("In SMAPIGenRsaKey::[RESPOND]=[%d][%s]", rst_len, debugBuff);
#endif
switch(rst_len)
    {
    	 case -1:
    		union_err_log("In SMAPIGenRsaKey::SOCKET EDLL!");
    		return CKR_PARAMETER_ERR;
    	 case -2:
    		union_err_log("In SMAPIGenRsaKey::SOCKET SEND ERROR!");
    		return CKR_SENDFAIL_ERR;
    	 case -3:
    		union_err_log("In SMAPIGenRsaKey::SOCKET RECIVE ERROR!");
    		return CKR_RCVTMOUT_ERR;
    	 case -4:
    		union_err_log("In SMAPIGenRsaKey::SOCKET RECIVE CKR_PARAMETER_ERR ERROR!");
    		return CKR_PARAMETER_ERR;
    	 default:
    	 	break;
    	}

#ifdef _DEBUG
    memset(debugBuff, 0x00, sizeof(debugBuff));
    UnpackBCD(cRst_info, (char *)debugBuff, rst_len*2);
    union_log("In SMAPIGenRsaKey::[RESPOND]=[%d][%s]", rst_len, debugBuff);
#endif

    offset = 0;
    /* Get the length of the private key */
    memcpy(cprnKeyLen, cRst_info, 4);
    prnKeyLen = atoi((char *)cprnKeyLen);
    offset += 4;
    if (prnKeyLen <= 0)
    {
	union_err_log("In SMAPIGenRsaKey::the length of the private key is short than  zero! private len=[%d]\n",prnKeyLen);
	return CRK_GENRSA_ERR;
    }
    *pnSKLen = prnKeyLen;
    /* Get content of the private key */
    memcpy(pbSK, cRst_info + offset, prnKeyLen);
    offset += prnKeyLen;

#ifdef _DEBUG
    UnpackBCD((char*)pbSK, (char *) debugBuff, prnKeyLen * 2);
    union_log("In SMAPIGenRsaKey::private key =[%d][%s]", prnKeyLen, debugBuff);
#endif

    /* Get public-key(DER)'s length and contents */
    pubKeyDerLen = rst_len - offset;
    memcpy(pubKeyDer, cRst_info + offset, pubKeyDerLen);

    /* Get public-key from public-key(DER) */
    memcpy(pbPK, pubKeyDer, pubKeyDerLen);
    *pnPKLen=pubKeyDerLen;

    return (CKR_SMAPI_OK);
}



/***************************************************************************************************************/
/* 函数名称：  SMAPIGenMasterKey                                                                               */
/*            5.2 产生随机应用主密钥（7.2.1 产生密钥）  农行    "X0"                                            */
/* 功能说明：                                                                                                  */
/*           根据指定长度随机生成一个IC 卡的应用主密钥，并返回密钥的效验值，                                      */
/*           并根据nIndex 和nTag 选择是否将产生的密钥保存到加密机的某个索引位                                    */
/*           上，及保存密钥的类型                                                                              */
/* 输入参数：                                                                                                  */
/*	      UINT nSock：  连接的socket 句柄                                                                  */
/*	      int nKeyLen： 要生成密钥的长度，取值范围：{8,16,24}                                               */
/*	      int nIndex：  索引位，0：不保存在索引位上；	1—255：相应索引位的值                          */ 
/*	      Int nTag：    密钥类型，取值范围{0, 1, 2}，其中 0 ：表示为MDK_AC, 1： 为MDK_ENC，2： 为MDK_MAC     */
/*				                                                                              */
/* 输出参数：                                                                                                  */
/*	      byte *pbKey：          随机产生的密钥(被HMK 加密)，二进制数，调用函数应分配24 字节                 */
/*		                     的存储空间，实际长度返回数据由nKeyLen 指定。                               */
/*	      char pszCheckValue[8]：产生密钥的效验值，是将CheckValue 的前四个字节进行扩                        */
/*		                     展，得到的8 个十六进制字符                                                */ 
/* 返回说明：                                                                                                 */ 
/*            0： 成功                                                                                        */
/*	      1： 输入参数验证失败                                                                             */
/*	      3： 向加密机发送数据失败                                                                         */  
/*	      4： 接收加密机数据超时                                                                           */
/*	      5： 接收到的数据格式错                                                                           */
/*	      9:  其他错误                                                                                     */
/* 维护记录：                                                                                                 */
/*          2017-03-07 by zhaomx                                                                              */
/***************************************************************************************************************/ 
int SMAPIGenMasterKey(UINT nSock, int nKeyLen, int nIndex,int nTag, 
	              byte * pbKey, char pszCheckValue[8])
{

    int    retCode=0;
    int    nCmd_len;
    int    nRc;
    char   *p = NULL;
    char   cCmd_info[500];
    char   cRst_info[64 + 1];

    if(UnionIsSocket(nSock)<1)
    {
    	union_err_log("In SMAPIGenMasterKey::nSock=[%d] wrong.", nSock);
	return CKR_SENDFAIL_ERR;
    }
    if((nKeyLen!=8)&&(nKeyLen!=16)&&(nKeyLen!=24))
    {
    	union_err_log("In SMAPIGenMasterKey::nKeyLen=[%d] wrong.", nKeyLen);
	return CKR_PARAMETER_ERR;
    }
    if(nIndex<0||nIndex>255||nTag<0||nTag>2)
    {
    	union_err_log("In SMAPIGenMasterKey::nIndex=[%d] or nTag=[%d]wrong.\n", nIndex,nTag);
	return CKR_PARAMETER_ERR;
    }
    //parameters check end

    memset(cCmd_info, 0, sizeof(cCmd_info));
    memset(cRst_info, 0, sizeof(cRst_info));
    p = cCmd_info;
    
    //命令
    memcpy(p, "X0", 2);
    p += 2;

    //模式   '0' -产生随机密钥    '1'-产生分散密钥
    memcpy(p, "0", 1);
    p += 1;

    //介质类型  '00'-没有存储介质
    sprintf(p, "%02d", 0);
    p += 2;

    //算法类型及分量数	
    //密钥长度
    if(nKeyLen == 8)
    {
	memcpy(p, "3", 1);
	p+=1;
	memcpy(p, "10008", 5);
	p += 5;
    }
    else if(nKeyLen == 16)
    {
	memcpy(p, "1", 1);
	p+=1;
	memcpy(p, "10016", 5);
	p += 5;
    }
    else if(nKeyLen == 24)
    {
	memcpy(p, "3", 1);
	p+=1;
	memcpy(p, "10024", 5);
	p += 5;
    }
    else 
    {
	union_err_log("In SMAPIGenMasterKey::nKeyLen=[%d] wrong.", nKeyLen);
	return CKR_PARAMETER_ERR;
    }
    //密钥索引
    if(nIndex==0)
    {
	*p = 0;
	nCmd_len = p - cCmd_info;
    }
    else
    {
	if(nIndex>=0 && nIndex<255)
        {
	    memcpy(p, "K", 1);
	    p += 1;
            //密钥类型   3 H     zhaomx-2017-2-27
            sprintf(p, "%01d", nTag);
            p += 1;
	    sprintf(p, "%03d", nIndex);
	    p += 3;
        }
	*p = 0;
	nCmd_len = p - cCmd_info;
    }

#ifdef	_DEBUG
    union_log("In SMAPIGenMasterKey::nCmd_len=[%d] cCmd_info=[%s]", nCmd_len, cCmd_info);
#endif

    nRc = UnionHSMCmd(nSock, cCmd_info, nCmd_len, cRst_info, gUnionTimeout, &retCode);
    switch(nRc)
    {
    	 case -1:
	    	 union_err_log("In SMAPIGenMasterKey::SOCKET EDLL!");
	    	 return CKR_PARAMETER_ERR;
    	 case -2:
	    	 union_err_log("In SMAPIGenMasterKey::SOCKET SEND ERROR!");
	    	 return CKR_SENDFAIL_ERR;
    	 case -3:
	    	 union_err_log("In SMAPIGenMasterKey::SOCKET RECIVE ERROR!");
	    	 return CKR_RCVTMOUT_ERR;
    	 case -4:
	    	 union_err_log("In SMAPIGenMasterKey::SOCKET RECIVE CKR_PARAMETER_ERR ERROR!");
	    	 return CKR_PARAMETER_ERR;
    	 default:
    	 	 break;
    	}
#ifdef	_DEBUG
    union_log("In SMAPIGenMasterKey::nRc=[%d] cRst_info=[%s]", nRc, cRst_info+1);
#endif
    //20170420   nKeyLen*2
    PackBCD(cRst_info+1, pbKey, 32);

    PackBCD(cRst_info+33, pszCheckValue, 16);

    return (CKR_SMAPI_OK);
}

/***************************************************************************************************************/
/* 函数名称： SMAPIExportMasterKey                                                                             */
/*           5.3  导出应用主密钥（7.2.5 HMK 加密密钥）  农行    "X2"                                            */
/* 功能说明：                                                                                                  */
/*          将制定索引位上特定类型的应用主密钥导出                                                               */
/* 输入参数：										                       */
/*	    UINT nSock：  连接的socket 句柄                                                                    */
/*	    int nIndex：  导出密钥的索引位，固定值为0。                                                         */
/*	    Int nTag：    导出密钥的类型，取值范围{0, 1, 2}，                                                   */
/* 输出参数：												      */	
/*	    byte *pbKey：   导出密钥的密文(被HMK 加密)，二进制数，调用函数应分配24 字节                          */
/*		            的存储空间，实际长度返回数据由pnKeyLen 指定。                                       */
/*	    int *pnKeyLen： 导出密钥的长度，取值范围：{8,16,24}                                                 */
/*	    char pszCheckValue[8]： 导出密钥的效验值，是将CheckValue 的前四个字节进行扩                         */
/*		                    展，得到的8 个十六进制字符                                                 */
/* 返回说明：	                                                                                              */
/*          0： 成功                                                                                          */
/*	    1： 输入参数验证失败                                                                               */
/*	    3： 向加密机发送数据失败                                                                           */ 
/*	    4： 接收加密机数据超时                                                                             */
/*	    5： 接收到的数据格式错                                                                             */
/*	    9:  其他错误                                                                                      */
/* 维护记录：                                                                                                 */
/*          2017-03-07 by zhaomx                                                                              */
/***************************************************************************************************************/ 
int SMAPIExportMasterKey(UINT nSock, int nIndex, int nTag,
	                 byte * pbKey,int *pnKeyLen, char pszCheckValue[8])
{

    int  retCode=0;
    int  nCmd_len;
    int  nRc;
    int  tl;
    char *p = NULL;
    char *pRet = NULL;
    char cCmd_info[500];
    char cRst_info[128];
    char cTmpBuf[2048];

    if(UnionIsSocket(nSock)<1)
    {
    	union_log("In SMAPIExportMasterKey:: nSock checkerror nSocket=[%d]\n",nSock);
	return CKR_SENDFAIL_ERR;
    }

    if(nIndex<0||nIndex>255||nTag<0||nTag>2)
    {
    	union_log("In SMAPIExportMasterKey:: nIndex or nTag Error nIndex=[%d] nTag=[%d]\n",nIndex,nTag);
	return CKR_PARAMETER_ERR;
    }
    //parameters check end

    memset(cCmd_info, 0, sizeof(cCmd_info));
    memset(cRst_info, 0, sizeof(cRst_info));

    p = cCmd_info;
    //命令
    memcpy(p, "X2", 2);
    p += 2;

    //算法类型   ‘1’-SM4 ‘2’-SM1 ‘3’-3DES ‘4’-AES
    memcpy(p, "3", 1);
    p += 1;

    //密钥方案     "X"-16  "Y"-24  "Z"-8  zhaomx-2017-2-27
    memcpy(p, "K", 1);
    p += 1;

    if(nIndex>=0 && nIndex<487)
    {
        //密钥类型    zhaomx-2017-2-27
        sprintf(p, "%01d", nTag);
        p += 1;
        sprintf(p, "%03d", nIndex);
        p += 3;
    }
	
    *p = 0;
    nCmd_len = p - cCmd_info;

#ifdef	_DEBUG
    union_log("In SMAPIExportMasterKey::nCmd_len=[%d] cCmd_info=[%s]", nCmd_len, cCmd_info);
#endif
    nRc = UnionHSMCmd(nSock, cCmd_info, nCmd_len, cRst_info, gUnionTimeout, &retCode);
switch(nRc)
    {
    	 case -1:
    		 union_err_log("In SMAPIExportMasterKey::SOCKET EDLL!");
    		 return CKR_PARAMETER_ERR;
    	 case -2:
    		 union_err_log("In SMAPIExportMasterKey::SOCKET SEND ERROR!");
    		 return CKR_SENDFAIL_ERR;
    	 case -3:
    		 union_err_log("In SMAPIExportMasterKey::SOCKET RECIVE ERROR!");
    		 return CKR_RCVTMOUT_ERR;
    	  case -4:
    		 union_err_log("In SMAPIExportMasterKey::SOCKET RECIVE CKR_PARAMETER_ERR ERROR!");
    		 return CKR_PARAMETER_ERR;
    	 default:
    	 	 break;
    	}
#ifdef	_DEBUG
    union_log("In SMAPIExportMasterKey::nRc=[%d] cRst_info=[%s]", nRc, cRst_info);
#endif

    if(nTag == 0) 
    {
        PackBCD(cRst_info, pbKey, 16*1);
        PackBCD(cRst_info+16*1, pszCheckValue, 16);
    }
    else if(nTag == 1)
    {
        PackBCD(cRst_info+1, pbKey, 16*2);
        PackBCD(cRst_info+16*2+1, pszCheckValue, 16);
    } 
    else if(nTag == 2)
    {
        PackBCD(cRst_info+1, pbKey, 16*3);
        PackBCD(cRst_info+16*3+1, pszCheckValue, 16);
    } 
	

    return (CKR_SMAPI_OK);

}

/***************************************************************************************************************/
/* 函数名称： SMAPIDigest                                                                                      */
/*           5.4 计算信息摘要（7.4.7 产生消息摘要）  农行    "GM"                                               */
/* 功能说明：                                                                                                  */
/*          生成摘要                                                                                           */
/* 输入参数：                                                                                                  */
/*	     UINT nSock：  连接的socket 句柄                                                                   */
/*	     int nAlgo：   算法类型, 0-MD5 算法；1—SHA-1 算法; 2—SHA-224；3—SHA-256；                          */
/*		           4—SHA-384；5—SHA-512；7—SM3                                                        */
/*	     byte *pbData：计算信息摘要的报文数据，二进制数，长度由nDataLen 指定                                 */
/*	     int nDataLen：数据长度, 取值范围[16, 4096]                                                        */ 
/* 输出参数：                                                                                                  */
/*	     byte *pbDigest：信息摘要，二进制数，                                                               */
/*		             当nAlgo = 0 时，16 字节长                                                         */  
/*			     当nAlgo = 1 时，20 字节长                                                         */
/*			     当nAlgo = 2 时，28 字节长                                                         */
/*			     当nAlgo = 3 时，32 字节长                                                         */
/* 			     当nAlgo = 4 时，48 字节长                                                         */
/*			     当nAlgo = 5 时，64 字节长                                                         */
/*			     当nAlgo = 7 时，32 字节长                                                         */
/* 返回说明：                                                                                                  */
/*           0： 生成成功                                                                                      */
/*	     1： 输入参数验证失败                                                                              */
/*	     3： 向加密机发送数据失败                                                                          */   
/*	     4： 接收加密机数据超时                                                                            */   
/*	     5： 接收到的数据格式错                                                                            */ 
/*	     9:  其他错误                                                                                     */ 
/* 维护记录：                                                                                                 */
/*          2017-03-07 by zhaomx                                                                              */
/***************************************************************************************************************/ 
int SMAPIDigest(UINT nSock, 	int nAlgo,	byte *pbData,	int nDataLen,
                byte *pbDigest) 
{

    int             retCode=0;
    char            cCmd_info[40960 + 1];
    char            cRst_info[40960 + 1];
    char            cTmpBuf[2048];
    int             nCmd_len;
    int             rst_len;
    char           *pcmd_info;
#ifdef _DEBUG
    /* use for DEBUG */
    unsigned char debugBuff[40960];
#endif
    unsigned char pcData[4096 + 1];

    //parameters check
    if(UnionIsSocket(nSock)<1)
    {
    	union_err_log("In SMAPIDigest::Parameter error nSock=[%d]!!!!!!",nSock);
	return CKR_SENDFAIL_ERR;
    }

    if((nAlgo != 0) && (nAlgo != 1) && (nAlgo != 2) && (nAlgo != 3) && (nAlgo != 4) && (nAlgo != 5) && (nAlgo != 7) && (nAlgo != 99))
    {
	union_err_log("In SMAPIDigest::Parameter error!!!!!! nAlgo=[%d]\n",nAlgo);
	return CKR_PARAMETER_ERR;
    }
    if(nDataLen < 16 || nDataLen > 4096)
    {
	union_err_log("In SMAPIDigest::nDataLen Parameter error! nDataLen=[%d]\n",nDataLen);
	return CKR_PARAMETER_ERR;
    }
    //parameters check ends
 
    /* parameter initialize */
    memset(cCmd_info, 0x00, sizeof(cCmd_info));
    memset(cRst_info, 0x00, sizeof(cRst_info));
    memset(pcData, 0x00, sizeof(pcData));
    

#ifdef _DEBUG
    memset(debugBuff, 0x00, sizeof(debugBuff));
#endif

    nCmd_len = 0;
    rst_len = 0;

    pcmd_info = NULL;
    /* command */
    pcmd_info = cCmd_info;
    memcpy(pcmd_info, "GM", 2);
    pcmd_info += 2;
    /*
     Algorithmic 
    if (nAlgo == 0 || nAlgo == 1 || nAlgo == 2 || nAlgo == 3 || 
        nAlgo == 4 || nAlgo == 5 || nAlgo == 6 || nAlgo == 7) 
    {
	sprintf(pcmd_info, "%02d", nAlgo);
	pcmd_info += 2;
    }
    else 
    {
	union_err_log("In SMAPIDigest::Parameter error,[nAlgo] is not valide value! valide= [%d]", nAlgo);
	return CKR_PARAMETER_ERR;
    }
    */
    // mody by chenf date 201704014
    switch(nAlgo)
    {
	case 0:memcpy(pcmd_info, "07", 2);break;
	case 1:memcpy(pcmd_info, "02", 2);break;
	case 2:memcpy(pcmd_info, "03", 2);break;
	case 3:memcpy(pcmd_info, "04", 2);break;
	case 4:memcpy(pcmd_info, "05", 2);break;
	case 5:memcpy(pcmd_info, "06", 2);break;
	//case 6:memcpy(pcmd_info, "", 2);break;
	case 7:memcpy(pcmd_info, "01", 2);break;
	default:
		union_err_log("In SMAPIDigest::Parameter error,[nAlgo] is not valide value! valide= [%d]", nAlgo);
		return CKR_PARAMETER_ERR;
    }
    pcmd_info += 2;

    //2017-06-20  zhaomx
    //memcpy(pcmd_info, ";", 1);
    //pcmd_info += 1;
    // mody end
    
    /* the length of the input data */
    if (nDataLen > 0)
    {
	sprintf(pcmd_info, "%05d", nDataLen);
	pcmd_info += 5;
    }
    else
    {
	union_err_log("In SMAPIDigest::Parameter error,[nDataLen] is not valide value! iLen= [%04d]", nDataLen);
	return CKR_PARAMETER_ERR;
    }
    
    /* length of input data */
    if (pbData != NULL) 
    {
	memcpy(pcmd_info, pbData, nDataLen);
	pcmd_info += nDataLen;
    }
    else
    {
	union_err_log("In SMAPIDigest::Parameter error,[pbData] is null");
	return CKR_PARAMETER_ERR;
    }
 
    /* set the last char '\0' */
    *pcmd_info = 0;

    /* calculate the length of requst package */
    nCmd_len = pcmd_info - cCmd_info;

#ifdef	_DEBUG
    UnpackBCD(cCmd_info, (char *) debugBuff, nCmd_len * 2);
    union_log(" In SMAPIDigest::[REQUEST]=[%d][%s] ", nCmd_len, debugBuff);
#endif

    rst_len = UnionHSMCmd(nSock, cCmd_info, nCmd_len, cRst_info, gUnionTimeout, &retCode);
    
	switch(rst_len)
    {
    	 case -1:
    		 union_err_log("In SMAPIDigest::SOCKET EDLL!");
    		 return CKR_PARAMETER_ERR;
    	 case -2:
    		 union_err_log("In SMAPIDigest::SOCKET SEND ERROR!");
    		 return CKR_SENDFAIL_ERR;
    	 case -3:
    		 union_err_log("In SMAPIDigest::SOCKET RECIVE ERROR!");
    		 return CKR_RCVTMOUT_ERR;
    	 case -4:
    		 union_err_log("In SMAPIDigest::SOCKET RECIVE CKR_PARAMETER_ERR ERROR!");
    		 return CKR_PARAMETER_ERR;
    	 default:
    	 	 break;
    	}
#ifdef	_DEBUG
    UnpackBCD(cRst_info, (char *) debugBuff, rst_len*2);
    union_log("In SMAPIDigest::[RESPOND]=[%d][%s]", rst_len, debugBuff);
#endif
    // Get len of the Digest 
    memset(cTmpBuf, 0x00, sizeof(cTmpBuf));
    
    // mody by chenf 20170417 
   /* memcpy(cTmpBuf, cRst_info, 4);
    int digestLen = atoi((char*)cTmpBuf);

    // Get content of the Digest 
    memcpy(pbDigest, cRst_info+4, digestLen);
    */
    memcpy(cTmpBuf, cRst_info, 4);
    int digestLen = atoi((char*)cTmpBuf);

    // Get content of the Digest 
    memcpy(pbDigest, cRst_info+2, digestLen);

    return (0);
}

/***************************************************************************************************************/
/* 函数名称： SMAPIPublicCalc                                                                                   */
/*           5.5 公钥加解密   （7.5.4 RSA 公钥运算）  农行    "UK"                                               */
/* 功能说明：                                                                                                   */
/*           RSA 公钥加解密                                                                                     */
/* 输入参数：                                                                                                   */ 
/*	     UINT nSock：    连接的socket 句柄                                                                  */
/*	     int nFlag：     加密、解密标志, 1-加密; 0-解密                                                      */
/*	     int nPad:       填充模式， 0：不填充；1：PKCS#1 填充算法；2：OAEP 填充算法。                         */
/*			     注：公钥解密时不支持OAEP 填充                                                       */ 
/* 			     当nFlag = 0 时，nPad = 0 或者nPad = 1                                              */ 
/*	     byte * pbPK：   公钥明文，DER 格式，二进制数，长度由nPKLen 指定                                      */ 
/*	     int nPKLen：    公钥数据长度，取值范围[1, 2048] (有效长度范围参见附录一)                             */
/*	     byte *pbInData：需要进行加密/解密的数据，二进制数，长度由nInLen 指定                                 */
/*	     int nInLen：    pbInData 的长度， 取值范围[1, 256]                                                 */
/*			     注：nFlag、nPad、nInLen、pnOutLen 四个参数之间的关系：                              */
/*			     当nPad = 0 时，nInLen== pnOutLen ==公钥模长                                        */  
/*			     当nPad = 1，nFlag = 0 时，nInLen <= pnOutLen==公钥模长                             */
/*			     当nPad = 1，nFlag = 1 时，pnOutLen<= nInLen ==公钥模长                             */  
/* 输出参数：                                                                                                   */
/*	     byte *pbOutData：经过加密/解密之后的密文/明文数据，二进制数，                                        */
/*	     int *pnOutLen：  返回的pbOutData 的数据长度，                                                       */
/* 返回说明：                                                                                                   */
/*           0： 生成成功                                                                                      */
/*	     1： 输入参数验证失败                                                                               */
/*	     2： 无效的密钥(PK)                                                                                */  
/*	     3： 向加密机发送数据失败                                                                           */
/*	     4： 接收加密机数据超时                                                                             */
/*	     5： 接收到的数据格式错                                                                             */
/*	     9:  其他错误                                                                                      */
/* 维护记录：                                                                                                  */
/*          2017-03-07 by zhaomx                                                                              */
/***************************************************************************************************************/ 
int SMAPIPublicCalc(UINT nSock, int nFlag, int nPad,byte * pbPK, int nPKLen, byte * pbInData, int nInLen, 	
		    byte * pbOutData, 	int *pnOutLen)
{
    int    retCode=0;
    char   cCmd_info[40960 + 1];
    char   cRst_info[40960 + 1];
    int    nCmd_len;
    int    rst_len;
    char   *pcmd_info = NULL;
    unsigned char cTmpBuf[1024 + 1];
    int    pubKeyLen;
    int    iDiff = 0;

    if(UnionIsSocket(nSock)<1)
    {
    	union_err_log("In SMAPIPublicCalc::parameter Error nSocket　edl nSocket=[%d]\n",nSock);
	return CKR_SENDFAIL_ERR;
    }

    if(nPad!=0 && nPad!=1 && nPad!=2)
    {
	union_err_log("In SMAPIPublicCalc::parameter error. [nPad]=[%d] ", nPad);
	return CKR_PARAMETER_ERR;
    }

    if(nInLen < 1 || nInLen > 256)
    {
	union_err_log("In SMAPIPublicCalc::parameter error. [nInLen]=[%d] ", nInLen);
	return CKR_PARAMETER_ERR;
    }


    if(nPKLen < 1 || nPKLen > 2048)
    {
	union_err_log("In SMAPIPublicCalc::parameter error. [nPKLen]=[%d] ", nPKLen);
	return CKR_PARAMETER_ERR;
    }

    if (nFlag == 0 && nPad == 2)
    {
	union_err_log("In SMAPIPublicCalc::parameter error. [nPad]=[%d] ", nPad);
	return CKR_PARAMETER_ERR;
    }

#ifdef _DEBUG
    char debugBuff[4096 + 1];
    memset(debugBuff, 0x00, sizeof(debugBuff));
#endif
    memset(cCmd_info, 0x00, sizeof(cCmd_info));
    memset(cRst_info, 0x00, sizeof(cRst_info));
    memset(cTmpBuf, 0x00, sizeof(cTmpBuf));
    nCmd_len = 0;
    rst_len = 0;
    pcmd_info = NULL;
    /* command */
    pcmd_info = cCmd_info;

    memcpy(pcmd_info, "UK", 2);
    pcmd_info += 2;

    //nFlag  加密、解密标志
    if (nFlag == 0)    //解密
    {
	memcpy(pcmd_info, "0", 1);
    }
    else if (nFlag == 1)   //加密
    {
	memcpy(pcmd_info, "1", 1);
    }
    else
    {
	union_err_log("In SMAPIPublicCalc::parameter error. [nFlag]=[%d]", nFlag);
	return CKR_PARAMETER_ERR;
    }
    pcmd_info += 1;

    /* pad flag  nPad:   填充模式  0：不填充；1：PKCS#1 填充算法；2：OAEP 填充算法。*/
    sprintf(pcmd_info, "%d", nPad);
    pcmd_info += 1;

    //填充模式为2时：MGF： 01-MGF1;  MGF哈希算法:  01;  OAEP编码参数长: "00";  OAEP编码参数 :""
    if(nPad == 2)
    {
	memcpy(pcmd_info, "010100", 6);
	pcmd_info += 6;
    }
	
    //消息类型       '1'-Hex   '0'-二进制
    memcpy(pcmd_info, "1", 1);
    pcmd_info += 1;

    /* Public key index default is 00*/
    memcpy(pcmd_info, "00", 2);
    pcmd_info += 2;

    //公钥编码格式  '1'-DER
    memcpy(pcmd_info, "1", 1);
    pcmd_info += 1;

    /*public key length */
    if(nPKLen)
    {
        sprintf(pcmd_info, "%04d", nPKLen);
	pcmd_info += 4;
    }

    /* Public key */
    memcpy(pcmd_info, pbPK, nPKLen);
    pcmd_info += nPKLen;

    //数据长度   
    sprintf(pcmd_info,"%04d",nInLen*2);
    pcmd_info += 4;

    /* in data H */
    memset(cTmpBuf, 0x00, sizeof(cTmpBuf));
    UnpackBCD((char*)pbInData, cTmpBuf, nInLen*2);
    memcpy(pcmd_info, cTmpBuf, nInLen*2);
    pcmd_info += nInLen*2;

    
    /* set the last char '\0' */
    *pcmd_info = 0;
    /* calculate the length of requst package */
    nCmd_len = pcmd_info - cCmd_info;

#ifdef _DEBUG
    memset(debugBuff, 0x00, sizeof(debugBuff));
    UnpackBCD(cCmd_info, (char *) debugBuff, nCmd_len * 2);
    union_log("In SMAPIPublicCalc::[REQUEST]=[%d][%s]", nCmd_len, debugBuff);
#endif
    rst_len = UnionHSMCmd(nSock, cCmd_info, nCmd_len, cRst_info, gUnionTimeout, &retCode);

     switch(rst_len)
    {
    	 case -1:
    		 union_err_log("In SMAPIPublicCalc::SOCKET EDLL!");
    		 return CKR_PARAMETER_ERR;
    	 case -2:
    		 union_err_log("In SMAPIPublicCalc::SOCKET SEND ERROR!");
    		 return CKR_SENDFAIL_ERR;
    	 case -3:
    		 union_err_log("In SMAPIPublicCalc::SOCKET RECIVE ERROR!");
    		 return CKR_RCVTMOUT_ERR;
    	 case -4:
    		 union_err_log("In SMAPIPublicCalc::SOCKET RECIVE CKR_PARAMETER_ERR ERROR!");
    		 return CKR_PARAMETER_ERR;
    	 default:
    	 	 break;
    	}
#ifdef _DEBUG
    memset(debugBuff, 0x00, sizeof(debugBuff));
    UnpackBCD(cRst_info, (char *) debugBuff, rst_len * 2);
    union_log("In SMAPIPublicCalc::[REPLAY]=[%d][%s]", rst_len, debugBuff);
#endif
    /* Get the length of the outData */
    memset(cTmpBuf, 0x00, sizeof(cTmpBuf));
    memcpy(cTmpBuf, cRst_info, 4);

    *pnOutLen = atoi((char*)cTmpBuf);

    memcpy(pbOutData, cRst_info+4, *pnOutLen);

    return (0);

}

/***************************************************************************************************************/
/* 函数名称： SMAPIPrivateCalc                                                                                  */
/*           5.6      私钥加解密（7.5.5 RSA 私钥运算）  农行    "VA"                                             */
/* 功能说明：                                                                                                   */
/*	     RSA 私钥加解密										       */
/* 输入参数：                                                                                                   */
/*	     UINT nSock：       连接的socket 句柄                                                               */
/*	     int nFlag：        加密、解密标志, 1-加密; 0-解密                                                   */
/*	     int nPad:          填充模式，0：不填充；1：PKCS#1 填充算法；2：OAEP 填充算法。                       */
/*	                        注：私钥加密时不支持OAEP 填充                                                    */  
/*				当nFlag = 1 时，nPad = 0 或者nPad = 1                                           */
/*	     byte * pbSK：      私钥密文(由HMK 加密)，二进制数，长度由nSKLen 指定                                 */ 
/*	     int nSKLen：       私钥数据长度，取值范围[1, 2048] (有效长度范围参见附录一)                          */  
/*	     byte *pbInData：   需要进行加密/解密的数据，二进制数，长度由nInLen 指定                              */
/*	     int nInLen：       pbInData 的长度取值范围[1, 256]                                                 */
/*			        注：nFlag、nPad、nInLen、pnOutLen 四个参数之间的关系：                           */
/*				当nPad = 0 时，nInLen== pnOutLen ==私钥模长                                     */ 
/*				当nPad = 1，nFlag = 0 时，nInLen <= pnOutLen==私钥模长                          */ 
/*				当nPad = 1，nFlag = 1 时，pnOutLen<= nInLen ==私钥模长                          */ 
/* 输出参数：                                                                                                   */ 
/*	     byte *pbOutData：经过加密/解密之后的密文/明文数据，二进制数，                                        */
/*	     int *pnOutLen：    返回的pbOutData 的数据长度，                                                     */
/* 返回说明：                                                                                                   */
/*	     0： 生成成功                                                                                       */
/*	     1： 输入参数验证失败                                                                               */
/*	     2： 无效的密钥(SK)                                                                                 */
/*	     3： 向加密机发送数据失败                                                                           */ 
/*	     4： 接收加密机数据超时                                                                             */
/*	     5： 接收到的数据格式错                                                                             */
/*	     9:  其他错误                                                                                      */ 
/* 维护记录：                                                                                                  */
/*          2017-03-07 by zhaomx                                                                              */
/***************************************************************************************************************/ 
int SMAPIPrivateCalc(UINT nSock, int nFlag,int nPad,byte * pbSK,int nSKLen, 
		     byte * pbInData, int nInLen, byte * pbOutData, int *pnOutLen)
{

    int           retCode=0;
    char          cCmd_info[40960 + 1];
    char          cRst_info[40960 + 1];
    int           nCmd_len;
    int           rst_len;
    char          *pcmd_info = NULL;
    unsigned char cTmpBuf[1024 + 1];
    int           iDiff;


    if(UnionIsSocket(nSock)<1)
    {
    	union_err_log("In SMAPIPrivateCalc::nSKLen error! socket edle nSocket=[%d]\n",nSock);
	return CKR_PARAMETER_ERR;
    }
    //parameters check end

    if(nSKLen<1 || nSKLen>2048)
    {
	union_err_log("In SMAPIPrivateCalc::nSKLen error! nSKLen=[%d]\n",nSKLen);
	return CKR_PARAMETER_ERR;
    }

    if(nInLen<1 || nInLen>256)
    {
	union_err_log("In SMAPIPrivateCalc::nInLen error! nInLen=[%d]\n",nInLen);
	return CKR_PARAMETER_ERR;
    }

    if(nPad != 0 && nPad != 1 && nPad != 2)
    {
	union_err_log("In SMAPIPrivateCalc::parameter error! [nPad]=[%d] ", nPad);
	return CKR_PARAMETER_ERR;
    }

    if (nFlag == 1 && nPad == 2)
    {
	union_err_log("In SMAPIPrivateCalc::parameter error! [nPad] = [%d] ", nPad);
	return CKR_PARAMETER_ERR;
    }

#ifdef	_DEBUG
    unsigned char   debugBuff[40960];
    memset(debugBuff, 0x00, sizeof(debugBuff));
#endif

    memset(cCmd_info, 0x00, sizeof(cCmd_info));
    memset(cRst_info, 0x00, sizeof(cRst_info));

    nCmd_len = 0;
    rst_len = 0;

    /* command */
    pcmd_info = NULL;
    pcmd_info = cCmd_info;
	
    memcpy(pcmd_info, "VA", 2);
    pcmd_info += 2;

    //nFlag：加密、解密标志, 1-加密;  0-解密
    if (nFlag == 0) 
    {
	memcpy(pcmd_info, "0", 1);
    } 
    else if (nFlag == 1) 
    {
	memcpy(pcmd_info, "1", 1);
    }
    else
    {
	union_err_log("In SMAPIPrivateCalc::parameter error! [nFlag] = [%d] ", nFlag);
	return CKR_PARAMETER_ERR;
    }
    pcmd_info += 1;

    /* pad flag 填充模式  0：不填充；1：PKCS#1 填充算法；2：OAEP 填充算法。*/
    sprintf(pcmd_info, "%d", nPad);
    pcmd_info += 1;

    //填充模式为2时：MGF： 01-MGF1;  MGF哈希算法:  01;  OAEP编码参数长: "00";  OAEP编码参数 :""
    if(nPad == 2)
    {
	memcpy(pcmd_info, "010100", 6);
	pcmd_info += 6;
    }

    /* private key index */
    memcpy(pcmd_info, "00", 2);
    pcmd_info += 2;

    /* private key length */
    sprintf(pcmd_info, "%04d", nSKLen);
    pcmd_info += 4;

    /* private key */
   // memset(cTmpBuf, 0x00, sizeof(cTmpBuf));
   // UnpackBCD((char*)pbSK, cTmpBuf, nSKLen*2);
   // memcpy(pcmd_info, cTmpBuf, nSKLen*2);
   // pcmd_info += nSKLen*2;

    memcpy(pcmd_info, pbSK, nSKLen);    //zhaomx  2017-04-10
    pcmd_info += nSKLen;
    
    //数据长度
    sprintf(pcmd_info, "%04d", nInLen);
    pcmd_info += 4;

    /* in data */
   // memset(cTmpBuf, 0x00, sizeof(cTmpBuf));
   // UnpackBCD((char*)pbInData, cTmpBuf, nInLen*2);
   // memcpy(pcmd_info, cTmpBuf, nInLen*2);
   // pcmd_info += nInLen*2;

    memcpy(pcmd_info, pbInData, nInLen); //zhaomx  2017-04-10
    pcmd_info += nInLen;


     /* set the last char '\0' */
    *pcmd_info = 0;
    /* calculate the length of requst package */
    nCmd_len = pcmd_info - cCmd_info;

#ifdef	_DEBUG
    memset(debugBuff, 0x00, sizeof(debugBuff));
    UnpackBCD(cCmd_info, (char *) debugBuff, nCmd_len * 2);
    union_log(" In SMAPIPrivateCalc::[REQUEST]=[%d][%s] ", nCmd_len, debugBuff);
#endif
    rst_len = UnionHSMCmd(nSock, cCmd_info, nCmd_len, cRst_info, gUnionTimeout,&retCode);
switch(rst_len)
    {
    	 case -1:
    		 union_err_log("In SMAPIPrivateCalc::SOCKET EDLL!");
    		 return CKR_PARAMETER_ERR;
    	 case -2:
    		 union_err_log("In SMAPIPrivateCalc::SOCKET SEND ERROR!");
    		 return CKR_SENDFAIL_ERR;
    	 case -3:
    		 union_err_log("In SMAPIPrivateCalc::SOCKET RECIVE ERROR!");
    		 return CKR_RCVTMOUT_ERR;
    	 case -4:
    		 union_err_log("In SMAPIPrivateCalc::SOCKET RECIVE CKR_PARAMETER_ERR ERROR!");
    		 return CKR_PARAMETER_ERR;
    	 default:
    	 	 break;
    	}
#ifdef	_DEBUG
    memset(debugBuff, 0x00, sizeof(debugBuff));
    UnpackBCD(cRst_info, (char *) debugBuff, rst_len * 2);
    union_log("In SMAPIPrivateCalc::[RESPOND]=[%d][%s]", rst_len, debugBuff);
#endif

    /* Get the length of the outData */
    memset(cTmpBuf, 0x00, sizeof(cTmpBuf));
    memcpy(cTmpBuf, cRst_info, 4);
    *pnOutLen = atoi((char*)cTmpBuf);
    //*pnOutLen = *pnOutLen / 2;
    printf("-------------------* pnoutLen=[%d] \n",*pnOutLen);
    /* Get content of the outData */
    /* mody by chenf 20170414 */
   // memset(cTmpBuf, 0x00, sizeof(cTmpBuf));
   memcpy(pbOutData, cRst_info+4, *pnOutLen);
  // printf("-------------------* cTmpBuf=[%s] \n",cTmpBuf);
 // PackBCD(pbOutData, cTmpBuf, *pnOutLen*2);

    return CKR_SMAPI_OK;

}

/***************************************************************************************************************/
/* 函数名称： SMAPIPrivateSign                                                                                  */
/*           5.7 私钥签名（7.5.2 RSA 签名）   农行    "EW"                                                      */
/* 功能说明：                                                                                                   */
/*           RSA 私钥签名                                                                                       */
/*           注：对输入数据计算摘要，然后直接对其进行私钥加密，非证书签名用接口。                                  */
/* 输入参数：                                                                                                   */ 
/*	    UINT nSock：    连接的socket 句柄 		                                                       */ 
/*	    int nAlgo：     算法类型,                                                                          */
/*                                    “00”一 MD5  “01” -SHA1  “02” -SHA224 “03” -SHA256 “04” -SHA384           */
/*                                    “05” -SHA512 “07” –SM3  "99" = 不计算hash                                */
/*	    int nPad:       填充模式， 0：不填充；1：PKCS#1 填充算法；2：OAEP 填充算法。                         */ 
/*	    byte *pbSK：    私钥密文(由HMK 加密)，二进制数，长度由nSKLen 指定                                    */
/*	    int nSKLen：    私钥数据长度，取值范围[1, 2048] (有效长度范围参见附录一)                             */
/*	    byte *pbData：  进行签名数据，二进制数，长度由nDataLen 指定                                         */
/*	    int nDataLen：  pbData 的长度取值范围[1, 2048]                                                     */
/* 输出参数：                                                                                                  */
/*	    byte *pbSign：  签名值，二进制数，长度由pnSignLen 指定                                              */
/*	    int *pnSignLen：返回的pbSign 的数据长度，应等于私钥的模长                                           */   
/* 返回说明：                                                                                                  */
/*	    0： 生成成功                                                                                       */
/*	    1： 输入参数验证失败                                                                                */
/*	    2： 无效的密钥(SK)                                                                                 */ 
/*	    3： 向加密机发送数据失败                                                                            */
/*	    4： 接收加密机数据超时                                                                              */
/*	    5： 接收到的数据格式错                                                                             */
/*	    9:  其他错误                                                                                      */
/* 维护记录：                                                                                                  */
/*          2017-03-07 by zhaomx                                                                              */
/***************************************************************************************************************/ 

int SMAPIPrivateSign(UINT nSock, int nAlgo, int nPad, byte *pbSK, int nSKLen,byte *pbData, int nDataLen, 
	             byte *pbSign, int *pnSignLen) 
{
    int retCode=0;
    int dataLen;
    int nCmd_len;
    int rst_len;
    char *pcmd_info = NULL;
    char pcLen[4 + 1];
    char cCmd_info[40960 + 1];
    char rst_info[40960 + 1];
    char pbSignTemp[4096 + 1];

    //增加填充模式检查
  /*  if(nDataLen==1)
    {
    	if(nAlgo==0||nAlgo==2)
    	{
    	    union_err_log("In SMAPIPrivateSign::nDataLen not format nAlgo errornDataLen=[%d] nAlgo=[%d]\n",nDataLen,nAlgo);
	    return CKR_PARAMETER_ERR;
	}
    }*/

    if(UnionIsSocket(nSock)<1)
    {
	union_err_log("In SMAPIPrivateSign::nSock error nSock=[%d]",nSock);
	return CKR_SENDFAIL_ERR;
    }
    
    if(nSKLen<1 || nSKLen>2048)
    {
	union_err_log("In SMAPIPrivateSign::nSKLen error nSKLen=[%d]\n",nSKLen);
	return CKR_PARAMETER_ERR;
    }

    if(nDataLen<1 || nDataLen>2048)
    {
	union_err_log("In SMAPIPrivateSign::nDataLen error DataLen=[%d]\n",nDataLen);
	return CKR_PARAMETER_ERR;
    }

    if(nPad != 0 && nPad != 1 && nPad != 2)
    {
	union_err_log("In SMAPIPrivateSign::PAD MODE WRONG nPad=[%d]",nPad);
	return CKR_PARAMETER_ERR;
    }
    if((nAlgo != 0) && (nAlgo != 1) && (nAlgo != 2) && (nAlgo != 3) && (nAlgo != 4) && (nAlgo != 5) && (nAlgo != 7) && (nAlgo != 99))
    {
    	union_err_log("In SMAPIPrivateSign::nAlgo WRONG nPad=[%d]",nAlgo);
	return CKR_PARAMETER_ERR;
    }

    if(nAlgo == 0)
    {
        nAlgo = 2;            //API nAlgo = 0 对应指令算法  nAlgo = 2  ‘02’=MD5
    } 
    else if(nAlgo == 2)
    {
        nAlgo = 5;            //API nAlgo = 2 对应指令算法  nAlgo = 5  ‘05’=SHA-224
    }
    else if(nAlgo == 3)
    {
        nAlgo = 6;            //API nAlgo = 3 对应指令算法  nAlgo = 6  ‘06’=SHA-256
    }
    else if(nAlgo == 4)
    {
        nAlgo = 7;            //API nAlgo = 4 对应指令算法  nAlgo = 7  ‘07’=SHA-384
    }
    else if(nAlgo == 5)
    {
        nAlgo = 8;            //API nAlgo = 5 对应指令算法  nAlgo = 8  ‘08’=SHA-512
    }
    else if(nAlgo == 99)
    {
        nAlgo = 4;            //API nAlgo = 99 对应指令算法 nAlgo = 4  ‘04’=No hash  
    }

#ifdef _DEBUG
    /* use for DEBUG */
    char debugBuff[40960];
    memset(debugBuff, 0x00, sizeof(debugBuff));
#endif
    /* command */
    memset(cCmd_info, 0x00, sizeof(cCmd_info));
    memset(pcLen, 0x00, sizeof(pcLen));

    nCmd_len = 0;
    dataLen = 0;

    pcmd_info = NULL;

    pcmd_info = cCmd_info;
    memcpy(pcmd_info, "EW", 2);
    pcmd_info += 2;

    /*HASH 标识 */
    sprintf(pcmd_info,"%02d",nAlgo);
    pcmd_info += 2;

    /* Fill type:default PKCS */
    if(nPad == 0)
    {
        memcpy(pcmd_info, "00", 2);
    }
    else if(nPad == 1)
    {
        memcpy(pcmd_info, "01", 2);
    }
    else if(nPad == 2)
    {
        memcpy(pcmd_info, "02", 2);
    }
    pcmd_info += 2;

    //填充模式为2时：MGF： 01-MGF1;  MGF哈希算法:  01;  OAEP编码参数长: "02";  OAEP编码参数 :"12"
    if(nPad == 2)
    {
	memcpy(pcmd_info, "010100", 6);
	pcmd_info += 6;
    }

    //数据长度
    sprintf(pcmd_info, "%04d", nDataLen);
    pcmd_info += 4;
	
    //数据
    memcpy(pcmd_info, pbData, nDataLen);
    pcmd_info += nDataLen;

    /* 增加分隔符  zhaomx 20170208  */
    memcpy(pcmd_info,";",1);
    pcmd_info++;
        
    /* index of private key  is 00  */
    memcpy(pcmd_info, "00", 2);
    pcmd_info += 2;

    /* here place private key/
    /* private key length */
    sprintf(pcmd_info, "%04d", nSKLen);
    pcmd_info += 4;

    /* private key */
    memcpy(pcmd_info, pbSK, nSKLen);
    pcmd_info += nSKLen;


    /* set the last char '\0' */
    *pcmd_info = 0;

    /* calculate the length of requst package */
    nCmd_len = pcmd_info - cCmd_info;

#ifdef	_DEBUG
    memset(debugBuff, 0x00, sizeof(debugBuff));
    UnpackBCD(cCmd_info, (char *) debugBuff, nCmd_len * 2);
    union_log(" In SMAPIPrivateSign::[REQUEST]=[%d][%s] ", nCmd_len, debugBuff);
#endif

    rst_len = UnionHSMCmd(nSock, cCmd_info,nCmd_len, rst_info, gUnionTimeout,&retCode);
		
   switch(rst_len)
    {
    	 case -1:
    		 union_err_log("In SMAPIPrivateSign::SOCKET EDLL!");
    		 return CKR_PARAMETER_ERR;
    	 case -2:
    		 union_err_log("In SMAPIPrivateSign::SOCKET SEND ERROR!");
    		 return CKR_SENDFAIL_ERR;
    	 case -3:
    		 union_err_log("In SMAPIPrivateSign::SOCKET RECIVE ERROR!");
    		 return CKR_RCVTMOUT_ERR;
    	 case -4:
    		 union_err_log("In SMAPIPrivateSign::SOCKET RECIVE CKR_PARAMETER_ERR ERROR!");
    		 return CKR_PARAMETER_ERR;
    	 default:
    	 	 break;
    	}
#ifdef	_DEBUG
    memset(debugBuff, 0x00, sizeof(debugBuff));
    UnpackBCD(rst_info, (char *) debugBuff, rst_len * 2);
    union_log("In SMAPIPrivateSign::[RESPOND]=[%d][%s]", rst_len, debugBuff);
#endif
    /* get length of out data */
    memcpy(pcLen, rst_info, 4);
    *pnSignLen = (int) atoi((char *) pcLen);

    /* get content of out data */
    memcpy(pbSign, rst_info + 4, *pnSignLen);

#ifdef	_DEBUG
    memset(debugBuff, 0x00, sizeof(debugBuff));
    UnpackBCD((char*)pbSign, (char *) debugBuff, (*pnSignLen) * 2);
    union_log("In SMAPIPrivateSign::Sign=[%d][%s]\n", *pnSignLen, debugBuff);
#endif
    return (0);

}


/***************************************************************************************************************/
/* 函数名称： SMAPIVerifySign                                                                                  */
/*           5.8   签名验证（7.5.3 RSA 验签）   农行    "EY"                                                    */
/* 功能说明：                                                                                                  */
/*          RSA 验证签名                                                                                       */
/*	    注：对输入数据计算摘要，对输入的签名进行公钥解密，比较计算出的摘要和解密出                             */
/*	        的摘要是否一致，非证书签名验证用接口。                                                           */
/* 输入参数：                                                                                                  */
/*	    UINT nSock：    连接的socket 句柄                                                                  */
/*	    int nAlgo：     算法类型, 0-MD5 算法；1—SHA-1 算法; 2—SHA-224；3—SHA-256；                          */ 
/*		                      4—SHA-384；5—SHA-512                                                     */
/*	    int nPad:       填充模式， 0：不填充；1：PKCS#1 填充算法；2：OAEP 填充算法。                         */
/*	    byte *pbPK：    公钥明文，DER 格式，二进制数，长度由nPKLen 指定                                      */
/*	    int nPKLen：    公钥数据长度，取值范围[1, 2048] (有效长度范围参见附录一)                             */ 
/*	    byte *pbData：  签名对应的数据，二进制数，长度由nDataLen 指定                                       */
/*	    int nDataLen：  pbData 的长度取值范围[1, 2048]                                                     */
/*	    byte *pbSign：  签名值，二进制数，长度由nSignLen 指定                                               */
/*	    int nSignLen：  pbSign 的长度，应等于公钥的模长                                                     */   
/* 输出参数：                                                                                                  */
/*          无                                                                                                */ 
/* 返回说明：                                                                                                  */ 
/*	    0： 验证成功                                                                                       */
/*	    1： 输入参数验证失败                                                                               */
/*	    2： 无效的密钥(PK)                                                                                 */
/*	    3： 向加密机发送数据失败                                                                           */
/*	    4： 接收加密机数据超时                                                                             */
/*	    5： 接收到的数据格式错 		                                                              */ 
/*	    9:  其他错误                                                                                      */
/*         10:  Hash 结果匹配失败                                                                              */ 
/* 维护记录：                                                                                                  */
/*          2017-03-07 by zhaomx                                                                              */
/***************************************************************************************************************/ 
int SMAPIVerifySign(UINT nSock, int nAlgo, int nPad, unsigned char *pbPK, int nPKLen, unsigned char *pbData, 
		    int nDataLen, unsigned char *pbSign, int nSignLen) 
{

    int            retCode=0;
    char           cCmd_info[40960 + 1];
    char           rst_info[40960 + 1];
    unsigned char  tmpBuf[1024 + 1];
    int            nCmd_len;
    int            rst_len;
    char           *pcmd_info;
    int            pubKeyDerLen;
    int            pubKeyLen;
    int            rv;

    unsigned char pbDigestTemp[256];
    unsigned char pubKeyDer[1024 + 1];

    if (UnionIsSocket(nSock)<1)
    {
	union_err_log("In SMAPIVerifySign nSock error, [nSock=%u]", nSock);
	return(CKR_SENDFAIL_ERR);
    }

    if ((nAlgo < 0) || (nAlgo > 5)){
	union_err_log("In SMAPIVerifySign nAlgo error, [nAlgo=%d]", nAlgo);
        return(CKR_PARAMETER_ERR);
    }

    if ((nPad < 0) || (nPad > 2)){
	union_err_log("In SMAPIVerifySign nPad error, [nPad=%d]", nPad);
        return(CKR_PARAMETER_ERR);
    }
    
    if (NULL == pbPK){
        union_err_log("In SMAPIVerifySign [pbPK is NULL]");
        return(CKR_PARAMETER_ERR);
    }

    if ((nPKLen < 1) || (nPKLen > 2048)){
	union_err_log("In SMAPIVerifySign nPKLen error, [nPKLen=%d]", nPKLen);
        return(CKR_PARAMETER_ERR);
    }
    
    if (NULL == pbData){
        union_err_log("In SMAPIVerifySign [pbData is NULL]");
        return(CKR_PARAMETER_ERR);
    }    

    if ((nDataLen < 1) || (nDataLen > 2048)){
        union_err_log("In SMAPIVerifySign [nDataLen=%d]", nDataLen);
        return(CKR_PARAMETER_ERR);
    }

    if (NULL == pbSign){
        union_err_log("In SMAPIVerifySign [pbSign is NULL]");
        return(CKR_PARAMETER_ERR);
    }
/*
    if (0 != (nPKLen % nSignLen))
    	{
        union_err_log("In SMAPIVerifySign [nSignLen=%d]", nSignLen);

        return(CKR_PARAMETER_ERR);
    }    
    */
    if(nAlgo == 0)
    {
        nAlgo = 2;            //API nAlgo = 0 对应指令算法  nAlgo = 2  ‘02’=MD5
    } 
    else if(nAlgo == 2)
    {
        nAlgo = 5;            //API nAlgo = 2 对应指令算法  nAlgo = 5  ‘05’=SHA-224
    }
    else if(nAlgo == 3)
    {
        nAlgo = 6;            //API nAlgo = 3 对应指令算法  nAlgo = 6  ‘06’=SHA-256
    }
    else if(nAlgo == 4)
    {
        nAlgo = 7;            //API nAlgo = 4 对应指令算法  nAlgo = 7  ‘07’=SHA-384
    }
    else if(nAlgo == 5)
    {
        nAlgo = 8;            //API nAlgo = 5 对应指令算法  nAlgo = 8  ‘08’=SHA-512
    }
    else if(nAlgo == 99)
    {
        nAlgo = 4;            //API nAlgo = 99 对应指令算法 nAlgo = 4  ‘04’=No hash  
    }


#ifdef _DEBUG
    /* use for debug */
    unsigned char   debugBuff[8192+1];
    memset(debugBuff, 0x00, sizeof(debugBuff));
#endif

    memset(cCmd_info, 0x00, sizeof(cCmd_info));
    memset(rst_info, 0x00, sizeof(rst_info));

    memset(pbDigestTemp, 0x00, sizeof(pbDigestTemp));
    memset(pubKeyDer, 0x00, sizeof(pubKeyDer));

    /* command */
    pcmd_info = cCmd_info;
    memcpy(pcmd_info, "EY", 2);
    pcmd_info += 2;

    //摘要方法
    sprintf(pcmd_info,"%02d",nAlgo);
    pcmd_info+=2;
	
    /* Fill type:default PKCS */
    sprintf(pcmd_info, "%02d", nPad);
    pcmd_info += 2;

    //填充模式为2时：MGF： 01-MGF1;  MGF哈希算法:  01;  OAEP编码参数长: "00";  OAEP编码参数 :""
    if(nPad == 2)
    {
	memcpy(pcmd_info, "010100", 6);
	pcmd_info += 6;
    }

    /*add end*/

    /* length of content of sign */
    if (nSignLen > 0) 
    {
	sprintf(pcmd_info, "%04d", nSignLen);
	pcmd_info += 4;
    } 
    else 
    {
	union_err_log("In SMAPIVerifySign::Parameter error,[nSignLen] is not valid value! nSignLen= [%04d]", nSignLen);
	return CKR_PARAMETER_ERR;
    }

    /* content of sign */
    if (pbSign != NULL) 
    {
	memcpy(pcmd_info, pbSign, nSignLen);
	pcmd_info += nSignLen;
    } 
    else
    {
	union_err_log("In SMAPIVerifySign::Parameter error,[pbSign] is NULL!");
	return CKR_PARAMETER_ERR;
    }

    /* seperater */
    memcpy(pcmd_info, ";", 1);
    pcmd_info += 1;

    //数据长度
    sprintf(pcmd_info,"%04d",nDataLen);
    pcmd_info+=4;
    
    //数据
    memcpy(pcmd_info,pbData,nDataLen);
    pcmd_info+=nDataLen;
  
    /* seperater */
    memcpy(pcmd_info, ";", 1);
    pcmd_info += 1;

    /* in data  zhaomx   2017-4-12 */
    //memset(tmpBuf, 0x00, sizeof(tmpBuf));
    //PackBCD("00000000", tmpBuf, 8);
    //memcpy(pcmd_info, tmpBuf, 4);
    //pcmd_info += 4; 

    //索引    zhaomx   2017-4-12
    memcpy(pcmd_info, "00", 2);
    pcmd_info += 2;

    //公钥编码格式   zhaomx   2017-4-12
    memcpy(pcmd_info, "1", 1);
    pcmd_info += 1;

    //公钥长度 zhaomx   2017-4-12
    sprintf(pcmd_info, "%04d", nPKLen);
    pcmd_info += 4;

    memcpy(pubKeyDer, pbPK, nPKLen);
    pubKeyDerLen = nPKLen;

    //公钥 add end
    memcpy(pcmd_info, pubKeyDer, pubKeyDerLen);
    pcmd_info += pubKeyDerLen;

#ifdef _DEBUG
    {
	memset(debugBuff, 0x00, sizeof(debugBuff));
	UnpackBCD((char*)pubKeyDer, (char *) debugBuff, pubKeyDerLen * 2);
	union_log("In SMAPIVerifySign::pubKeyDer=[%d][%s]", pubKeyDerLen, debugBuff);
    }
#endif
    /* set the last char '\0' */
    *pcmd_info = 0;

    /* calculate the length of requst package */
    nCmd_len = pcmd_info - cCmd_info;
#ifdef	_DEBUG
    UnpackBCD(cCmd_info, (char *)debugBuff, nCmd_len*2);
    union_log(" In SMAPIVerifySign::[REQUEST]=[%s][%d]", debugBuff,nCmd_len);
#endif
    rst_len = UnionHSMCmd(nSock, cCmd_info, 
	nCmd_len, rst_info, gUnionTimeout,&retCode);

    switch(rst_len)
    {
    	 case -1:
    		 union_err_log("In SMAPIVerifySign::SOCKET EDLL!");
    		 return CKR_PARAMETER_ERR;
    	 case -2:
    		 union_err_log("In SMAPIVerifySign::SOCKET SEND ERROR!");
    		 return CKR_SENDFAIL_ERR;
    	 case -3:
    		 union_err_log("In SMAPIVerifySign::SOCKET RECIVE ERROR!");
    		 return CKR_RCVTMOUT_ERR;
    	 case -4:
    		 union_err_log("In SMAPIVerifySign::SOCKET RECIVE CKR_PARAMETER_ERR ERROR!");
    		 return CKR_PARAMETER_ERR;
    	 default:
		 break;
    }       
 
#ifdef	_DEBUG
    UnpackBCD(rst_info, (char *) debugBuff, rst_len * 2);
    union_log("In SMAPIVerifySign::[RESPOND]=[%d][%s]", rst_len, debugBuff);
#endif

    return (0);

}

/***************************************************************************************************************/
/* 函数名称： SMAPITransKeyOutofPK                                                                              */
/*           5.9 RSA 公钥转加密（7.6.17 RSA 公私钥转加密）   农行    "UE"                                        */
/* 功能说明：                                                                                                   */
/*            将被HMK 加密的密钥转化为被PK 加密                                                                  */
/* 输入参数：                                                                                                   */
/*	      UINT nSock：      连接的socket 句柄                                                               */
/*	      int nPad:         填充模式， 0：不填充；1：PKCS#1 填充算法；2：OAEP 填充算法                        */
/*	      byte *pbPK：      公钥的明文，DER 格式，二进制数，长度由nPKLen 指定                                 */
/*	      int nPKLen：      公钥的长度, 取值范围[1, 2048] (有效长度范围参见附录一)                            */
/*	      byte *pbKeyByHMK：被HMK 加密的密钥，二进制数，长度由nKeyLen 指定，                                  */
/*	      int iKeyByMfkLen：pbKeyByHMK 的长度, 取值范围[8, 2048]并能被8 整除且不超过公钥模长。                 */  
/*				注：把“被HMK 加密的密钥”看做单纯的被HMK 加密的数据进行处理。                       */
/* 输出参数：                                                                                                    */
/*	      byte *pbKeyByPK：  被PK 加密的密钥，二进制数，长度由*pnKeyByPKLen 给出                              */ 
/*	      int *pnKeyByPKLen：pbKeyByPK 的长度，等于公钥模长。                                                */
/* 返回说明：                                                                                                   */
/*	      0： 执行成功                                                                                      */
/*	      1： 输入参数验证失败                                                                               */
/*	      2： 无效的密钥(PK)                                                                                */
/*	      3： 向加密机发送数据失败                                                                           */
/*	      4： 接收加密机数据超时                                                                             */
/*	      5： 接收到的数据格式错                                                                             */
/*	      9:  其他错误	                                                                                */
/* 维护记录：                                                                                                   */
/*          2017-03-07 by zhaomx                                                                               */
/****************************************************************************************************************/ 
int SMAPITransKeyOutofPK(UINT nSock, UINT nPad, unsigned char *pbPK, int nPKLen, unsigned char *pbKeyByMfk, int iKeyByMfkLen, 
	                 unsigned char *pbKeyByPK, int *piKeyByPKLen)
{

    int retCode = 0;
    int nCmd_len = 0;
    int rst_len = 0;
    int pubKeyDDerLen = 0;
    int iMkLen = 0;
    int iModLen = 0, iExpLen = 0; 
    int iLen;  
 
    char cCmd_info[40960 + 1];
    char rst_info[40960 + 1];
    char *pcmd_info = NULL;
    
    unsigned char pubKeyDDer[10240 + 2];
    unsigned char KeyByHsm[10240 + 1];
    unsigned char pcLen[8 + 1];
    char          tmpBuf[12800];
	
    char mod[MAX_MODULUS_LEN+1];
    char exp[MAX_MODULUS_LEN+1];

    if (UnionIsSocket(nSock)<1)
    {
	union_err_log("In SMAPITransKeyOutofPK nSock error, [nSock=%u]", nSock);
	return(CKR_SENDFAIL_ERR);
    }

    if (nPad > 3) {
	union_err_log("In SMAPITransKeyOutofPK nPad error, [nPad=%u]", nPad);
        return(CKR_PARAMETER_ERR);
    }
    
    if (NULL == pbPK) {
        union_err_log("In SMAPITransKeyOutofPK [pbPK is NULL]");
        return(CKR_PARAMETER_ERR);
    }

    if ((nPKLen < 1) || (nPKLen > 2048)) {
        union_err_log("In SMAPITransKeyOutofPK, [nPKLen=%u]", nPKLen);
        return(CKR_PARAMETER_ERR);
    }

    if (NULL == pbKeyByMfk) {
        union_err_log("In SMAPITransKeyOutofPK [pbKeyByMfk is NULL]");
        return(CKR_PARAMETER_ERR);
    }

    if (((iKeyByMfkLen < 8) || (iKeyByMfkLen > 2048)) && (0 != (iKeyByMfkLen % 8))) {
        union_err_log("In SMAPITransKeyOutofPK [iKeyByMfkLen=%d]", iKeyByMfkLen);
        return(CKR_PARAMETER_ERR);
    } 
   
#ifdef	_DEBUG
    unsigned char debugBuff[40960];
    memset(debugBuff, 0x00, sizeof(debugBuff));
#endif

    memset(cCmd_info, 0x00, sizeof(cCmd_info));
    memset(rst_info, 0x00, sizeof(rst_info));

    nCmd_len = 0;
    rst_len = 0;
    pcmd_info = NULL;

    /* command */
    pcmd_info = cCmd_info;
    memcpy(pcmd_info, "UE", 2);
    pcmd_info += 2;

    //算法转换类型   01: 3DES加密转RSA公钥加密    03：SM4加密转RSA公钥加密
    memcpy(pcmd_info, "01", 2);
    pcmd_info += 2;

    //填充模式      
    sprintf(pcmd_info, "%02d", nPad);
    pcmd_info += 2;

    //填充模式为2时：MGF： 01-MGF1;  MGF哈希算法:  01;  OAEP编码参数长: "02";  OAEP编码参数 :"12"
    if(nPad == 2)
    {
	memcpy(pcmd_info, "010100", 6);
	pcmd_info += 6;
    }

    //ntag    zhaomx 2017-02-28
    //sprintf(pcmd_info, "%03X", 0);
    //pcmd_info += 3;

    if(iKeyByMfkLen%8 !=0 ||iKeyByMfkLen<8 || iKeyByMfkLen>2048)
    {
	union_err_log("In SMAPITransKeyOutofPK::parameter [iKeyByMfkLen] is not valide iKeyByMfkLen=[%d]!",iKeyByMfkLen);
	return CKR_PARAMETER_ERR;
    }
    iLen=iKeyByMfkLen/8;

    //被加密密钥长度 
    sprintf(pcmd_info,"%04d",iKeyByMfkLen);
    pcmd_info+=4;

    //被加密密钥
    memcpy(pcmd_info,pbKeyByMfk,iKeyByMfkLen);
    pcmd_info+=iKeyByMfkLen;
    
    //密钥索引号
    sprintf(pcmd_info,"%02d",0);
    pcmd_info+=2;

    //公钥编码格式   zhaomx   2017-4-12
    memcpy(pcmd_info, "1", 1);
    pcmd_info += 1;

    //公钥长度 zhaomx   2017-4-12
    sprintf(pcmd_info, "%04d", nPKLen);
    pcmd_info += 4;

    //RSA公钥	
    memcpy(pcmd_info, pbPK, nPKLen);
    pcmd_info += nPKLen;

    /* set the last char '\0' */
    *pcmd_info = 0;

    /* calculate the length of requst package */
    nCmd_len = pcmd_info - cCmd_info;

#ifdef	_DEBUG
    memset(debugBuff, 0x00, sizeof(debugBuff));
    UnpackBCD(cCmd_info, (char *)debugBuff, nCmd_len*2);
    union_log(" In SMAPITransKeyOutofPK::[REQUEST]=[%d][%s]", nCmd_len, debugBuff);
#endif

    rst_len = UnionHSMCmd(nSock, cCmd_info, nCmd_len, rst_info, gUnionTimeout,&retCode);
    switch(rst_len)
    {
    	 case -1:
    		 union_err_log("In SMAPITransKeyOutofPK::SOCKET EDLL!");
    		 return CKR_PARAMETER_ERR;
    	 case -2:
    		 union_err_log("In SMAPITransKeyOutofPK::SOCKET SEND ERROR!");
    		 return CKR_SENDFAIL_ERR;
    	 case -3:
    		 union_err_log("In SMAPITransKeyOutofPK::SOCKET RECIVE ERROR!");
    		 return CKR_RCVTMOUT_ERR;
    	 case -4:
    		 union_err_log("In SMAPITransKeyOutofPK::SOCKET RECIVE  CKR_PARAMETER_ERR ERROR!");
    		 return CKR_PARAMETER_ERR;
    	 default:
		 break;
    }

#ifdef	_DEBUG
    memset(debugBuff, 0x00, sizeof(debugBuff));
    UnpackBCD(rst_info, (char *) debugBuff, rst_len * 2);
    union_log("In SMAPITransKeyOutofPK::[RESPOND]=[%d][%s]", rst_len, debugBuff);
#endif

    /* Get the length of the key encryted by public key */
    memset(pcLen, 0x00, sizeof(pcLen));
    memcpy(pcLen, rst_info, 4);
     // mody by chenf 20170414
    *piKeyByPKLen = atoi((char*)pcLen);
   // *piKeyByPKLen = atoi((char*)pcLen)-4;

    /* Get content of the key */
    // mody by chenf 20170414
    //memcpy(pbKeyByPK, rst_info + 4, *piKeyByPKLen);
    memcpy(pbKeyByPK, rst_info + 8, *piKeyByPKLen);
    return (0);

}

/***************************************************************************************************************/
/* 函数名称： SMAPIDisreteSubKey                                                                               */
/*           5.10 子密钥离散（7.6.15 分散卡密钥）   农行    "EG"                                                */
/* 功能说明：                                                                                                  */
/*           将应用主密钥离散为卡子密钥或者会话子密钥，用传入的KEK 加密输出                                       */
/*           （接口设计参见附录四）                                                                             */
/* 输入参数：                                                                                                  */
/*	    UINT nSock：       连接的socket 句柄                                                               */
/*	    int nDivNum：      离散的次数，取值范围{1, 2}                                                       */
/*			       当nDivNum =1 时，离散为卡密钥                                                    */
/*			       当nDivNum =2 时，离散为会话密钥                                                  */
/*	    int iccType：      IC 卡类型，具体格式参见附录二，对应的算法参见附录三。                              */
/*                              '0'-pboc   '1'-visa   '2'-mastercard  '3'-pboc-sm4                                         */ 
/*	    int nAlgo：        KEK 加密的算法类型，取值范围{1,2,3}                                              */ 
/*			       当nAlgo = 1 时，用KEK 单DES 加密子密钥，此时pbKek 为8 字节长。                    */ 
/*			       当nAlgo = 2 时，用KEK 双DES 加密子密钥，此时pbKek 为16 字节长。                   */ 
/*			       当nAlgo = 3 时，用KEK 三DES 加密子密钥，此时pbKek 为24 字节长。                   */
/*	    byte *pbKek：      加密子密钥的KEK(被HMK 加密)，长度由nAlgo 决定                                    */
/*	    byte *pbMasterKey：被离散的应用主密钥，可以为应用密文主密钥、安全报文加                              */
/*			       密主密钥和安全报文认证主密钥(被HMK 加密)，二进制数，16 字节长。                   */
/*	    byte *pbCardFactor：   卡密钥分散因子，                                                            */
/*		                   iccType=0 时，长度为8 字节，由卡号+卡序号经过PBOC 规则产生的8 字节二进制数。  */ 
/*		                   iccType!=0 时，由上层接口拼接好的卡片密钥离散因子，长度为16 字节              */
/*	    byte *pbSessionFactor：会话密钥分散因子，当nDivNum=1 时，该参数不参与运算，设为null。                */
/*		                   iccType=0 时，为交易序列号(ATC), 二进制数，2 字节长                          */
/*				   iccType!=0 时，由上层接口拼接好的会话密钥离散因子，长度为16 字节。            */ 
/* 输出参数：                                                                                                  */
/*	    byte *pbSubKey：       离散的子密钥的密文(被KEK 加密)，二进制数，16 字节长，                         */
/*		                   当nDivNum =1，为卡子密钥；当nDivNum =2，为会话子密钥                         */
/*  	    char pszCheckValue[8]: 产生子密钥的效验值，是将CheckValue 的前四个字节进行                          */
/*		                   扩展，得到的8 个十六进制字符                                                */   
/* 返回说明：                                                                                                 */
/*	    0： 执行成功                                                                                      */ 
/*	    1： 输入参数验证失败                                                                              */ 
/*	    2： 无效的密钥(MasterKey)                                                                         */
/*	    3： 向加密机发送数据失败                                                                           */
/*	    4： 接收加密机数据超时                                                                             */  
/*	    5： 接收到的数据格式错                                                                             */ 
/*	    9:  其他错误                                                                                      */
/* 维护记录：                                                                                                 */
/*          2017-03-07 by zhaomx                                                                              */
/*          2017-04-20                                                                                        */    
/**************************************************************************************************************/ 
int SMAPIDisreteSubKey(UINT nSock, int nDivNum,int iccType, int nAlgo, byte * pbKek, 
	               byte * pbMasterKey, byte * pbCardFactor, byte * pbSessionFactor, 
	               byte * pbSubKey, char pszCheckValue[8 + 1])
{

    char     cCmd_info[40960 + 1];
    char     rst_info[40960 + 1];
    char     tmpBuf[40960 + 1];
    char     *pcmd_info = NULL;
    int      retCode=0;
    int      nCmd_len;
    int      rst_len;
    int      iKeyLen = 0;
    int      n = 0;

    if (UnionIsSocket(nSock)<1)
    {
	union_err_log("In SMAPIDisreteSubKey nSock error, [nSock=%u]", nSock);
	return(CKR_SENDFAIL_ERR);
    }

    if ((1 != nDivNum) && (2 != nDivNum)) {
	union_err_log("In SMAPIDisreteSubKey nDivNum error, [nDivNum=%d]", nDivNum);
        return(CKR_PARAMETER_ERR);
    }

    if ((0 != (iccType >> 16)) && (1 != (iccType >> 16)) && (2 != (iccType >> 16))) {
	union_err_log("In SMAPIDisreteSubKey iccType error, [iccType=%d]", iccType >> 16);
        return(CKR_PARAMETER_ERR);
    }
    
    if ((nAlgo < 1) || (nAlgo > 3)) {
        union_err_log("In SMAPIDisreteSubKey nAlgo error, [nAlgo=%d]", nAlgo);
        return(CKR_PARAMETER_ERR);
    }

    if (NULL == pbKek) {
        union_err_log("In SMAPIDisreteSubKey [pbKek is NULL]");
        return(CKR_PARAMETER_ERR);
    }

    if (NULL == pbMasterKey) {
        union_err_log("In SMAPIDisreteSubKey [pbMasterKey is NULL]");
        return(CKR_PARAMETER_ERR);
    }

    if (NULL == pbCardFactor) {
        union_err_log("In SMAPIDisreteSubKey [pbCardFactor is NULL]");
        return(CKR_PARAMETER_ERR);
    }

    if (NULL == pbSessionFactor) {
        union_err_log("In SMAPIDisreteSubKey [pbSessionFactor is NULL]");
        return(CKR_PARAMETER_ERR);
    }     
		
#ifdef	_DEBUG
    unsigned char debugBuff[40960];
    memset(debugBuff, 0x00, sizeof(debugBuff));
#endif

    memset(cCmd_info, 0x00, sizeof(cCmd_info));
    memset(rst_info, 0x00, sizeof(rst_info));
    memset(tmpBuf, 0x00, sizeof(tmpBuf));
    nCmd_len = 0;
    rst_len = 0;
    pcmd_info = NULL;

    /* command */
    pcmd_info = cCmd_info;
    memcpy(pcmd_info, "EG", 2);
    pcmd_info += 2;

    //子密钥类型 1时: 离散为卡密钥  2时: 离散为会话密钥 
    sprintf(pcmd_info,"%d",nDivNum);
    pcmd_info++;

    //IC卡类型   固定写死   2017-04-25
    if((iccType >> 16) == 0)
    {
    //    iccType = 2;
        sprintf(pcmd_info, "%04X", 2);
    }
    else if((iccType >> 16) == 1)
    {
    //    iccType = 0;
        sprintf(pcmd_info, "%04X", 0);
    }
    else if((iccType >> 16) == 2)
    {
    //    iccType = 1;
        sprintf(pcmd_info, "%04X", 1);
    }
    else if ((iccType == 1025) || (iccType == 1047))
    {
    //    iccType = 3;
        sprintf(pcmd_info, "%04X", 3);
    }
    //sprintf(pcmd_info,"%04X",iccType);
    pcmd_info += 4;

    //根密钥分散次数
    sprintf(pcmd_info,"%d",1);
    pcmd_info++;

    //保护密钥 
    memset(tmpBuf, 0x00, sizeof(tmpBuf));
    switch(nAlgo)
    {   
        //8 字节长
	case 1:
 	      UnpackBCD((char*)pbKek, tmpBuf, 16); 
              memcpy(pcmd_info, (char*)tmpBuf, 16);
	      pcmd_info += 16;
	      break;
	//16 字节长
        case 2:
              if((iccType == 1025) || (iccType == 1047))
              {
                  memcpy(pcmd_info,"S",1);
              }
	      else
              {
                  memcpy(pcmd_info,"X",1); 
              }
	      pcmd_info+=1;
	      UnpackBCD((char*)pbKek, tmpBuf, 32); 
              memcpy(pcmd_info, (char*)tmpBuf, 32);
	      pcmd_info += 32;
	      break;
        //24 字节长  
	case 3:
	      memcpy(pcmd_info,"Y",1);
	      pcmd_info+=1;
	      UnpackBCD((char*)pbKek, tmpBuf, 48); 
              memcpy(pcmd_info, (char*)tmpBuf, 48);
	      pcmd_info += 48;
	      break;
	default:
	      union_err_log("In SMAPIDisreteSubKey:: parameter error! [nAlgo] = [%d] ", nAlgo);
	      return CKR_PARAMETER_ERR;
	      break;
    }

    /* 根密钥 */
    memcpy(pcmd_info, (char*)pbMasterKey, 16);
    pcmd_info += 16;

     /*分散因子*/
    if((iccType == 1025) || (iccType == 1047))      //pboc SM4 16
    { 
	memcpy(pcmd_info,(char*)pbCardFactor,16);
	pcmd_info += 16;
    }
    else
    {
	memcpy(pcmd_info,(char*)pbCardFactor,8);
	pcmd_info += 8;
    }
	
    /*过程密钥计算 */
    if(nDivNum == 1 || (iccType >> 16) == 1)   //visa 子密钥类型为1时
    {

    }
    else if(iccType == 0)         //pboc-des
    {
    	memset(tmpBuf, 0x00, sizeof(tmpBuf));
	memcpy(pcmd_info,(char*)pbSessionFactor,2);
	pcmd_info+=2;
    }
    else 
    {
    	memset(tmpBuf, 0x00, sizeof(tmpBuf));
	memcpy(pcmd_info,(char*)pbSessionFactor,16);
	pcmd_info+=16;
    }

    /* set the last char '\0' */
    *pcmd_info = 0;

    /* calculate the length of requst package */
    nCmd_len = pcmd_info - cCmd_info;

#ifdef	_DEBUG
    memset(debugBuff, 0x00, sizeof(debugBuff));
    UnpackBCD(cCmd_info, (char *) debugBuff, nCmd_len*2);
    union_log("In SMAPIDisreteSubKey::[REQUEST]=[%d] pack=[%s] unpack=[%s]", nCmd_len,cCmd_info, debugBuff);
#endif

    rst_len = UnionHSMCmd(nSock, cCmd_info, nCmd_len, rst_info, gUnionTimeout,&retCode);
    /*add by chenf for select socket error*/
    switch(rst_len)
    {
    	 case -1:
    		 union_err_log("In SMAPIDisreteSubKey::SOCKET EDLL!");
    		 return CKR_PARAMETER_ERR;
    	 case -2:
    		 union_err_log("In SMAPIDisreteSubKey::SOCKET SEND ERROR!");
    		 return CKR_SENDFAIL_ERR;
    	 case -3:
    		 union_err_log("In SMAPIDisreteSubKey::SOCKET RECIVE ERROR!");
    		 return CKR_RCVTMOUT_ERR;
    	 case -4:
    		 union_err_log("In SMAPIDisreteSubKey::SOCKET RECIVE CKR_PARAMETER_ERR ERROR!");
    		 return CKR_PARAMETER_ERR;
    	 default:
    	 	 break;
    	}

#ifdef	_DEBUG
    memset(debugBuff, 0x00, sizeof(debugBuff));
    UnpackBCD(rst_info, (char *) debugBuff, rst_len * 2);
    union_log("In SMAPIDisreteSubKey::[RESPOND]=[%d][%s][%s]", 	rst_len, debugBuff,rst_info);
#endif

    /* Get the sub key */
    iKeyLen = rst_len-20;
    memset(tmpBuf, 0x00, sizeof(tmpBuf));
    memcpy(pbSubKey, rst_info, 16);

    /* Get the key checkValue */
    memset(tmpBuf, 0x00, sizeof(tmpBuf));
    memcpy(tmpBuf, rst_info + 16, 8);
    memcpy(pszCheckValue,tmpBuf,8);
    return (0);
}

/***************************************************************************************************************/
/* 函数名称： SMAPIVerifyARQC                                                                                  */
/*           5.11 ARQC 验证（7.3.2 ARQC/ARPC 产生或验证）  农行    "VM"                                         */
/* 功能说明：                                                                                                  */
/*           验证ARQC （接口设计参见附录四）                                                                    */
/* 输入参数：                                                                                                  */
/*	     UINT nSock：           连接的socket 句柄                                                          */
/*	     int iccType：          IC 卡类型，具体格式参见附录二，对应的算法参见附录三。                        */
/*	     byte *pbKey：          应用密文主密钥，二进制数，16 字节长                                         */
/*	     byte *pbCardFactor：   卡密钥分散因子                                                             */
/*		   		    iccType=0 时，由有卡号+卡序号经过PBOC 规则产生的8字节二进制数。              */  
/*				    iccType!=0 时，长度为16 字节。                                             */
/*	     byte *pbSessionFactor：会话密钥分散因子                                                           */
/*		                    iccType=0 时，为交易序列号(ATC), 二进制数2字节长                            */
/*				    iccType!=0 时，长度为16 字节。如果值为NULL，表示只进行                      */ 
/*				    一次密钥离散（即使用卡片密钥而非会话密钥对数据进行MAC 计算）                 */ 
/*	     byte *pbData：         用于计算ARQC 的数据，二进制数，长度由nDataLen 指定。                        */
/*	     int nDataLen：         pbData 的长度, 取值范围[1, 1024]                                           */
/*	     byte *pbARQC：         待验证的ARQC 值，二进制数，8 字节长                                         */
/* 输出参数：                                                                                                  */
/*	     无                                                                                                */
/* 返回说明：                                                                                                  */
/*	     0： 验证成功                                                                                      */
/*	     1： 输入参数验证失败                                                                              */ 
/*	     2： 无效的密钥(Key)                                                                               */
/*	     3： 向加密机发送数据失败                                                                           */
/*	     4： 接收加密机数据超时                                                                             */
/*	     5： 接收到的数据格式错                                                                             */
/*	     9:  其他错误                                                                                      */
/*	    10:  匹配失败                                                                                      */
/* 维护记录：                                                                                                  */
/*          2017-03-07 by zhaomx                                                                               */
/****************************************************************************************************************/ 
int SMAPIVerifyARQC(UINT nSock, int iccType, byte * pbKey, byte * pbCardFactor, 
	            byte * pbSessionFactor, byte * pbData, int nDataLen, byte * pbARQC)
{

    int   retCode=0;
    char  cmd_info[40960 + 1];
    char  rst_info[40960 + 1];
    char  tmpBuf[1024 + 1];
    char  pbKeyUnpackBCD[148+1];
    int   nCmd_len;
    int   rst_len;
    char  *pcmd_info = NULL;

    if (UnionIsSocket(nSock)<1)
    {
	union_err_log("In SMAPIVerifyARQC nSock error, [nSock=%u]", nSock);
	return(CKR_PARAMETER_ERR);
    }

    if ((0 != (iccType >> 16)) && (1 != (iccType >> 16)) && (2 != (iccType >> 16))) {
	union_err_log("In SMAPIVerifyARQC iccType error, [iccType=%d]", iccType);
        return(CKR_PARAMETER_ERR);
    }
   
    if (NULL == pbKey) {
        union_err_log("In SMAPIVerifyARQC [pbKey is NULL]");
        return(CKR_PARAMETER_ERR);
    }

    if (NULL == pbCardFactor) {
        union_err_log("In SMAPIVerifyARQC [pbCardFactor is NULL]");
        return(CKR_PARAMETER_ERR);
    }

    if (NULL == pbSessionFactor) {
        union_err_log("In SMAPIVerifyARQC [pbSessionFactor is NULL]");
        return(CKR_PARAMETER_ERR);
    }
    
    if (NULL == pbData) {
        union_err_log("In SMAPIVerifyARQC [pbData is NULL]");
        return(CKR_PARAMETER_ERR);
    }    

    if ((nDataLen < 1) || (nDataLen > 1024)) {
        union_err_log("In SMAPIVerifyARQC [nDataLen=%d]", nDataLen);
        return(CKR_PARAMETER_ERR);
    }

    if (NULL == pbARQC){
        union_err_log("In SMAPIVerifyARQC [pbARQC is NULL]");
        return(CKR_PARAMETER_ERR);
    }      
 
#ifdef	_DEBUG
    unsigned char debugBuff[40960];
    memset(debugBuff, 0x00, sizeof(debugBuff));
#endif

    memset(cmd_info, 0x00, sizeof(cmd_info));
    memset(rst_info, 0x00, sizeof(rst_info));
    memset(tmpBuf, 0x00, sizeof(tmpBuf));
    nCmd_len = 0;
    rst_len = 0;
    pcmd_info = NULL;

    /* command */
    pcmd_info = cmd_info;
    memcpy(pcmd_info, "VM", 2);
    pcmd_info += 2;

    //算法类型   "1"-SM4   "2"-SM1   "3"-3DES   "4"-AES
    if((iccType == 1025) || (iccType == 1047))
    {
    	memcpy(pcmd_info, "1", 1);
    	pcmd_info++;
    }
    else
    {
    	memcpy(pcmd_info, "3", 1);
    	pcmd_info++;
    }

    //IC卡类型   ‘0’-  PBOC  ‘1’Visa  ‘2’  MasterCard 
    //sprintf(pcmd_info, "%01d", iccType);
    //IC卡类型   固定写死   2017-04-17
    if((iccType >> 16) == 0)
    {
        sprintf(pcmd_info, "%d", 2);
    }
    else if((iccType >> 16) == 1)
    {
        sprintf(pcmd_info, "%d", 0);
    }
    else if((iccType >> 16) == 2)
    {
        sprintf(pcmd_info, "%d", 1);
    }
    pcmd_info++;
	
    /* 模式标志  '0'-只验证ARQC    */
    memcpy(pcmd_info, "0", 1);
    pcmd_info++;

    //密钥类型、密钥tag   zhaomx-0228
    //memcpy(pcmd_info, "00A", 3);
    //pcmd_info += 3;

    /* MK-AC  密钥 HMK加密 */
    if((iccType == 1025) || (iccType == 1047))
    {
	memcpy(pcmd_info,"S",1);
	pcmd_info+=1;
    }
    else
    {
	memcpy(pcmd_info,"X",1);
	pcmd_info+=1;
    }

    memset(pbKeyUnpackBCD, 0x00, sizeof(pbKeyUnpackBCD));
    UnpackBCD((char*)pbKey, pbKeyUnpackBCD, 32);
    memcpy(pcmd_info, pbKeyUnpackBCD, 32);
    printf("key=[%s]\n",pbKeyUnpackBCD);
    pcmd_info += 32;

    /* PAN/PAN序列号  卡密钥分散因子*/
    if((iccType == 1025) || (iccType == 1047))   //pboc-SM4
    {
	
	memset(pbKeyUnpackBCD, 0x00, sizeof(pbKeyUnpackBCD));
	UnpackBCD((char*)pbCardFactor, pbKeyUnpackBCD, 32);
        memcpy(pcmd_info, pbKeyUnpackBCD, 32);
	pcmd_info += 32;
    }
    else
    {

	memset(pbKeyUnpackBCD, 0x00, sizeof(pbKeyUnpackBCD));
	UnpackBCD((char*)pbCardFactor, pbKeyUnpackBCD, 16);
	memcpy(pcmd_info, pbKeyUnpackBCD, 16);
	pcmd_info += 16;
    }

    /* ATC 长度固定为2字节 */
    if(iccType == 0)         //pboc-3des    
    {
        memset(pbKeyUnpackBCD, 0x00, sizeof(pbKeyUnpackBCD));
 	UnpackBCD((char*)pbSessionFactor, pbKeyUnpackBCD, 4);
    	memcpy(pcmd_info, pbKeyUnpackBCD, 4);
    	pcmd_info += 4;
    }
    else if((iccType >> 16) == 1)      //visa
    {

    }
    else
    {
        memset(pbKeyUnpackBCD, 0x00, sizeof(pbKeyUnpackBCD));
 	UnpackBCD((char*)pbSessionFactor, pbKeyUnpackBCD, 32);
    	memcpy(pcmd_info, pbKeyUnpackBCD, 32);
    	pcmd_info += 32;
    }  

    /* ARQC/TC/AAC */
    memset(pbKeyUnpackBCD, 0x00, sizeof(pbKeyUnpackBCD));
    UnpackBCD((char*)pbARQC, pbKeyUnpackBCD, 16);
    memcpy(pcmd_info, pbKeyUnpackBCD, 16);
    pcmd_info += 16;

    /* 交易数据长度  */
    sprintf(pcmd_info, "%04d", nDataLen);
    pcmd_info += 4;

    /* 交易数据 */
    memcpy(pcmd_info, pbData, nDataLen);
    pcmd_info += nDataLen;
	
    /* set the last char '\0' */
    *pcmd_info = 0;

    /* calculate the length of requst package */
    nCmd_len = pcmd_info - cmd_info;

#ifdef _DEBUG
    memset(debugBuff, 0x00, sizeof(debugBuff));
    UnpackBCD(cmd_info, (char *) debugBuff, nCmd_len * 2);
    union_log(" In SMAPIVerifyARQC::nCmd_len[%d][REQUEST]=[%s]", nCmd_len, debugBuff);
#endif
    
    rst_len = UnionHSMCmd(nSock, cmd_info, nCmd_len, rst_info, gUnionTimeout, &retCode);
	
    switch(rst_len)
    {
    	 case -1:
    		 union_err_log("In SMAPIVerifyARQC::SOCKET EDLL!");
    		 return CKR_SENDFAIL_ERR;
    	 case -2:
    		 union_err_log("In SMAPIVerifyARQC::SOCKET SEND ERROR!");
    		 return CKR_SENDFAIL_ERR;
    	 case -3:
    		 union_err_log("In SMAPIVerifyARQC::SOCKET RECIVE ERROR!");
    		 return CKR_RCVTMOUT_ERR;
    	 case -4:
    		 union_err_log("In SMAPIVerifyARQC::SOCKET RECIVE CKR_PARAMETER_ERR ERROR!");
    		 return CKR_PARAMETER_ERR;
    	 default:
    	 	 break;
    	}

#ifdef	_DEBUG
    memset(debugBuff, 0x00, sizeof(debugBuff));
    UnpackBCD(rst_info, (char *)debugBuff, rst_len*2);
    union_log("In SMAPIVerifyARQC::rst_len=[%d][RESPOND]=[%s]", rst_len, debugBuff);
#endif

    return (0);

}

/***************************************************************************************************************/
/* 函数名称： SMAPICalcARPC                                                                                    */
/*           5.12 ARPC 计算（7.3.2 ARQC/ARPC 产生或验证）  农行    "VM"                                         */
/* 功能说明：                                                                                                  */
/*	     计算ARPC （接口设计参见附录四）                                                                    */
/* 输入参数：                                                                                                  */ 
/*	     UINT nSock：           连接的socket 句柄                                                          */
/*	     int iccType：          IC 卡类型，具体格式参见附录二，对应的算法参见附录三。                        */
/*	     byte *pbKey：          应用密文主密钥，二进制数，16 字节长，                                       */
/*	     byte *pbCardFactor：   卡密钥分散因子                                                             */ 
/*		                    iccType=0 时，由有卡号+卡序号经过PBOC 规则产生的8 字节二进制数。             */
/*		                    iccType!=0 时，长度为16 字节。                                             */ 
/*	     byte *pbSessionFactor：会话密钥分散因子                                                           */
/*		                    iccType=0 时，为交易序列号(ATC), 二进制数，2 字节长                         */
/*				    iccType!=0 时，长度为16 字节。如果值为NULL，表示只进行                      */
/*				    一次密钥离散（即使用卡片密钥而非会话密钥对数据进行MAC 计算）                 */ 
/*	     byte *pbARQC：         计算ARPC 所需数据                                                          */
/*	                            iccType=0 时，输入的数据为ARQC，8 字节长。                                  */
/*			            iccType!=0 时，输入的数据为计算ARPC 所需的数据块，数据块长度根据卡片类型      */
/*                                   中的算法类型值而定。                                                      */  
/*	     byte *pbARC：          授权响应码，二进制数，2 字节长                                              */
/* 输出参数：                                                                                                  */ 
/*	     byte *pbARPC：         生成的ARPC 值，二进制数，8 字节长                                           */
/* 返回说明：                                                                                                  */
/*	     0： 执行成功                                                                                      */
/*	     1： 输入参数验证失败                                                                              */
/*	     2： 无效的密钥(Key)                                                                               */
/*	     3： 向加密机发送数据失败                                                                          */
/*	     4： 接收加密机数据超时                                                                            */
/*	     5： 接收到的数据格式错                                                                            */
/*	     9:  其他错误                                                                                      */
/* 维护记录：                                                                                                  */
/*          2017-03-07 by zhaomx                                                                               */
/****************************************************************************************************************/ 

int  SMAPICalcARPC(UINT nSock, int iccType, byte * pbKey, byte * pbCardFactor, 
	           byte * pbSessionFactor, byte * pbARQC, byte * pbARC, 
	           byte * pbARPC)
{

    int      retCode=0;
    char     cmd_info[40960 + 1];
    char     rst_info[40960 + 1];
    char     tmpBuf[40960 + 1];
    char     pbKeyUnpackBCD[128];

    int   nCmd_len;
    int   rst_len;
    char  *pcmd_info = NULL;

    unsigned char pubKeyDer[1024 + 1];
    unsigned char pcLen[4 + 1];
    unsigned char pubExp[] = {0x01, 0x00, 0x01};
    int pubExpLen = 3;

    if (UnionIsSocket(nSock)<1)
    {
	union_err_log("In SMAPICalcARPC nSock error, [nSock=%u]", nSock);
	return(CKR_SENDFAIL_ERR);
    }

    if ((0 != (iccType >> 16)) && (1 != (iccType >> 16)) && (2 != (iccType >> 16))) {
	union_err_log("In SMAPIVerifyARQC iccType error, [iccType=%d]", iccType);
        return(CKR_PARAMETER_ERR);
    }
    
    if (NULL == pbKey) {
        union_err_log("In SMAPICalcARPC [pbKey is NULL]");
        return(CKR_PARAMETER_ERR);
    }

    if (NULL == pbCardFactor) {
        union_err_log("In SMAPICalcARPC [pbCardFactor is NULL]");
        return(CKR_PARAMETER_ERR);
    }

    if (NULL == pbSessionFactor) {
        union_err_log("In SMAPICalcARPC [pbSessionFactor is NULL]");
        return(CKR_PARAMETER_ERR);
    }
    
    if (NULL == pbARQC) {
        union_err_log("In SMAPICalcARPC [pbARQC is NULL]");
        return(CKR_PARAMETER_ERR);
    }    

    if (NULL == pbARC) {
        union_err_log("In SMAPICalcARPC [pbARC is NULL]");
        return(CKR_PARAMETER_ERR);
    }

#ifdef	_DEBUG
    unsigned char   debugBuff[40960];
    memset(debugBuff, 0x00, sizeof(debugBuff));
#endif

    memset(cmd_info, 0x00, sizeof(cmd_info));
    memset(rst_info, 0x00, sizeof(rst_info));
    memset(pcLen, 0x00, sizeof(pcLen));
    memset(pubKeyDer, 0x00, sizeof(pubKeyDer));
    memset(pbKeyUnpackBCD, 0x00, sizeof(pbKeyUnpackBCD));

    nCmd_len = 0;
    rst_len = 0;
    pcmd_info = NULL;

    /* command */
    pcmd_info = cmd_info;
    memcpy(pcmd_info, "VM", 2);
    pcmd_info += 2;

    /* 算法类型   "1"-SM4   "2"-SM1   "3"-3DES   "4"-AES*/
    if((iccType == 1025) || (iccType == 1047))
    {
    	memcpy(pcmd_info, "1", 1);
    	pcmd_info++;
    }
    else
    {
    	memcpy(pcmd_info, "3", 1);
    	pcmd_info++;
    }

    //IC卡类型   固定写死   2017-04-17
    if((iccType >> 16) == 0)
    {
        sprintf(pcmd_info, "%d", 2);
    }
    else if((iccType >> 16) == 1)
    {
        sprintf(pcmd_info, "%d", 0);
    }
    else if((iccType >> 16) == 2)
    {
        sprintf(pcmd_info, "%d", 1);
    }
    pcmd_info++;

    /* 模式标志 ’2’-只产生 ARPC   */
    memcpy(pcmd_info, "2", 1);
    pcmd_info++; 

    /* MK-AC  密钥 HMK加密 */
    if((iccType == 1025) || (iccType == 1047))
    {
	memcpy(pcmd_info,"S",1);
	pcmd_info+=1;
    }
    else
    {
	memcpy(pcmd_info,"X",1);
	pcmd_info+=1;
    }

    memset(pbKeyUnpackBCD, 0x00, sizeof(pbKeyUnpackBCD));
    UnpackBCD((char*)pbKey, pbKeyUnpackBCD, 32);
    memcpy(pcmd_info, pbKeyUnpackBCD, 32);
    printf("key=[%s]\n",pbKeyUnpackBCD);
    pcmd_info += 32;

    /* PAN/PAN序列号  卡密钥分散因子*/
    if((iccType == 1025) || (iccType == 1047))
    {
	
	memset(pbKeyUnpackBCD, 0x00, sizeof(pbKeyUnpackBCD));
	UnpackBCD((char*)pbCardFactor, pbKeyUnpackBCD, 32);
        memcpy(pcmd_info, pbKeyUnpackBCD, 32);
	pcmd_info += 32;
    }
    else
    {

	memset(pbKeyUnpackBCD, 0x00, sizeof(pbKeyUnpackBCD));
	UnpackBCD((char*)pbCardFactor, pbKeyUnpackBCD, 16);
	memcpy(pcmd_info, pbKeyUnpackBCD, 16);
	pcmd_info += 16;
    }

    /* ATC 长度固定为2字节 */
    if(iccType == 0)               //PBOC-3DES      
    {
        memset(pbKeyUnpackBCD, 0x00, sizeof(pbKeyUnpackBCD));
 	UnpackBCD((char*)pbSessionFactor, pbKeyUnpackBCD, 4);
    	memcpy(pcmd_info, pbKeyUnpackBCD, 4);
    	pcmd_info += 4;
    }
    else if((iccType >> 16) == 1)      //visa
    {

    }
    else
    {
        memset(pbKeyUnpackBCD, 0x00, sizeof(pbKeyUnpackBCD));
 	UnpackBCD((char*)pbSessionFactor, pbKeyUnpackBCD, 32);
    	memcpy(pcmd_info, pbKeyUnpackBCD, 32);
    	pcmd_info += 32;
    }  

    /* ARQC/TC/AAC */
    memset(pbKeyUnpackBCD, 0x00, sizeof(pbKeyUnpackBCD));
    UnpackBCD((char*)pbARQC, pbKeyUnpackBCD, 16);
    memcpy(pcmd_info, pbKeyUnpackBCD, 16);
    pcmd_info += 16;

    /* ARC */
    //20170421  
    memset(pbKeyUnpackBCD, 0x00, sizeof(pbKeyUnpackBCD));
    UnpackBCD((char*)pbARC,pbKeyUnpackBCD , 4);
    memcpy(pcmd_info,pbKeyUnpackBCD , 4);
    pcmd_info += 4; 
    /* 
    if(iccType == 0)      //PBOC-3DES
    {
        memset(pbKeyUnpackBCD, 0x00, sizeof(pbKeyUnpackBCD));
 	UnpackBCD((char*)pbARC,pbKeyUnpackBCD , 4);
    	memcpy(pcmd_info,pbKeyUnpackBCD , 4);
    	pcmd_info += 4;
    }
   
    else
    {
        memset(pbKeyUnpackBCD, 0x00, sizeof(pbKeyUnpackBCD));
 	UnpackBCD((char*)pbARC,pbKeyUnpackBCD , 32);
    	memcpy(pcmd_info,pbKeyUnpackBCD , 32);
    	pcmd_info += 32;

    }*/

    /* set the last char '\0' */
    *pcmd_info = 0;

    /* calculate the length of requst package */
    nCmd_len = pcmd_info - cmd_info;

#ifdef	_DEBUG
    memset(debugBuff, 0x00, sizeof(debugBuff));
    UnpackBCD(cmd_info, (char *) debugBuff, nCmd_len * 2);
    union_log(" In SMAPICalcARPC::[REQUEST]=[%d][%s] ", nCmd_len, debugBuff);
#endif
 
    rst_len = UnionHSMCmd(nSock, cmd_info, nCmd_len, rst_info, gUnionTimeout,&retCode);
    switch(rst_len)
    {
    	 case -1:
	    	 union_err_log("In SMAPICalcARPC::SOCKET EDLL!");
	    	 return CKR_PARAMETER_ERR;
    	 case -2:
	    	 union_err_log("In SMAPICalcARPC::SOCKET SEND ERROR!");
	    	 return CKR_SENDFAIL_ERR;
    	 case -3:
	    	 union_err_log("In SMAPICalcARPC::SOCKET RECIVE ERROR!");
	    	 return CKR_RCVTMOUT_ERR;
    	case -4:
	    	 union_err_log("In SMAPICalcARPC::SOCKET RECIVE ERROR CKR_PARAMETER_ERR!");
	    	 return CKR_PARAMETER_ERR;
    	 default:
		 break;
    }
#ifdef	_DEBUG
    memset(debugBuff, 0x00, sizeof(debugBuff));
    UnpackBCD(rst_info, (char *) debugBuff, rst_len * 2);
    union_log("In SMAPICalcARPC::[RESPOND]=[%d][%s]", rst_len, debugBuff);
#endif

    /* Get pbARPC */
    memset(tmpBuf, 0x00, sizeof(tmpBuf));
    memcpy(tmpBuf, rst_info, 16);
    PackBCD(tmpBuf,pbARPC, 32);

    return (0);

}

/*********************************************************************************************************************/
/* 函数名称： SMAPIEncryptWithDerivedKey                                                                              */
/*           5.13 脚本加解密（7.3.3 脚本加解密）  农行    "VI"                                                         */
/* 功能说明：                                                                                                         */
/*           加解密发卡行脚本数据及其它密秘数据（接口设计参见附录四）                                                    */  
/* 输入参数：                                                                                                         */
/*	     UINT nSock：           连接的socket 句柄                                                                 */
/*	     int nType：            1—加密； 0—解密                                                                   */
/*	     int iccType：          IC 卡类型，具体格式参见附录二，对应的算法参见附录三。                               */
/*                                  0-pboc   1-visa   2-mastercard                                                   */
/*	     int nMode：            加密模式， nMode = 0，ECB 模式			nMode =1，CBC 模式           */
/*	     byte *pbKey：          安全报文加密主密钥，二进制数，16 字节长                                            */ 
/*	     byte *pbCardFactor：   卡密钥分散因子                                                                    */
/*		 		    iccType=0 时，由有卡号+卡序号经过PBOC 规则产生的8 字节二进制数。                    */
/*				    iccType!=0 时，长度为16 字节。                                                    */
/*	     byte *pbSessionFactor：会话密钥分散因子                                                                  */
/*		 	            iccType=0 时，为交易序列号(ATC), 二进制数，2 字节长                                */
/*				    iccType!=0 时，长度为16 字节。如果值为NULL，表示只进行                             */
/*				    一次密钥离散（即使用卡片密钥而非会话密钥对数据进行MAC 计算）                        */
/*	     byte *pbIV：           当nMode = 0 时，为NULL，当nMode = 1 时， 为CBC 模式的初始化向量，二进制数，8字节长，*/
/*	     byte *pbInData：       需要加密的明文数据，二进制数，长度由nInLen 指定                                    */
/*	     int nInLen：           pbInData 的长度,取值范围[8, 128]                                                  */
/* 输出参数：                                                                                                         */
/*	     byte *pbOutData：      加密之后的密文数据，二进制数，长度由pnOutLen 指定                                  */
/*	     int *pnOutLen：        pbOutData 的长度，应等于pbInData                                                  */ 
/* 返回说明：                                                                                                         */
/*	     0： 执行成功                                                                                            */
/*	     1： 输入参数验证失败                                                                                    */
/*	     2： 无效的密钥(Key)                                                                                     */
/*	     3： 向加密机发送数据失败                                                                                 */
/*	     4： 接收加密机数据超时                                                                                   */
/*	     5： 接收到的数据格式错                                                                                   */ 
/*	     9:  其他错误                                                                                            */
/* 维护记录：                                                                                                        */
/*          2017-03-07 by zhaomx                                                                                    */
/********************************************************************************************************************/ 

int SMAPIEncryptWithDerivedKey(UINT nSock, int nType, int iccType, int nMode, byte * pbKey, byte * pbCardFactor, 
	                       byte * pbSessionFactor, byte * pbIV, byte * pbInData, int nInLen, 
			       byte * pbOutData, int *pnOutLen)
{

    int   retCode = 0;
    char  cmd_info[40960 + 1];
    char  rst_info[40960 + 1];
    char  tmpBuf[1024 + 1];
    int   nCmd_len = 0;
    int   rst_len = 0;
    char  *pcmd_info = NULL;

    if (UnionIsSocket(nSock)<1)
    {
	union_err_log("In SMAPIEncryptWithDerivedKey nSock error, [nSock=%u]", nSock);
	return(CKR_SENDFAIL_ERR);
    }

    if ((0 != nType) && (1 != nType)) {
	union_err_log("In SMAPIEncryptWithDerivedKey nType error, [nType=%d]", nType);
        return(CKR_PARAMETER_ERR);
    }
    
    if ((0 != (iccType >> 16)) && (1 != (iccType >> 16)) && (2 != (iccType >> 16))) {
	union_err_log("In SMAPIEncryptWithDerivedKey iccType error, [iccType=%d]", iccType);
        return(CKR_PARAMETER_ERR);
    }
    
    if ((0 != nMode) && (1 != nMode)) {
	union_err_log("In SMAPIEncryptWithDerivedKey nMode error, [nMode=%d]", nMode);
        return(CKR_PARAMETER_ERR);
    }
      
    if (NULL == pbKey) {
        union_err_log("In SMAPIEncryptWithDerivedKey [pbKey is NULL]");
        return(CKR_PARAMETER_ERR);
    }

    if (NULL == pbCardFactor) {
        union_err_log("In SMAPIEncryptWithDerivedKey [pbCardFactor is NULL]");
        return(CKR_PARAMETER_ERR);
    }

    if (NULL == pbSessionFactor) {
        union_err_log("In SMAPIEncryptWithDerivedKey [pbSessionFactor is NULL]");
        return(CKR_PARAMETER_ERR);
    }

    if (1 == nMode) {
        if (NULL == pbIV) {
            union_err_log("In SMAPIEncryptWithDerivedKey [pbIV is NULL]");
            return(CKR_PARAMETER_ERR);
        }
    }    

    if (NULL == pbInData) {
        union_err_log("In SMAPIEncryptWithDerivedKey [pbInData is NULL]");
        return(CKR_PARAMETER_ERR);
    }

    if ((nInLen < 8) || (nInLen > 128)) {
	union_err_log("In SMAPIEncryptWithDerivedKey pbInData error, [pbInData=%d]", pbInData);
        return(CKR_PARAMETER_ERR);
    }

#ifdef	_DEBUG
    unsigned char debugBuff[40960];
    memset(debugBuff, 0x00, sizeof(debugBuff));
#endif

    memset(cmd_info, 0x00, sizeof(cmd_info));
    memset(rst_info, 0x00, sizeof(rst_info));
    memset(tmpBuf, 0x00, sizeof(tmpBuf));
    nCmd_len = 0;
    rst_len = 0;
    pcmd_info = NULL;

    /* command */
    pcmd_info = cmd_info;
    memcpy(pcmd_info, "VI", 2);
    pcmd_info += 2;

    //算法类型   ‘1’-SM4  ‘2’-SM1 ‘3’-3DES ‘4’-AES
    if((iccType == 1025) || (iccType == 1047))   //PBOC-SM4
    {
    	memcpy(pcmd_info, "1", 1);
    	pcmd_info++;
    }
    else
    {
    	memcpy(pcmd_info, "3", 1);
    	pcmd_info++;
    }

    /*加解密标志   1—加密； 0—解密 */
    if(nType==1)
    {
	memcpy(pcmd_info,"1",1);
    }
    else
    {
	memcpy(pcmd_info,"0",1);
    }
    pcmd_info++;

    //IC卡类型   固定写死   2017-04-17
    if((iccType >> 16) == 0)    
    {
        //iccType = 2; 
        sprintf(pcmd_info, "%d", 2);
    }
    else if((iccType >> 16) == 1)
    {
        //iccType = 0;
        sprintf(pcmd_info, "%d", 0);
    }
    else if((iccType >> 16)== 2)
    {
        //iccType = 1; 
        sprintf(pcmd_info, "%d", 1);
    }

    pcmd_info++;

    //mode 加密模式  0，ECB 模式  1，CBC 模式
    if(nMode==0)
    {
	memcpy(pcmd_info,"0",1);
    }
    if(nMode==1)
    {
	memcpy(pcmd_info,"1",1);
    }
    pcmd_info+=1;

    /* 根密钥类型 */
    //memcpy(pcmd_info, "000", 3);
    //pcmd_info += 3;

    /* 根密钥 */
    if((iccType == 1025) || (iccType == 1047))   //PBOC-SM4
    {
	memcpy(pcmd_info,"S",1);
        pcmd_info+=1;
    }
    else
    {
        memcpy(pcmd_info,"X",1);
        pcmd_info+=1;
    }

    memset(tmpBuf, 0x00, sizeof(tmpBuf));
    UnpackBCD((char*)pbKey,tmpBuf,32);
    memcpy(pcmd_info, tmpBuf, 32);
    pcmd_info += 32;

    /* 卡密钥离散数据    len=16 */
    if(iccType == 0)   //pboc-3des
    {
	memset(tmpBuf, 0x00, sizeof(tmpBuf));
	UnpackBCD((char*)pbCardFactor,tmpBuf, 16);
	memcpy(pcmd_info,tmpBuf, 16);
	pcmd_info += 16;
    }
    else
    {
	memset(tmpBuf, 0x00, sizeof(tmpBuf));
	UnpackBCD((char*)pbCardFactor,tmpBuf, 32);
	memcpy(pcmd_info,tmpBuf, 32);
	pcmd_info += 32;

    }
    /* 会话密钥分散因子 */
    if(iccType == 0)    //pboc-3des
    {
        memset(tmpBuf, 0x00, sizeof(tmpBuf));
	UnpackBCD((char*)pbSessionFactor,tmpBuf, 4);
	memcpy(pcmd_info,tmpBuf, 4);
    	pcmd_info += 4;
    }
    else
    {
        memset(tmpBuf, 0x00, sizeof(tmpBuf));
	UnpackBCD((char*)pbSessionFactor,tmpBuf, 32);
    	memcpy(pcmd_info, tmpBuf, 32);
    	pcmd_info += 32;
    }
    
    /* 数据   CBC*/
    if(nMode == 1)
    {
   	if((iccType == 1025) || (iccType == 1047))   //PBOC-SM4
    	{
	    memset(tmpBuf, 0x00, sizeof(tmpBuf));
	    UnpackBCD((char*)pbIV,tmpBuf, 32);
	    memcpy(pcmd_info,tmpBuf, 32);
	    pcmd_info += 32;
	}
        else
        {
	    memset(tmpBuf, 0x00, sizeof(tmpBuf));
	    UnpackBCD((char*)pbIV,tmpBuf, 16);
	    memcpy(pcmd_info,tmpBuf, 16);
	    pcmd_info += 16;
        }
    }
    /* 数据长度 */
    if(nMode == 1)
    	sprintf(pcmd_info, "%04d", nInLen);
    else
	sprintf(pcmd_info, "%04d", nInLen);
    pcmd_info += 4;


    memset(tmpBuf, 0x00, sizeof(tmpBuf));
    memcpy(pcmd_info, pbInData, nInLen);
    pcmd_info += nInLen;

    *pcmd_info = 0;

    /* calculate the length of requst package */
    nCmd_len = pcmd_info - cmd_info;

#ifdef	_DEBUG
    memset(debugBuff, 0x00, sizeof(debugBuff));
    UnpackBCD(cmd_info, (char *) debugBuff, nCmd_len * 2);
    union_log(" In SMAPIEncryptWithDerivedKey::[REQUEST]=" \
	"[%d][%s][%s] \n ", nCmd_len,cmd_info, debugBuff);
#endif

    rst_len = UnionHSMCmd(nSock, cmd_info, nCmd_len, rst_info, gUnionTimeout,&retCode);

    switch(rst_len)
    {
    	 case -1:
    		 union_err_log("In SMAPIEncryptWithDerivedKey::SOCKET EDLL!");
    		 return CKR_PARAMETER_ERR;
    	 case -2:
    		 union_err_log("In SMAPIEncryptWithDerivedKey::SOCKET SEND ERROR!");
    		 return CKR_SENDFAIL_ERR;
    	 case -3:
    		 union_err_log("In SMAPIEncryptWithDerivedKey::SOCKET RECIVE ERROR!");
    		 return CKR_RCVTMOUT_ERR;
    	 case -4:
    		 union_err_log("In SMAPIEncryptWithDerivedKey::SOCKET RECIVE ERROR! CKR_PARAMETER_ERR");
    		 return CKR_PARAMETER_ERR;
    	 default:
		 break;
    }

#ifdef	_DEBUG
    memset(debugBuff, 0x00, sizeof(debugBuff));
    UnpackBCD(rst_info, (char *) debugBuff, rst_len * 2);
    union_log("In SMAPIEncryptWithDerivedKey::[RESPOND]=[%d][%s][%s]", rst_len, debugBuff,rst_info);
#endif

    /* Get the length of the out data */
    memset(tmpBuf,0,sizeof(tmpBuf));
    memcpy(tmpBuf, rst_info, 4);
    nCmd_len = atoi(tmpBuf);
    *pnOutLen = nCmd_len;

    /* Get content of the out data */
    memset(tmpBuf,0,sizeof(tmpBuf));
    memcpy(tmpBuf, rst_info + 4, nCmd_len*2);
    memcpy(pbOutData, rst_info + 4, nCmd_len*2);

    return (0);
}

/*****************************************************************************************************************/
/* 函数名称： SMAPICalcMacWithDerivedKey                                                                         */
/*           5.14 脚本数据计算MAC（7.3.4 计算脚本MAC）  农行    "VK"                                              */
/* 功能说明：                                                                                                    */
/*	     计算发卡行脚本MAC（接口设计参见附录四）                                                              */
/* 输入参数：                                                                                                    */
/*	     UINT nSock：           连接的socket 句柄                                                            */
/*	     int iccType：          IC 卡类型，具体格式参见附录二，对应的算法参见附录三。                          */
/*                                  0-pboc   1-visa   2-mastercard                                              */ 
/*	     byte *pbKey：          安全报文认证主密钥，二进制数，16 字节长                                       */
/*	     byte *pbCardFactor：   卡密钥分散因子                                                               */
/*		  		    iccType=0 时，由有卡号+卡序号经过PBOC 规则产生的8 字节二进制数。               */
/*			  	    iccType!=0 时，长度为16 字节。                                               */ 
/*	     byte *pbSessionFactor：会话密钥分散因子                                                             */    
/*				    iccType=0 时，为交易序列号(ATC), 二进制数，2 字节长                           */
/*				    iccType!=0 时，长度为16 字节。如果值为NULL，表示只进行                        */
/*				    一次密钥离散（即使用卡片密钥而非会话密钥对数据进行MAC 计算）                   */
/*	     byte *pbData：         需要计算MAC 的脚本数据，二进制数，长度由nDataLen 指定                         */
/*	     int nDataLen：         pbData 的长度, 取值范围[8, 128]                                              */
/* 输出参数：                                                                                                    */
/*	     byte *pbMac：脚本数据的MAC 值，二进制数，8 字节长                                                    */
/* 返回说明：                                                                                                    */
/*	     0： 执行成功                                                                                        */
/*	     1： 输入参数验证失败                                                                                */
/*	     2： 无效的密钥(Key)                                                                                 */
/*	     3： 向加密机发送数据失败                                                                             */
/*	     4： 接收加密机数据超时                                                                               */
/*	     5： 接收到的数据格式错                                                                               */ 
/*	     9:  其他错误                                                                                         */ 
/* 维护记录：                                                                                                     */
/*          2017-03-07 by zhaomx                                                                                 */
/******************************************************************************************************************/ 

int SMAPICalcMacWithDerivedKey(UINT nSock, int iccType, byte *pbKey, 	byte *pbCardFactor, byte *pbSessionFactor,byte *pbData, int nDataLen,
	                       byte *pbMac)
{

    int  retCode=0;
    char cmd_info[40960 + 1];
    char rst_info[40960 + 1];
    char tmpBuf[1024 + 1];
    int  nCmd_len;
    int  rst_len;
    char *pcmd_info = NULL;

    if (UnionIsSocket(nSock)<1)
    {
	union_err_log("In SMAPICalcMacWithDerivedKey nSock error, [nSock=%u]", nSock);
	return(CKR_SENDFAIL_ERR);
    }

    if ((0 != (iccType >> 16)) && (1 != (iccType >> 16)) && (2 != (iccType >> 16))  ) {
	union_err_log("In SMAPICalcMacWithDerivedKey iccType error, [iccType=%d]", iccType);
        return(CKR_PARAMETER_ERR);
    }

    if (NULL == pbKey) {
        union_err_log("In SMAPICalcMacWithDerivedKey [pbKey is NULL]");
        return(CKR_PARAMETER_ERR);
    }

    if (NULL == pbCardFactor) {
        union_err_log("In SMAPICalcMacWithDerivedKey [pbCardFactor is NULL]");
        return(CKR_PARAMETER_ERR);
    }

    if (NULL == pbSessionFactor) {
        union_err_log("In SMAPICalcMacWithDerivedKey [pbSessionFactor is NULL]");
        return(CKR_PARAMETER_ERR);
    }

    if (NULL == pbData) {
        union_err_log("In SMAPICalcMacWithDerivedKey [pbData is NULL]");
        return(CKR_PARAMETER_ERR);
    }

    if ((nDataLen < 8) || (nDataLen > 128)) {
	union_err_log("In SMAPICalcMacWithDerivedKey nDataLen error, [nDataLen=%d]", nDataLen);
        return(CKR_PARAMETER_ERR);
    }    

#ifdef	_DEBUG
    unsigned char debugBuff[40960];
    memset(debugBuff, 0x00, sizeof(debugBuff));
#endif

    memset(cmd_info, 0x00, sizeof(cmd_info));
    memset(rst_info, 0x00, sizeof(rst_info));
    memset(tmpBuf, 0x00, sizeof(tmpBuf));
    nCmd_len = 0;
    rst_len = 0;
    pcmd_info = NULL;

    /* command */
    pcmd_info = cmd_info;
    memcpy(pcmd_info, "VK", 2);
    pcmd_info += 2;
	
    /* 算法类型     "1"-SM4    "2"-SM1    "3"-3DES    "4"-AES    */
    if((iccType == 1025) || (iccType == 1047))   //PBOC-SM4
    {
        memcpy(pcmd_info, "1", 1);
    }
    else
    {
        memcpy(pcmd_info, "3", 1);  
    }
    pcmd_info++;

    //IC卡类型   固定写死   2017-04-17
    if((iccType >> 16) == 0)
    {
        //iccType = 2;
        sprintf(pcmd_info, "%d", 2);
    }
    else if((iccType >> 16) == 1)
    {
        //iccType = 0;
        sprintf(pcmd_info, "%d", 0);
    }
    else if((iccType >> 16) == 2)
    {
        //iccType = 1;
        sprintf(pcmd_info, "%d", 1);
    }
    pcmd_info++;

    // 密钥类型    zhaomx-20170228 
    //memcpy(pcmd_info, "000", 3);
    //pcmd_info += 3;

    /* 安全报文认证主密钥 */
    if((iccType == 1025) || (iccType == 1047))   //PBOC-SM4
    {
        memcpy(pcmd_info,"S",1);
    }
    else
    {
        memcpy(pcmd_info,"X",1);
    }
    pcmd_info+=1;
    memset(tmpBuf, 0x00, sizeof(tmpBuf));
    UnpackBCD((char*)pbKey, tmpBuf, 32);
    memcpy(pcmd_info, tmpBuf, 32);
    pcmd_info += 32;

    /* 卡片密钥分散因子  */
    if(iccType == 0)
    {
	memset(tmpBuf, 0, sizeof(tmpBuf));
	UnpackBCD((char*)pbCardFactor,tmpBuf,16);
	memcpy(pcmd_info, tmpBuf, 16);
	pcmd_info += 16;
    }
    else
    {
	memset(tmpBuf, 0, sizeof(tmpBuf));
	UnpackBCD((char*)pbCardFactor,tmpBuf,32);
	memcpy(pcmd_info, tmpBuf, 32);
	pcmd_info += 32;
    } 

    /* 会话密钥分散因子 */
    if(iccType == 0)
    {
	memset(tmpBuf, 0x00, sizeof(tmpBuf));
	UnpackBCD((char*)pbSessionFactor, tmpBuf, 4);
	memcpy(pcmd_info, tmpBuf,4);
	pcmd_info += 4;	
    }
    else
    {
	memset(tmpBuf, 0x00, sizeof(tmpBuf));
	UnpackBCD((char*)pbSessionFactor, tmpBuf, 32);
	memcpy(pcmd_info, tmpBuf, 32);
	pcmd_info += 32;
    }

    /* 数据长度 */
    sprintf(pcmd_info, "%04d", nDataLen);
    pcmd_info += 4;

    /* MAC计算数据 */
    memset(tmpBuf, 0x00, sizeof(tmpBuf));
    memcpy(pcmd_info, pbData, nDataLen);
    pcmd_info += nDataLen;

    /* set the last char '\0' */
    *pcmd_info = 0;

    /* calculate the length of requst package */
    nCmd_len = pcmd_info - cmd_info;

#ifdef	_DEBUG
    memset(debugBuff, 0x00, sizeof(debugBuff));
    UnpackBCD(cmd_info, (char *) debugBuff, nCmd_len * 2);
    union_log(" In SMAPICalcMacWithDerivedKey::[REQUEST]=[%d][%s][%s] \n", nCmd_len, debugBuff,cmd_info);
#endif

    rst_len = UnionHSMCmd(nSock, cmd_info, nCmd_len, rst_info, gUnionTimeout, &retCode);

    if (10 == retCode) {
        union_err_log("In SMAPICalcMacWithDerivedKey::UnionHSMCmd [invalid key]");
        return(CKR_INVALIDKEY_ERR);
    }
    
    switch(rst_len)
    {
    	 case -1:
    		 union_err_log("In SMAPICalcMacWithDerivedKey::SOCKET EDLL!");
    		 return CKR_PARAMETER_ERR;
    	 case -2:
    		 union_err_log("In SMAPICalcMacWithDerivedKey::SOCKET SEND ERROR!");
    		 return CKR_SENDFAIL_ERR;
    	 case -3:
    		 union_err_log("In SMAPICalcMacWithDerivedKey::SOCKET RECIVE ERROR!");
    		 return CKR_RCVTMOUT_ERR;
    	 case -4:
    		 union_err_log("In SMAPICalcMacWithDerivedKey::SOCKET RECIVE ERROR! CKR_PARAMETER_ERR");
    		 return CKR_PARAMETER_ERR;
    	 default:
		 break;
    }
#ifdef	_DEBUG
    union_log("In SMAPICalcMacWithDerivedKey::[RESPOND]=[%d][%s]", rst_len, rst_info);
#endif

    /* Get MAC */
    memset(tmpBuf, 0, sizeof(tmpBuf));	
    PackBCD(rst_info, (unsigned char*)tmpBuf, rst_len*2);
    memcpy(pbMac, tmpBuf, rst_len*2);

    return (0);
}

/******************************************************************************************************/
/* 函数名称： SMAPIPrivateAnalyse                                                                     */
/*           5.15 私钥解析（7.5.6 分解RSA 私钥分量）  农行    "UA"                                     */
/* 功能说明：                                                                                         */
/*              将私钥解析为各个分量(以KEK 加密)，以便个人化制卡时写入私钥分量                           */
/*              注：私钥的6 个分量(pbD, pbP, pbQ, pbDmP1, pbDmQ1, pbCoef)不管长度                      */
/*                  是不是8 的整数倍，都先强制补80，之后填充最少个0x00，使得分量                        */ 
/*                  的长度为8 的整数倍，之后再用pbKEK 加密。                                           */
/*                                                                                                   */
/* 输入参数：                                                                                         */
/*		UINT nSock：  连接的socket 句柄                                                       */
/*		byte *pbSK：  私钥密文值，二进制数，DER 编码格式，被HMK 加密，长度由nSKLen指定          */   
/*		int nSKLen：  私钥的长度, 私钥长度取值范围[1, 2048] (有效长度范围参见附录一)            */
/*		int nAlgo：   KEK 加密算法类型。Single_Des = 1，Double_Des = 2 ,Triple_Des = 3        */ 
/*		byte *pbKEK： 经HMK 加密的KEK 的密文值，二进制数，                                     */
/*		              当nAlgo =1 是，8 字节长                                                 */
/*		              当nAlgo =2 是，16 字节长                                                */
/*		              当nAlgo =3 是，24 字节长                                                */ 
/* 输出参数：                                                                                         */
/*		byte *pbD：      私钥指数，二进制数，被pbKEK 加密，长度由pnDLen 指定                    */  
/*		int *pnDLen：    私钥指数的长度                                                       */
/*		byte *pbP：      RSA 的第一个大素数，二进制数，被pbKEK 加密，长度由pnPLen 指定          */
/*		int *pnPLen：    pbP 的长度                                                           */ 
/*		byte *pbQ：      RSA 的第二个大素数，二进制数，被pbKEK 加密，长度由pnQLen 指定          */
/*		int *pnQLen：    pbQ 的长度                                                           */   
/*		byte *pbDmP1：   D mod (P-1) 的值，二进制数，被pbKEK 加密，长度由pnDmP1Len指定          */
/*		int *pnDmP1Len： pbDmP1 的长度                                                        */ 
/*		byte *pbDmQ1：   D mod (Q-1) 的值，二进制数，被pbKEK 加密，长度由pnDmQ1Len指定          */
/*		int *pnDmQ1Len： pbDmQ1 的长度                                                        */
/*		byte *pbCoef：   Q^-1mod P 的值，二进制数，被pbKEK 加密，长度由pnCoefLen指定            */
/*		int *pnCoefLen： pbCoef 的长度                                                        */
/* 返回值：                                                                                           */
/*		0： 执行成功                                                                          */
/*		1： 输入参数验证失败                                                                   */
/*		2： 无效的密钥(pbSK)                                                                   */
/*		3： 向加密机发送数据失败                                                               */
/*		4： 接收加密机数据超时                                                                 */ 
/*		5： 接收到的数据格式错                                                                 */  
/*		9:  其他错误                                                                          */ 
/* 维护记录：                                                                                         */
/*          2017-03-07 by zhaomx                                                                      */
/******************************************************************************************************/ 
int SMAPIPrivateAnalyse(UINT nSock, byte * pbSK, int nSKLen, int nAlgo,byte * pbKEK,
	                byte * pbD, int *pnDLen, byte * pbP, int *pnPLen, byte * pbQ, 
	                int *pnQLen, byte * pbDmP1, int *pnDmP1Len, 	byte * pbDmQ1, 
	                int *pnDmQ1Len, byte * pbCoef, int *pnCoefLen)
{

    int      retCode=0;
    char     cmd_info[40960 + 1];
    char     rst_info[40960 + 1];
    char     tmpBuf[4096 + 1];
    int      nCmd_len;
    int      rst_len;
    int      offset;
    char     *pcmd_info = NULL;

    if (UnionIsSocket(nSock)<1)
    {
	union_err_log("In SMAPIPrivateAnalyse nSock error, [nSock=%u]", nSock);
        return(CKR_SENDFAIL_ERR);
    }

    if (NULL == pbSK) {
        union_err_log("In SMAPIPrivateAnalyse [pbSK is NULL]");
	return(CKR_PARAMETER_ERR);
    }

    if ((nSKLen < 1) || (nSKLen > 2048)) {
        union_err_log("In SMAPIPrivateAnalyse [nSKLen=%d]", nSKLen);
	return(CKR_PARAMETER_ERR);
    }
    
    if ((nAlgo < 1) || (nAlgo > 4)) {
        union_err_log("In SMAPIPrivateAnalyse [nAlgo=%d]", nAlgo);
	return(CKR_PARAMETER_ERR);
    }

    if (NULL == pbKEK) {
        union_err_log("In SMAPIPrivateAnalyse [pbKEK is NULL]");
	return(CKR_PARAMETER_ERR);
    }

#ifdef	_DEBUG
    unsigned char   debugBuff[40960];
    memset(debugBuff, 0x00, sizeof(debugBuff));
#endif

    memset(cmd_info, 0x00, sizeof(cmd_info));
    memset(rst_info, 0x00, sizeof(rst_info));
    memset(tmpBuf, 0x00, sizeof(tmpBuf));
    nCmd_len = 0;
    rst_len = 0;
    offset = 0;
    pcmd_info = NULL;

    /* command */
    pcmd_info = cmd_info;
    memcpy(pcmd_info, "UA", 2);
    pcmd_info += 2;

    //密钥类型  Key Type   zhaomx-20170228
    //memcpy(pcmd_info, "00A", 3);
    //pcmd_info += 3;
	
    /* 算法类型 Key Length */
    if(nAlgo == 1)
	memcpy(pcmd_info, "3", 1);
    if(nAlgo == 2)
	memcpy(pcmd_info, "3", 1);
    if(nAlgo == 3)
	memcpy(pcmd_info, "3", 1);

    pcmd_info += 1;

    /* 保护密钥密文 Key */
    memset(tmpBuf, 0, sizeof(tmpBuf));
    UnpackBCD((char*)pbKEK, tmpBuf, nAlgo*16);
    
    if(nAlgo == 2)
    {
    	memcpy(pcmd_info, "X", 1);
    	pcmd_info += 1;
    }
    if(nAlgo == 3)
    {
    	memcpy(pcmd_info, "Y", 1);
    	pcmd_info += 1;
    }
  

    memcpy(pcmd_info, tmpBuf, nAlgo*16);
    pcmd_info += (nAlgo*16);
    
    //保护密钥分散次数       
    memcpy(pcmd_info, "0", 1);
    pcmd_info += 1;
		
    /* Private key length */
    sprintf(pcmd_info, "%04d", nSKLen);
    pcmd_info += 4;
 
    /* Private Key */
    memcpy(pcmd_info,pbSK,nSKLen);
    pcmd_info += nSKLen;
    
    /* set the last char '\0' */
    *pcmd_info = 0;

    /* calculate the length of requst package */
    nCmd_len = pcmd_info - cmd_info;

#ifdef	_DEBUG
    memset(debugBuff, 0x00, sizeof(debugBuff));
    UnpackBCD(cmd_info, (char *) debugBuff, nCmd_len * 2);
    union_log(" In SMAPIPrivateAnalyse::[REQUEST]=[%d][%s] ", nCmd_len, debugBuff);
#endif

    rst_len = UnionHSMCmd(nSock, cmd_info,nCmd_len, rst_info, gUnionTimeout,&retCode);
    switch(rst_len)
    {
    	 case -1:
    		 union_err_log("In SMAPIPrivateAnalyse::SOCKET EDLL!");
    		 return CKR_PARAMETER_ERR;
    	 case -2:
    		 union_err_log("In SMAPIPrivateAnalyse::SOCKET SEND ERROR!");
    		 return CKR_SENDFAIL_ERR;
    	 case -3:
    		 union_err_log("In SMAPIPrivateAnalyse::SOCKET RECIVE ERROR!");
    		 return CKR_RCVTMOUT_ERR;
    	 case -4:
    		 union_err_log("In SMAPIPrivateAnalyse::SOCKET RECIVE ERROR! CKR_PARAMETER_ERR");
    		 return CKR_PARAMETER_ERR;
    	 default:
		 break;
    }
#ifdef	_DEBUG
    memset(debugBuff, 0x00, sizeof(debugBuff));
    UnpackBCD(rst_info, (char *) debugBuff, rst_len * 2);
    union_log("In SMAPIPrivateAnalyse::[RESPOND]=[%d][%s]", rst_len, debugBuff);
#endif

    offset = 0;
    /*skip m    */
    memset(tmpBuf,0,sizeof(tmpBuf));
    memcpy(tmpBuf,rst_info+offset,4);
    offset += atoi(tmpBuf)+4;
    /*skip e   */
    memset(tmpBuf,0,sizeof(tmpBuf));
    memcpy(tmpBuf,rst_info+offset,4);
    offset += atoi(tmpBuf)+4;

    /* Get the D */
    memset(tmpBuf,0,sizeof(tmpBuf));
    memcpy(tmpBuf, rst_info + offset, 4);
    offset += 4;

    *pnDLen=atoi(tmpBuf);
    memcpy(pbD,rst_info+offset,*pnDLen);
    offset += (*pnDLen);

    /* Get the P */
    memset(tmpBuf, 0x00, sizeof(tmpBuf));
    memcpy(tmpBuf, rst_info + offset, 4);
    offset += 4;

    *pnPLen = atoi(tmpBuf);
    memcpy(pbP, rst_info + offset, *pnPLen);
    offset += (*pnPLen);
    //printf("num 1= [%d] [%s]  offset=[%d]\n",(*pnPLen),pbP,offset);
    
    /* Get the Q */
    memset(tmpBuf, 0x00, sizeof(tmpBuf));
    memcpy(tmpBuf, rst_info + offset, 4);
    offset += 4;

    *pnQLen = atoi(tmpBuf);
    memcpy(pbQ, rst_info + offset, *pnQLen);
    offset += (*pnQLen);
    //printf("num 2= [%d] [%s] ofset=[%d]\n",(*pnQLen),pbQ,offset);
    
    /* Get the D mod (P-1) */
    memset(tmpBuf, 0x00, sizeof(tmpBuf));
    memcpy(tmpBuf, rst_info + offset, 4);
    offset += 4;

    *pnDmP1Len = atoi(tmpBuf);
    memcpy(pbDmP1, rst_info + offset, *pnDmP1Len);
    offset += (*pnDmP1Len);
    //printf("num 3= [%d] [%s] ofset=[%d]\n",(*pnDmP1Len),pbDmP1,offset);
    
    /* Get the D mod (Q-1) */
    memset(tmpBuf, 0x00, sizeof(tmpBuf));
    memcpy(tmpBuf, rst_info + offset, 4);
    offset += 4;

    *pnDmQ1Len = atoi(tmpBuf);
    memcpy(pbDmQ1, rst_info + offset, *pnDmQ1Len);
    offset += (*pnDmQ1Len);
   // printf("num 4= [%d] [%s] ofset=[%d]\n",(*pnDmQ1Len),pbDmQ1,offset);

    /* Get the Coef */
    memset(tmpBuf, 0x00, sizeof(tmpBuf));
    memcpy(tmpBuf, rst_info + offset, 4);
    offset += 4;

    *pnCoefLen = atoi(tmpBuf);
    memcpy(pbCoef, rst_info + offset, *pnCoefLen);

    return (0);

}


/*****************************************************************************************************/
/* 函数名称： SMAPIGenEccKey                                                                         */
/*           5.16 产生ECC 公私钥对（7.4.1 产生SM2 密钥对）  农行    "U0"                              */
/* 功能说明：                                                                                        */
/*           产生ECC 密钥对。                                                                        */
/* 输入参数：                                                                                        */
/*	     UINT nSock： 连接的socket 句柄                                                          */
/*	     int nIndex： 索引位，0：不保存在索引位上；1—19：相应索引位的值                            */
/*	     int nEcMark：椭圆曲线标识                                                               */
/*	                  0x01：ECC 128 位，NIST P-256，公钥长度64 字节（暂不支持）                   */
/*		 	  0x02：ECC 256 位，NIST P-521，公钥长度132 字节（暂不支持）                  */
/*			  0x11：SM2 128 位，SM2 曲线，公钥长度64 字节                                 */
/* 输出参数：                                                                                        */
/*	     byte *pbPK：    产生的公钥的明文，二进制数，调用函数应分配足够的存储空间，实               */
/*	                     际返回的数据长度由pnPKLen 指定。                                         */
/*	     int *pnPKLen：  返回的公钥数据长度                                                       */
/*	     byte *pbSK：    私钥密文值，二进制数，强制填充”80 00…”至8 的整数倍后被HMK                 */
/*		             加密，调用函数应分配足够的存储空间，实际返回的数据长度由pnSKLen 指定       */ 
/*	     int * pnSKLen： 返回的私钥数据长度                                                       */
/* 返回说明：                                                                                        */ 
/*	     0： 生成成功                                                                            */
/*	     1： 输入参数验证失败                                                                     */ 
/*	     3： 向加密机发送数据失败                                                                 */    
/*	     4： 接收加密机数据超时                                                                   */
/*	     5： 接收到的数据格式错                                                                   */
/*	     9:  其他错误                                                                            */
/*	     补充：如果指定的索引位上已经存有数据，清除原数据后保存新密钥对。密钥存储                    */
/*	  	   索引与RSA 密钥共用。                                                               */
/*                                                                                                   */ 
/* 维护记录：                                                                                         */
/*          2017-03-07 by zhaomx                                                                     */
/*****************************************************************************************************/ 
int SMAPIGenEccKey (UINT nSock, int nIndex, int nEcMark,
	            byte *pbPK, int *pnPKLen, byte *pbSK, int *pnSKLen)
{
    int          retCode = 0;
    int          nCmd_len;
    int          rst_len;
    int          offset;
    int          prnKeyLen;
    int          pubKeyDerLen;
    int          pubKeyLen;
    int          expLen;
    int          modLen;
    int          iCmdLen = 0;
    char         pszExp_char[12];
    char         cprnKeyLen[4 + 1];
    char         cmd_info[128 + 1];
    char         mod[2048 + 1];
    char         exp[2048 + 1];
    char         pubKeyDer[4096 + 2];
    char         rst_info[40960];
    unsigned int nExp = 0;
    char         nExp_buf[20];
    char         tmpBuf[24];

    if(UnionIsSocket(nSock)<1)
    {
	union_err_log("In SMAPIGenEccKey::Parameter[Nsock] error socket=[%d]\n",nSock);
	return CKR_SENDFAIL_ERR;
    }

    if(nIndex<0||nIndex>19)
    {
	union_err_log("In SMAPIGenEccKey::Parameter[nIndex] error nIndex=[%d]\n",nIndex);
	return CKR_PARAMETER_ERR;
    }

    if((nEcMark!=17) && (nEcMark !=1) && (nEcMark !=2))
    {
	union_err_log("In SMAPIGenEccKey::Parameter[nModLen] error ModeLen=[%d]\n",nEcMark);
	return CKR_PARAMETER_ERR;
    }

#ifdef	_DEBUG
    unsigned char debugBuff[8192];
#endif

    memset(cmd_info, 0x00, sizeof(cmd_info));
    memset(rst_info, 0x00, sizeof(rst_info));
    memset(pubKeyDer, 0x00, sizeof(pubKeyDer));
    memset(mod, 0x00, sizeof(mod));
    memset(exp, 0x00, sizeof(exp));
    offset = 0;

    /* command */
    memcpy(cmd_info, "UO", 2);
    iCmdLen += 2;
	
    /* length of SM2 key    密钥长度  比特长度： 应为256  */
    sprintf(cmd_info+iCmdLen, "%04d", 256);
    iCmdLen += 4;

    //密钥用途   "1"-签名   "2"-加密    "3"-签名和加密   
    memcpy(cmd_info+iCmdLen, "3", 1);
    iCmdLen += 1;

    //密钥索引
    if (nIndex > 0 && nIndex < 50) 
    {
	sprintf(cmd_info+iCmdLen, "%02d", nIndex);
	iCmdLen += 2;
	//密钥口令    索引不等于"00"时存在
	memcpy(cmd_info+iCmdLen, "12345678", 8);
        iCmdLen += 8;
    }
    else if(nIndex == 0)
    {
	sprintf(cmd_info+iCmdLen, "%02d", 0);
	iCmdLen += 2;
    }
    else
    {
	union_err_log("In SMAPIGenEccKey::Parameter error,[nIndex] must between [0,19] or equal 99! nLmkId= [%02d]", nIndex);
	return CKR_PARAMETER_ERR;
    }

    cmd_info[iCmdLen++] = '\0';
    nCmd_len = iCmdLen - 1;	
	
#ifdef	_DEBUG
    memset(debugBuff, 0x00, sizeof(debugBuff));
    UnpackBCD(cmd_info, (char *) debugBuff, nCmd_len*2);
    union_log("In SMAPIGenEccKey::[REQUEST]=[%d][%s]", nCmd_len, debugBuff);
#endif
    rst_len = UnionHSMCmd(nSock, cmd_info, nCmd_len, rst_info, gUnionTimeout, &retCode);

#ifdef _DEBUG
    memset(debugBuff, 0x00, sizeof(debugBuff));
    UnpackBCD(rst_info, (char *)debugBuff, rst_len*2);
    union_log("In SMAPIGenEccKey::[RESPOND]=[%d][%s]", rst_len, debugBuff);
#endif
switch(rst_len)
    {
    	 case -1:
    		 union_err_log("In SMAPIGenEccKey::SOCKET EDLL!");
    		 return CKR_PARAMETER_ERR;
    	 case -2:
    		 union_err_log("In SMAPIGenEccKey::SOCKET SEND ERROR!");
    		 return CKR_SENDFAIL_ERR;
    	 case -3:
    		 union_err_log("In SMAPIGenEccKey::SOCKET RECIVE ERROR!");
    		 return CKR_RCVTMOUT_ERR;
    	 case -4:
    		 union_err_log("In SMAPIGenEccKey::SOCKET RECIVE CKR_PARAMETER_ERR ERROR!");
    		 return CKR_PARAMETER_ERR;
    	 default:
    	 	 break;
    	}

#ifdef _DEBUG
    memset(debugBuff, 0x00, sizeof(debugBuff));
    UnpackBCD(rst_info, (char *)debugBuff, rst_len*2);
    union_log("In SMAPIGenEccKey::[RESPOND]=[%d][%s]", rst_len, debugBuff);
#endif

    offset = 0;

    /* Get public-key(DER)'s length and contents */
    pubKeyDerLen = 64;
    memcpy(pubKeyDer, rst_info + offset, pubKeyDerLen);

    /* Get public-key from public-key(DER) */
    memcpy(pbPK, pubKeyDer, pubKeyDerLen);
    *pnPKLen=pubKeyDerLen;

#ifdef _DEBUG
    memset(debugBuff, 0x00, sizeof(debugBuff));
    UnpackBCD((char*)pbPK, (char *) debugBuff, pubKeyDerLen * 2);
    union_log("In SMAPIGenEccKey::public key =[%d][%s]", pubKeyDerLen, debugBuff);
#endif

    offset += *pnPKLen;

    /* Get the length of the private key */
   // memcpy(cprnKeyLen, rst_info, 4);
    prnKeyLen = 40;                //20170510   zhaomx

   // if (prnKeyLen <= 0)
   // {
   //	union_err_log("In SMAPIGenEccKey::the length of the private key is short than  zero! private len=[%d]\n",prnKeyLen);
   //	return CRK_GENRSA_ERR;
   // }
    *pnSKLen = prnKeyLen;
    /* Get content of the private key */
    memcpy(pbSK, rst_info + offset, prnKeyLen);
   // offset += prnKeyLen;

#ifdef _DEBUG
    memset(debugBuff, 0x00, sizeof(debugBuff));
    UnpackBCD((char*)pbSK, (char *) debugBuff, prnKeyLen * 2);
    union_log("In SMAPIGenEccKey::private key =[%d][%s]", prnKeyLen, debugBuff);
#endif


    return (CKR_SMAPI_OK);
}


/*****************************************************************************************************/
/* 函数名称： SMAPIGetEccPkBySk                                                                      */
/*           5.17 根据ECC 私钥生成公钥  （7.6.19 根据ECC 私钥生成公钥）  农行    "EB"                  */
/* 功能说明：                                                                                        */
/*          通过指定的EC 及私钥获取对应的公钥。                                                       */
/* 输入参数：                                                                                        */
/*	     UINT nSock：连接的socket 句柄                                                           */ 
/*	     int nEcMark：椭圆曲线标识                                                               */
/*		 	  0x01：ECC 128 位，NIST P-256，公钥长度64 字节（暂不支持）                   */  
/*			  0x02：ECC 256 位，NIST P-521，公钥长度132 字节（暂不支持）                  */
/*			  0x11：SM2 128 位，SM2 曲线，公钥长度64 字节                                 */
/*	     byte *pbSK： 私钥密文值，二进制数，强制填充”80 00…”至8 的整数倍后被HMK                    */
/*			  加密，数据长度由pnSKLen 指定                                               */  
/*	     int  nSKLen：私钥数据长度                                                               */ 
/* 输出参数：                                                                                        */
/*	     byte *pbPK：产生的公钥的明文，二进制数，调用函数应分配足够的存储空间，实                   */
/*		         际返回的数据长度由pnPKLen 指定。                                             */
/*	     int *pnPKLen：返回的公钥数据长度                                                         */    
/* 返回说明：                                                                                        */ 
/*	     0： 生成成功                                                                            */
/*	     1： 输入参数验证失败                                                                    */
/*	     3： 向加密机发送数据失败                                                                */ 
/*	     4： 接收加密机数据超时                                                                  */ 
/*	     5： 接收到的数据格式错                                                                  */ 
/*	     9:  其他错误                                                                           */ 
/* 维护记录：                                                                                       */
/*          2017-03-07 by zhaomx                                                                    */
/*****************************************************************************************************/ 
int SMAPIGetEccPkBySk (UINT nSock, int nEcMark, byte *pbSK, int nSKLen,
                       byte *pbPK, int *pnPKLen)
{
    int           retCode=0;
    char          cmd_info[40960 + 1];
    char          rst_info[40960 + 1];
    int           nRc,nCmd_len;
    int           rst_len;
    char          *pcmd_info = NULL;
    unsigned char tmpBuf[1024 + 1];
    int           iDiff;	
    byte          *pbOutData;
    int           *pnOutLen;
    char          cmd_info_2[1000];
    char          tmp[200 + 1];
    int           ret=0;

    if(UnionIsSocket(nSock)<1)
    {
    	union_err_log("In SMAPIGetEccPkBySk::nSKLen error! socket edle nSocket=[%d]\n",nSock);
	return CKR_PARAMETER_ERR;
    }

    if(nEcMark!= 1  && nEcMark!= 2 && nEcMark!= 17)
    {
	union_err_log("In SMAPIGetEccPkBySk::parameter error. [nEcMark]=[%d] ", nEcMark);
	return CKR_PARAMETER_ERR;
    } 	

    if(nSKLen<8 || nSKLen>2048  || (nSKLen%8) !=0  )
    {
	union_err_log("In SMAPIGetEccPkBySk::nKeyCipherLen error! nKeyCipherLen=[%d]\n",nSKLen);
	return CKR_PARAMETER_ERR;
    }
	
#ifdef	_DEBUG
    unsigned char debugBuff[40960];
    memset(debugBuff, 0x00, sizeof(debugBuff));
#endif

    memset(cmd_info, 0x00, sizeof(cmd_info));
    memset(rst_info, 0x00, sizeof(rst_info));
    memset(tmpBuf, 0x00, sizeof(tmpBuf));
    nCmd_len = 0;
    rst_len = 0;
    pcmd_info = NULL;

    /* command    */
    pcmd_info = cmd_info;
    memcpy(pcmd_info, "EB", 2);
    pcmd_info += 2;

    // 私钥密文长度  private key length    2017-04-12 
    //sprintf(pcmd_info, "%04d", nSKLen);
    //pcmd_info += 4;

    /* 私钥密文 private key */
    memcpy(pcmd_info, pbSK, nSKLen);
    pcmd_info += nSKLen;
	
	/* set the last char '\0' */
    *pcmd_info = 0;
    /* calculate the length of requst package */
    nCmd_len = pcmd_info - cmd_info;

#ifdef	_DEBUG
    memset(debugBuff, 0x00, sizeof(debugBuff));
    UnpackBCD(cmd_info, (char *) debugBuff, nCmd_len * 2);
    union_log(" In SMAPIGetEccPkBySk::[REQUEST]=[%d][%s] ", nCmd_len, debugBuff);
#endif
	
    rst_len = UnionHSMCmd(nSock, cmd_info, nCmd_len, rst_info, gUnionTimeout,&retCode);
    
    switch(rst_len)
    {
    	 case -1:
    	        union_err_log("In SMAPIGetEccPkBySk::SOCKET EDLL!");
    	        return CKR_PARAMETER_ERR;
    	 case -2:
    	        union_err_log("In SMAPIGetEccPkBySk::SOCKET SEND ERROR!");
    	        return CKR_SENDFAIL_ERR;
    	 case -3:
    	        union_err_log("In SMAPIGetEccPkBySk::SOCKET RECIVE ERROR!");
    	        return CKR_RCVTMOUT_ERR;
    	 case -4:
	        union_err_log("In SMAPIGetEccPkBySk::SOCKET RECIVE CKR_PARAMETER_ERR ERROR!");
    	        return CKR_PARAMETER_ERR;
    	 default:
    	 	break;
    	}
#ifdef	_DEBUG
    memset(debugBuff, 0x00, sizeof(debugBuff));
    UnpackBCD(rst_info, (char *) debugBuff, rst_len * 2);
    union_log("In SMAPIGetEccPkBySk::[RESPOND]=[%d][%s]", rst_len, debugBuff);
#endif

    /* Get the length of the outData */
    memset(tmpBuf, 0x00, sizeof(tmpBuf));

    memcpy(tmpBuf, rst_info, 4);

    //公钥长度   4
    *pnPKLen = atoi((char*)tmpBuf);
 
    //公钥
    memcpy(pbPK, rst_info+4,*pnPKLen);
 
    return CKR_SMAPI_OK;
}


/*****************************************************************************************************/
/* 函数名称： SMAPIEccPkEncrypt                                                                      */
/*           5.18 ECC 公钥加密（7.4.3 SM2 公钥加密）  农行    "UU"                                    */
/* 功能说明：                                                                                        */
/*           ECC 公钥加密                                                                            */
/* 输入参数：                                                                                        */
/*		UINT nSock：     连接的socket 句柄                                                   */
/*		int nEcMark：    椭圆曲线标识                                                        */  
/*		 	         0x01：ECC 128 位，NIST P-256，公钥长度64 字节（暂不支持）            */
/*				 0x02：ECC 256 位，NIST P-521，公钥长度132 字节（暂不支持）           */ 
/*				 0x11：SM2 128 位，SM2 曲线，公钥长度64 字节                          */
/*		int nPad:        填充模式， 0：不填充(具体填充方式待补充，暂不支持)。                  */ 
/*		byte * pbPK：    公钥明文，二进制数，（字节）长度由nPKLen 指定                         */
/*		int   nPKLen：   公钥长度，取值范围[1, 512]                                           */
/*		byte *pbInData： 需要进行加密的数据，二进制数，（字节）长度由nInLen 指定                */
/*		int nInLen：     pbInData 的长度，取值范围[1, 4000]                                   */ 
/* 输出参数：                                                                                         */
/*		byte *pbOutData：经过加密后的密文数据，二进制数，                                      */
/*		int *pnOutLen：  返回的pbOutData 的数据长度，                                         */
/* 返回说明：                                                                                        */
/*		0： 生成成功                                                                         */
/*		1： 输入参数验证失败                                                                 */
/*		2： 无效的密钥(PK)                                                                   */
/*		3： 向加密机发送数据失败                                                             */
/*		4： 接收加密机数据超时                                                               */
/*		5： 接收到的数据格式错                                                               */
/*		9:  其他错误                                                                        */
/* 维护记录：                                                                                       */
/*          2017-03-07 by zhaomx                                                                    */
/*****************************************************************************************************/ 
int SMAPIEccPkEncrypt(UINT nSock, int nEcMark, int nPad, byte * pbPK,int nPKLen, byte *pbInData, int nInLen, 
	              byte *pbOutData, int *pnOutLen)
{

    int            retCode=0;
    char           cmd_info[40960 + 1];
    char           rst_info[40960 + 1];
    int            nCmd_len;
    int            rst_len;
    char           *pcmd_info = NULL;
    unsigned char  tmpBuf[1024 + 1];
    int            pubKeyLen;
    int            iDiff = 0;

    if(UnionIsSocket(nSock)<1)
    {
    	union_err_log("In SMAPIEccPkEncrypt::parameter Error nSocket　edl nSocket=[%d]\n",nSock);
	return CKR_SENDFAIL_ERR;
    }

    if(nEcMark!= 1  && nEcMark!= 2 && nEcMark!= 17)
    {
	union_err_log("In SMAPIEccPkEncrypt::parameter error. [nEcMark]=[%d] ", nEcMark);
	return CKR_PARAMETER_ERR;
    }  

    if(nPad!=0 && nPad!=1 && nPad!=2)
    {
	union_err_log("In SMAPIEccPkEncrypt::parameter error. [nPad]=[%d] ", nPad);
	return CKR_PARAMETER_ERR;
    }

    if(nInLen < 1 || nInLen > 4000)
    {
	union_err_log("In SMAPIEccPkEncrypt::parameter error. [nInLen]=[%d] ", nInLen);
	return CKR_PARAMETER_ERR;
    }

    if(nPKLen < 1 || nPKLen > 2048)
    {
	union_err_log("In SMAPIEccPkEncrypt::parameter error. [nPKLen]=[%d] ", nPKLen);
	return CKR_PARAMETER_ERR;
    }

    if (nEcMark == 0 && nPad == 2)
    {
	union_err_log("In SMAPIEccPkEncrypt::parameter error. [nPad]=[%d] ", nPad);
	return CKR_PARAMETER_ERR;
    }

#ifdef _DEBUG
    char debugBuff[40960 + 1];
    memset(debugBuff, 0x00, sizeof(debugBuff));
#endif
    memset(cmd_info, 0x00, sizeof(cmd_info));
    memset(rst_info, 0x00, sizeof(rst_info));
    memset(tmpBuf, 0x00, sizeof(tmpBuf));
    nCmd_len = 0;
    rst_len = 0;
    pcmd_info = NULL;
    /* command */
    pcmd_info = cmd_info;

    memcpy(pcmd_info, "UU", 2);
    pcmd_info += 2;

    /* Public key index default is 00*/
    memcpy(pcmd_info, "00", 2);
    pcmd_info += 2;

    /*public key length */
    //if(!nEcMark)
    //{
        //sprintf(pcmd_info, "%04d", nPKLen);
        //pcmd_info += 4;
    //}

    // Public key    2017-04-17  zhaomx
    //memset(tmpBuf, 0, sizeof(tmpBuf));
    //PackBCD((char*)pbPK, tmpBuf, nPKLen*2);
    //memcpy(pcmd_info, tmpBuf, nPKLen*2);
    //pcmd_info += nPKLen;
    memcpy(pcmd_info, pbPK, nPKLen);
    pcmd_info += nPKLen;

    //数据长度
    sprintf(pcmd_info,"%04d",nInLen);
    pcmd_info += 4;

    /* in data */
    memcpy(pcmd_info, pbInData, nInLen);
    pcmd_info += nInLen;
    
    /* set the last char '\0' */
    *pcmd_info = 0;
    /* calculate the length of requst package */
    nCmd_len = pcmd_info - cmd_info;

#ifdef _DEBUG
    memset(debugBuff, 0x00, sizeof(debugBuff));
    UnpackBCD(cmd_info, (char *) debugBuff, nCmd_len * 2);
    union_log("In SMAPIEccPkEncrypt::[REQUEST]=[%d][%s]", nCmd_len, debugBuff);
#endif
    rst_len = UnionHSMCmd(nSock, cmd_info, nCmd_len, rst_info, gUnionTimeout, &retCode);

     switch(rst_len)
    {
    	 case -1:
    		 union_err_log("In SMAPIEccPkEncrypt::SOCKET EDLL!");
    		 return CKR_PARAMETER_ERR;
    	 case -2:
    		 union_err_log("In SMAPIEccPkEncrypt::SOCKET SEND ERROR!");
    		 return CKR_SENDFAIL_ERR;
    	 case -3:
    		 union_err_log("In SMAPIEccPkEncrypt::SOCKET RECIVE ERROR!");
    		 return CKR_RCVTMOUT_ERR;
    	 case -4:
    		 union_err_log("In SMAPIEccPkEncrypt::SOCKET RECIVE CKR_PARAMETER_ERR ERROR!");
    		 return CKR_PARAMETER_ERR;
    	 default:
    	 	 break;
    	}
#ifdef _DEBUG
    memset(debugBuff, 0x00, sizeof(debugBuff));
    UnpackBCD(rst_info, (char *) debugBuff, rst_len+4);
    union_log("In SMAPIEccPkEncrypt::[REPLAY]=[%d][%s]", rst_len, debugBuff);
#endif
    /* Get the length of the outData */
    memcpy(tmpBuf, rst_info, 4);

    *pnOutLen = atoi((char*)tmpBuf);
    
    /* Get content of the outData */
    memset(tmpBuf,0,sizeof(tmpBuf));
    memcpy(tmpBuf, rst_info + 4, *pnOutLen*2);
    UnpackBCD(tmpBuf,pbOutData, *pnOutLen*2);
    
    return (0);
}

/*****************************************************************************************************/
/* 函数名称： SMAPIEccSkDecrypt                                                                      */
/*           5.19 ECC 私钥解密（7.4.4 SM2 私钥解密）  农行    "UW"                                    */
/* 功能说明：                                                                                        */
/*              ECC 私钥解密                                                                         */ 
/* 输入参数：                                                                                        */
/*		UINT nSock：    连接的socket 句柄                                                    */ 
/*		int nEcMark：   椭圆曲线标识                                                         */  
/*				0x01：ECC 128 位，NIST P-256，公钥长度64 字节（暂不支持）             */
/*				0x02：ECC 256 位，NIST P-521，公钥长度132 字节（暂不支持）            */
/*				0x11：SM2 128 位，SM2 曲线，公钥长度64 字节                           */ 
/*		int nPad:       填充模式， 0：不填充(具体填充方式待补充，暂不支持)。                   */
/*		byte *pbSK：    私钥密文(经填充并由HMK 加密)，二进制数，(字节)长度由nSKLen 指定        */
/*		int nSKLen：    私钥长度，取值范围[1, 256]                                           */
/*		byte *pbInData：需要进行解密的数据，二进制数，(字节)长度由nInLen 指定                  */
/*		int nInLen：    pbInData 的长度取值范围[1, 4096]                                     */ 
/* 输出参数：                                                                                        */
/*		byte *pbOutData：经过解密之后的明文数据，二进制数，                                   */  
/*		int *pnOutLen：  返回的pbOutData 的数据长度，                                        */ 
/* 返回值：                                                                                         */  
/*		0： 生成成功                                                                        */   
/*		1： 输入参数验证失败                                                                */ 
/*		2： 无效的密钥(SK)                                                                  */   
/*		3： 向加密机发送数据失败                                                             */
/*		4： 接收加密机数据超时                                                               */
/*		5： 接收到的数据格式错                                                               */
/*		9:  其他错误                                                                        */ 
/* 维护记录：                                                                                       */
/*          2017-03-07 by zhaomx                                                                    */
/*****************************************************************************************************/ 
int SMAPIEccSkDecrypt(UINT nSock, int nEcMark, int nPad, byte * pbSK,int nSKLen, byte *pbInData, int nInLen, 
                      byte *pbOutData, int *pnOutLen)
{
    int retCode=0;
    char cmd_info[40960 + 1];
    char rst_info[40960 + 1];
    int nCmd_len;
    int rst_len;
    char *pcmd_info = NULL;
    unsigned char tmpBuf[1024 + 1];
    int iDiff;

    if(UnionIsSocket(nSock)<1)
    {
    	union_err_log("In SMAPIEccSkDecrypt::nSKLen error! socket edle nSocket=[%d]\n",nSock);
	return CKR_PARAMETER_ERR;
    }

    if(nEcMark!= 1  && nEcMark!= 2 && nEcMark!= 17)
    {
	union_err_log("In SMAPIEccSkDecrypt::parameter error. [nEcMark]=[%d] ", nEcMark);
	return CKR_PARAMETER_ERR;
    }  
    
    if(nSKLen<1 || nSKLen>2048)
    {
	union_err_log("In SMAPIEccSkDecrypt::nSKLen error! nSKLen=[%d]\n",nSKLen);
	return CKR_PARAMETER_ERR;
    }

    if(nInLen<1 || nInLen>4096)
    {
	union_err_log("In SMAPIEccSkDecrypt::nInLen error! nInLen=[%d]\n",nInLen);
	return CKR_PARAMETER_ERR;
    }

    if(nPad != 0 && nPad != 1 && nPad != 2)
    {
	union_err_log("In SMAPIEccSkDecrypt::parameter error! [nPad]=[%d] ", nPad);
	return CKR_PARAMETER_ERR;
    }

    if (nEcMark == 1 && nPad == 2)
    {
	union_err_log("In SMAPIEccSkDecrypt::parameter error! [nPad] = [%d] ", nEcMark);
	return CKR_PARAMETER_ERR;
    }

#ifdef	_DEBUG
    unsigned char   debugBuff[40960];
    memset(debugBuff, 0x00, sizeof(debugBuff));
#endif

    memset(cmd_info, 0x00, sizeof(cmd_info));
    memset(rst_info, 0x00, sizeof(rst_info));

    nCmd_len = 0;
    rst_len = 0;

    /* command */
    pcmd_info = NULL;
    pcmd_info = cmd_info;
	
    memcpy(pcmd_info, "UW", 2);
    pcmd_info += 2;

    /* private key index */
    memcpy(pcmd_info, "00", 2);
    pcmd_info += 2;

    /* private key length 20170418*/
    //sprintf(pcmd_info, "%04d", nSKLen);
    //pcmd_info += 4;

    /* private key   20170418*/
   /* memset(tmpBuf, 0, sizeof(tmpBuf));
    PackBCD((char*)pbSK, tmpBuf, nSKLen*2);
    memcpy(pcmd_info, tmpBuf, nSKLen*2);
    pcmd_info += nSKLen;*/
    memcpy(pcmd_info, pbSK, nSKLen);
    pcmd_info += nSKLen;

    
    sprintf(pcmd_info, "%04d", nInLen);
    pcmd_info += 4;

    /* in data 20170418*/
  /*  memset(tmpBuf, 0, sizeof(tmpBuf));
    PackBCD(pbInData, tmpBuf, nInLen*2);
    memcpy(pcmd_info, tmpBuf, nInLen*2);
    pcmd_info += nInLen;*/
    memcpy(pcmd_info, pbInData, nInLen);
    pcmd_info += nInLen;


     /* set the last char '\0' */
    *pcmd_info = 0;
    /* calculate the length of requst package */
    nCmd_len = pcmd_info - cmd_info;

#ifdef	_DEBUG
    memset(debugBuff, 0x00, sizeof(debugBuff));
    UnpackBCD(cmd_info, (char *) debugBuff, nCmd_len * 2);
    union_log(" In SMAPIEccSkDecrypt::[REQUEST]=[%d][%s] ", nCmd_len, debugBuff);
#endif

    rst_len = UnionHSMCmd(nSock, cmd_info, nCmd_len, rst_info, gUnionTimeout,&retCode);

    switch(rst_len)
    {
    	 case -1:
    		 union_err_log("In SMAPIEccSkDecrypt::SOCKET EDLL!");
    		 return CKR_PARAMETER_ERR;
    	 case -2:
    		 union_err_log("In SMAPIEccSkDecrypt::SOCKET SEND ERROR!");
    		 return CKR_SENDFAIL_ERR;
    	 case -3:
    		 union_err_log("In SMAPIEccSkDecrypt::SOCKET RECIVE ERROR!");
    		 return CKR_RCVTMOUT_ERR;
    	 case -4:
    		 union_err_log("In SMAPIEccSkDecrypt::SOCKET RECIVE CKR_PARAMETER_ERR ERROR!");
    		 return CKR_PARAMETER_ERR;
    	 default:
    	 	 break;
    	}
#ifdef	_DEBUG
    memset(debugBuff, 0x00, sizeof(debugBuff));
    UnpackBCD(rst_info, (char *) debugBuff, rst_len * 2);
    union_log("In SMAPIEccSkDecrypt::[RESPOND]=[%d][%s]", rst_len, debugBuff);
#endif

    /* Get the length of the outData */
    memset(tmpBuf, 0x00, sizeof(tmpBuf));
    memcpy(tmpBuf, rst_info, 4);
    *pnOutLen = atoi((char*)tmpBuf);
  
    /* Get content of the outData */
    memcpy(pbOutData, rst_info+4, *pnOutLen);
  
    return CKR_SMAPI_OK;

}

/*****************************************************************************************************/
/* 函数名称： SMAPIEccSign                                                                            */
/*           5.20 ECC 私钥签名（7.4.5 SM2 签名）  农行    "UQ"                                        */
/* 功能说明：                                                                                         */
/*              ECC 私钥签名                                                                          */ 
/* 输入参数：                                                                                         */   
/*		UINT nSock：    连接的socket 句柄                                                     */ 
/*		int nEcMark：   椭圆曲线标识                                                          */ 
/*				0x01：ECC 128 位，NIST P-256，公钥长度64 字节（暂不支持）              */ 
/*				0x02：ECC 256 位，NIST P-521，公钥长度132 字节（暂不支持）             */
/*				0x11：SM2 128 位，SM2 曲线，公钥长度64 字节                            */
/*                                    （使用PBOC 3.0 规范第17部分5.4.2.2 中定义的签名算法）            */
/*		int nPad:       填充模式， 0：不填充(具体填充方式待补充，暂不支持)。                    */ 
/*		byte * pbPK：   公钥明文，二进制数，（字节）长度由nPKLen 指定                           */ 
/* 		int nPKLen：    公钥长度，取值范围[1, 512]                                             */
/*		byte *pbSK：    私钥密文(经填充并由HMK 加密)，二进制数，(字节)长度由nSKLen 指定          */
/*		int nSKLen：    私钥数据长度，取值范围[1, 256]                                         */
/*		byte *pbData：  进行签名数据，二进制数，(字节)长度由nDataLen 指定                       */
/*		int nDataLen：  pbData 的长度取值范围[1, 4096]                                         */ 
/* 输出参数：                                                                                         */ 
/*		byte *pbSign：  签名值，二进制数，(字节)长度由pnSignLen 指定                           */
/*		int *pnSignLen：返回的pbSign 的数据长度                                               */
/* 返回值：                                                                                           */
/*	        0： 生成成功                                                                          */
/*		1： 输入参数验证失败                                                                  */
/*		2： 无效的密钥(SK)                                                                    */
/*		3： 向加密机发送数据失败                                                              */
/*		4： 接收加密机数据超时                                                                */ 
/*		5： 接收到的数据格式错                                                                */
/*		9:  其他错误                                                                         */
/* 维护记录：                                                                                       */
/*          2017-03-07 by zhaomx                                                                    */
/*****************************************************************************************************/ 
int SMAPIEccSign (UINT nSock, int nEcMark, int nPad, byte *pbPK,int nPKLen, byte *pbSK, int nSKLen, byte *pbData, int nDataLen, 
	          byte *pbSign, int *pnSignLen)
{
    int   retCode=0;
    int   dataLen;
    int   nCmd_len;
    int   rst_len;
    char  *pcmd_info = NULL;
    char  pcLen[4 + 1];
    char  cmd_info[40960 + 1];
    char  rst_info[40960 + 1];
    char  pbSignTemp[4096 + 1];
    char  tmpBuf[1024];  

    //增加填充模式检查
   /* if(nDataLen==1)
    {
    	if(nEcMark==0||nEcMark==2)
    	{
    	    union_err_log("In SMAPIEccSign::nDataLen not format nAlgo errornDataLen=[%d] nAlgo=[%d]\n",nDataLen,nEcMark);
	    return CKR_PARAMETER_ERR;
	}
    }*/

    if(UnionIsSocket(nSock)<1)
    {
	union_err_log("In SMAPIEccSign::nSock error nSock=[%d]",nSock);
	return CKR_SENDFAIL_ERR;
    }
    
    if(nSKLen<1 || nSKLen>2048)
    {
	union_err_log("In SMAPIEccSign::nSKLen error nSKLen=[%d]\n",nSKLen);
	return CKR_PARAMETER_ERR;
    }

    if(nDataLen<1 || nDataLen>4096)
    {
	union_err_log("In SMAPIEccSign::nDataLen error DataLen=[%d]\n",nDataLen);
	return CKR_PARAMETER_ERR;
    }

    if(nPad != 0 && nPad != 1 && nPad != 2)
    {
	union_err_log("In SMAPIEccSign::PAD MODE WRONG nPad=[%d]",nPad);
	return CKR_PARAMETER_ERR;
    }

    if(nEcMark<0||nEcMark>18)
    {
    	union_err_log("In SMAPIEccSign::nAlgo WRONG nPad=[%d]",nEcMark);
	return CKR_PARAMETER_ERR;
    }
    
#ifdef _DEBUG
    /* use for DEBUG */
    char debugBuff[40960];
    memset(debugBuff, 0x00, sizeof(debugBuff));
#endif
    
    /* command */
    memset(cmd_info, 0x00, sizeof(cmd_info));
    memset(pcLen, 0x00, sizeof(pcLen));

    nCmd_len = 0;
    dataLen = 0;

    pcmd_info = NULL;

    pcmd_info = cmd_info;
    memcpy(pcmd_info, "UQ", 2);
    pcmd_info += 2;

    // 密钥索引index of private key  is 00  
    memcpy(pcmd_info, "00", 2);
    pcmd_info += 2;

    // 外部输入密钥长度 here place private key
    // private key length 
    //sprintf(pcmd_info, "%04d", nSKLen);
    //pcmd_info += 4;

    // private key 
    /*memset(tmpBuf, 0, sizeof(tmpBuf));
    PackBCD((char*)pbSK,tmpBuf, nSKLen*2);
    memcpy(pcmd_info, tmpBuf, nSKLen*2);
    pcmd_info += nSKLen;*/
    //20170418
    memcpy(pcmd_info, pbSK, nSKLen);
    pcmd_info += nSKLen;

    //HASH 标识 摘要算法 02:用 SM3 在内部做摘要
    memcpy(pcmd_info, "02", 2);
    pcmd_info += 2;

    //用户标识长度
    memcpy(pcmd_info, "0016", 4);
    pcmd_info += 4;

    //用户标识
    memset(tmpBuf, 0, sizeof(tmpBuf));
    memcpy(pcmd_info, "1234567812345678", 16);
    pcmd_info += 16;

    //公钥   密钥索引"00"  
    memcpy(pcmd_info, pbPK, nPKLen);
    pcmd_info += nPKLen; 
    
    //数据长度
    sprintf(pcmd_info, "%04d", nDataLen);
    pcmd_info += 4;
	
    //数据
    memset(tmpBuf, 0, sizeof(tmpBuf));
    memcpy(pcmd_info, pbData, nDataLen);
    pcmd_info += nDataLen;

    /* set the last char '\0' */
    *pcmd_info = 0;

    /* calculate the length of requst package */
    nCmd_len = pcmd_info - cmd_info;

#ifdef	_DEBUG
    memset(debugBuff, 0x00, sizeof(debugBuff));
    UnpackBCD(cmd_info, (char *) debugBuff, nCmd_len * 2);
    union_log(" In SMAPIEccSign::[REQUEST]=[%d][%s] ", nCmd_len, debugBuff);
#endif

    rst_len = UnionHSMCmd(nSock, cmd_info,nCmd_len, rst_info, gUnionTimeout,&retCode);
		
   switch(rst_len)
    {
    	 case -1:
    		 union_err_log("In SMAPIEccSign::SOCKET EDLL!");
    		 return CKR_PARAMETER_ERR;
    	 case -2:
    		 union_err_log("In SMAPIEccSign::SOCKET SEND ERROR!");
    		 return CKR_SENDFAIL_ERR;
    	 case -3:
    		 union_err_log("In SMAPIEccSign::SOCKET RECIVE ERROR!");
    		 return CKR_RCVTMOUT_ERR;
    	 case -4:
    		 union_err_log("In SMAPIEccSign::SOCKET RECIVE CKR_PARAMETER_ERR ERROR!");
    		 return CKR_PARAMETER_ERR;
    	 default:
    	 	 break;
    	}
#ifdef	_DEBUG
    memset(debugBuff, 0x00, sizeof(debugBuff));
    UnpackBCD(rst_info, (char *) debugBuff, rst_len * 2);
    union_log("In SMAPIEccSign::[RESPOND]=[%d][%s]", rst_len, debugBuff);
#endif
    // get length of out data  
    memcpy(pcLen, rst_info, 4);
    *pnSignLen =  64;   // (int) atoi((char *) pcLen);

    // get content of out data 
    // 签名结果 R 部分
    // 签名结果 S 部分  20170424
    memcpy(pbSign, rst_info, *pnSignLen);

#ifdef	_DEBUG
    memset(debugBuff, 0x00, sizeof(debugBuff));
    UnpackBCD((char*)pbSign, (char *) debugBuff, (*pnSignLen) * 2);
    union_log("In SMAPIEccSign::Sign=[%d][%s]\n", *pnSignLen, debugBuff);
#endif
    return (0);
}


/*****************************************************************************************************/
/* 函数名称： SMAPIEccSign                                                                            */
/*           5.21 ECC 签名验证（7.4.6 SM2 验签）    "US"                                              */
/* 功能说明：                                                                                         */
/*               ECC 验证签名                                                                         */
/*		注：对输入数据计算摘要，对输入的签名进行公钥解密，比较计算出的摘要和解密出               */ 
/*		的摘要是否一致，非证书签名验证用接口。                                                 */
/* 输入参数：                                                                                        */ 
/*		UINT nSock：  连接的socket 句柄                                                      */
/*		int nEcMark： 椭圆曲线标识                                                           */
/*		              0x01：ECC 128 位，NIST P-256，公钥长度64 字节（暂不支持）               */
/*		              0x02：ECC 256 位，NIST P-521，公钥长度132 字节（暂不支持）              */
/*		              0x11：SM2 128 位，SM2 曲线，公钥长度64 字节                            */
/*		int nPad:     填充模式， 0：不填充(具体填充方式待补充，暂不支持)。                    */
/*		byte *pbPK：  公钥明文，二进制数，(字节)长度由nPKLen 指定                             */
/*		int nPKLen：  公钥数据长度，取值范围[1, 512]                                         */
/*		byte *pbData：签名对应的数据，二进制数，(字节)长度由nDataLen 指定                     */ 
/*		int nDataLen：pbData 的长度取值范围[1, 4096]                                         */
/*		byte *pbSign：签名值，二进制数，长度由nSignLen 指定                                   */  
/*		int nSignLen：pbSign 的长度                                                          */
/* 输出参数：                                                                                        */ 
/*               无                                                                                  */
/* 返回说明：                                                                                        */ 
/*		0： 验证成功                                                                         */  
/*		1： 输入参数验证失败                                                                 */
/*		2： 无效的密钥(PK)                                                                  */
/*		3： 向加密机发送数据失败                                                             */
/*		4： 接收加密机数据超时                                                               */
/*		5： 接收到的数据格式错                                                               */
/*		9:  其他错误                                                                        */
/*		10: Hash 结果匹配失败                                                               */
/* 维护记录：                                                                                       */
/*          2017-03-07 by zhaomx                                                                    */
/*****************************************************************************************************/ 
int SMAPIEccVerify (UINT nSock, int nEcMark, int nPad, byte *pbPK,int nPKLen, byte *pbData,
	            int nDataLen, byte *pbSign, int nSignLen)
{
    int  retCode=0;
    char cmd_info[40960 + 1];
    char rst_info[40960 + 1];
    char tmpBuf[1024]; 

    int  nCmd_len;
    int  rst_len;
    char *pcmd_info;
    int  pubKeyDerLen;
    int  pubKeyLen;
    int  rv;

    unsigned char pbDigestTemp[256];
    unsigned char pubKeyDer[1024 + 1];

    if (UnionIsSocket(nSock)<1)
    {
	union_err_log("In SMAPIEccVerify nSock error, [nSock=%u]", nSock);
	return(CKR_SENDFAIL_ERR);
    }

    if ((nEcMark < 0) || (nEcMark > 18)){
	union_err_log("In SMAPIEccVerify nAlgo error, [nAlgo=%d]", nEcMark);
        return(CKR_PARAMETER_ERR);
    }

    if ((nPad < 0) || (nPad > 2)){
	union_err_log("In SMAPIEccVerify nPad error, [nPad=%d]", nPad);
        return(CKR_PARAMETER_ERR);
    }
    
    if (NULL == pbPK){
        union_err_log("In SMAPIEccVerify [pbPK is NULL]");
        return(CKR_PARAMETER_ERR);
    }

    if ((nPKLen < 1) || (nPKLen > 2048)){
	union_err_log("In SMAPIEccVerify nPKLen error, [nPKLen=%d]", nPKLen);
        return(CKR_PARAMETER_ERR);
    }
    
    if (NULL == pbData){
        union_err_log("In SMAPIEccVerify [pbData is NULL]");
        return(CKR_PARAMETER_ERR);
    }    

    if ((nDataLen < 1) || (nDataLen > 4096)){
        union_err_log("In SMAPIEccVerify [nDataLen=%d]", nDataLen);
        return(CKR_PARAMETER_ERR);
    }

    if (NULL == pbSign){
        union_err_log("In SMAPIEccVerify [pbSign is NULL]");
        return(CKR_PARAMETER_ERR);
    }

#ifdef _DEBUG
    /* use for debug */
    unsigned char   debugBuff[8192+1];
    memset(debugBuff, 0x00, sizeof(debugBuff));
#endif

    memset(cmd_info, 0x00, sizeof(cmd_info));
    memset(rst_info, 0x00, sizeof(rst_info));

    memset(pbDigestTemp, 0x00, sizeof(pbDigestTemp));
    memset(pubKeyDer, 0x00, sizeof(pubKeyDer));

    /* command */
    pcmd_info = cmd_info;
    memcpy(pcmd_info, "US", 2);
    pcmd_info += 2;

    // 密钥索引index of private key  is 00  
    memcpy(pcmd_info, "00", 2);
    pcmd_info += 2;

    //公钥明文
    memcpy(pcmd_info, pbPK, nPKLen);
    pcmd_info += nPKLen;

    /* content of sign */
    if (pbSign != NULL) 
    {
	memcpy(pcmd_info, pbSign, nSignLen);
	pcmd_info += nSignLen;
    } 
    else
    {
	union_err_log("In SMAPIEccVerify::Parameter error,[pbSign] is NULL!");
	return CKR_PARAMETER_ERR;
    }

    //摘要方法
    sprintf(pcmd_info,"%02d",2);
    pcmd_info+=2;

    //用户标识长度
    memcpy(pcmd_info, "0016", 4);
    pcmd_info += 4;

    //用户标识
    memset(tmpBuf, 0, sizeof(tmpBuf));
    memcpy(pcmd_info, "1234567812345678", 16);
    pcmd_info += 16;

    //数据长度
    sprintf(pcmd_info,"%04d",nDataLen);
    pcmd_info+=4;
    
    //数据
    memcpy(pcmd_info,pbData,nDataLen);
    pcmd_info+=nDataLen;

#ifdef _DEBUG
    {
	memset(debugBuff, 0x00, sizeof(debugBuff));
	UnpackBCD((char*)pubKeyDer, (char *) debugBuff, pubKeyDerLen * 2);
	union_log("In SMAPIEccVerify::pubKeyDer=[%d][%s]", pubKeyDerLen, debugBuff);
    }
#endif
    /* set the last char '\0' */
    *pcmd_info = 0;

    /* calculate the length of requst package */
    nCmd_len = pcmd_info - cmd_info;
#ifdef	_DEBUG
    UnpackBCD(cmd_info, (char *)debugBuff, nCmd_len*2);
    union_log(" In SMAPIEccVerify::[REQUEST]=[%s][%d]", debugBuff,nCmd_len);
#endif
    rst_len = UnionHSMCmd(nSock, cmd_info, nCmd_len, rst_info, gUnionTimeout,&retCode);

    switch(rst_len)
    {
    	 case -1:
    		 union_err_log("In SMAPIEccVerify::SOCKET EDLL!");
    		 return CKR_PARAMETER_ERR;
    	 case -2:
    		 union_err_log("In SMAPIEccVerify::SOCKET SEND ERROR!");
    		 return CKR_SENDFAIL_ERR;
    	 case -3:
    		 union_err_log("In SMAPIEccVerify::SOCKET RECIVE ERROR!");
    		 return CKR_RCVTMOUT_ERR;
    	 case -4:
    		 union_err_log("In SMAPIEccVerify::SOCKET RECIVE CKR_PARAMETER_ERR ERROR!");
    		 return CKR_PARAMETER_ERR;
    	 default:
		 break;
    }       

#ifdef	_DEBUG
    UnpackBCD(rst_info, (char *) debugBuff, rst_len * 2);
    union_log("In SMAPIEccVerify::[RESPOND]=[%d][%s]", rst_len, debugBuff);
#endif

    return (0);
}

/*****************************************************************************************************/
/* 函数名称： SMAPISm4Calc                                                                            */
/*           5.22 SM4 加解密（7.3.6 数据加解密）    "V2"                                              */
/* 功能说明：                                                                                         */
/*                用SM4 算法以ECB、CBC 等模式对数据进行加解密。                                        */
/* 输入参数：                                                                                        */
/*		UINT nSock：       连接的socket 句柄                                                 */
/*		int nFlag：        加密、解密标志。1-加密；0-解密                                     */
/*		int nMode：        加密模式。ECB = 0；CBC = 1；（其它待补充）                         */
/*		byte * pbKey：     SM4 密钥的密文(由HMK 经3DES 加密)，二进制数，16 字节长             */
/*		byte *pbInData：   需要加密/解密的数据，二进制数, （字节）长度由nDataLen 指定          */
/*		int nDataLen：     数据长度，取值范围：16 的整数倍，小于等于4096                      */
/*		byte *pbIV：       初始化向量，二进制数，16 字节长  nMode = 1                        */
/* 输出参数：                                                                                       */
/*		byte *pbOutData：  经解密/加密后的输出数据，二进制数，（字节）长度由nDataLen指定      */
/* 返回值：                                                                                        */
/*		0： 成功                                                                           */
/*		1： 输入参数验证失败                                                                */
/*		2： 无效的密钥（KEY）                                                               */
/*		3： 向加密机发送数据失败                                                            */
/*		4： 接收加密机数据超时                                                              */
/*		5： 接收到的数据格式错                                                              */
/*		9:  其他错误                                                                        */
/* 维护记录：                                                                                       */
/*          2017-03-07 by zhaomx                                                                    */
/*****************************************************************************************************/ 
int SMAPISm4Calc (UINT nSock, int nFlag, int nMode, byte *pbKey, byte *pbInData, int nDataLen, byte *pbIV,
	          byte *pbOutData)
{
    int    retCode=0;
    int    nCmd_len = 0;
    int    nRc;
    char   *p = NULL;
    char   pcKey[48 + 1];
    char   tmpBuf[10240*8 + 1];
    char   cmd_info[10240*8];
    char   rst_info[10240*8 + 1];
    char   pcIV[16 + 1];
    int    ret=0;

    if(UnionIsSocket(nSock)<1)
    {
	union_err_log("In SMAPISm4Calc::parameter nSock=【%d】is eddle\n",nSock);
	return CKR_SENDFAIL_ERR;
    }

    if ((nFlag != 0) && (nFlag != 1))    
    {
	union_err_log("In SMAPISm4Calc::parameter nFlag=【%d】is eddle\n",nFlag);
	return (CKR_PARAMETER_ERR);
    }
    
    if((nMode !=0) &&  (nMode !=1))
    {
	union_err_log("In SMAPISm4Calc::parameter nMode=【%d】is eddle\n",nMode);
	return CKR_PARAMETER_ERR;
    }

    if ((NULL == pbKey) || (NULL == pbIV)  || ((strlen(pbKey)%16) != 0) || ((strlen(pbIV)%16) != 0))
    {
        union_err_log("In SMAPISm4Calc [pbKey is NULL or pbIV is NULL]");
        return(CKR_PARAMETER_ERR);
    }

    if ((nDataLen < 0) || (nDataLen > 4096)  || ((nDataLen%16) != 0))
    {
	union_err_log("In SMAPISm4Calc nDataLen error, [nDataLen=%d]", nDataLen);
        return(CKR_PARAMETER_ERR);
    }    

    memset(cmd_info, 0, sizeof(cmd_info));
    memset(rst_info, 0, sizeof(rst_info));

    p = cmd_info;
    // 命令
    memcpy(p, "V2", 2);
    p += 2;

    //算法类型   "1"-SM4 
    memcpy(p, "1", 1);
    p += 1;
	
    //密钥类型             zhamx-20170228
    //memcpy(p, "000", 3);
    //p += 3;
	
    //加解密密钥
    memcpy(p, "S", 1);
    p += 1;

    //memcpy(p, (char*)pbKey, 32);
    //p += 32;
    memset(tmpBuf, 0x00, sizeof(tmpBuf));
    UnpackBCD((char*)pbKey, tmpBuf, 32);
    memcpy(p, tmpBuf, 32);
    p += 32;

    //密钥离散次数 缺省为"0"
    memcpy(p, "0", 1);
    p += 1;

    //加/解密标识    1-加密；0-解密
    sprintf(p, "%d", nFlag);
    p += 1;

    //算法应用模式  ECB = 0；CBC = 1；
    sprintf(p, "%d", nMode);
    p += 1;

    //当算法模式为1时，初始向量IV
    if(nMode == 1)
    {
    	//memcpy(p, pbIV, strlen(pbIV));
    	//p += strlen(pbIV);
        ////des:16  sm4 :32    
        memset(tmpBuf, 0x00, sizeof(tmpBuf));
	UnpackBCD((char*)pbIV,tmpBuf, 32);
	memcpy(p,tmpBuf, 32);
    	p += 32;
    }

    //填充模式   1
    memcpy(p, "1", 1);
    p += 1;

    /* 计算数据长度 */
    sprintf(p, "%04d", nDataLen);
    p += 4;

    /* 计算数据 */
   /* memset(tmpBuf, 0x00, sizeof(tmpBuf));
    UnpackBCD((char*)pbInData, tmpBuf, (nDataLen*2));
    memcpy(p, tmpBuf, (nDataLen*2));
    p += (nDataLen*2);*/
    //2017-0418
    memcpy(p, pbInData, nDataLen);
    p += nDataLen;

    *p = 0;
    nCmd_len = p - cmd_info;
#ifdef	_DEBUG
    unsigned char debugBuff[40960];
    memset(debugBuff, 0x00, sizeof(debugBuff));
#endif

#ifdef	_DEBUG
    union_log("In SMAPISm4Calc::nCmd_len = [%d] cmd_info = [%s]", nCmd_len, cmd_info);
#endif

    nRc = UnionHSMCmd(nSock, cmd_info, nCmd_len, rst_info, gUnionTimeout,&retCode);

    ret= CheckCmdReturn(nRc,"SMAPISm4Calc",rst_info);
	
    switch(nRc)
    {
    	 case -1:
    	    	union_err_log("In SMAPISm4Calc::SOCKET EDLL!");
    	    	return CKR_PARAMETER_ERR;
    	 case -2:
    	    	union_err_log("In SMAPISm4Calc::SOCKET SEND ERROR!");
    	    	return CKR_SENDFAIL_ERR;
    	 case -3:
    	    	union_err_log("In SMAPISm4Calc::SOCKET RECIVE ERROR!");
    	    	return CKR_RCVTMOUT_ERR;
    	 case -4:
		union_err_log("In SMAPISm4Calc::SOCKET RECIVE CKR_PARAMETER_ERR ERROR!");
    	        return CKR_PARAMETER_ERR;
    	 default:
    	 	break;
    	}
#ifdef	_DEBUG
    memset(debugBuff, 0x00, sizeof(debugBuff));
    UnpackBCD(rst_info, (char *) debugBuff, nRc * 2);
    union_log("In SMAPISm4Calc::[RESPOND]=[%d][%s]", nRc, debugBuff);
#endif

  if(nRc<0) return ret;
#ifdef	_DEBUG
    union_log("In SMAPISm4Calc::rst_len = [%d] rst_info = [%s]", nRc, rst_info);
#endif
    if (nFlag == 1)       //加密
    {
    	memcpy(pbOutData, rst_info+4, nRc-4);
        
        memset(tmpBuf, 0x00, sizeof(tmpBuf));
        UnpackBCD((char*)pbOutData, tmpBuf, ((nRc-4)*2));
        printf("nRc is %d,pbOutData is %s\n",nRc-4,tmpBuf);
    }
    else if(nFlag ==0)    //解密
    {
        memcpy(pbOutData, rst_info+4, nRc-4);
        printf("nRc is %d,pbOutData is %s\n",nRc-4,pbOutData); 
    }
    return (0);

}

/*******************************************************************************************************/
/* 函数名称： SMAPITransKeyIntoSK                                                                       */
/*           5.23 RSA 私钥转加密（7.6.17 RSA 公私钥转加密）    "UE"                                      */
/* 功能说明：                                                                                           */
/*              将被RSA 算法的PK 加密的密钥（先用SK 解密再）转化为被HMK 加密                              */
/* 输入参数：                                                                                           */
/*		UINT nSock：      连接的socket 句柄                                                     */
/*		int nPad:         填充模式， 0：不填充；1：PKCS#1 填充算法；2：OAEP 填充算法              */
/*		byte *pbSK：      私钥的密文（被HMK 加密），DER 格式，二进制数，（字节）长度由nSKLen 指定  */
/*		int nSKLen：      私钥的长度, 取值范围[1, 2048]                                         */   
/*		byte *pbKeyByPK： 被公钥PK 加密的密钥，二进制数，密文数据（字节）长度由nKeyLen指定，      */
/*		int nKeyLen：     pbKeyByPK 的长度, 取值范围[8, 2048]并能被8 整除且不超过公钥模长。       */ 
/*		                  注：把“被HMK 加密的密钥”看做单纯的被HMK 加密的数据进行处理。            */  
/* 输出参数：                                                                                           */
/*		byte *pbKeyByHMK：被HMK 加密的密钥，二进制数，长度由*pnKeyByHMKLen 给出                  */
/*		int *pnKeyByHMKLen：pbKeyByHMK 的长度。                                                 */
/* 返回说明：                                                                                           */
/*		0： 执行成功                                                                            */
/*		1： 输入参数验证失败                                                                    */
/*		2： 无效的密钥(PK)                                                                      */
/*		3： 向加密机发送数据失败                                                                 */
/*		4： 接收加密机数据超时                                                                   */
/*		5： 接收到的数据格式错                                                                   */
/*		9:  其他错误                                                                            */
/* 维护记录：                                                                                           */
/*          2017-03-07 by zhaomx                                                                       */
/*******************************************************************************************************/ 
int SMAPITransKeyIntoSK(UINT nSock, int nPad, byte *pbSK, int nSKLen, byte *pbKeyByPK, int nKeyLen,
	                byte *pbKeyByHMK, int *pnKeyByHMKLen)
{
    int   retCode=0;
    char  cmd_info[40960 + 1];
    char  rst_info[40960 + 1];
    int   nRc,nCmd_len;
    int   rst_len;
    char  *pcmd_info = NULL;
    unsigned char tmpBuf[1024 + 1];
    unsigned char pcLen[1024 + 1];
    int   iDiff;	
    byte  *pbOutData;
    int   *pnOutLen;
    char  cmd_info_2[1000];
    int   iLen = 0;

    char tmp[200 + 1];
    int ret=0;
	
    if(UnionIsSocket(nSock)<1)
    {
    	union_err_log("In SMAPITransKeyIntoSK::nSKLen error! socket edle nSocket=[%d]\n",nSock);
	return CKR_PARAMETER_ERR;
    }

	
    if (nPad != 0 && nPad != 1 && nPad != 2)
    {
	union_err_log("In SMAPITransKeyIntoSK::parameter error! [nPad]=[%d]\n", nPad);
	return CKR_PARAMETER_ERR;
    }

    if(nSKLen<1 || nSKLen>2048)
    {
	union_err_log("In SMAPITransKeyIntoSK::nSKLen error! nSKLen=[%d]\n",nSKLen);
	return CKR_PARAMETER_ERR;
    }
	
    if(nSKLen<8 || nSKLen>2048  || (nSKLen%8) !=0  )
    {
	union_err_log("In SMAPITransKeyIntoSK::nKeyCipherLen error! nKeyCipherLen=[%d]\n",nSKLen);
	return CKR_PARAMETER_ERR;
    }
	
#ifdef	_DEBUG
    unsigned char debugBuff[40960];
    memset(debugBuff, 0x00, sizeof(debugBuff));
#endif

    memset(cmd_info, 0x00, sizeof(cmd_info));
    memset(rst_info, 0x00, sizeof(rst_info));
    memset(tmpBuf, 0x00, sizeof(tmpBuf));
    nCmd_len = 0;
    rst_len = 0;
    pcmd_info = NULL;

    /* command */
    pcmd_info = cmd_info;
    memcpy(pcmd_info, "UE", 2);
    pcmd_info += 2;

    //算法转换类型   02:RSA 公钥转 3DES 加密    04:RSA 公钥转 SM4 加密
    memcpy(pcmd_info, "02", 2);
    pcmd_info += 2;

    //填充模式      
    sprintf(pcmd_info, "%02d", nPad);
    pcmd_info += 2;

    //填充模式为2时：MGF： 01-MGF1;  MGF哈希算法:  01;  OAEP编码参数长: "02";  OAEP编码参数 :"12"
    if(nPad == 2)
    {
	memcpy(pcmd_info, "010100", 6);
	pcmd_info += 6;
    }

    //ntag zhaomx-2-28
    //sprintf(pcmd_info, "%03X", 0);
    //pcmd_info += 3;

    if(nKeyLen%8 !=0 ||nKeyLen<8 || nKeyLen>2048)
    {
	union_err_log("In SMAPITransKeyIntoSK::parameter [nKeyLen] is not valide iKeyByMfkLen=[%d]!",nKeyLen);
	return CKR_PARAMETER_ERR;
    }
    iLen=nKeyLen/8;

    //被加密密钥长度 
    sprintf(pcmd_info,"%04d",nKeyLen);
    pcmd_info+=4;

    //被加密密钥
    memset(tmpBuf,0,sizeof(tmpBuf));
    memcpy(pcmd_info,pbKeyByPK,nKeyLen);
    pcmd_info+=nKeyLen;
		
    //密钥索引号
    sprintf(pcmd_info,"%02d",0);
    pcmd_info+=2;

    //公钥编码格式   zhaomx   2017-4-24
    //sprintf(pcmd_info,"%01d",1);
    //pcmd_info+=1;

    /* private key length */
    sprintf(pcmd_info, "%04d", nSKLen);
    pcmd_info += 4;

    //RSA私钥密文	
    memcpy(pcmd_info, pbSK, nSKLen);
    pcmd_info += nSKLen;

    /* set the last char '\0' */
    *pcmd_info = 0;

    /* calculate the length of requst package */
    nCmd_len = pcmd_info - cmd_info;

#ifdef	_DEBUG
    memset(debugBuff, 0x00, sizeof(debugBuff));
    UnpackBCD(cmd_info, (char *)debugBuff, nCmd_len*2);
    union_log(" In SMAPITransKeyIntoSK::[REQUEST]=[%d][%s]", nCmd_len, debugBuff);
#endif

    rst_len = UnionHSMCmd(nSock, cmd_info, nCmd_len, rst_info, gUnionTimeout,&retCode);
    switch(rst_len)
    {
    	 case -1:
    		 union_err_log("In SMAPITransKeyIntoSK::SOCKET EDLL!");
    		 return CKR_PARAMETER_ERR;
    	 case -2:
    		 union_err_log("In SMAPITransKeyIntoSK::SOCKET SEND ERROR!");
    		 return CKR_SENDFAIL_ERR;
    	 case -3:
    		 union_err_log("In SMAPITransKeyIntoSK::SOCKET RECIVE ERROR!");
    		 return CKR_RCVTMOUT_ERR;
    	 case -4:
    		 union_err_log("In SMAPITransKeyIntoSK::SOCKET RECIVE  CKR_PARAMETER_ERR ERROR!");
    		 return CKR_PARAMETER_ERR;
    	 default:
		 break;
    }

#ifdef	_DEBUG
    memset(debugBuff, 0x00, sizeof(debugBuff));
    UnpackBCD(rst_info, (char *) debugBuff, rst_len * 2);
    union_log("In SMAPITransKeyIntoSK::[RESPOND]=[%d][%s]", rst_len, debugBuff);
#endif

    /* Get the length of the key encryted by public key */
    memset(pcLen, 0x00, sizeof(pcLen));
    memcpy(pcLen, rst_info, 4);
 
    if(nPad==0)
        *pnKeyByHMKLen = atoi((char*)pcLen);
    else
        *pnKeyByHMKLen = atoi((char*)pcLen);

    /* Get content of the key */
 
    memset(tmpBuf,0,sizeof(tmpBuf));
    if(nPad==0)
    	memcpy(tmpBuf, rst_info + 4, *pnKeyByHMKLen);
    else
    	memcpy(tmpBuf, rst_info + 4, *pnKeyByHMKLen);

    //20170424
    //UnpackBCD(tmpBuf,pbKeyByHMK,*pnKeyByHMKLen*2);
    memcpy(pbKeyByHMK,tmpBuf,*pnKeyByHMKLen);

    return CKR_SMAPI_OK;

}

/**************************************************************************************************************/
/* 函数名称： SMAPISm2PKTransOutof                                                                             */
/*           5.24 SM2 公钥转加密（7.6.18 SM2 公私钥转加密）   //算法转换类型  01:3DES 加密转 SM2 公钥加密   "UC" */
/* 功能说明：                                                                                                  */
/*              将被HMK 加密的数据转化为被SM2 算法的PK 加密                                                     */
/* 输入参数：                                                                                                 */
/*		UINT nSock：      连接的socket 句柄                                                           */
/*		int nEcMark：     椭圆曲线标识                                                                */
/*				  0x01：ECC 128 位，NIST P-256，公钥长度64 字节（暂不支持）                    */
/*				  0x02：ECC 256 位，NIST P-521，公钥长度132 字节（暂不支持）                   */
/*				  0x11：SM2 128 位，SM2 曲线，公钥长度64 字节                                  */
/*		int nPad:         填充模式， 0：不填充（具体填充方式待补充，暂不支持）                          */
/*		byte *pbPK：      公钥的明文，二进制数，（字节）长度由nPKLen 指定                               */
/*		int nPKLen：      公钥的长度, 取值范围[1, 512]                                                 */
/*		byte *pbKeyByHMK：被HMK 加密的密钥，二进制数，长度由nKeyLen 指定，                              */
/*		int nKeyLen：     pbKeyByHMK 的长度, 取值范围[8, 2048]并能被8 整除且不超过公钥模长。            */
/*				  注：把“被HMK 加密的密钥”看做单纯的被HMK 加密的数据进行处理。                  */
/* 输出参数：                                                                                                 */
/*		byte *pbKeyByPK：被PK 加密的密钥，二进制数，长度由*pnKeyByPKLen 给出                           */
/*		int *pnKeyByPKLen：pbKeyByPK 的长度，等于公钥模长。                                           */
/* 返回值：                                                                                                  */
/*		0： 执行成功                                                                                 */
/*		1： 输入参数验证失败                                                                         */
/*		2： 无效的密钥(PK)                                                                           */
/*		3： 向加密机发送数据失败                                                                      */
/*		4： 接收加密机数据超时                                                                        */
/*		5： 接收到的数据格式错                                                                        */
/*		9:  其他错误                                                                                 */
/* 维护记录：                                                                                                */
/*          2017-03-07 by zhaomx                                                                            */
/************************************************************************************************************/ 
int SMAPISm2PKTransOutof(UINT nSock, int nEcMark, int nPad, byte *pbPK,int nPKLen, byte *pbKeyByHMK, int nKeyLen, 
	                 byte *pbKeyByPK, int  *pnKeyByPKLen)
{
    int retCode = 0;
    int nCmd_len = 0;
    int rst_len = 0;
    int pubKeyDDerLen = 0;
    int iMkLen = 0;
    int iModLen = 0, iExpLen = 0; 
    int iLen;  
 
    char cmd_info[40960 + 1];
    char rst_info[40960 + 1];
    char *pcmd_info = NULL;
    
    unsigned char pubKeyDDer[10240 + 2];
    unsigned char KeyByHsm[10240 + 1];
    unsigned char pcLen[8 + 1];
    char          tmpBuf[12800];
	
    char mod[MAX_MODULUS_LEN+1];
    char exp[MAX_MODULUS_LEN+1];

    if (UnionIsSocket(nSock)<1)
    {
	union_err_log("In SMAPISm2PKTransOutof nSock error, [nSock=%u]", nSock);
	return(CKR_SENDFAIL_ERR);
    }

    if (nPad > 3) {
	union_err_log("In SMAPISm2PKTransOutof nPad error, [nPad=%u]", nPad);
        return(CKR_PARAMETER_ERR);
    }
    
    if (NULL == pbPK) {
        union_err_log("In SMAPISm2PKTransOutof [pbPK is NULL]");
        return(CKR_PARAMETER_ERR);
    }

    if ((nPKLen < 1) || (nPKLen > 512)) {
        union_err_log("In SMAPISm2PKTransOutof, [nPKLen=%u]", nPKLen);
        return(CKR_PARAMETER_ERR);
    }

    if (NULL == pbKeyByPK) {
        union_err_log("In SMAPISm2PKTransOutof [pbKeyByMfk is NULL]");
        return(CKR_PARAMETER_ERR);
    }

    if (((nKeyLen < 8) || (nKeyLen > 2048)) && (0 != (nKeyLen % 8))) {
        union_err_log("In SMAPISm2PKTransOutof [iKeyByMfkLen=%d]", nKeyLen);
        return(CKR_PARAMETER_ERR);
    } 
   
#ifdef	_DEBUG
    unsigned char debugBuff[40960];
    memset(debugBuff, 0x00, sizeof(debugBuff));
#endif

    memset(cmd_info, 0x00, sizeof(cmd_info));
    memset(rst_info, 0x00, sizeof(rst_info));

    nCmd_len = 0;
    rst_len = 0;
    pcmd_info = NULL;

    /* command */
    pcmd_info = cmd_info;
    memcpy(pcmd_info, "UC", 2);
    pcmd_info += 2;

    //算法转换类型  01:3DES 加密转 SM2 公钥加密 03：SM4加密转SM2公钥加密
    memcpy(pcmd_info, "01", 2);
    pcmd_info += 2;

    //被加密密钥类型密钥 Tag     
    //sprintf(pcmd_info, "%03d", nPad);
    //pcmd_info += 3;

    if(nKeyLen%8 !=0 ||nKeyLen<8 || nKeyLen>2048)
    {
	union_err_log("In SMAPISm2PKTransOutof::parameter [nKeyLen] is not valide nKeyLen=[%d]!",nKeyLen);
	return CKR_PARAMETER_ERR;
    }
    iLen=nKeyLen/8;

    //被加密密钥长度
    memset(tmpBuf,0,sizeof(tmpBuf));
    sprintf(tmpBuf,"%04d",nKeyLen);
    memcpy(pcmd_info,tmpBuf,4);
    pcmd_info+=4;
							
    //被加密密钥
    memcpy(pcmd_info,pbKeyByHMK,nKeyLen);
    pcmd_info+=nKeyLen;

    //密钥索引号
    memcpy(pcmd_info, "00", 2);
    pcmd_info += 2;

    //SM2 公钥	
   /* memset(tmpBuf,0,sizeof(tmpBuf));
    PackBCD((char*)pbPK,tmpBuf, nPKLen*2);
    memcpy(pcmd_info, tmpBuf, nPKLen*2);
    pcmd_info += nPKLen; */
    //20170418 
    memcpy(pcmd_info, pbPK, nPKLen);
    pcmd_info += nPKLen;

    /* set the last char '\0' */
    *pcmd_info = 0;

    /* calculate the length of requst package */
    nCmd_len = pcmd_info - cmd_info;

#ifdef	_DEBUG
    memset(debugBuff, 0x00, sizeof(debugBuff));
    UnpackBCD(cmd_info, (char *)debugBuff, nCmd_len*2);
    union_log(" In SMAPISm2PKTransOutof::[REQUEST]=[%d][%s]", nCmd_len, debugBuff);
#endif

    rst_len = UnionHSMCmd(nSock, cmd_info, nCmd_len, rst_info, gUnionTimeout,&retCode);

    switch(rst_len)
    {
    	 case -1:
    		 union_err_log("In SMAPISm2PKTransOutof::SOCKET EDLL!");
    		 return CKR_PARAMETER_ERR;
    	 case -2:
    		 union_err_log("In SMAPISm2PKTransOutof::SOCKET SEND ERROR!");
    		 return CKR_SENDFAIL_ERR;
    	 case -3:
    		 union_err_log("In SMAPISm2PKTransOutof::SOCKET RECIVE ERROR!");
    		 return CKR_RCVTMOUT_ERR;
    	  case -4:
    		 union_err_log("In SMAPISm2PKTransOutof::SOCKET RECIVE  CKR_PARAMETER_ERR ERROR!");
    		 return CKR_PARAMETER_ERR;
    	 default:
		 break;
    }

#ifdef	_DEBUG
    memset(debugBuff, 0x00, sizeof(debugBuff));
    UnpackBCD(rst_info, (char *) debugBuff, rst_len * 2);
    union_log("In SMAPISm2PKTransOutof::[RESPOND]=[%d][%s]", rst_len, debugBuff);
#endif

    /* Get the length of the key encryted by public key */
    memset(pcLen, 0x00, sizeof(pcLen));
    memcpy(pcLen, rst_info, 4);
    if(nPad==0)
        *pnKeyByPKLen = atoi((char*)pcLen);
    else
        *pnKeyByPKLen = atoi((char*)pcLen);

    /* Get content of the key */
    memset(tmpBuf,0,sizeof(tmpBuf));
    if(nPad==0)
    	memcpy(tmpBuf, rst_info + 4, *pnKeyByPKLen);
    else
    	memcpy(tmpBuf, rst_info + 4, *pnKeyByPKLen);

    UnpackBCD(tmpBuf,pbKeyByPK,*pnKeyByPKLen*2);
    
    return (0);
}

/**************************************************************************************************************/
/* 函数名称： SMAPISm2SKTransInto                                                                             */
/*           5.25 SM2 私钥转加密（7.6.18 SM2 公私钥转加密）  农行   "UC"                                       */
/* 功能说明：                                                                                                  */
/*		将被SM4 算法PK 加密的密钥（先用SK 解密再）转化为被HMK 加密                                       */
/* 输入参数：                                                                                                  */   
/*		UINT nSock：     连接的socket 句柄                                                             */
/*		int nEcMark：    椭圆曲线标识                                                                  */
/*		                 0x01：ECC 128 位，NIST P-256，公钥长度64 字节（暂不支持）                      */ 
/*				 0x02：ECC 256 位，NIST P-521，公钥长度132 字节（暂不支持）                     */
/*				 0x11：SM2 128 位，SM2 曲线，公钥长度64 字节                                   */
/*		int nPad:        填充模式， 0：不填充（具体填充方式待补充，暂不支持）                            */
/*		byte *pbSK：     私钥的密文（被HMK 加密），二进制数，（字节）长度由nSKLen 指定                   */
/*		int nSKLen：     私钥的长度, 取值范围[1, 256]                                                  */
/*		byte *pbKeyByPK：被公钥PK 加密的密钥，二进制数，密文数据（字节）长度由nKeyLen	指定，        */
/*		int nKeyLen：    pbKeyByPK 的长度, 取值范围[8, 2048]并能被8 整除且不超过公钥模长。              */
/*				 注：把“被HMK 加密的密钥”看做单纯的被HMK 加密的数据进行处理。                   */
/* 输出参数：                                                                                                 */
/*		byte *pbKeyByHMK：被HMK 加密的密钥，二进制数，长度由*pnKeyByHMKLen 给出                        */
/*		int *pnKeyByHMKLen：pbKeyByHMK 的长度。                                                      */
/* 返回值：                                                                                                  */
/*		0： 执行成功                                                                                 */
/*		1： 输入参数验证失败                                                                          */
/*		2： 无效的密钥(PK)                                                                            */
/*		3： 向加密机发送数据失败                                                                      */
/*		4： 接收加密机数据超时                                                                        */
/*		5： 接收到的数据格式错                                                                        */
/*		9:  其他错误                                                                                 */
/* 维护记录：                                                                                                */
/*          2017-03-07 by zhaomx                                                                             */
/*************************************************************************************************************/ 
int SMAPISm2SKTransInto(UINT nSock, int nEcMark, int nPad, byte *pbSK,int nSKLen, byte *pbKeyByPK, int nKeyLen, 
	                byte *pbKeyByHMK, int  *pnKeyByHMKLen)
{
    int   retCode=0;
    char  cmd_info[40960 + 1];
    char  rst_info[40960 + 1];
    int   nRc,nCmd_len;
    int   rst_len;
    char  *pcmd_info = NULL;
    byte  *pbOutData;
    int   *pnOutLen;
    char  cmd_info_2[1000];
    char  tmp[200 + 1];
    int   ret=0;
    int   iLen = 0; 

    unsigned char tmpBuf[1024 + 1];
    unsigned char pcLen[1024 + 1];

    if(UnionIsSocket(nSock)<1)
    {
    	union_err_log("In SMAPISm2SKTransInto::nSKLen error! socket edle nSocket=[%d]\n",nSock);
	return CKR_PARAMETER_ERR;
    }

	
    if (nPad != 0 && nPad != 1 && nPad != 2)
    {
	union_err_log("In SMAPISm2SKTransInto::parameter error! [nPad]=[%d]\n", nPad);
	return CKR_PARAMETER_ERR;
    }

    if(nSKLen<1 || nSKLen>256)
    {
	union_err_log("In SMAPISm2SKTransInto::nSKLen error! nSKLen=[%d]\n",nSKLen);
	return CKR_PARAMETER_ERR;
    }
	
    if(nSKLen<8 || nSKLen>256  || (nSKLen%8) !=0  )
    {
	union_err_log("In SMAPISm2SKTransInto::nKeyCipherLen error! nKeyCipherLen=[%d]\n",nSKLen);
	return CKR_PARAMETER_ERR;
    }
	
#ifdef	_DEBUG
    unsigned char debugBuff[40960];
    memset(debugBuff, 0x00, sizeof(debugBuff));
#endif

    memset(cmd_info, 0x00, sizeof(cmd_info));
    memset(rst_info, 0x00, sizeof(rst_info));
    memset(tmpBuf, 0x00, sizeof(tmpBuf));
    nCmd_len = 0;
    rst_len = 0;
    pcmd_info = NULL;

    /* command */
    pcmd_info = cmd_info;
    memcpy(pcmd_info, "UC", 2);
    pcmd_info += 2;

    //算法转换类型  02: SM2 公钥转 3DES 加密 04：SM2 公钥转 SM4 加密
    memcpy(pcmd_info, "02", 2);
    pcmd_info += 2;

    //被加密密钥类型密钥 Tag     
    /*sprintf(pcmd_info, "%03d", nPad);
    pcmd_info += 3;*/

    if(nKeyLen%8 !=0 ||nKeyLen<8 || nKeyLen>2048)
    {
	union_err_log("In SMAPISm2SKTransInto::parameter [nKeyLen] is not valide nKeyLen=[%d]!",nKeyLen);
	return CKR_PARAMETER_ERR;
    }
    iLen=nKeyLen/8;

    //被加密密钥长度
    memset(tmpBuf,0,sizeof(tmpBuf));
    sprintf(tmpBuf,"%04d",nKeyLen);
    memcpy(pcmd_info,tmpBuf,4);
    pcmd_info+=4;
							
    //被加密密钥
    memset(tmpBuf,0,sizeof(tmpBuf));
    memcpy(pcmd_info,pbKeyByPK,nKeyLen);
    pcmd_info+=nKeyLen;
		
    //密钥索引号
    memcpy(pcmd_info, "00", 2);
    pcmd_info += 2;

    // private key length 20170421
    //sprintf(pcmd_info, "%04d", nSKLen);
    //pcmd_info += 4;

    //SM2 私钥密文
  /*
    memset(tmpBuf,0,sizeof(tmpBuf));
    PackBCD((char*)pbSK,tmpBuf, nSKLen*2);
    memcpy(pcmd_info, pbSK, nSKLen*2);
    pcmd_info += nSKLen;*/
    //20170418
    memcpy(pcmd_info, pbSK, nSKLen);
    pcmd_info += nSKLen;

    /* set the last char '\0' */
    *pcmd_info = 0;

    /* calculate the length of requst package */
    nCmd_len = pcmd_info - cmd_info;

#ifdef	_DEBUG
    memset(debugBuff, 0x00, sizeof(debugBuff));
    UnpackBCD(cmd_info, (char *)debugBuff, nCmd_len*2);
    union_log(" In SMAPISm2SKTransInto::[REQUEST]=[%d][%s]", nCmd_len, debugBuff);
#endif

    rst_len = UnionHSMCmd(nSock, cmd_info, nCmd_len, rst_info, gUnionTimeout,&retCode);

    switch(rst_len)
    {
    	 case -1:
    		 union_err_log("In SMAPISm2SKTransInto::SOCKET EDLL!");
    		 return CKR_PARAMETER_ERR;
    	 case -2:
    		 union_err_log("In SMAPISm2SKTransInto::SOCKET SEND ERROR!");
    		 return CKR_SENDFAIL_ERR;
    	 case -3:
    		 union_err_log("In SMAPISm2SKTransInto::SOCKET RECIVE ERROR!");
    		 return CKR_RCVTMOUT_ERR;
    	  case -4:
    		 union_err_log("In SMAPISm2SKTransInto::SOCKET RECIVE  CKR_PARAMETER_ERR ERROR!");
    		 return CKR_PARAMETER_ERR;
    	 default:
		 break;
    }

#ifdef	_DEBUG
    memset(debugBuff, 0x00, sizeof(debugBuff));
    UnpackBCD(rst_info, (char *) debugBuff, rst_len * 2);
    union_log("In SMAPISm2SKTransInto::[RESPOND]=[%d][%s]", rst_len, debugBuff);
#endif

    /* Get the length of the key encryted by public key */
    memset(pcLen, 0x00, sizeof(pcLen));
    memcpy(pcLen, rst_info, 4);
    if(nPad==0)
        *pnKeyByHMKLen = atoi((char*)pcLen);
    else
        *pnKeyByHMKLen = atoi((char*)pcLen);

    /* Get content of the key */
    memset(tmpBuf,0,sizeof(tmpBuf));
    if(nPad==0)
    	memcpy(tmpBuf, rst_info + 4, *pnKeyByHMKLen);
    else
    	memcpy(tmpBuf, rst_info + 4, *pnKeyByHMKLen);


    //UnpackBCD(tmpBuf,pbKeyByHMK,*pnKeyByHMKLen*2);
    //20170424
    memcpy(pbKeyByHMK,tmpBuf,*pnKeyByHMKLen);

    return CKR_SMAPI_OK;

}

/**************************************************************************************************************/
/* 函数名称： SMAPITransKeyDesToSm4                                                                           */
/*           5.26 DES到SM4 密钥转加密（7.3.5 数据转加密）  农行   "VS"                                         */
/* 功能说明：                                                                                                 */
/*		将被DES算法加密的密钥密文，转换为以SM4 加密的密文。                                             */
/* 输入参数：                                                                                                 */
/*		UINT nSock：         连接的socket 句柄                                                        */
/*		int nAlgo：          DES 加密算法类型。Single_Des = 1，Double_Des = 2 ,Triple_Des = 3         */ 
/*		byte *pbDesKey：     经HMK 加密的DES-Key 的密文值，二进制数，（字节）长度由算法确定             */
/*		byte *pbSm4Key：     经HMK 加密的SM4-Key 的密文值，二进制数，（字节）长度=16                   */
/*		byte *pbKeyUnderDes：被DES-Key 加密的密钥密文，二进制数，（字节）长度=16                       */
/* 输出参数：                                                                                                */
/*		byte *pbKeyUnderSm4：被SM4-Key 加密的密钥的密文，二进制数，长度=16                            */
/* 返回值：                                                                                                  */
/*		0： 成功                                                                                     */
/*		1： 输入参数验证失败                                                                          */
/*		3： 向加密机发送数据失败                                                                      */
/*		4： 接收加密机数据超时                                                                        */
/*		5： 接收到的数据格式错                                                                        */
/*		9:  其他错误                                                                                 */
/* 维护记录：                                                                                                */
/*          2017-03-07 by zhaomx                                                                             */
/*************************************************************************************************************/ 
int SMAPITransKeyDesToSm4(UINT nSock, int nAlgo, byte *pbDesKey, byte  *pbSm4Key, byte *pbKeyUnderDes, 
	                  byte *pbKeyUnderSm4)
{
    int    retCode=0;
    int    nCmd_len = 0;
    int    nRc;
    char   *p = NULL;
    char   pcKey[48 + 1];
    char   pcPlainBlock[16 + 1];
    char   cmd_info[10240];
    unsigned char   tmpBuf[10240];
    char   rst_info[10240 + 1];
    char   pcIV[16 + 1];
    int    ret=0;

    if(UnionIsSocket(nSock)<1)
    {
	union_err_log("In SMAPITransKeyDesToSm4::parameter nSock=【%d】is eddle\n",nSock);
	return CKR_SENDFAIL_ERR;
    }

    if (nAlgo != 1 && nAlgo != 2 && nAlgo != 3)
    {
	union_err_log("In SMAPITransKeyDesToSm4::parameter error! [nPad]=[%d]\n", nAlgo);
	return CKR_PARAMETER_ERR;
    }

    if (NULL == pbDesKey) {
        union_err_log("In SMAPITransKeyDesToSm4 [pbDesKey is NULL]");
        return(CKR_PARAMETER_ERR);
    }

    if (NULL == pbSm4Key) {
        union_err_log("In SMAPITransKeyDesToSm4 [pbSm4Key is NULL]");
        return(CKR_PARAMETER_ERR);
    }

    if (NULL == pbKeyUnderDes) {
        union_err_log("In SMAPITransKeyDesToSm4 [pbKeyUnderDes is NULL]");
        return(CKR_PARAMETER_ERR);
    }


    memset(pcPlainBlock, 0, sizeof(pcPlainBlock));
    memset(cmd_info, 0, sizeof(cmd_info));
    memset(rst_info, 0, sizeof(rst_info));

    p = cmd_info;
    
    //命令
    memcpy(p, "VS", 2);
    p += 2;
    
    //解密算法类型   "1"- SM4  "2"-SM1  "3"-3DES  "4"-AES 
    memcpy(p, "3", 1);
    p += 1;
    
    //密钥类型  zhaomx-2017-02-27
    //memcpy(p, "000",3);
    //p += 3;
    if(nAlgo == 1)
    {

    } 
    else if(nAlgo == 2)
    {
	memcpy(p, "X", 1);
	p += 1;
    }
    else if(nAlgo == 3)
    {
	memcpy(p, "Y", 1);
	p += 1;
    }

    //printf("strlen(pbDesKey) is %d\n",strlen(pbDesKey));
    memset(pcKey, 0, sizeof(pcKey));
    UnpackBCD((char*)pbDesKey, pcKey, nAlgo*16);
    memcpy(p, pcKey, nAlgo*16);
    p += (nAlgo*16);

    //解密算法模式  '0'-ECB   '1'-CBC
    memcpy(p, "0", 1);
    p += 1;

    if (((nAlgo != 1) && (nAlgo != 2) && (nAlgo != 3)))   
    {
	union_err_log("In SMAPITransKeyDesToSm4::parameter nAlgo=【%d】is eddle\n",nAlgo);
	return (CKR_PARAMETER_ERR);
    }

    //CBC模式   加密 IV
    //memset(pcIV, 0, sizeof(pcIV));
    //UnpackBCD((char*)pbKeyUnderDes, pcIV, CBCIVLEN*2);
    //memcpy(p, pcIV, CBCIVLEN*2);
    //p += (CBCIVLEN*2);

    //加密算法类型
    sprintf(p, "%d", 1);
    p += 1;
	
    //密钥类型   zhaomx-2017-02-27
    //memcpy(p, "000",3);
    //p += 3;

    memcpy(p, "S", 1);
    p += 1;

    memset(pcKey, 0, sizeof(pcKey));
    UnpackBCD((char*)pbSm4Key, pcKey, 32);
    memcpy(p, pcKey, 32);
    p += 32;

    //加密算法模式  '0'-ECB   '1'-CBC
    memcpy(p, "0", 1);
    p += 1;

    //数据长度 
   // memset(tmpBuf ,0,sizeof(tmpBuf));
   // memcpy(tmpBuf,(unsigned char*)pbKeyUnderDes,1024);

    sprintf(p,"%04d",strlen(pbKeyUnderDes)/2);
    p += 4;

    /* in data */
    //memset(tmpBuf, 0x00, sizeof(tmpBuf));
    //UnpackBCD((char*)pbKeyUnderDes, tmpBuf, strlen(pbKeyUnderDes));
    //memcpy(p, tmpBuf, strlen(pbKeyUnderDes));
    //p += strlen(pbKeyUnderDes);

    memcpy(p, pbKeyUnderDes, strlen(pbKeyUnderDes));
    p += strlen(pbKeyUnderDes)/2;

    *p = 0;
    nCmd_len = p - cmd_info;

#ifdef	_DEBUG
    union_log("In SMAPITransKeyDesToSm4::nCmd_len = [%d] cmd_info = [%s]", nCmd_len, cmd_info);
#endif

    nRc = UnionHSMCmd(nSock, cmd_info, nCmd_len, rst_info, gUnionTimeout,&retCode);

    ret= CheckCmdReturn(nRc,"SMAPITransKeyDesToSm4",rst_info);

    if(nRc<0) return ret;
#ifdef	_DEBUG
    union_log("In SMAPITransKeyDesToSm4::rst_len = [%d] rst_info = [%s]", nRc, rst_info);
#endif

    memcpy(pbKeyUnderSm4, rst_info+4, nRc-4);
    
    return (0);
}


/*************************************************************************************************************/
/* 函数名称： SMAPITransKeySm4ToDes                                                                          */
/*           5.27 SM4 到DES 密钥转加密（7.3.5 数据转加密）  农行   "VS"                                       */
/* 功能说明：                                                                                                */
/*              将被SM4算法加密的密钥密文，转换为以DES加密的密文。                                             */ 
/* 输入参数：                                                                                                */
/*	        UINT nSock：         连接的socket 句柄                                                       */
/*		int  nAlgo：         DES加密算法类型。Single_Des = 1，Double_Des = 2 ,Triple_Des = 3         */
/*		byte *pbSm4Key：     经HMK加密的SM4-Key 的密文值，二进制数，（字节）长度=16                   */
/*		byte *pbDesKey：     经HMK加密的DES-Key 的密文值，二进制数，（字节）长度由算法确定             */
/*		byte *pbKeyUnderSm4：被SM4-Key 加密的密钥密文，二进制数，（字节）长度=16                      */ 
/* 输出参数：                                                                                               */
/*		byte *pbKeyUnderDes：被DES-Key 加密的密钥的密文，二进制数，长度=16                            */
/* 返回值：                                                                                                 */
/*		0： 成功                                                                                    */
/*		1： 输入参数验证失败                                                                         */
/*		3： 向加密机发送数据失败                                                                     */
/*		4： 接收加密机数据超时                                                                       */
/*		5： 接收到的数据格式错                                                                       */
/*		9:  其他错误                                                                                */
/* 维护记录：                                                                                               */
/*          2017-03-07 by zhaomx                                                                            */
/************************************************************************************************************/ 
int SMAPITransKeySm4ToDes(UINT nSock, int nAlgo, byte *pbSm4Key, byte *pbDesKey, byte *pbKeyUnderSm4, 
	                  byte *pbKeyUnderDes)
{

    int   retCode=0;
    int   nCmd_len = 0;
    int   nRc;
    char  *p = NULL;
    char  pcKey[48 + 1];
    char  pcPlainBlock[16 + 1];
    char  cmd_info[10240];
    char  tmpBuf[10240];
    char  rst_info[10240 + 1];
    char  pcIV[16 + 1];
    int   ret=0;
 
    if(UnionIsSocket(nSock)<1)
    {
	union_err_log("In SMAPITransKeySm4ToDes::parameter nSock=【%d】is eddle\n",nSock);
	return CKR_SENDFAIL_ERR;
    }

    if (nAlgo != 1 && nAlgo != 2 && nAlgo != 3)
    {
	union_err_log("In SMAPITransKeySm4ToDes::parameter error! [nPad]=[%d]\n", nAlgo);
	return CKR_PARAMETER_ERR;
    }

    if (NULL == pbDesKey) {
        union_err_log("In SMAPITransKeySm4ToDes [pbDesKey is NULL]");
        return(CKR_PARAMETER_ERR);
    }

    if (NULL == pbSm4Key) {
        union_err_log("In SMAPITransKeySm4ToDes [pbSm4Key is NULL]");
        return(CKR_PARAMETER_ERR);
    }

    if (NULL == pbKeyUnderSm4) {
        union_err_log("In SMAPITransKeySm4ToDes [pbKeyUnderDes is NULL]");
        return(CKR_PARAMETER_ERR);
    }


    memset(pcPlainBlock, 0, sizeof(pcPlainBlock));
    memset(cmd_info, 0, sizeof(cmd_info));
    memset(rst_info, 0, sizeof(rst_info));

    p = cmd_info;
    memcpy(p, "VS", 2);
    p += 2;

   //解密算法类型   "1"- SM4  "2"-SM1  "3"-3DES  "4"-AES 
    memcpy(p, "1", 1);
    p += 1;
    
    //密钥类型    zhaomx-2-28
    //memcpy(p, "000",3);
    //p += 3;

    memcpy(p, "S", 1);
    p += 1;

    memset(pcKey, 0, sizeof(pcKey));
    UnpackBCD((char*)pbSm4Key, pcKey, 32);
    memcpy(p, pcKey, 32);
    p += 32;

    //解密算法模式  '0'-ECB   '1'-CBC
    memcpy(p, "0", 1);
    p += 1;

    if (((nAlgo != 1) && (nAlgo != 2) && (nAlgo != 3)))   
    {
	union_err_log("In SMAPITransKeySm4ToDes::parameter nAlgo=【%d】is eddle\n",nAlgo);
	return (CKR_PARAMETER_ERR);
    }

    //CBC模式   加密 IV
    //memset(pcIV, 0, sizeof(pcIV));
    //UnpackBCD((char*)pbKeyUnderDes, pcIV, CBCIVLEN*2);
    //memcpy(p, pcIV, CBCIVLEN*2);
    //p += (CBCIVLEN*2);

    //加密算法类型
    sprintf(p, "%d", 3);
    p += 1;
	
    //密钥类型   zhaomx-
   // memcpy(p, "000",3);
   // p += 3;

    if(nAlgo == 1)
    {

    } 
    else if(nAlgo == 2)
    {
	memcpy(p, "X", 1);
	p += 1;
    }
    else if(nAlgo == 3)
    {
	memcpy(p, "Y", 1);
	p += 1;
    }

    memset(pcKey, 0, sizeof(pcKey));
    UnpackBCD((char*)pbDesKey, pcKey, nAlgo*16);
    memcpy(p, pcKey, nAlgo*16);
    p += (nAlgo*16);

    //加密算法模式  '0'-ECB   '1'-CBC
    memcpy(p, "0", 1);
    p += 1;

    //CBC模式   加密 IV
    //memcpy(p, pbIV, CBCIVLEN);
    //p += strlen(pbIV);
    //sprintf(p, "%04d", nBlockLen);   // by liubn
    //p += 4;
    //memcpy(p, pbPlainBlock, nBlockLen);
     //p += nBlockLen;

    //数据长度  
    sprintf(p,"%04d",16);
    p += 4;

    /* in data */
    //memset(tmpBuf, 0x00, sizeof(tmpBuf));
    //UnpackBCD((char*)pbKeyUnderSm4, tmpBuf, strlen(pbKeyUnderSm4));
    //memcpy(p, tmpBuf, strlen(pbKeyUnderSm4));
    //p += strlen(pbKeyUnderSm4);

    memcpy(p, pbKeyUnderSm4, 16);
    p += 16;

    *p = 0;
    nCmd_len = p - cmd_info;

#ifdef	_DEBUG
    union_log("In SMAPITransKeySm4ToDes::nCmd_len = [%d] cmd_info = [%s]", nCmd_len, cmd_info);
#endif

    nRc = UnionHSMCmd(nSock, cmd_info, nCmd_len, rst_info, gUnionTimeout,&retCode);

    ret= CheckCmdReturn(nRc,"SMAPITransKeySm4ToDes",rst_info);

    if(nRc<0) return ret;
#ifdef	_DEBUG
    union_log("In SMAPITransKeySm4ToDes::rst_len = [%d] rst_info = [%s]", nRc, rst_info);
#endif

    memcpy(pbKeyUnderDes, rst_info+4, nRc-4);

    return (0);
}











