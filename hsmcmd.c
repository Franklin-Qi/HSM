
/*********************************************************************/
/* 文 件 名：  hsmcmd.c                                               */
/* 版 本 号：  v1.1                                                  */
/* 所 有 者：                                                        */
/* 版    权：  Union Beijing                                         */
/* 功    能：  农行ICCM_密钥安全系统_第05号_加密机接口（国密）api      */
/* 维护记录： 1. 2008-6-11 by  Liwb                                  */
/*           2. 2008-12-11 by xusj                                   */
/*           3. 2012-07-11 by zhangx                                 */
/*           4. 2017-03-07 by zhaomx                                 */
/*********************************************************************/

#include "unionsck.h"
#include "unionlog.h"
#define _DEBUG 0

#define G_UNIONCMDLEN (81920)
#define G_UNIONRSTLEN (81920)
#define G_UNIONDEBLEN (41960)

int HTOA(char source[],int len)
{
    char s[8];
    int i,m,temp=0,n;
    memset(s,0,sizeof(s));
    UnpackBCD(source,s,len*2);
    //十六进制是按字符串传进来的，所以要获得他的长度 	
    m=len*2;	
    for(i=0;i<m;i++)
    {
        //十六进制还要判断他是不是在A-F或者a-f之间a=10。
        if(s[i]>='A'&&s[i]<='F')
         n=s[i]-'A'+10;
        else if(s[i]>='a'&&s[i]<='f')
         n=s[i]-'a'+10;
         else n=s[i]-'0';
        temp=temp*16+n;
    }
    return temp;
}

int UnionHSMCmd(UINT nSck, char *in, 
	int inlen, char *out, int timeout,int * retCode)
{

#ifdef _DEBUG
    union_log("==============================Begain UnionHSMCmd====================");
#endif
    int ret = 0;
    int iRcvLen = 0;
    int iSndLen = 0;
    int cmd_len = 0;
    int rst_len = 0;
    int ret2=0;
    char tmp[4];
    int dlen;

    unsigned char cmd_buf[G_UNIONCMDLEN];
    unsigned char HsmReturnBuf[G_UNIONRSTLEN];
    unsigned char HsmReturnBuf2[G_UNIONRSTLEN];
    unsigned char error_code[16] = {0};
    unsigned char short_error_code[8] = {0};

    struct timeval stNow, stTm;
    struct sigaction sa;

    if ((inlen+1) > G_UNIONCMDLEN)
    {
	union_err_log("In UnionHSMCmd::" \
		"The Cmd Len parameter [inlen] is too long!");
	return -4;
    }

    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, 0);

    memset(cmd_buf, 0, sizeof(cmd_buf));
    stTm.tv_sec = 0;
    stNow.tv_sec = 0;

    cmd_buf[0] = (inlen/256);
    cmd_buf[1] = (inlen%256);

    memcpy(&cmd_buf[2], in, inlen);
    cmd_len = inlen + 2;

#ifdef	_DEBUG		
    int iTotal=0;
    struct timeval now;
    unsigned char OutBuf[G_UNIONDEBLEN];
    iTotal = (cmd_len-2)*2;
    memset(OutBuf, 0, sizeof(OutBuf));
    UnpackBCD(cmd_buf+2, (char *)OutBuf, iTotal);
    union_log("In UnionHSMCmd::datalen(HEX)=[%d] Send date=[%s] ",iTotal,OutBuf);
#endif  
    ret = send(nSck, cmd_buf, cmd_len, 0);
    if(ret<0)
    {
	    
#ifdef _DEBUG
	printf("In UnionHSMCmd::Send errno[%d]\n", errno);
    	union_err_log("In UnionHSMCmd::Send errno[%d]\n", errno);
    	union_log("==============================END UnionHSMCmd==============================");
#endif
    	return -2;
    }
    while(ret<cmd_len)
    {
	if(UnionIsSocket(nSck)<0)
    	{
#ifdef _DEBUG			
 	    union_err_log("In UnionHSMCmd::sending socket edle HSM close nSock ");
	     			
#endif
  	    return -1;
	}
#ifdef _DEBUG
 	printf("In UnionHSMCmd::Send len != len send=[%d] cmd_len=[%d]\n", ret,cmd_len);
 	union_err_log("In UnionHSMCmd::Send len != len send=[%d] cmd_len=[%d]\n", ret,cmd_len);
#endif
	ret2 = send(nSck, cmd_buf, cmd_len-ret, 0);
	ret+=ret2;
    }
		
    memset(HsmReturnBuf, 0, sizeof(HsmReturnBuf));
    ret = recv(nSck, HsmReturnBuf, G_UNIONRSTLEN, 0);
    if(ret <0)
    {
	printf("In UnionHSMCmd::Recv errno[%d]\n", errno);
#ifdef _DEBUG			
	union_err_log("In UnionHSMCmd::Recv errno[%d]\n", errno);
	union_log("==============================END UnionHSMCmd==============================");
#endif
	return -1;
    }
    memset(tmp,0,sizeof(tmp));
    memcpy(tmp,HsmReturnBuf,2);
    dlen=HTOA(tmp,2);
    while(ret<dlen)
    {
    	if(UnionIsSocket(nSck)<0)
    	{
    		#ifdef _DEBUG			
	     	union_err_log("In UnionHSMCmd::socket edle HSM close nSock ");
	     	#endif
		return -1;
	}
    	memset(HsmReturnBuf2, 0, sizeof(HsmReturnBuf2));
    	ret2=0;
    	ret2 = read(nSck, HsmReturnBuf2, G_UNIONRSTLEN);
    	memcpy(HsmReturnBuf+ret,HsmReturnBuf2,ret2);
    	#ifdef _DEBUG			
	union_err_log("In UnionHSMCmd::Recv ADD[%d] dlen=[%d]\n", ret2,dlen);
	#endif
	ret+=ret2;
    }		
    rst_len = ret-2;
#ifdef _DEBUG   
    iTotal = rst_len;
    memset(OutBuf, 0, sizeof(OutBuf));
    UnpackBCD(HsmReturnBuf, (char *)OutBuf,ret*2);
   // printf("In UnionHSMCmd::Recv from HSM 	datalen = [%d] restbuf=[%s]\n",ret,OutBuf);
    union_log("In UnionHSMCmd::Recv from HSM 	datalen = [%d] HsmReturnBuf=[%s]\n", ret,OutBuf);
#endif

    if ((cmd_buf[2] != HsmReturnBuf[2]) || (cmd_buf[3] + 1 != HsmReturnBuf[3]))
    {
	printf("In UnionHSMCmd::Command code " \
		"Form HSM ERROR! HsmReturnBuf=[%s]", HsmReturnBuf + 2);
	memcpy(out, HsmReturnBuf + 2, 2);
	#ifdef _DEBUG
	union_err_log("In UnionHSMCmd::Command code Form HSM ERROR! return not [00]HsmReturnBuf=[%s]", HsmReturnBuf + 2);
	union_log("==============================END UnionHSMCmd==============================");
	#endif
	if(HsmReturnBuf[2]=='s')
	{
	#ifdef _DEBUG
	    union_err_log("In UnionHSMCmd::HSM return  ERROR! time out HSM cloese socket HsmReturnBuf=[%s]", HsmReturnBuf + 2);
	    union_log("==============================END UnionHSMCmd==============================");
	#endif
	    return -1;
	}
	return -4;
    }

    if ((HsmReturnBuf[4] != '0') || (HsmReturnBuf[5] != '0'))
    {
	/*对PR指令特殊处理  */
	if ((cmd_buf[2] == 'P') && (cmd_buf[3] == 'R'))
	{
	    if ((HsmReturnBuf[4] == '6') && (HsmReturnBuf[5] == '0'))
	    {
	    	memcpy(out, HsmReturnBuf + 2, 2);
		return -4;
	    }
	}

	memcpy(error_code, &HsmReturnBuf[2], 4);
	memcpy(short_error_code, &HsmReturnBuf[4], 2);
	*retCode=atoi(short_error_code);
	union_log("\nIn UnionHSMCmd::out = \n[%s]\n" \
		"short_code=[%d]\n", error_code,*retCode);
	if (!memcmp(error_code, "6928", 4))
	{
	    printf("In UnionHSMCmd::send to HSM data=[%s]", cmd_buf + 2);
	} 
	memcpy(out,error_code,4);
	#ifdef _DEBUG
	    union_log("==============================END UnionHSMCmd==============================");
	#endif
	return (-4);
   }
    memcpy(out, HsmReturnBuf + 6, (ret - 6));
    #ifdef _DEBUG
	union_log("==============================END UnionHSMCmd==============================");
    #endif
    memset(HsmReturnBuf,0,sizeof(HsmReturnBuf));
    return (ret - 6);
}

int UnionHSMCmdForNE(UINT nSck, char *in, int inlen, int iKeyLen, 
char *out, char *pcKey, int timeout, int printset)
{

    unsigned char cmd_buf[G_UNIONCMDLEN];
    unsigned char HsmReturnBuf[G_UNIONRSTLEN];
    unsigned char error_code[32] = {0};
    int cmd_len = 0, rst_len = 0;
    int ret = 0;
    int iRcvLen = 0;
    int iSndLen = 0;
    int i = 0;
    struct timeval stNow, stTm;
    struct sigaction sa;

    /* modify by lisq 20120112 */
    if (nSck < 0)
    {
#ifdef _DEBUG
	union_err_log("In UnionHSMCmdForNE::nSck Value Error");
#endif
    	return -1;
    }

    if ((inlen+1) > G_UNIONCMDLEN)
    {
#ifdef _DEBUG
	union_err_log("In UnionHSMCmdForNE::inlen Value Long");
#endif
	return -1;
    }

    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, 0);

    memset(cmd_buf, 0x00, sizeof(cmd_buf));
    memset(HsmReturnBuf, 0x00, sizeof(HsmReturnBuf));
    memset(error_code, 0x00, sizeof(error_code));
    
    cmd_buf[0] = inlen / 256;
    cmd_buf[1] = inlen % 256;

    memcpy(&cmd_buf[2], in, inlen);
    cmd_len = inlen + 2;

#ifdef	_DEBUG
    struct timeval now;
    union_log("In UnionHSMCmdForNE::cmd_len=[%d] " \
	"cmd_buf=[%s]", cmd_len, cmd_buf + 2);
#endif

    gettimeofday(&stTm, NULL);
    stTm.tv_sec += timeout;
    iSndLen = 0;
    while(cmd_len)
    {
	ret = send(nSck, cmd_buf + iSndLen, cmd_len, 0);
	if(ret <= 0)
	{
	    if(errno == EAGAIN || errno == EINTR)
	    {
		gettimeofday(&stNow, NULL);
		if(stNow.tv_sec >= stTm.tv_sec)
		{
		    union_log("In UnionHSMCmdForNE::Send TimeOut");
		    return -1;
		}
		usleep(1);	
		continue;
	    }
#ifdef _DEBUG
	    union_err_log("In UnionHSMCmdForNE::Send errno[%d]", errno);
#endif
	    return -1;
	}
	cmd_len -= ret;
	iSndLen += ret;
	gettimeofday(&stNow, NULL);
	if(stNow.tv_sec >= stTm.tv_sec)
	{
#ifdef _DEBUG
	    union_err_log("In UnionHSMCmdForNE::Send to HSM TimeOut");
#endif
	    //return -1;
	}
	usleep(1);
    }

#ifdef _DEBUG
    gettimeofday(&now, NULL);
    printf(">>>>>>>>>>>>start[%d][%d]>>>>>>>>>>>>\n", now.tv_sec, now.tv_usec); 
#endif

    iRcvLen = 0;
    while(1)
    {
        ret = recv(nSck, HsmReturnBuf+iRcvLen, G_UNIONRSTLEN-1-iRcvLen, 0);
	if(ret <= 0)
	{
	    if(errno == EAGAIN || errno == EINTR)
	    {
		gettimeofday(&stNow, NULL);
		if(stNow.tv_sec - stTm.tv_sec >= 500)
		{
		    union_log("In UnionHSMCmdForNE::Recv TimeOut");
		    return -1;
		}
		usleep(1);	
                printf("********************************\n");
		continue;
	    }
#ifdef _DEBUG
	    union_err_log("In UnionHSMCmdForNE::Recv errno[%d]", errno);
#endif
	    return -1;
	}
	if((ret < 6))
	{
#ifdef _DEBUG
	    union_err_log("In UnionHSMCmdForNE::Recv From HSM Too Short");
#endif
	    return -1;
	}
	rst_len = (HsmReturnBuf[0]*256 + HsmReturnBuf[1] + 2);
	iRcvLen += ret;
	if(iRcvLen >= rst_len)
	{
printf("iRcvLen >= rst_len \n");
	    break;
	}
	gettimeofday(&stNow, NULL);
	if(stNow.tv_sec >= stTm.tv_sec)
	{
#ifdef _DEBUG
	    union_err_log("In UnionHSMCmdForNE::Recv From HSM TimeOut");
#endif
	    return -1;
	}
	usleep(1);
    }

	
#ifdef _DEBUG
    gettimeofday(&now, NULL);
    printf("<<<<<<<<<<<<<end[%d][%d]<<<<<<<<<<<<<\n", now.tv_sec, now.tv_usec);
#endif


    if ((cmd_buf[2] != HsmReturnBuf[2]) || (cmd_buf[3] + 1 != HsmReturnBuf[3]))
    {
#ifdef _DEBUG
	union_err_log("In UnionHSMCmdForNE::The Command code form HSM error");
#endif
	return -1;
    }
printf("HsmReturnBuf %s\n", HsmReturnBuf);
for(i = 0; i < iRcvLen; i++)
printf("%02X", HsmReturnBuf[i]);
printf("\n");
    if ((HsmReturnBuf[4] != '0') || (HsmReturnBuf[5] != '0'))
    {
	memcpy(error_code, &HsmReturnBuf[2], 4);
printf("[***]error_code %s\n", error_code);
#ifdef _DEBUG
	union_err_log("In UnionHSMCmdForNE::error_code=[%s]", error_code);
#endif
	return -1;
    }

    memcpy(pcKey, &HsmReturnBuf[6], iKeyLen*2);
    if (printset == 1)
    {
	return (iKeyLen*2);
    }
    else
    {
	if ((HsmReturnBuf[4] != '0') || (HsmReturnBuf[5] != '0'))
	{
	    memcpy(error_code, &HsmReturnBuf[2], 4);
#ifdef _DEBUG
	    union_err_log("In UnionHSMCmdForNE::error_code=[%s]", error_code);
#endif
	    return -1;
	}
    }

#ifdef	_DEBUG
    union_log("In UnionHSMCmdForNE::Receive form HSM Len=" \
	"[%d] HsmReturnBuf=[%s]", iRcvLen, HsmReturnBuf+2);
#endif

    return iRcvLen;

}
