/*----------------------------------------------------------------------|
|    hsmapi_tools.c                                                     |
|    Version :     1.0                                                  |
|    Author:       Luo Cangjian                                         |
|    Description:  SJJ1310密码机接口工具函数                            |
|                                                                       |
|    Copyright :   Beijing JN TASS Technology Co., Ltd.                 |
|    data:         2015-05-21. Create                                   |
|-----------------------------------------------------------------------|
|    Modify History:                                                    |
|----------------------------------------------------------------------*/
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include "hsmapi_log.h"
#include "hsmapi_define.h"
#include "hsmapi_tools.h"
#include "hsmapi_der.h"

#ifdef _MSC_VER
#pragma warning(disable:4996)
#endif

/***************************************************************************
* Subroutine: Tools_CheckNum
* Function:   判断一个字符串是不是纯数字的字符串
* Input:
*   @pcInData   pcInData
*
* Output:
*   无
*
* Return:       0:纯数字字符串   -1:不是纯数字字符串
* Description:
* Date:         2015.05.21
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_CheckNum(char *pcInData)
{
    unsigned int i;

    for(i = 0; i < strlen(pcInData); i++)
    {
        if(!isdigit(pcInData[i]))
        {
            return -1;
        }
    }

    return 0;
}

/***************************************************************************
* Subroutine: Tools_CheckHex
* Function:   判断一个字符串是不是纯数字的字符串
* Input:
*   @pcInData   待处理的字符串
*
* Output:
*   无
*
* Return:       0:十六进制字符串   -1:不是十六进制字符串
* Description:
* Date:         2015.05.21
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_CheckHex(char *pcInData)
{
    unsigned int i = 0;

    for(i = 0; i < strlen(pcInData); i++)
    {
        if(!isxdigit(pcInData[i]))
        {
            return -1;
        }
    }

    return HAR_OK;
}

/***************************************************************************
* Subroutine: Toos_CheckKeyType
* Function:   判断对称密钥类型是否合法
* Input:
*   @pcKeyType   密钥类型
*
* Output:
*   无
*
* Return:       0:密钥类型合法     返回其他标识类型非法
* Description:
* Date:         2015.05.21
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Toos_CheckKeyType(char *pcKeyType)
{
    if(pcKeyType == NULL || strlen(pcKeyType) != 3)
    {
        return HAR_PARAM_KEY_TYPE;
    }

    if(strcmp(pcKeyType, KEY_TYPE_KEKZMK)
            && strcmp(pcKeyType, KEY_TYPE_ZPK)
            && strcmp(pcKeyType, KEY_TYPE_PVKTPK)
            && strcmp(pcKeyType, KEY_TYPE_CVK)
            && strcmp(pcKeyType, KEY_TYPE_TAK)
            && strcmp(pcKeyType, KEY_TYPE_ZAK)
            && strcmp(pcKeyType, KEY_TYPE_BDK)
            && strcmp(pcKeyType, KEY_TYPE_MDKMKAC)
            && strcmp(pcKeyType, KEY_TYPE_MKSMI)
            && strcmp(pcKeyType, KEY_TYPE_MKDAK)
            && strcmp(pcKeyType, KEY_TYPE_MKDN)
            && strcmp(pcKeyType, KEY_TYPE_DEKZEK)
            && strcmp(pcKeyType, KEY_TYPE_TEK)
            && strcmp(pcKeyType, KEY_TYPE_HMAC)
            && strcmp(pcKeyType, KEY_TYPE_KMC))
    {
        return HAR_PARAM_KEY_TYPE;
    }

    return HAR_OK;
}

/***************************************************************************
* Subroutine: Tools_ConvertHexBuf2Int
* Function:   将指定长度的十六进制字符缓存区转为int类型
* Input:
*   @pucBuffer   待处理的数据
*   @iLen        指定的长度
* Output:
*   无
*
* Return:       转换后的整型数据
* Description:
* Date:         2015.05.21
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_ConvertHexBuf2Int(unsigned char *pucBuffer, int iBufferLen)
{
    register unsigned int  rv = 0, i;
    register unsigned char *ptr;

    ptr = pucBuffer;

    for(i = 0; i < (unsigned int)iBufferLen; i++, ptr++)
    {
        rv = rv * 16 + (((*ptr = toupper(*ptr)) > '9') ? (*ptr - 'A' + 10) : (*ptr - '0'));
    }

    return rv;
}

/***************************************************************************
* Subroutine: Tools_ConvertDecBuf2Int
* Function:   将指定长度的十进制字符缓存区转换为整型
* Input:
*   @pucBuffer   待处理的数据
*   @iLen        指定的长度
* Output:
*   无
*
* Return:       转换后的整型数据
* Description:
* Date:         2015.05.21
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_ConvertDecBuf2Int(unsigned char *pucBuffer, int iBufferLen)
{
    register unsigned int  rv = 0, i;
    register unsigned char *ptr;

    ptr = pucBuffer;

    for(i = 0; i < (unsigned int)iBufferLen; i++, ptr++)
    {
        rv = rv * 10 + (*ptr - '0');
    }

    return rv;
}

/***************************************************************************
* Subroutine: Tools_ConvertUint2Ucbuf
* Function:   将4字节的int转换为unsigned char 类型的数据
* Input:
*   @uiInData   待处理的数据
* Output:
*   @pucOutBuf  转换后的数据
*
* Return:
* Description:
* Date:         2015.05.21
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_ConvertUint2Ucbuf(unsigned int uiInData, unsigned char *pucOutBuf)
{
    *pucOutBuf ++= (uiInData >> 24) & 0xff;
    *pucOutBuf ++= (uiInData >> 16) & 0xff;
    *pucOutBuf ++= (uiInData >> 8) & 0xff;
    *pucOutBuf ++= uiInData & 0xff;

    return 0;
}

/***************************************************************************
* Subroutine: Tools_AddFieldPan
* Function:   根据检测账号是否十进制数据，根据PIN格式添加到命令报文中
* Input:
*   @iPinFmt  PIN块格式
*   @pcPan    PAN号
* Output:
*   @pucDst   命令报文
*
* Return:       成功则返回有效的PAN长度，否则返回 HAR_PARAM_PAN
* Description:  pinfmt=4, pan为18N；pinfmt=0，pan为作为分散因子的域，16N；其他，pan为12N
* Date:         2015.05.21
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_AddFieldPan(int iPinFmt, char *pcPan, unsigned char *pucDst)
{
    int rv;
    int iPanLen = strlen(pcPan);

    rv = Tools_CheckNum(pcPan);
    if (rv)
    {
        return HAR_PARAM_PAN;
    }

    /*** pan为作为分散因子的域，与PIN BLOCK无关 ***/
    if (iPinFmt == PANFMT_DISPER)
    {
        if (iPanLen >= 16)
        {
            memcpy(pucDst, &pcPan[iPanLen - 16], 16);
        }
        else
        {
            memset(pucDst, '0', 16 - iPanLen);
            memcpy(&pucDst[16 - iPanLen], pcPan, iPanLen);
        }
        return 16;
    }

    /*** PIN Format4: 帐号域长度必须为18字节 ***/
    /*** 若该帐号域少于18个数字，则必须右对齐并左填充X’F ***/
    if (iPinFmt == PANFMT_PIN4)
    {
        if (iPanLen < 18)
        {
            memset(pucDst, 'F', 18);
            memcpy(&pucDst[18 - iPanLen], pcPan, iPanLen);
        }
        else
        {
            memcpy(pucDst, pcPan, 18);
        }

        return 18;
    }

    /*** 计算CVV时，账号长度不限 ***/
    if (iPinFmt == PANFMT_CVV)
    {
        memcpy(pucDst, pcPan, iPanLen);
        return iPanLen;
    }

    /*** 其他的PIN运算格式，包括LMK加密PIN时，取账号最右12位 ***/
    memset(pucDst, '0', 12);
    if (iPanLen < 12)
    {
        memcpy(&pucDst[12 - iPanLen], pcPan, iPanLen);
    }
    else
    {
        memcpy(pucDst, pcPan, 12);
    }

    return 12;
}

/***************************************************************************
* Subroutine: Tools_AddFieldKey
* Function:    将密钥索引或密钥密文添加到命令报文域中
* Input:
*   @iKeyIdx       密钥索引
*   @pcKeyCipher   密钥密文
* Output:
*   @pucDst        命令报文
*
* Return:       成功返回添加的数据长度，否则返回 HAR_PARAM_VALUE
* Description:
* Date:         2015.05.22
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_AddFieldKey(int iKeyIdx, char *pcKeyCipher, unsigned char *pucDst)
{
    int iKeyCipherLen;

    if(pcKeyCipher == NULL || pcKeyCipher[0] == 0x00)
    {
        if (iKeyIdx <= 0)
        {
            return HAR_PARAM_VALUE;
        }

        TASS_SPRINTF(pucDst, 6, "K%04d", iKeyIdx);
        return 5;
    }

    if(iKeyIdx == 0)
    {
        iKeyCipherLen = Tools_GetFieldKeyLength(pcKeyCipher);
        memcpy(pucDst, pcKeyCipher, iKeyCipherLen);
        return iKeyCipherLen;
    }

    if(iKeyIdx < 0)
    {
        return HAR_PARAM_VALUE;
    }

    TASS_SPRINTF(pucDst, 6, "K%04d", iKeyIdx);
    return 5;
}

/***************************************************************************
* Subroutine: Tools_AddFieldSavedKey
* Function:    将要存到内部的密钥索引和密钥标识添加到命令报文域中
* Input:
*   @iKeyIdx       密钥索引
*   @pcKeyLabel    密钥标签
* Output:
*   @pucDst        命令报文
*
* Return:       成功返回添加的数据长度，否则返回 HAR_PARAM_VALUE
* Description:
* Date:         2015.05.22
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_AddFieldSavedKey(int iKeyIdx, char *pcKeyLabel, unsigned char *pucDst)
{
    int iKeyLabelLen;

    if(iKeyIdx <= 0)
    {
        return 0;
    }

    /*** 密钥索引, 4N ***/
    TASS_SPRINTF(pucDst, 6, "K%04d", iKeyIdx);
    pucDst += 5;

    /*** 密钥标签长度, 2N ***/
    if(pcKeyLabel)
    {
        iKeyLabelLen = strlen(pcKeyLabel);
        if(iKeyLabelLen > 16)
        {
            return HAR_PARAM_VALUE;
        }
    }
    else
    {
        iKeyLabelLen = 0;
    }

    TASS_SPRINTF(pucDst, 3, "%02d", iKeyLabelLen);
    pucDst += 2;

    /*** 密钥标签, nA ***/
    memcpy(pucDst, pcKeyLabel, iKeyLabelLen);

    return iKeyLabelLen + 5 + 2;
}

/***************************************************************************
* Subroutine: Tools_AddFieldDiversifyData
* Function:    添加密钥分散级数及分散因子域到命令报文中
* Input:
*   @iMode          0-每级分散因子8字节，1-每级分散因子16字节
*   @iDiversifyNum     分散级数
*   @pcDiversifyData   分散因子
* Output:
*   @pucDst        命令报文
*
* Return:       成功返回添加的数据长度，否则返回 HAR_PARAM_Diversify_DATA
* Description:
* Date:         2015.05.22
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_AddFieldDiversifyData(int iMode, int iDiversifyNum, char *pcDiversifyData, unsigned char *pucDst)
{
    unsigned int uiDiversifyDataLen = 0;
    unsigned char *p = pucDst;

    TASS_SPRINTF(p, 2, "%d", iDiversifyNum);
    ++p;

    if (iMode == 0)
    {
        uiDiversifyDataLen = iDiversifyNum * 16;
    }
    else
    {
        uiDiversifyDataLen = iDiversifyNum * 32;
    }

    strncpy(p, pcDiversifyData, uiDiversifyDataLen);

    return uiDiversifyDataLen + 1;
}

/***************************************************************************
* Subroutine: Tools_AddFieldSessionData
* Function:    添加会话密钥模式和会话密钥因子域到命令报文中
* Input:
*   @iMode          会话密钥生成模式
*   @pcSessData     会话密钥因子
* Output:
*   @pucDst        命令报文
*
* Return:       成功则返回有效的添加数据长度
*               失败返回 HAR_PARAM_SESSION_KEY_DATA
*                       或HAR_PARAM_SESSION_KEY_MODE
* Description:
* Date:         2015.05.22
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_AddFieldSessionData(int iMode, char *pcSessData, unsigned char *pucDst)
{
    unsigned int uiSessDataLen = 0;
    unsigned char *p = pucDst;

    TASS_SPRINTF(p, 3, "%02d", iMode);
    p += 2;

    if(iMode == 0 || iMode == 3 || iMode == 4)
    {
        uiSessDataLen = 0;
    }
    else if( iMode == 1 )
    {
        uiSessDataLen = 16;
    }
    else if(iMode ==2 || iMode == 5)
    {
        uiSessDataLen = 32;
    }
    else
    {
        return HAR_PARAM_SESSION_KEY_MODE;
    }

    if(uiSessDataLen > 0)
    {
        if (strlen(pcSessData) != uiSessDataLen)
        {
            return HAR_PARAM_SESSION_KEY_DATA;
        }
    }

    memcpy(p, pcSessData, uiSessDataLen);

    return 2 + uiSessDataLen;
}

/***************************************************************************
* Subroutine: Tools_GetFieldKeyLength
* Function:   获取密钥长度
* Input:
*   @pcKeyCipher   密钥密文
* Output:
*   无
*
* Return:       密钥密文长度（包含算法标识）
* Description:
* Date:         2015.05.21
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_GetFieldKeyLength(char *pcKeyCipher)
{
    char ch = pcKeyCipher[0];

    if (ch == 'X' || ch == 'S' || ch == 'P' || ch == 'L')
    {
        return 32+1;
    }

    if (ch == 'Y')
    {
        return 48 + 1;
    }

    if (ch == 'Z')
    {
        return 16 + 1;
    }

    return 16;
}

/***************************************************************************
* Subroutine: Tools_GetFieldDerBufLength
* Function:   获取DER编码的数据长度
* Input:
*   @pucDst          报文数据
* Output:
*   无
*
* Return:       成功则返回有效数据长度
*               失败返回 HAR_DER_DECODE
* Description:
* Date:         2015.05.22
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_GetFieldDerBufLength(unsigned char *pucDst)
{
    if(pucDst[0] != 0x30)
    {
        return HAR_DER_DECODE;
    }

    if(pucDst[1] == 0x81)
    {
        return pucDst[2] + 3;
    }

    if(pucDst[1] == 0x82)
    {
        return pucDst[2] * 256 + pucDst[3] + 4;
    }

    if(pucDst[1] == 0x59)
    {
        return pucDst[1] + 2;
    }

    return HAR_DER_DECODE;
}

/***************************************************************************
* Subroutine: Tools_PrintBuf
* Function:   按十六进制打印缓存区
* Input:
*   @pucDst   待打印的数据
* Output:
*   无
*
* Return:
* Description:
* Date:         2015.05.22
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
void Tools_PrintBuf(char *pcTitle, unsigned char *pucBuf, int iBufLen)
{
    int i;

    printf("%s[%d]:\n", pcTitle, iBufLen);

    for(i = 0; i < iBufLen; i++)
    {
        printf("%02X", pucBuf[i]);
        if ( i % 32 == 31)
        {
            printf("\n");
        }
    }

    printf("\n");

    return;
}

/***************************************************************************
* Subroutine: Tools_ConvertToupper
* Function:   将小写的字符转换为大写
* Input:
*   @pcInData   待处理的字符串
* Output:
*   无
*
* Return:
* Description:
* Date:         2015.05.22
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
void Tools_ConvertToupper(char *pcInData)
{
    int i;
    for(i = 0; i < strlen(pcInData); i++)
    {
        pcInData[i] = toupper(pcInData[i]);
    }
}

/***************************************************************************
* Subroutine: Tools_ConvertByte2HexStr
* Function:   将字节数组转换为十六进制字符串
* Input:
*   @pucInBuf    待处理字节数组
*   @iInBufLen   待处理的数据的字节数
* Output:
*   @pcOutBuf    转换后的十六进制字符串
*
* Return:       成功返回十六进制字符串长度， 失败返回-1
* Description:
* Date:         2015.05.22
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_ConvertByte2HexStr(unsigned char *pucInBuf, int iInBufLen, char *pcOutBuf)
{
    int rv = HAR_OK;
    unsigned char ch;
    register int i, active = 0;

    iInBufLen *= 2;

    for(i = 0; i < iInBufLen; i++)
    {
        ch = *pucInBuf;
        if (active)
        {
            (*pcOutBuf = (ch & 0x0F)) < 10 ? (*pcOutBuf += '0') : (*pcOutBuf += ('A' - 10));
            pucInBuf++;
        }
        else
        {
            (*pcOutBuf = (ch & 0xF0) >> 4) < 10 ? (*pcOutBuf += '0') : (*pcOutBuf += ('A' - 10));
        }

        active ^= 1;

        if (!isxdigit(*pcOutBuf))
        {
            rv = -1;
            break;
        }

        pcOutBuf++;
    }

    *pcOutBuf = 0x00;

    return iInBufLen;
}

/***************************************************************************
* Subroutine: Tools_ConvertHexStr2Byte
* Function:   将十六进制字符串转换为字节数组
* Input:
*   @pcInBuf    待处理的字符串
*   @iInBufLen  待处理的字符串长度
* Output:
*   @pucOutBuf  输出的字节数组
*
* Return:
* Description: 成功返回转换后的字节数， 失败返回-1
* Date:         2015.05.22
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_ConvertHexStr2Byte(char *pcInBuf, int iInBufLen, unsigned char *pucOutBuf)
{
    int              rv = HAR_OK;
    int              len = iInBufLen / 2;
    register int     iActive = 0;
    char             cCharIn;
    unsigned char    cCharOut;

    if(iInBufLen % 2 != 0)
    {
        return -1;
    }

    rv = Tools_CheckHex(pcInBuf);
    if(rv)
    {
        return -1;
    }

    for( ; iInBufLen > 0; iInBufLen--, pcInBuf++)
    {
        cCharIn = *pcInBuf;

        if(cCharIn > '9')
        {
            cCharIn += 9;
        }

        cCharOut = *pucOutBuf;
        if(iActive)
        {
            *pucOutBuf++ = (unsigned char)((cCharOut & 0xF0) | (cCharIn & 0x0F));
        }
        else
        {
            *pucOutBuf = (unsigned char)((cCharOut & 0x0F) | ((cCharIn & 0x0F) << 4));
        }
        iActive ^= 1;
    }

    return len;
}

/***************************************************************************
* Subroutine: Tools_Padding_0
* Function:   非强制填充0x80
* Input:
*   @pcInData    待处理的字符串（十六进制）
* Output:
*   @pcOutData   填充后的数据
*
* Return:       成功返回0， 失败返回-1
* Description:  将数据填充为16的倍数（十六进制）
* Date:         2015.05.22
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_Padding_0(char *pcInData, char *pcOutData/*out*/)
{
    int iInDataLen = 0;
    int iResidue = 0;
    char pcPaddingData[16 + 1] = "8000000000000000";

    if(pcInData == NULL || pcOutData == NULL)
    {
        return -1;
    }

    iInDataLen = strlen(pcInData);
    if(iInDataLen % 2 != 0)
    {
        return -1;
    }

    iResidue = 16 - iInDataLen % 16;
    if(iResidue != 16)
    {
        strcpy(pcOutData, pcInData);
        strncat(pcOutData + iInDataLen, pcPaddingData, iResidue);
    }
    else
    {
        strcpy(pcOutData, pcInData);
    }

    return HAR_OK;
}

/***************************************************************************
* Subroutine: Tools_Padding_00
* Function:   非强制填充0x00
* Input:
*   @pcInData    待处理的字符串（十六进制）
* Output:
*   @pcOutData   填充后的数据
*
* Return:       成功返回0， 失败返回-1
* Description:  将数据填充为16的倍数（十六进制）
* Date:         2015.05.22
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_Padding_00(char *pcInData, char *pcOutData/*out*/)
{
    int iInDataLen = 0;
    int iResidue = 0;
    char pcPaddingData[16 + 1] = "0000000000000000";

    if(pcInData == NULL || pcOutData == NULL)
    {
        return -1;
    }

    iInDataLen = strlen(pcInData);
    if(iInDataLen % 2 != 0)
    {
        return -1;
    }

    iResidue = 16 - iInDataLen % 16;
    if(iResidue != 16)
    {
        strcpy(pcOutData, pcInData);
        strncat(pcOutData + iInDataLen, pcPaddingData, iResidue);
    }
    else
    {
        strcpy(pcOutData, pcInData);
    }

    return HAR_OK;
}

/***************************************************************************
* Subroutine: Tools_CycleXorHexStr
* Function:   对十六进制字符串按指定分组长度循环异或
* Input:
*   @iMode       分组模式： 0-按8字节异或   1-按16字节异或
*   @pcInData    待处理的字符串
* Output:
*   @pcOutData   异或后的数据
*
* Return:       成功返回0， 失败返回-1
* Description:
* Date:         2015.05.22
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_CycleXorHexStr(int iMode, char *pcInData, char *pcOutData/*out*/)
{
    int rv = HAR_OK;
    int i, j;
    int iBlockNum = 0;
    int iBlockLen = 0;
    unsigned char *pucData = NULL;
    unsigned char pucResult[16] = {0};
    unsigned char pucNextDataBlock[16] = {0};
    int iInDataLen = strlen(pcInData);

    pucData = (unsigned char *)malloc(iInDataLen / 2);
    if(pcInData == NULL || pcOutData == NULL || pucData == NULL)
    {
    	if(pucData)
    	{
    	    free(pucData);
    	}
        return -1;
    }

    switch(iMode)
    {
        case 0:
            iBlockLen = 8;
            break;
        case 1:
            iBlockLen = 16;
            break;
        default:
	    if(pucData)
	    {
	        free(pucData);
	    }
            return -1;
    }

    iInDataLen = Tools_ConvertHexStr2Byte(pcInData, iInDataLen, pucData);
    if(iInDataLen == -1 || iInDataLen % iBlockLen != 0)
    {
    	if(pucData)
    	{
    	    free(pucData);
    	}

        return -1;
    }

    iBlockNum = iInDataLen / iBlockLen;

    for(i = 0; i < iBlockNum; i++)
    {
        memcpy(pucNextDataBlock, pucData + i * iBlockLen, iBlockLen);
        for(j = 0; j < iBlockLen; j++)
        {
            pucResult[j] ^= pucNextDataBlock[j];
        }
    }

    rv = Tools_ConvertByte2HexStr(pucResult, iBlockLen, pcOutData);
    if(rv == -1)
    {
    	if(pucData)
    	{
    	    free(pucData);
    	}

        return rv;
    }

    if(pucData)
        {
    	free(pucData);
        }

    return HAR_OK;
}

/***************************************************************************
* Subroutine: Tools_CycleXorHexStr
* Function:   对二进制数据按指定分组长度循环异或
* Input:
*   @iMode       分组模式： 0-按8字节异或   1-按16字节异或
*   @pucInData   待处理的字节数组
*   @iInDataLen  待处理的字节数组长度
* Output:
*   @pucOutData   异或后的数据
*
* Return:       成功返回0， 失败返回-1
* Description:
* Date:         2015.05.22
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_CycleXorByteArray(int iMode, unsigned char *pucInData, int iInDataLen, unsigned char *pucOutData/*out*/)
{
    int rv = HAR_OK;
    int i, j;
    int iBlockNum = 0;
    int iBlockLen = 0;
    unsigned char pucResult[16] = {0};
    unsigned char pucNextDataBlock[16] = {0};

    if(pucInData == NULL || pucOutData == NULL)
    {
        return -1;
    }

    switch(iMode)
    {
        case 0:
            iBlockLen = 8;
            break;
        case 1:
            iBlockLen = 16;
            break;
        default:
            return -1;
    }

    if(iInDataLen % iBlockLen != 0)
    {
        return -1;
    }

    iBlockNum = iInDataLen / iBlockLen;

    for(i = 0; i < iBlockNum; i++)
    {
        memcpy(pucNextDataBlock, pucInData + i * iBlockLen, iBlockLen);
        for(j = 0; j < iBlockLen; j++)
        {
            pucResult[j] ^= pucNextDataBlock[j];
        }
    }

    memcpy(pucOutData, pucResult, iBlockLen);

    return rv;
}

/***************************************************************************
* Subroutine: Tools_GenDiversifyData
* Function:   计算分散因子
* Input:
*   @pcInData    待处理的数据，要求长度为16H
* Output:
*   @pcOutData   处理后的分散因子 32H
*
* Return:       成功返回0， 失败返回-1
* Description:  用于计算将十六进制的数据进行取反，然后将原数据与取反后的数据进行拼接，
*               形成一个分散因子。
* Date:         2015.05.22
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_GenDiversifyData(char *pcInData, char *pcOutData/*out*/)
{
    int iInDataLen = strlen(pcInData);
    int rv = HAR_OK;
    char pcTmpData[32 + 1] = {0};
    char pcNotData[16 + 1] = {0};

    if( pcInData == NULL || strlen(pcInData) != 16 || pcOutData == NULL )
    {
        return -1;
    }

    strcpy(pcTmpData, pcInData);
    strcat(pcTmpData, "FFFFFFFFFFFFFFFF");

    /*** 按8字节异或 ***/
    rv = Tools_CycleXorHexStr(1, pcTmpData, pcNotData/*out*/);
    if(rv == -1)
    {
        return rv;
    }

    strcpy(pcOutData, pcInData);
    strcat(pcOutData, pcNotData);

    return HAR_OK;
}

/***************************************************************************
* Subroutine: Tools_CheckSchemeValidity
* Function:   检查算法标识有效性
* Input:
*   @cScheme  算法标识
* Output:
*   无
*
* Return:       成功返回0， 失败返回其他
* Description:  暂时不支持AES算法
*
* Date:         2015.06.08
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_CheckSchemeValidity(char cScheme)
{
    switch(cScheme)
    {
        case 'Z':
        case 'U':
        case 'T':
        case 'X':
        case 'Y':
        case 'P':
        case 'R':
            break;
        default:
            return HAR_PARAM_KEY_SCHEME;
    }

    return HAR_OK;
}

/***************************************************************************
* Subroutine: Tools_CheckKeyValidity
* Function:   检查密钥信息有效性
* Input:
*   @iKeyIdx            密钥索引
*   @pcKeyCipherByLmk   密钥密文
* Output:
*   @pcOutData          完整的密钥密文（待算法标识）
*
* Return:       成功返回0， 失败返回其他
* Description:  暂时不支持AES算法
*
* Date:         2015.06.08
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_CheckKeyValidity(int iKeyIdx, char *pcKeyCipherByLmk, char *pcOutData)
{
    if(iKeyIdx < 0 || iKeyIdx > 2048)
    {
        return HAR_PARAM_KEY_ID;
    }

    if(iKeyIdx == 0)
    {
        if(pcKeyCipherByLmk == NULL)
        {
            return HAR_PARAM_KEY_CIPHER;
        }

        if(strlen(pcKeyCipherByLmk) != 16
                && strlen(pcKeyCipherByLmk) != 17
                && strlen(pcKeyCipherByLmk) != 33
                && strlen(pcKeyCipherByLmk) != 49)
        {
            return HAR_PARAM_KEY_CIPHER;
        }

        if(strlen(pcKeyCipherByLmk) == 16)
        {
            strcpy(pcOutData, "Z");
            strcat(pcOutData, pcKeyCipherByLmk);
        }
        else
        {
            strcpy(pcOutData, pcKeyCipherByLmk);
        }
    }

    return HAR_OK;
}

/***************************************************************************
* Subroutine: Tools_CheckKeyValidity_1
* Function:   检查密钥信息有效性
* Input:
*   @iKeyIdx            密钥索引
*   @pcKeyCipherByLmk   密钥密文
* Output:
*   无
*
* Return:       成功返回0， 失败返回其他
* Description:  当密钥索引值为0时，密钥密文长度是否为16,33，49,如果不是则报错
*
* Date:         2015.06.08
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_CheckKeyValidity_1(int iKeyIdx, char *pcKeyCipherByLmk)
{
    if(iKeyIdx < 0 || iKeyIdx > 2048)
    {
        return HAR_PARAM_KEY_ID;
    }

    if(iKeyIdx == 0)
    {
        if(pcKeyCipherByLmk == NULL)
        {
            return HAR_PARAM_KEY_CIPHER;
        }

        if(strlen(pcKeyCipherByLmk) != 16 && strlen(pcKeyCipherByLmk) != 33 && strlen(pcKeyCipherByLmk) != 49)
        {
            return HAR_PARAM_KEY_CIPHER;
        }
    }

    return HAR_OK;
}

/***************************************************************************
* Subroutine: Tools_CheckKeyValidity_2
* Function:   检查密钥信息有效性
* Input:
*   @iKeyIdx            密钥索引
*   @pcKeyCipherByLmk   密钥密文
* Output:
*   无
*
* Return:       成功返回0， 失败返回其他
* Description:  当密钥索引值为0时，密钥密文长度是否为17,33，49,如果不是则报错
*
* Date:         2015.06.08
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_CheckKeyValidity_2(int iKeyIdx, char *pcKeyCipherByLmk)
{
    if(iKeyIdx < 0 || iKeyIdx > 2048)
    {
        return HAR_PARAM_KEY_ID;
    }

    if(iKeyIdx == 0)
    {
        if(pcKeyCipherByLmk == NULL)
        {
            return HAR_PARAM_KEY_CIPHER;
        }

        if(strlen(pcKeyCipherByLmk) != 17 && strlen(pcKeyCipherByLmk) != 33 && strlen(pcKeyCipherByLmk) != 49)
        {
            return HAR_PARAM_KEY_CIPHER;
        }
    }

    return HAR_OK;
}

/***************************************************************************
* Subroutine: Tools_CheckKeyValidity_3
* Function:   检查密钥信息有效性
* Input:
*   @iKeyIdx            密钥索引
*   @pcKeyCipherByLmk   密钥密文
* Output:
*   @pcOutData          完整的密钥密文（待算法标识）
*
* Return:       成功返回0， 失败返回其他
* Description:  密钥密文长度只支持32或33H，当长度为32H时，则填充算法标识X
*
* Date:         2015.06.08
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_CheckKeyValidity_3(int iKeyIdx, char *pcKeyCipherByLmk, char *pcOutData)
{
    if(iKeyIdx < 0 || iKeyIdx > 2048)
    {
        return HAR_PARAM_KEY_ID;
    }

    if(iKeyIdx == 0)
    {
        if(pcKeyCipherByLmk == NULL)
        {
            return HAR_PARAM_KEY_CIPHER;
        }

        if(strlen(pcKeyCipherByLmk) != 32 && strlen(pcKeyCipherByLmk) != 33)
        {
            return HAR_PARAM_KEY_CIPHER;
        }

        if(strlen(pcKeyCipherByLmk) == 32)
        {
            strcpy(pcOutData, "X");
            strcat(pcOutData + 1, pcKeyCipherByLmk);
        }
        else
        {
            strcpy(pcOutData, pcKeyCipherByLmk);
        }
    }

    return HAR_OK;
}

/***************************************************************************
* Subroutine: Tools_CheckSessionKeyDataValidity
* Function:   检查会话密钥生成模式及数据的有效性
* Input:
*   @iSessionKeyMode           会话密钥生成模式
*   @pcSessionKeyData          会话密钥因子
* Output:
*   无
*
* Return:       成功返回0， 失败返回其他
* Description:
*
* Date:         2015.06.08
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_CheckSessionKeyDataValidity(int iSessionKeyMode, char *pcSessionKeyData)
{
    if(iSessionKeyMode != 0
            && iSessionKeyMode != 1
            && iSessionKeyMode != 2
            && iSessionKeyMode != 3
            && iSessionKeyMode != 4
            && iSessionKeyMode != 5)
    {
        LOG_ERROR("Parameter iSessionKeyMode = [%d] is invalid. It must be 00, 01, 02, 03, 04 or 05.",
                iSessionKeyMode);
        return HAR_PARAM_SESSION_KEY_MODE;
    }

    if(iSessionKeyMode == 0 || iSessionKeyMode == 3 || iSessionKeyMode == 4)
    {
        return HAR_OK;
    }

    if(pcSessionKeyData == NULL)
    {
        LOG_ERROR("Parameter pcSessionKeyData = [%s] is invalid.", "NULL");
        return HAR_PARAM_SESSION_KEY_DATA;
    }

    if(iSessionKeyMode == 1)
    {
        if(strlen(pcSessionKeyData) != 16)
        {
            LOG_ERROR("Parameter pcSessionKeyData length = [%d] is invalid. It must be 16 characters.",
                    strlen(pcSessionKeyData));
            return HAR_PARAM_SESSION_KEY_DATA;
        }
    }
    else
    {
        if(strlen(pcSessionKeyData) != 32)
        {
            LOG_ERROR("Parameter pcSessionKeyData length = [%d] is invalid. It must be 32 characters.",
                    strlen(pcSessionKeyData));
            return HAR_PARAM_SESSION_KEY_DATA;
        }
    }

    return HAR_OK;
}

/***************************************************************************
* Subroutine: Tools_CheckPaddingModeValidity
* Function:   检查数据填充模式的有效性
* Input:
*   @iPaddingMode           数据填充模式
* Output:
*   无
*
* Return:       成功返回0， 失败返回其他
* Description:
*
* Date:         2015.06.08
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_CheckPaddingModeValidity(int iPaddingMode)
{
    switch(iPaddingMode)
    {
        case 0:
        case 1:
        case 2:
        case 3:
        case 4:
        case 5:
        case 10:
        case 11:
            return HAR_OK;
        default:
            return HAR_PARAM_PADDING_MODE;
    }

    return HAR_OK;
}

/***************************************************************************
 * * Subroutine: Tools_Der
 * * Function:   对RSA公钥的模、指数序列做DER编码
 * * Input:
 * *   @N           模
 * *   @E           指数（十六进制）
 * * Output:
 * *   @pubkeyDer   公钥
 * *   @pubkeyDerLen公钥长度
 * *
 * * Return:       成功返回0， 失败返回其他
 * * Description:
 * *
 * * Date:         2015.06.08
 * * Author:       Luo Cangjian
 * * ModifyRecord:
 * * *************************************************************************/
int Tools_Der(char *N, char *E, char *pubkeyDer,int *pubkeyDerLen)
{
   int rv = HAR_OK;
   unsigned char modulus[2048+1] = {0};
   unsigned char pubExp[12] = {0};
   unsigned char pubkeyDer1[512+128] = {0};
   int pubkeyDerLen1 = 512 + 128;
   int modulusLen,pubExpLen;
    modulusLen = Tools_ConvertHexStr2Byte(N, strlen(N), modulus);
    if(modulusLen == -1)
    {
        LOG_ERROR("Parameter: N convert hex to byte failed ,code = [%#010X],[%d]",HAR_HEX_TO_BYTE);
        return HAR_HEX_TO_BYTE;
    }

    pubExpLen = Tools_ConvertHexStr2Byte(E, strlen(E), pubExp);
    if(pubExpLen == -1)
    {
        LOG_ERROR("Parameter: E convert hex to byte failed ,code = [%#010X],[%d]",HAR_HEX_TO_BYTE);
        return HAR_HEX_TO_BYTE;
    }
    // Tools_PrintBuf("modulus",modulus,modulusLen);
    // Tools_PrintBuf("pubExp",pubExp,pubExpLen);
    rv = Der_Pubkey_Pkcs1(
            modulus,
            modulusLen,
            pubExp,
            pubExpLen,
            pubkeyDer1,
            &pubkeyDerLen1);
    //Tools_PrintBuf("pubkeyDer",pubkeyDer,pubkeyDerLen);
    *pubkeyDerLen = Tools_ConvertByte2HexStr(pubkeyDer1,pubkeyDerLen1,pubkeyDer);
    if(rv)
    {
        printf("der coding return code = [%#010X].\n", rv);
    }
  return rv;
}
/***************************************************************************
 * Subroutine: Tools_DDer
 * Function:   对Der编码的公钥解码，生成模和指数
 * Input:
 *   @pubkeyDer      Der编码
 *   @pubkeyDerLen   Der长
 * Output
 *   @ppmodulus      模
 *   @modulusLen     模长
 *   @pppubExp       指数
 *   @pubExpLen      指数长度
 * Output:
 *   @pubkeyDer   公钥
 *
 * Return:       成功返回0， 失败返回其他
 * Description:
 *
 * Date:         2015.06.08
 * Author:       Luo Cangjian
 * ModifyRecord:
 * *************************************************************************/
int Tools_DDer(unsigned char *pubkeyDer, unsigned char *ppmodulus,
               int *modulusLen, unsigned char *pppubExp, int *pubExpLen)
{
     int rv = HAR_OK;
     int len = Tools_ConvertHexStr2Byte(pubkeyDer, strlen(pubkeyDer), pubkeyDer);
   
     unsigned char *pM = NULL;
     unsigned char *pE = NULL;
     int modulusLen_m = 0;
     int pubExpLen_m = 0;
    
     rv = DDer_Pubkey_Pkcs1(
            pubkeyDer, len,
            &pM, &modulusLen_m,
            &pE, &pubExpLen_m   
            );
// Tools_PrintBuf("++++",pM,modulusLen_m);
// Tools_PrintBuf("++++",pE,pubExpLen_m);

*modulusLen = Tools_ConvertByte2HexStr(pM, modulusLen_m, ppmodulus);
*pubExpLen = Tools_ConvertByte2HexStr(pE, pubExpLen_m, pppubExp);
// printf("_+_+_+_+:%s\n",ppmodulus);
// printf("_+_+_+_+:%s\n",pppubExp);
   return rv;
}

/***************************************************************************
* Subroutine: Tools_ReadBuf
* Function:   按十六进制读取缓存区数据
* Input:
*   @pucDst   待读取的数据
* Output:
*   @BufData  读取到的数据（十六进制）
* 
* Return:     返回BufData的长度
* Description:
* Date:         2015.05.22
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_ReadBuf(unsigned char *pucBuf, int iBufLen, unsigned char *BufData/*out*/)
{
    Tools_ConvertByte2HexStr(pucBuf,iBufLen,BufData);
    return strlen(BufData);
}


