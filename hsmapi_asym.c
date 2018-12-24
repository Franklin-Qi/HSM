/*----------------------------------------------------------------------|
|    hsmapi_asym.c                                                      |
|    Version :     1.0                                                  |
|    Author:       Luo Cangjian                                         |
|    Description:  SJJ1310密码机接口非对称算法主机命令函数              |
|                                                                       |
|    Copyright :   Beijing JN TASS Technology Co., Ltd.                 |
|    data:         2015-06-04. Create                                   |
|-----------------------------------------------------------------------|
|    Modify History:                                                    |
|----------------------------------------------------------------------*/
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <string.h>

#ifdef _MSC_VER
#include <windows.h>
#pragma warning(disable:4996)
#endif

#include "hsmapi_define.h"
#include "hsmapi_log.h"
#include "hsmapi_tools.h"
#include "hsmapi_init.h"
#include "hsmapi_asym.h"
#include "hsmsocket.h"

/*
 * HSM_SM2_GenerateNewKeyPair, 产生一对新的SM2密钥对
 * iKeyIndex            IN        要产生的SM2密钥索引，<=0或=9999时标识不存储
 * pcKeyLabel           IN        SM2密钥标签，仅当iKeyIndex>0且!=9999时有效;
 * pucDerPublicKey      OUT       新生成的SM2公钥，DER编码
 * piDerPublicKeyLen    OUT       新生成的SM2公钥长度
 * pucPrivateKey_Lmk    OUT       LMK下加密的SM2私钥密文
 * piPrivateKeyLen_Lmk  OUT       LMK下加密的SM2私钥密文长度
 */
int HSM_SM2_GenerateNewKeyPair(
    void *hSessionHandle,int nSock,  int iKeyIndex, char *pcKeyLabel,
    unsigned char *pucDerPublicKey, int *piDerPublicKeyLen,
    unsigned char *pucPrivateKey_Lmk, int *piPrivateKeyLen_Lmk )
{
    int rv = HAR_OK;
    int len = 0;
    int plainlen = 0;
    int iCmdLen;
    int iRspLen = 512;
    unsigned char aucCmd[128] = {0};
    unsigned char aucRsp[512] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "E7" ***/
    *p ++ = 'E';
    *p ++ = '7';

    /*** 曲线标识, 2N, 07-国密-256新曲线，SM2 ***/
    *p ++ = '0';
    *p ++ = '7';

    /*** 内部存储的密钥, 密钥索引、标签长度、标签 ***/
    rv = Tools_AddFieldSavedKey(iKeyIndex, pcKeyLabel, p);
    if(rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("Parameter: pcKeyLabel length = [%d] is invalid.", strlen(pcKeyLabel));
        return rv;
    }
    p += rv;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, nSock, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** 公钥, nB ***/
    len = Tools_GetFieldDerBufLength(p);
    if(piDerPublicKeyLen)
    {
        *piDerPublicKeyLen = len;
    }
    if(pucDerPublicKey)
    {
        memcpy(pucDerPublicKey, p, len);
    }
    p += len;

    /*** 私钥长度, 4N ***/
    len = Tools_ConvertDecBuf2Int(p, 4);
    if (piPrivateKeyLen_Lmk)
    {
        *piPrivateKeyLen_Lmk = len;
    }
    p += 4;

    /*** LMK加密的私钥数据, nB ***/
    if (pucPrivateKey_Lmk)
    {
        memcpy(pucPrivateKey_Lmk, p, len);
    }

    return HAR_OK;
}

/*
 * HSM_SM2_LoadKeyPair, 装载一对SM2密钥对到密码机内存储
 * iKeyIndex            IN        要导入的SM2密钥索引
 * pcKeyLabel           IN        要导入的SM2密钥标签
 * pucDerPublicKey      IN        要导入的SM2公钥，DER编码
 * piDerPublicKeyLen    IN        要导入的SM2公钥长度
 * pucPrivateKey_Lmk    IN        LMK下加密的SM2私钥密文
 * piPrivateKeyLen_Lmk  IN        LMK下加密的SM2私钥密文长度
 */
int HSM_SM2_LoadKeyPair(
    int iKeyIndex, char *pcKeyLabel,
    unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucPrivateKey_Lmk, int iPrivateKeyLen_Lmk)
{
    int rv = HAR_OK;
    int len = 0;
    int plainlen = 0;
    int iCmdLen;
    int iRspLen = 2048;
    unsigned char aucCmd[2048] = {0};
    unsigned char aucRsp[2048] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "E1" ***/
    *p ++ = 'E';
    *p ++ = '1';

    /*** 曲线标识, 2N, 07-国密-256新曲线，SM2 ***/
    *p ++ = '0';
    *p ++ = '7';

    /*** 公钥, nB ***/
    memcpy(p, pucDerPublicKey, iDerPublicKeyLen);
    p += iDerPublicKeyLen;

    /*** 私钥长度, 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iPrivateKeyLen_Lmk);
    p += 4;

    /*** LMK加密的私钥数据, nB ***/
    memcpy(p, pucPrivateKey_Lmk, iPrivateKeyLen_Lmk);
    p += iPrivateKeyLen_Lmk;

    /*** 密钥索引, 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iKeyIndex);
    p += 4;

    /*** 标签长度, 2N ***/
    if (!pcKeyLabel)
    {
        len = 0;
    }
    else
    {
        len = strlen(pcKeyLabel);
    }

    TASS_SPRINTF((char*)p, 3, "%02d", len);
    p += 2;

    /*** 标签, 0-16A ***/
    memcpy(p, pcKeyLabel, len);
    p += len;

    iCmdLen = (int)(p - aucCmd);
    //rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/*
 * HSM_SM2_GetPublicKey, 获取一对SM2密钥的公钥
 * iKeyIndex            IN        要导出公钥的SM2密钥索引
 * pucDerPublicKey      OUT       导出的SM2公钥，DER编码
 * piDerPublicKeyLen    OUT       导出的SM2公钥长度
 */
int HSM_SM2_GetPublicKey( int iKeyIndex, unsigned char *pucDerPublicKey/*out*/, int *piDerPublicKeyLen/*out*/ )
{
    int rv = HAR_OK;
    int len = 0;
    int plainlen = 0;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[256] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "E2" ***/
    *p ++ = 'E';
    *p ++ = '2';

    /*** 密钥索引, K+4N ***/
    TASS_SPRINTF((char*)p, 6, "K%04d", iKeyIndex);
    p += 5;

    iCmdLen = (int)(p - aucCmd);
    //rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** 公钥, nB ***/
    len = Tools_GetFieldDerBufLength(p);
    if (piDerPublicKeyLen)
    {
        *piDerPublicKeyLen = len;
    }
    if (pucDerPublicKey)
    {
        memcpy(pucDerPublicKey, p, len);
    }

    return rv;
}

/*
 * HSM_SM2_EncryptData, SM2公钥加密数据
 * iKeyIndex            IN        SM2密钥索引，<=0或=9999时下述2个参数有效
 * pucDerPublicKey      IN        DER编码的SM2公钥，当iKeyIndex=9999时有效
 * iDerPublicKeyLen     IN        DER编码的SM2公钥长度，当iKeyIndex=9999时有效
 * pucInput             IN        要加密的输入数据，最多支持136字节的加密运算
 * iInputLength         IN        要加密的输入数据长度，最大136
 * pucOutput            OUT       加密后的输出数据
 * piOutputLength       OUT       加密后的输出数据长度
 */
int HSM_SM2_EncryptData(void *hSessionHandle,int nSock,
    int iKeyIndex, unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucInput, int iInputLength,
    unsigned char *pucOutput/*out*/, int *piOutputLength/*out*/ )
{
    int rv = HAR_OK;
    int len = 0;
    int plainlen = 0;
    int iCmdLen;
    int iRspLen = 1900 + 128;
    unsigned char aucCmd[1900 + 256] = {0};
    unsigned char aucRsp[1900 + 128] = {0};
    unsigned char *p = aucCmd;

    if(iInputLength > 1900)
    {
        LOG_ERROR("Parameter: iInputLength = [%d] is invalid, it must be less than 1900.", iInputLength);
        return HAR_PARAM_LEN;
    }

    /*** Command Code    "E3" ***/
    *p ++ = 'E';
    *p ++ = '3';

    /*** 曲线标识, 2N, 07-国密-256新曲线，SM2 ***/
    *p ++ = '0';
    *p ++ = '7';

    /*** 数据块长度, 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iInputLength);
    p += 4;

    /*** 数据块, nB ***/
    memcpy(p, pucInput, iInputLength);
    p += iInputLength;

    /*** 分隔符, 1A ***/
    *p ++ = ';';

    /*** 密钥索引, K+4N ***/
    if(iKeyIndex <= 0)
    {
        iKeyIndex = 9999;
    }

    TASS_SPRINTF((char*)p, 6, "K%04d", iKeyIndex);
    p += 5;

    /*** 公钥DER编码 ***/
    if (iKeyIndex == 9999)
    {
        memcpy(p, pucDerPublicKey, iDerPublicKeyLen);
        p += iDerPublicKeyLen;
    }

    /*** 密文编码格式, 1N, 0 – 密文串（hash、密文序列 ***/
    *p ++ = '0';

    iCmdLen = (int)(p - aucCmd);
    
    rv = TCP_CommunicateHsm_ex(hSessionHandle, nSock, aucCmd, iCmdLen, aucRsp, &iRspLen);
    

    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** 密文长度, 4N ***/
    len = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;
    if(piOutputLength)
    {
        *piOutputLength = len;
    }

    /*** 密文数据, nB ***/
    if(pucOutput)
    {
        memcpy(pucOutput, p, len);
    }

    return HAR_OK;
}

/*
 * HSM_SM2_DecryptData, SM2私钥解密数据
 * iKeyIndex            IN        SM2密钥索引，<=0或=9999时下述2个参数有效
 * pucPrivateKey_Lmk    IN        LMK加密的SM2私钥，当iSm2KeyIndex=9999时有效
 * iPrivateKeyLen_Lmk   IN        LMK加密的SM2私钥长度，当iSm2KeyIndex=9999时有效
 * pucInput             IN        要解密的输入数据
 * iInputLength         IN        要解密的输入数据长度
 * pucOutput            OUT       解密后的输出数据
 * piOutputLength       OUT       解密后的输出数据长度
 */
int HSM_SM2_DecryptData(void *hSessionHandle,int nSock,
    int iKeyIndex, unsigned char *pucPrivateKey_Lmk, int iPrivateKeyLen_Lmk,
    unsigned char *pucInput, int iInputLength,
    unsigned char *pucOutput/*out*/, int *piOutputLength/*out*/ )
{
    int rv = HAR_OK;
    int len = 0;
    int plainlen = 0;
    int iCmdLen;
    int iRspLen = 1996 + 128;
    unsigned char aucCmd[1996 + 256] = {0};
    unsigned char aucRsp[1996 + 128] = {0};
    unsigned char *p = aucCmd;

    if(iInputLength > 1996)
    {
        LOG_ERROR("Parameter: iInputLength = [%d] is invalid, it must be less than 1996.", iInputLength);
        return HAR_PARAM_LEN;
    }

    /*** Command Code    "E4" ***/
    *p ++ = 'E';
    *p ++ = '4';

    /*** 曲线标识, 2N, 07-国密-256新曲线，SM2 ***/
    *p ++ = '0';
    *p ++ = '7';

    /*** 密文编码格式, 1N, 0 – 密文串（hash、密文序列） ***/
    *p ++ = '0';

    /*** 数据块长度, 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iInputLength);
    p += 4;

    /*** 数据块, nB ***/
    memcpy(p, pucInput, iInputLength);
    p += iInputLength;

    /*** 分隔符, 1A ***/
    *p ++ = ';';

    /*** 密钥索引, K+4N ***/
    if(iKeyIndex <= 0)
    {
        iKeyIndex = 9999;
    }

    TASS_SPRINTF((char*)p, 6, "K%04d", iKeyIndex);
    p += 5;

    if(iKeyIndex == 9999)
    {
        /*** 私钥长度, 4N ***/
        TASS_SPRINTF((char*)p, 5, "%04d", iPrivateKeyLen_Lmk);
        p += 4;

        /*** LMK加密的密文私钥数据, nB ***/
        memcpy(p, pucPrivateKey_Lmk, iPrivateKeyLen_Lmk);
        p += iPrivateKeyLen_Lmk;
    }

    iCmdLen = (int)(p - aucCmd); 
    
    rv = TCP_CommunicateHsm_ex(hSessionHandle,nSock,aucCmd, iCmdLen, aucRsp, &iRspLen);  
    
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }
    

    /*** Response Buffer ***/
    p = aucRsp;

    /*** 输出数据长度, 4N ***/
    len = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;
    if(piOutputLength)
    {
        *piOutputLength = len;
    }

    /*** 输出数据, nB ***/
    if(pucOutput)
    {
        memcpy(pucOutput, p, len);
    }

    return HAR_OK;
}

/*
 * HSM_SM2_GenerateSignature, SM2私钥对数据进行数字签名
 * hSessionHandle       IN        会话句柄
 * iKeyIndex            IN        SM2密钥索引，<=0或=9999时下述4个参数有效
 * pucDerPublicKey      IN        DER编码的SM2公钥，当iKeyIndex=9999时有效
 * iDerPublicKeyLen     IN        DER编码的SM2公钥长度，当iKeyIndex=9999时有效
 * pucPrivateKey_Lmk    IN        LMK加密的SM2私钥，当iSm2KeyIndex=9999时有效
 * iPrivateKeyLen_Lmk   IN        LMK加密的SM2私钥长度，当iSm2KeyIndex=9999时有效
 * pucUserId            IN        用户标识
 * iUserIdLength        IN        用户标识长度
 * pucInput             IN        待签名的输入数据
 * iInputLength         IN        待签名的输入数据长度
 * pucSignature         OUT       输出的数据签名
 * piSignatureLength    OUT       输出的数据签名长度
 */
int HSM_SM2_GenerateSignature(
	void *hSessionHandle,int nSock,
    int iKeyIndex,
    unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucPrivateKey_Lmk, int iPrivateKeyLen_Lmk,
    unsigned char *pucUserId, int iUserIdLength,
    unsigned char *pucInput, int iInputLength,
    unsigned char *pucSignature/*out*/, int *piSignatureLength/*out*/ )
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen = 0;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = {0};
    unsigned char aucRsp[4096] = {0};
    unsigned char *p = aucCmd;

    if(iInputLength > 1984)
    {
        LOG_ERROR("Parameter: iInputLength = [%d] is invalid, it must be less than 1984.", iInputLength);
        return HAR_PARAM_LEN;
    }

    /*** Command Code    "E5" ***/
    *p ++ = 'E';
    *p ++ = '5';

    /*** HASH算法标识, 2N, 20 – SM3 ***/
    *p ++ = '2';
    *p ++ = '0';

    /*** 曲线标识, 2N, 07-国密-256新曲线，SM2 ***/
    *p ++ = '0';
    *p ++ = '7';

    /*** 用户标识长度, 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iUserIdLength);
    p += 4;

    /*** 用户标识, nB ***/
    memcpy(p, pucUserId, iUserIdLength);
    p += iUserIdLength;

    /*** 分隔符, 1A ***/
    *p ++ = ';';

    /*** 数据块长度, 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iInputLength);
    p += 4;

    /*** 数据块, nB ***/
    memcpy(p, pucInput, iInputLength);
    p += iInputLength;

    /*** 分隔符, 1A ***/
    *p ++ = ';';

    /*** 密钥索引, K+4N ***/
    if(iKeyIndex <= 0)
    {
        iKeyIndex = 9999;
    }

    TASS_SPRINTF((char*)p, 6, "K%04d", iKeyIndex);
    p += 5;

    if(iKeyIndex == 9999)
    {
        /*** DER编码的SM2公钥, nB ***/
        memcpy(p, pucDerPublicKey, iDerPublicKeyLen);
        p += iDerPublicKeyLen;

        /*** 私钥长度, 4N ***/
        TASS_SPRINTF((char*)p, 5, "%04d", iPrivateKeyLen_Lmk);
        p += 4;

        /*** LMK加密的密文私钥数据, nB ***/
        memcpy(p, pucPrivateKey_Lmk, iPrivateKeyLen_Lmk);
        p += iPrivateKeyLen_Lmk;
    }

    /*** 签名编码格式, 1N, 0 – 签名值数据串（r、s序列） ***/
    *p ++ = '0';

    iCmdLen = (int)(p - aucCmd);
	//Tools_PrintBuf("cmd",aucCmd,iCmdLen);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, nSock,aucCmd, iCmdLen, aucRsp, &iRspLen);
	//Tools_PrintBuf("rsp",aucRsp,iRspLen);

    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** 数字签名长度, 4N ***/
    len = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;
    if(piSignatureLength)
    {
        *piSignatureLength = len;
    }

    /*** 输出数据, nB ***/
    if(pucSignature)
    {
        memcpy(pucSignature, p, len);
    }

    return rv;
}

/*
 * HSM_SM2_GenSignatureSummary, SM2私钥对数据摘要值进行数字签名
  * hSessionHandle      IN        会话句柄
 * iKeyIndex            IN        SM2公钥索引，<=0或=9999时下述4个参数有效
 * pucPrivateKey_Lmk    IN        LMK加密的SM2私钥，当iSm2KeyIndex=9999时有效
 * iPrivateKeyLen_Lmk   IN        LMK加密的SM2私钥长度，当iSm2KeyIndex=9999时有效
 * pucSummary           IN        数据块摘要值
 * iSummaryLen          IN        数据块摘要值长度
 * iSignatureFormat     IN        签名编码格式
 * pucSignature         OUT       输出的数据签名
 * piSignatureLength    OUT       输出的数据签名长度
 */
int HSM_SM2_GenSignatureSummary(
    void *hSessionHandle,int nSock, int iKeyIndex,
    unsigned char *pucPrivateKey_Lmk, int iPrivateKeyLen_Lmk,
    unsigned char *pucSummary, int iSummaryLen,
	int iSignatureFormat,
    unsigned char *pucSignature/*out*/, int *piSignatureLength/*out*/ )
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 256;
    unsigned char aucCmd[4096] = {0};
    unsigned char aucRsp[4096] = {0};
    unsigned char *p = aucCmd;

    if(iSummaryLen != 32)
    {
        LOG_ERROR("Parameter: pucSummary = [%d] is invalid, it must be 32.", iSummaryLen);
        return HAR_PARAM_LEN;
    }

    /*** Command Code    "E5" ***/
    *p ++ = 'E';
    *p ++ = 'D';

    /*** 曲线标识, 2N, 07-国密-256新曲线，SM2 ***/
    *p ++ = '0';
    *p ++ = '7';

  
    /*** 数据块摘要值, nB ***/
    memcpy(p, pucSummary, iSummaryLen);
    p += iSummaryLen;

    /*** 密钥索引, K+4N ***/
    if(iKeyIndex <= 0)
    {
        iKeyIndex = 9999;
    }

    TASS_SPRINTF((char*)p, 6, "K%04d", iKeyIndex);
    p += 5;

    if(iKeyIndex == 9999)
    {
       

        /*** 私钥长度, 4N ***/
        TASS_SPRINTF((char*)p, 5, "%04d", iPrivateKeyLen_Lmk);
        p += 4;

        /*** LMK加密的密文私钥数据, nB ***/
        memcpy(p, pucPrivateKey_Lmk, iPrivateKeyLen_Lmk);
        p += iPrivateKeyLen_Lmk;
    }

    /*** 签名编码格式, 1N, 0 – 签名值数据串（r、s序列） ***/
    *p ++ = '0' + iSignatureFormat;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, nSock, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** 数字签名长度, 4N ***/
    len = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;
    if(piSignatureLength)
    {
        *piSignatureLength = len;
    }

    /*** 输出数据, nB ***/
    if(pucSignature)
    {
        memcpy(pucSignature, p, len);
    }

    return rv;
}

int HSM_SM2_VerifySignature(
    void *hSessionHandle,int nSock,
    int iKeyIndex, unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucUserId, int iUserIdLength,
    unsigned char *pucInput, int iInputLength,
    unsigned char *pucSignature, int iSignatureLength )
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 8;
    unsigned char aucCmd[1984 + 512] = {0};
    unsigned char aucRsp[8] = {0};
    unsigned char *p = aucCmd;

    if(iInputLength > 1984)
    {
        LOG_ERROR("Parameter: iInputLength = [%d] is invalid, it must be less than 1984.", iInputLength);
        return HAR_PARAM_LEN;
    }

    /*** Command Code    "E6" ***/
    *p ++ = 'E';
    *p ++ = '6';

    /*** HASH算法标识, 2N, 20 – SM3 ***/
    *p ++ = '2';
    *p ++ = '0';

    /*** 曲线标识, 2N, 07-国密-256新曲线，SM2 ***/
    *p ++ = '0';
    *p ++ = '7';

    /*** 用户标识长度, 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iUserIdLength);
    p += 4;

    /*** 用户标识, nB ***/
    memcpy(p, pucUserId, iUserIdLength);
    p += iUserIdLength;

    /*** 分隔符, 1A ***/
    *p ++ = ';';

    /*** 签名编码格式, 1N, 0 – 签名值数据串（r、s序列） ***/
    *p ++ = '0';

    /*** 待验签的签名长度, 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iSignatureLength);
    p += 4;

    /*** 待验签的签名, nB ***/
    memcpy(p, pucSignature, iSignatureLength);
    p += iSignatureLength;

    /*** 分隔符, 1A ***/
    *p ++ = ';';

    /*** 数据块长度, 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iInputLength);
    p += 4;

    /*** 数据块, nB ***/
    memcpy(p, pucInput, iInputLength);
    p += iInputLength;

    /*** 分隔符, 1A ***/
    *p ++ = ';';

    /*** 密钥索引, K+4N ***/
    if(iKeyIndex <= 0)
    {
        iKeyIndex = 9999;
    }

    TASS_SPRINTF((char*)p, 6, "K%04d", iKeyIndex);
    p += 5;

    if(iKeyIndex == 9999)
    {
        /*** DER编码的SM2公钥, nB ***/
        memcpy(p, pucDerPublicKey, iDerPublicKeyLen);
        p += iDerPublicKeyLen;
    }

    iCmdLen = (int)(p - aucCmd);
	//Tools_PrintBuf("cmd",aucCmd,iCmdLen);
    rv = TCP_CommunicateHsm_ex(hSessionHandle,nSock,aucCmd, iCmdLen, aucRsp, &iRspLen);
	//Tools_PrintBuf("rsp",aucRsp,iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/*
 * HSM_SM2_VerifySummarySignature, SM2私钥对数据摘要值签名验签
 * hSessionHandle      IN        会话句柄
 * pucSignature        IN        待验证的签名
 * iSignatureLength    IN        待验证签名的长度
 * iKeyIndex           IN        SM2公钥索引，<=0或=9999时下述4个参数有效
 * pucPublicKey        IN        SM2公钥，当iSm2KeyIndex=9999时有效
 * iPublicKeyLen       IN        SM2公钥长度，当iSm2KeyIndex=9999时有效
 * pucSummary          IN        数据块摘要值
 * iSummaryLen         IN        数据块摘要值长度
 * iSignatureFormat    IN        签名编码格式
 */
int HSM_SM2_VerifySummarySignature(
	void *hSessionHandle,int nSock, 
	unsigned char *pucSignature, int iSignatureLength,
	int iKeyIndex,  unsigned char *pucPublicKey, 
	int iPublicKeyLen, unsigned char *pucSummary, 
	int iSummaryLen, int iSignatureFormat)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen = 4096;
    int iRspLen = 128;
    unsigned char aucCmd[4096] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    if(iSummaryLen != 32)
    {
        LOG_ERROR("Parameter: iSummaryLen = [%d] is invalid, it must be less than 1984.", iSummaryLen);
        return HAR_PARAM_LEN;
    }

    /*** Command Code    "EF" ***/
    *p ++ = 'E';
    *p ++ = 'F';


    /*** 曲线标识, 2N, 07-国密-256新曲线，SM2 ***/
    *p ++ = '0';
    *p ++ = '7';


    /*** 签名编码格式, 1N, 0 – 签名值数据串（r、s序列） ***/
    *p ++ = '0'+ iSignatureFormat;

    /*** 待验签的签名长度, 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iSignatureLength);
    p += 4;

    /*** 待验签的签名, nB ***/
    memcpy(p, pucSignature, iSignatureLength);
    p += iSignatureLength;

    /*** 分隔符, 1A ***/
    *p ++ = ';';

  
    /*** 数据块, nB ***/
    memcpy(p, pucSummary, iSummaryLen);
    p += iSummaryLen;

 

    /*** 密钥索引, K+4N ***/
    if(iKeyIndex <= 0)
    {
        iKeyIndex = 9999;
    }

    TASS_SPRINTF((char*)p, 6, "K%04d", iKeyIndex);
    p += 5;

    if(iKeyIndex == 9999)
    {
        /*** DER编码的SM2公钥, nB ***/
        memcpy(p, pucPublicKey, iPublicKeyLen);
        p += iPublicKeyLen;
    }

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle,nSock,aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
		return rv;
    }
    return HAR_OK;
}



/*
 * HSM_SM2_ExportByTK, 传输密钥（KEK/MDK，可分散可不分散）保护导出一对SM2密钥对
 * iMode                IN        0–ECB, 1–CBC
 * pcTkType             IN        "000"–KEK;  "109"–MDK;
 * iTkIndex             IN        <=0, 使用pcTk_Lmk参数；否则使用索引指定的密钥
 * pcTk_Lmk             IN        当iTkIndex<=0时有效
 * iTkDiversifyNumber      IN        保护密钥的分散级数
 * pcTkDiversifyData       IN        保护密钥的分散因子，每级32H
 * iSm2KeyIndex         IN        要被导出的SM2密钥索引，<=0或=9999时下述4个参数有效
 * pucDerPublicKey      IN        DER编码的SM2公钥，当iSm2KeyIndex=9999时有效
 * iDerPublicKeyLen     IN        DER编码的SM2公钥长度，当iSm2KeyIndex=9999时有效
 * pucPrivateKey_Lmk    IN        LMK加密的SM2私钥，当iSm2KeyIndex=9999时有效
 * iPrivateKeyLen_Lmk   IN        LMK加密的SM2私钥长度，当iSm2KeyIndex=9999时有效
 * pucPrivateKey_Tk     OUT       保护密钥加密的SM2私钥密文
 * piPrivateKeyLen_Tk   OUT       保护密钥加密的SM2私钥密文长度
 */
int HSM_SM2_ExportByTK(
    void *hSessionHandle,int nSock,
    int iMode, char *pcTkType,
    int iTkIndex, char *pcTk_Lmk,
    int iTkDiversifyNumber, char *pcTkDiversifyData,
    int iSm2KeyIndex,
    unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucPrivateKey_Lmk, int iPrivateKeyLen_Lmk,
    unsigned char *pucPrivateKey_Tk, int *piPrivateKeyLen_Tk/*out*/ )
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 256;
    unsigned char aucCmd[512] = {0};
    unsigned char aucRsp[256] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "TT" ***/
    *p ++ = 'T';
    *p ++ = 'T';

    /*** 加密算法模式, 2N, 00 – ECB, 01 – CBC ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iMode);
    p += 2;

    /*** 保护密钥类型, 3H, "000"–KEK;  "109"–MDK ***/
    memcpy(p, pcTkType, 3);
    p += 3;

    /*** 保护密钥 ***/
    rv = Tools_AddFieldKey(iTkIndex, pcTk_Lmk, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("Parameter: iTkIndex = [%d] is invalid.", iTkIndex);
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** 保护密钥分散级数及分散因子, 2H+n*32H ***/
    rv = Tools_AddFieldDiversifyData(1, iTkDiversifyNumber, pcTkDiversifyData, (char*)p);
    if (rv == HAR_PARAM_Diversify_DATA)
    {
        LOG_ERROR("Parameter: pcTkDiversifyData's length = [%d] is invalid.", strlen(pcTkDiversifyData));
        return HAR_PARAM_Diversify_DATA;
    }
    p += rv;

    /*** 曲线标识, 2N, 07-国密-256新曲线，SM2 ***/
    *p ++ = '0';
    *p ++ = '7';

    /*** 密钥索引, 4N ***/
    if(iSm2KeyIndex <= 0)
    {
        iSm2KeyIndex = 9999;
    }

    TASS_SPRINTF((char*)p, 5, "%04d", iSm2KeyIndex);
    p += 4;

    if(iSm2KeyIndex == 9999)
    {
        /*** DER编码的SM2公钥, nB ***/
        memcpy(p, pucDerPublicKey, iDerPublicKeyLen);
        p += iDerPublicKeyLen;

        /*** 私钥长度, 4N ***/
        TASS_SPRINTF((char*)p, 5, "%04d", iPrivateKeyLen_Lmk);
        p += 4;

        /*** LMK加密的密文私钥数据, nB ***/
        memcpy(p, pucPrivateKey_Lmk, iPrivateKeyLen_Lmk);
        p += iPrivateKeyLen_Lmk;
    }

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, nSock, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** 公钥， ASN.1 格式DER 编码, nB ***/
    len = Tools_GetFieldDerBufLength(p);
    p += len;

    /*** 传输密钥加密的私钥分量d密文长度, 4N ***/
    len = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;
    if(piPrivateKeyLen_Tk)
    {
        *piPrivateKeyLen_Tk = len;
    }

    /*** 传输密钥加密的私钥分量d密文, nB ***/
    if(pucPrivateKey_Tk)
    {
        memcpy(pucPrivateKey_Tk, p, len);
    }

    return HAR_OK;
}

/*
 * HSM_SM2_ImportByTK, 传输密钥（KEK/MDK，可分散可不分散）保护导入一对SM2密钥对
 * iMode                   IN        0–ECB, 1–CBC
 * pcTkType                IN        "000"–KEK;  "109"–MDK;
 * iTkIndex                IN        <=0, 使用pcTk_Lmk参数；否则使用索引指定的密钥
 * pcTk_Lmk                IN        当iTkIndex<=0时有效
 * iTkDiversifyNumber         IN        保护密钥的分散级数
 * pcTkDiversifyData          IN        保护密钥的分散因子，每级32H
 * iSm2KeyIndex            IN        要被导出的SM2密钥索引，<=0或=9999时下述4个参数有效
 * pucDerPublicKey         IN        DER编码的SM2公钥，当iSm2KeyIndex=9999时有效
 * iDerPublicKeyLen        IN        DER编码的SM2公钥长度，当iSm2KeyIndex=9999时有效
 * pucPrivateKey_Lmk       IN        LMK加密的SM2私钥，当iSm2KeyIndex=9999时有效
 * iPrivateKeyLen_Lmk      IN        LMK加密的SM2私钥长度，当iSm2KeyIndex=9999时有效
 * pucPrivateKey_Tk        OUT       保护密钥加密的SM2私钥密文
 * piPrivateKeyLen_Tk      OUT       保护密钥加密的SM2私钥密文长度
 */
int HSM_SM2_ImportByTK(
    int iMode, char *pcTkType,
    int iTkIndex, char *pcTk_Lmk,
    int iTkDiversifyNumber, char *pcTkDiversifyData,
    int iSm2KeyIndex, char *pcSm2KeyLabel,
    unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucPrivateKey_Tk, int iPrivateKeyLen_Tk,
    unsigned char *pucPrivateKey_Lmk/*out*/, int *piPrivateKeyLen_Lmk/*out*/ )
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 256;
    unsigned char aucCmd[512] = {0};
    unsigned char aucRsp[256] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "TU" ***/
    *p ++ = 'T';
    *p ++ = 'U';

    /*** 加密算法模式, 2N, 00 – ECB, 01 – CBC ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iMode);
    p += 2;

    /*** 保护密钥类型, 3H, "000"–KEK;  "109"–MDK ***/
    memcpy(p, pcTkType, 3);
    p += 3;

    /*** 保护密钥 ***/
    rv = Tools_AddFieldKey(iTkIndex, pcTk_Lmk, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("Parameter: iTkIndex = %d is invalid.", iTkIndex);
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** 保护密钥分散级数及分散因子, 2H+n*32H ***/
    rv = Tools_AddFieldDiversifyData(1, iTkDiversifyNumber, pcTkDiversifyData, p);
    if (rv == HAR_PARAM_Diversify_DATA)
    {
        LOG_ERROR("Parameter: pcTkDiversifyData's length = [%d] is invalid.", strlen(pcTkDiversifyData));
        return HAR_PARAM_Diversify_DATA;
    }
    p += rv;

    /*** 曲线标识, 2N, 07-国密-256新曲线，SM2 ***/
    *p ++ = '0';
    *p ++ = '7';

    /*** 密钥索引, 4N ***/
    if (iSm2KeyIndex <= 0)
    {
        iSm2KeyIndex = 9999;
    }

    TASS_SPRINTF((char*)p, 5, "%04d", iSm2KeyIndex);
    p += 4;

    /*** DER编码的SM2公钥, nB ***/
    memcpy(p, pucDerPublicKey, iDerPublicKeyLen);
    p += iDerPublicKeyLen;

    /*** 保护密钥加密的SM2私钥分量d密文长度, 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iPrivateKeyLen_Tk);
    p += 4;

    /*** 保护密钥加密的SM2私钥分量d密文, nB ***/
    memcpy(p, pucPrivateKey_Tk, iPrivateKeyLen_Tk);
    p += iPrivateKeyLen_Tk;

    if(iSm2KeyIndex != 9999)
    {
        /*** 标签长度，2N ***/
        if (!pcSm2KeyLabel)
        {
            len = 0;
        }
        else
        {
            len = strlen(pcSm2KeyLabel);
        }

        TASS_SPRINTF((char*)p, 3, "%02d", len);
        p += 2;

        /*** 密钥标签，nA ***/
        memcpy(p, pcSm2KeyLabel, len);
        p += len;
    }

    iCmdLen = (int)(p - aucCmd);
    //rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** LMK加密的私钥密文长度, 4N ***/
    len = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;
    if(piPrivateKeyLen_Lmk)
    {
        *piPrivateKeyLen_Lmk = len;
    }

    /*** LMK加密的私钥密文, nB ***/
    if(pucPrivateKey_Lmk)
    {
        memcpy(pucPrivateKey_Lmk, p, len);
    }

    return HAR_OK;
}

/*
 * HSM_SM2_GeneratePublicKeyMac, 在授权控制下为SM2公钥产生公钥MAC
 * pucDerPublicKey      IN        要计算MAC的SM2公钥，DER编码
 * iDerPublicKeyLen     IN        要计算MAC的SM2公钥长度
 * pucAuthData          IN        公钥鉴别数据，不能带';'字符
 * iAuthDataLen         IN        公钥鉴别数据长度
 * pucMac               OUT       SM2公钥的MAC值
 * piMacLen             OUT       SM2公钥的MAC值长度
 */
int HSM_SM2_GeneratePublicKeyMac(
    unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucAuthData, int iAuthDataLen,
    unsigned char *pucMac/*out*/, int *piMacLen/*out*/ )
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 256;
    unsigned char aucCmd[512] = {0};
    unsigned char aucRsp[256] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "TQ" ***/
    *p ++ = 'T';
    *p ++ = 'Q';

    /*** 曲线标识, 2N, 07-国密-256新曲线，SM2 ***/
    *p ++ = '0';
    *p ++ = '7';

    /*** DER编码的SM2公钥, nB ***/
    memcpy(p, pucDerPublicKey, iDerPublicKeyLen);
    p += iDerPublicKeyLen;

    /*** 用于计算公钥MAC的额外的数据（不能包含字符’;’）, nB ***/
    memcpy(p, pucAuthData, iAuthDataLen);
    p += iAuthDataLen;

    iCmdLen = (int)(p - aucCmd);
    //rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%#010X].", rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** 使用LMK分组对公钥和认证数据计算的MAC，4B ***/
    if(piMacLen)
    {
        *piMacLen = 4;
    }

    if(pucMac)
    {
        memcpy(pucMac, p, 4);
    }

    return HAR_OK;
}

/*
 * HSM_SM2_ExportSymmetricKey, 由SM2公钥加密保护导出一条对称密钥
 * pcKeyType            IN        被导出密钥的密钥类型："000"–KEK; 00A–DEK; "109"–MDK;
 * iKeyIndex            IN        被导出密钥的索引。<=0, 使用pcKey_Lmk参数；否则使用索引指定的密钥
 * pcKey_Lmk            IN        LMK加密的被导出密钥的密文。当iKeyIndex<=0时有效
 * iKeyDiversifyNumber     IN        被导出密钥的分散级数
 * pcKeyDiversifyData      IN        被导出密钥的分散因子，每级32H
 * iSm2KeyIndex         IN        作为保护密钥的SM2密钥索引，<=0或=9999时标识使用pucDerPublicKey参数
 * pucDerPublicKey      IN        作为保护密钥的DER编码的SM2公钥，仅当iSm2KeyIndex<=0或=9999时有效
 * iDerPublicKeyLen     IN        作为保护密钥的DER编码的SM2公钥长度，仅当iSm2KeyIndex<=0或=9999时有效
 * pucAuthData          IN        作为保护密钥的公钥鉴别数据，不能带';'字符
 * iAuthDataLen         IN        作为保护密钥的公钥鉴别数据长度
 * pucMac               IN        作为保护密钥的SM2公钥的MAC值
 * iMacLen              IN        作为保护密钥的SM2公钥的MAC值长度
 * pucCipherKey         OUT       SM2密钥加密的被导出密钥密文
 * piCipherKeyLen       OUT       SM2密钥加密的被导出密钥密文长度
 * pcKeyCv              OUT       被导出密钥的校验值
 */
int HSM_SM2_ExportSymmetricKey(
    char *pcKeyType, int iKeyIndex, char *pcKey_Lmk,
    int iKeyDiversifyNumber, char *pcKeyDiversifyData,
    int iSm2KeyIndex,
    unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucAuthData, int iAuthDataLen,
    unsigned char *pucMac,
    unsigned char *pucCipherKey/*out*/, int *piCipherKeyLen/*out*/,
    char *pcKeyCv/*out*/ )
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 256;
    unsigned char aucCmd[512] = {0};
    unsigned char aucRsp[256] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "TX" ***/
    *p ++ = 'T';
    *p ++ = 'X';

    /*** 曲线标识, 2N, 07-国密-256新曲线，SM2 ***/
    *p ++ = '0';
    *p ++ = '7';

    /*** 被导出密钥的密钥类型："000"–KEK; 00A–DEK; "109"–MDK; ***/
    memcpy(p, pcKeyType, 3);
    p += 3;

    /*** 被导出密钥 ***/
    rv = Tools_AddFieldKey(iKeyIndex, pcKey_Lmk, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("Parameter: iKeyIndex = [%d] is invalid.", iKeyIndex);
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** 被导出密钥分散级数及分散因子, 2H+n*32H ***/
    rv = Tools_AddFieldDiversifyData(1, iKeyDiversifyNumber, pcKeyDiversifyData, (char*)p);
    if (rv == HAR_PARAM_Diversify_DATA)
    {
        LOG_ERROR("Parameter: pcKeyDiversifyData's length = [%d] is invalid.", strlen(pcKeyDiversifyData));
        return HAR_PARAM_Diversify_DATA;
    }
    p += rv;

    /*** 密钥索引, 4N ***/
    if(iSm2KeyIndex <= 0)
    {
        iSm2KeyIndex = 9999;
    }

    TASS_SPRINTF((char*)p, 5, "%04d", iSm2KeyIndex);
    p += 4;

    if(iSm2KeyIndex == 9999)
    {
        /*** DER编码的SM2公钥, nB ***/
        memcpy(p, pucDerPublicKey, iDerPublicKeyLen);
        p += iDerPublicKeyLen;

        /*** 用于计算公钥MAC的额外的数据（不能包含字符’;’）, nB ***/
        memcpy(p, pucAuthData, iAuthDataLen);
        p += iAuthDataLen;

        /*** 认证数据分隔符,';' ***/
        *p ++ = ';';

        /*** 公钥MAC, 4B ***/
        memcpy(p, pucMac, 4);
        p += 4;
    }

    iCmdLen = (int)(p - aucCmd);
    //rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** SM2密钥加密的被导出密钥密文长度, 4N ***/
    len = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;
    if(piCipherKeyLen)
    {
        *piCipherKeyLen = len;
    }

    /*** SM2密钥加密的被导出密钥密文, nB ***/
    if(pucCipherKey)
    {
        memcpy(pucCipherKey, p, len);
    }
    p += len;

    /*** 被导出密钥的校验值  ***/
    if(pcKeyCv)
    {
        strncpy(pcKeyCv, (char *)p, 16);
    }

    return HAR_OK;
}

/*
 * HSM_SM2_ImportSymmetricKey, 由SM2公钥加密保护导入一条对称密钥
 * pcKeyType            IN        被导入密钥的密钥类型："000"–KEK; 00A–DEK; "109"–MDK;
 * cKeyScheme           IN        被导入密钥的算法标识：Z/X/Y/U/T/P/L/R
 * iKeyIndex            IN        被导入密钥的索引。<=0, 标识密钥不存储到内部
 * pcKeyLabel           IN        被导入密钥的标签。当iKeyIndex>0时有效
 * iSm2KeyIndex         IN        作为保护密钥的SM2密钥索引，<=0或=9999时标识使用pucPrivateKey_Lmk参数
 * pucPrivateKey_Lmk    IN        作为保护密钥的SM2私钥密文，仅当iSm2KeyIndex<=0或=9999时有效
 * iPrivateKeyLen_Lmk   IN        作为保护密钥的SM2私钥密文长度，仅当iSm2KeyIndex<=0或=9999时有效
 * pucCipherKey         IN        SM2公钥加密的被导入密钥密文
 * iCipherKeyLen        IN        SM2公钥加密的被导入密钥密文长度
 * pcKey_Lmk            OUT       LMK下加密的被导入密钥密文
 * pcKeyCv              OUT       被导入密钥的校验值
 */
int HSM_SM2_ImportSymmetricKey(
    char *pcKeyType, char cKeyScheme,
    int iKeyIndex, char *pcKeyLabel,
    int iSm2KeyIndex,
    unsigned char *pucPrivateKey_Lmk, int iPrivateKeyLen_Lmk,
    unsigned char *pucCipherKey, int iCipherKeyLen, 
    char *pcKey_Lmk/*out*/, char *pcKeyCv/*out*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 256;
    unsigned char aucCmd[512] = {0};
    unsigned char aucRsp[256] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "TY" ***/
    *p ++ = 'T';
    *p ++ = 'Y';

    /*** 曲线标识, 2N, 07-国密-256新曲线，SM2 ***/
    *p ++ = '0';
    *p ++ = '7';

    /*** 被导入密钥的密钥类型："000"–KEK; 00A–DEK; "109"–MDK; ***/
    memcpy(p, pcKeyType, 3);
    p += 3;

    /*** 被导入密钥的算法标识：Z/X/Y/U/T/P/L/R ***/
    *p ++ = cKeyScheme;

    /*** 内部存储的密钥, 密钥索引、标签长度、标签 ***/
    rv = Tools_AddFieldSavedKey(iKeyIndex, pcKeyLabel, p);
    if(rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("Parameter: pcKeyLabel length = [%d] is invalid.", strlen(pcKeyLabel));
        return rv;
    }
    p += rv;

    /*** 导入密钥的校验值, 16H, 全0则不校验，直接完成导入工作； ***/
    memset(p, '0', 16);
    p += 16;

    /*** SM2公钥加密的被导入密钥密文长度, 4H ***/
    TASS_SPRINTF((char*)p, 5, "%04X", iCipherKeyLen);
    p += 4;

    /*** SM2公钥加密的被导入密钥密文, nB ***/
    memcpy(p, pucCipherKey, iCipherKeyLen);
    p += iCipherKeyLen;

    /*** 密钥索引, 4N ***/
    if(iSm2KeyIndex <= 0)
    {
        iSm2KeyIndex = 9999;
    }

    TASS_SPRINTF((char*)p, 5, "%04d", iSm2KeyIndex);
    p += 4;

    if(iSm2KeyIndex == 9999)
    {
        /*** 私钥长度, 4N ***/
        TASS_SPRINTF((char*)p, 5, "%04d", iPrivateKeyLen_Lmk);
        p += 4;

        /*** LMK加密的密文私钥数据, nB ***/
        memcpy(p, pucPrivateKey_Lmk, iPrivateKeyLen_Lmk);
        p += iPrivateKeyLen_Lmk;
    }

    iCmdLen = (int)(p - aucCmd);
    //rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** LMK下加密的被导入密钥密文 ***/
    len = Tools_GetFieldKeyLength((char *)p);
    if(pcKey_Lmk)
    {
        strncpy(pcKey_Lmk, (char *)p, len);
    }
    p += len;

    /*** 校验值, 16H ***/
    if(pcKeyCv)
    {
        strncpy(pcKeyCv, (char *)p, 16);
    }

    return 0;
}

/*
 * HSM_RSA_GenerateNewKeyPair, 产生一对新的RSA密钥对
 * iKeyIndex            IN        要产生的RSA密钥索引，<=0或=9999时标识不存储
 * pcKeyLabel           IN        RSA密钥标签，仅当iKeyIndex>0且!=9999时有效;
 * iModulusBits         IN        RSA密钥模长，位数
 * iPubE                IN        RSA公钥指数E，3或65537
 * pucDerPublicKey      OUT       新生成的RSA公钥，DER编码
 * piDerPublicKeyLen    OUT       新生成的RSA公钥长度
 * pucPrivateKey_Lmk    OUT       LMK下加密的RSA私钥密文
 * piPrivateKeyLen_Lmk  OUT       LMK下加密的RSA私钥密文长度
 */
int HSM_RSA_GenerateNewKeyPair(void *hSessionHandle,int nSock,
    int iKeyIndex, char *pcKeyLabel,
    int iModulusBits, int iPubE,
    unsigned char *pucDerPublicKey/*out*/, int *piDerPublicKeyLen/*out*/,
    unsigned char *pucPrivateKey_Lmk/*out*/, int *piPrivateKeyLen_Lmk/*out*/ )
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = SOCKET_MAXDATALEN;
    unsigned char aucCmd[512] = {0};
    unsigned char aucRsp[SOCKET_MAXDATALEN] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "EI" ***/
    *p ++ = 'E';
    *p ++ = 'I';

    /*** 密钥用途, 1N, 0–签名密钥；1–密钥管理密钥；2–不限，建议使用此项 ***/
    *p ++ = '2';

    /*** 密钥模长, 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iModulusBits);
    p += 4;

    /*** 公钥编码类型, 2N, 01-ASN.1 格式DER 编码的公钥。整数使用2的补码表示法 ***/
    *p ++ = '0';
    *p ++ = '1';
#if 0
    /*** 公钥指数长度, 4N, 字节数/位数（TODO） ***/
    TASS_SPRINTF((char*)p, 5, "%04d", 4);
    p += 4;

    /*** 公钥指数, nB ***/
    Tools_ConvertUint2Ucbuf(iPubE, p);
    p += 4;
#endif
    /*** 内部存储的密钥, 密钥索引、标签长度、标签 ***/
    rv = Tools_AddFieldSavedKey(iKeyIndex, pcKeyLabel, (char*)p);
    if(rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("Parameter: pcKeyLabel length = [%d] is invalid.", strlen(pcKeyLabel));
        return rv;
    }
    p += rv;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, nSock, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** 公钥, nB ***/
    len = Tools_GetFieldDerBufLength(p);
    if(piDerPublicKeyLen)
    {
        *piDerPublicKeyLen = len;
    }

    if(pucDerPublicKey)
    {
        memcpy(pucDerPublicKey, p, len);
    }
    p += len;

    /*** 私钥长度, 4N ***/
    len = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;
    if(piPrivateKeyLen_Lmk)
    {
        *piPrivateKeyLen_Lmk = len;
    }

    /*** LMK加密的私钥数据, nB ***/
    if(pucPrivateKey_Lmk)
    {
        memcpy(pucPrivateKey_Lmk, p, len);
    }


    return HAR_OK;
}

/*
 * HSM_RSA_GetPublicKey, 获取一对RSA密钥的公钥
 * iKeyIndex            IN        要导出公钥的RSA密钥索引
 * pucDerPublicKey      OUT       导出的RSA公钥，DER编码
 * piDerPublicKeyLen    OUT       导出的RSA公钥长度
 */
int HSM_RSA_GetPublicKey(int iKeyIndex,
    unsigned char *pucDerPublicKey/*out*/, int *piDerPublicKeyLen/*out*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = SOCKET_MAXDATALEN;
    unsigned char aucCmd[512] = {0};
    unsigned char aucRsp[SOCKET_MAXDATALEN] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "ER" ***/
    *p ++ = 'E';
    *p ++ = 'R';

    /*** 密钥索引, K+4N ***/
    TASS_SPRINTF((char*)p, 6, "K%04d", iKeyIndex);
    p += 5;

    iCmdLen = (int)(p - aucCmd);
    //rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** 公钥, nB ***/
    len = Tools_GetFieldDerBufLength(p);
    if(piDerPublicKeyLen)
    {
        *piDerPublicKeyLen = len;
    }

    if(pucDerPublicKey)
    {
        memcpy(pucDerPublicKey, p, len);
    }

    return HAR_OK;
}

/*
 * HSM_RSA_EncryptData, RSA公钥加密数据
 * iPaddingMode            IN        填充模式：00–不填充（数据块长度必须和模长等长）；01–PKCS#1 v1.5
 * iKeyIndex               IN        RSA密钥索引，<=0或=9999时下述2个参数有效
 * pucDerPublicKey         IN        DER编码的RSA公钥，当iKeyIndex=9999时有效
 * iDerPublicKeyLen        IN        DER编码的RSA公钥长度，当iKeyIndex=9999时有效
 * pucInput                IN        要加密的输入数据，最多支持136字节的加密运算
 * iInputLength            IN        要加密的输入数据长度，最大136
 * pucOutput               OUT       加密后的输出数据
 * piOutputLength          OUT       加密后的输出数据长度
 */
int HSM_RSA_EncryptData( void *hSessionHandle,int nSock,int iPaddingMode,
    int iKeyIndex, unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucInput, int iInputLength,
    unsigned char *pucOutput/*out*/, int *piOutputLength/*out*/ )
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = SOCKET_MAXDATALEN;
    unsigned char aucCmd[SOCKET_MAXDATALEN] = {0};
    unsigned char aucRsp[SOCKET_MAXDATALEN] = {0};
    unsigned char *p = aucCmd;

    if(iInputLength > 256)
    {
        LOG_ERROR("Parameter: iInputLength = [%d] is invalid, it must be less than 256.", iInputLength);
        return HAR_PARAM_LEN;
    }

    /*** Command Code    "3A" ***/
    *p ++ = '3';
    *p ++ = 'A';

    /*** 算法标识, 2N, 01-RSA ***/
    *p ++ = '0';
    *p ++ = '1';

    /*** 填充模式, 2N, 00–不填充（数据块长度必须和模长等长）；01–PKCS#1 v1.5 ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iPaddingMode);
    p += 2;

    /*** 数据块长度, 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iInputLength);
    p += 4;

    /*** 数据块, nB ***/
    memcpy(p, pucInput, iInputLength);
    p += iInputLength;

    /*** 分隔符, 1A ***/
    *p ++ = ';';

    /*** 密钥索引, K+4N ***/
    if(iKeyIndex <= 0)
    {
        iKeyIndex = 9999;
    }

    TASS_SPRINTF((char*)p, 6, "K%04d", iKeyIndex);
    p += 5;

    /*** 公钥DER编码 ***/
    if(iKeyIndex == 9999)
    {
        memcpy(p, pucDerPublicKey, iDerPublicKeyLen);
        p += iDerPublicKeyLen;
    }

    iCmdLen = (int)(p - aucCmd);

    rv = TCP_CommunicateHsm_ex(hSessionHandle, nSock, aucCmd, iCmdLen, aucRsp, &iRspLen);
   
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** 密文长度, 4N ***/
    len = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;
    if(piOutputLength)
    {
        *piOutputLength = len;
    }

    /*** 密文数据, nB ***/
    if(pucOutput)
    {
        memcpy(pucOutput, p, len);
    }

    return HAR_OK;
}

/*
 * HSM_RSA_DecryptData, RSA私钥解密数据
 * iPaddingMode            IN        填充模式：00–不填充（解密后的数据直接输出）；01–PKCS#1 v1.5
 * iKeyIndex               IN        RSA密钥索引，<=0或=9999时下述2个参数有效
 * pucPrivateKey_Lmk       IN        LMK加密的RSA私钥，当iKeyIndex=9999时有效
 * iPrivateKeyLen_Lmk      IN        LMK加密的RSA私钥长度，当iKeyIndex=9999时有效
 * pucInput                IN        要解密的输入数据
 * iInputLength            IN        要解密的输入数据长度
 * pucOutput               OUT       解密后的输出数据
 * piOutputLength          OUT       解密后的输出数据长度
 */
int HSM_RSA_DecryptData(void *hSessionHandle,int nSock, int iPaddingMode,
    int iKeyIndex, unsigned char *pucPrivateKey_Lmk, int iPrivateKeyLen_Lmk,
    unsigned char *pucInput, int iInputLength,
    unsigned char *pucOutput/*out*/, int *piOutputLength/*out*/ )
{  
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = SOCKET_MAXDATALEN;
    unsigned char aucCmd[SOCKET_MAXDATALEN] = {0};
    unsigned char aucRsp[SOCKET_MAXDATALEN] = {0};
    unsigned char *p = aucCmd;

    if(iInputLength < 128 || iInputLength > 256)
    {
        LOG_ERROR("Parameter: iInputLength = [%d] is invalid, it must be 128 - 256.", iInputLength);
        return HAR_PARAM_LEN;
    }

    /*** Command Code    "3B" ***/
    *p ++ = '3';
    *p ++ = 'B';

    /*** 算法标识, 2N, 01-RSA ***/
    *p ++ = '0';
    *p ++ = '1';

    /*** 填充模式, 2N, 00–不填充（解密后的数据直接输出）；01–PKCS#1 v1.5 ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iPaddingMode);
    p += 2;

    /*** 数据块长度, 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iInputLength);
    p += 4;

    /*** 数据块, nB ***/
    memcpy(p, pucInput, iInputLength);
    p += iInputLength;

    /*** 分隔符, 1A ***/
    *p ++ = ';';

    /*** 密钥索引, K+4N ***/
    if(iKeyIndex <= 0)
    {
        iKeyIndex = 9999;
    }

    TASS_SPRINTF((char*)p, 6, "K%04d", iKeyIndex);
    p += 5;

    if(iKeyIndex == 9999)
    {
        /*** 私钥长度, 4N ***/
        TASS_SPRINTF((char*)p, 5, "%04d", iPrivateKeyLen_Lmk);
        p += 4;

        /*** LMK加密的密文私钥数据, nB ***/
        memcpy(p, pucPrivateKey_Lmk, iPrivateKeyLen_Lmk);
        p += iPrivateKeyLen_Lmk;
    }

    iCmdLen = (int)(p - aucCmd);
    //printf("aucCmd = %s\n", aucCmd);
   //printf("%s\n","开始与加密机交互" );
    rv = TCP_CommunicateHsm_ex(hSessionHandle,nSock,aucCmd, iCmdLen, aucRsp, &iRspLen);
   // printf("%s\n","加密机返回" );
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }
    
    /*** Response Buffer ***/
    p = aucRsp;

    /*** 输出数据长度, 4N ***/
    len = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;
    if(piOutputLength)
    {
        *piOutputLength = len;
    }

    /*** 输出数据, nB ***/
    if(pucOutput)
    {
        memcpy(pucOutput, p, len);
    }

    return HAR_OK;
}

/*
 * HSM_RSA_GenerateSignature, RSA私钥对数据进行数字签名
 * iHashMode               IN        HASH算法标识
 * iPaddingMode            IN        填充模式：00–不填充（解密后的数据直接输出）；01–PKCS#1 v1.5
 * iKeyIndex               IN        RSA密钥索引，<=0或=9999时下述4个参数有效
 * pucPrivateKey_Lmk       IN        LMK加密的RSA私钥，当iSm2KeyIndex=9999时有效
 * iPrivateKeyLen_Lmk      IN        LMK加密的RSA私钥长度，当iSm2KeyIndex=9999时有效
 * pucInput                IN        待签名的输入数据
 * iInputLength            IN        待签名的输入数据长度
 * pucSignature            OUT       输出的数据签名
 * piSignatureLength       OUT       输出的数据签名长度
 */
int HSM_RSA_GenerateSignature(
    void *hSessionHandle,int nSock,
    int iHashMode, int iPaddingMode,
    int iKeyIndex, unsigned char *pucPrivateKey_Lmk, int iPrivateKeyLen_Lmk,
    unsigned char *pucInput, int iInputLength,
    unsigned char *pucSignature/*out*/, int *piSignatureLength/*out*/ )
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[SOCKET_MAXDATALEN] = {0};
    unsigned char aucRsp[4096] = {0};
    unsigned char *p = aucCmd;

    if(iInputLength > 1984)
    {
        LOG_ERROR("Parameter: iInputLength = [%d] is invalid, it must be less than 1984.", iInputLength);
        return HAR_PARAM_LEN;
    }

    /*** Command Code    "EW" ***/
    *p ++ = 'E';
    *p ++ = 'W';

    /*** HASH算法标识, 2N, ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iHashMode);
    p += 2;

    /*** 算法标识, 2N, 01-RSA ***/
    *p ++ = '0';
    *p ++ = '1';

    /*** 填充模式, 2N, 00–不填充（解密后的数据直接输出）；01–PKCS#1 v1.5 ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iPaddingMode);
    p += 2;

    /*** 数据块长度, 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iInputLength);
    p += 4;

    /*** 数据块, nB ***/
    memcpy(p, pucInput, iInputLength);
    p += iInputLength;

    /*** 分隔符, 1A ***/
    *p ++ = ';';

    /*** 密钥索引, K+4N ***/
    if(iKeyIndex <= 0)
    {
        iKeyIndex = 9999;
    }

    TASS_SPRINTF((char*)p, 6, "K%04d", iKeyIndex);
    p += 5;
	
    if(iKeyIndex == 9999)
    {
        /*** 私钥长度, 4N ***/
        TASS_SPRINTF((char*)p, 5, "%04d", iPrivateKeyLen_Lmk);
        p += 4;

        /*** LMK加密的密文私钥数据, nB ***/
        memcpy(p, pucPrivateKey_Lmk, iPrivateKeyLen_Lmk);
        p += iPrivateKeyLen_Lmk;
    }
	//p和aucCmd都是指针，地址相减即长度
    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle,nSock,aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** 数字签名长度, 4N ***/
    len = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;
    if(piSignatureLength)
    {
        *piSignatureLength = len;
    }

    /*** 输出数据, nB ***/
    if(pucSignature)
    {
        memcpy(pucSignature, p, len);
    }

    return HAR_OK;
}

/*
 * HSM_RSA_VerifySignature, RSA公钥验证数据的签名
 * iHashMode               IN        HASH算法标识
 * iPaddingMode            IN        填充模式：00–不填充（解密后的数据直接输出）；01–PKCS#1 v1.5
 * iKeyIndex               IN        RSA密钥索引，<=0或=9999时下述2个参数有效
 * pucDerPublicKey         IN        DER编码的RSA公钥，当iKeyIndex=9999时有效
 * iDerPublicKeyLen        IN        DER编码的RSA公钥长度，当iKeyIndex=9999时有效
 * pucInput                IN        待验证签名的输入数据
 * iInputLength            IN        待验证签名的输入数据长度
 * pucSignature            IN        待验证的数据签名
 * iSignatureLength        IN        待验证的数据签名长度
 */
int HSM_RSA_VerifySignature(
    void *hSessionHandle,int nSock,  int iHashMode, int iPaddingMode,
    int iKeyIndex, unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucInput, int iInputLength,
    unsigned char *pucSignature, int iSignatureLength)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 8;
    unsigned char aucCmd[SOCKET_MAXDATALEN] = {0};
    unsigned char aucRsp[8] = {0};
    unsigned char *p = aucCmd;

    if(iInputLength > 1984)
    {
        LOG_ERROR("Parameter: iInputLength = [%d] is invalid, it must be less than 1984.", iInputLength);
        return HAR_PARAM_LEN;
    }

    /*** Command Code    "EY" ***/
    *p ++ = 'E';
    *p ++ = 'Y';

    /*** HASH算法标识, 2N, ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iHashMode);
    p += 2;

    /*** 算法标识, 2N, 01-RSA ***/
    *p ++ = '0';
    *p ++ = '1';

    /*** 填充模式, 2N, 00–不填充（解密后的数据直接输出）；01–PKCS#1 v1.5 ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iPaddingMode);
    p += 2;

    /*** 待验签的签名长度, 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iSignatureLength);
    p += 4;

    /*** 待验签的签名, nB ***/
    memcpy(p, pucSignature, iSignatureLength);
    p += iSignatureLength;

    /*** 分隔符, 1A ***/
    *p ++ = ';';

    /*** 数据块长度, 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iInputLength);
    p += 4;

    /*** 数据块, nB ***/
    memcpy(p, pucInput, iInputLength);
    p += iInputLength;

    /*** 分隔符, 1A ***/
    *p ++ = ';';

    /*** 密钥索引, K+4N ***/
    if(iKeyIndex<=0)
    {
        iKeyIndex = 9999;
    }

    TASS_SPRINTF((char*)p, 6, "K%04d", iKeyIndex);
    p += 5;

    if(iKeyIndex == 9999)
    {
        /*** DER编码的SM2公钥, nB ***/
        memcpy(p, pucDerPublicKey, iDerPublicKeyLen);
        p += iDerPublicKeyLen;
    }

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, nSock, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/*
 * HSM_RSA_GeneratePublicKeyMac, 在授权控制下为RSA公钥产生公钥MAC
 * pucDerPublicKey         IN        要计算MAC的RSA公钥，DER编码
 * iDerPublicKeyLen        IN        要计算MAC的RSA公钥长度
 * pucAuthData             IN        公钥鉴别数据，不能带';'字符
 * iAuthDataLen            IN        公钥鉴别数据长度
 * pucMac                  OUT       RSA公钥的MAC值
 * piMacLen                OUT       RSA公钥的MAC值长度
 * puDerPublicKey             OUT      der编码公钥
 *piDerPublicKeyLen   OUT   DER编码公钥长度
 */
int HSM_RSA_GeneratePublicKeyMac(
    void *hSessionHandle,int nSock,
    unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucAuthData, int iAuthDataLen,
    unsigned char *pucMac/*out*/, int *piMacLen/*out*/,
    unsigned char *puDerPublicKey,int *piDerPublicKeyLen)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[1024] = {0};
    unsigned char aucRsp[4096] = {0};
    unsigned char *p = aucCmd;

    if(iAuthDataLen > 128)
    {
        LOG_ERROR("Parameter: iAuthDataLen = [%d] is invalid, it must be less than 128.", iAuthDataLen);
        return HAR_PARAM_LEN;
    }

    /*** Command Code    "EO" ***/
    *p ++ = 'E';
    *p ++ = 'O';

    /*** 公钥编码类型, 2N, 01–ASN.1 格式DER 编码的公钥。整数使用无符号表示法 ***/
    *p ++ = '0';
    *p ++ = '1';

    /*** DER编码的RSA公钥, nB ***/
    memcpy(p, pucDerPublicKey, iDerPublicKeyLen);
    p += iDerPublicKeyLen;

    /*** 用于计算公钥MAC的额外的数据（不能包含字符’;’）, nB ***/
    memcpy(p, pucAuthData, iAuthDataLen);
    p += iAuthDataLen;

    iCmdLen = (int)(p - aucCmd);
    //Tools_PrintBuf("cmd",aucCmd,iCmdLen);
    rv = TCP_CommunicateHsm_ex(hSessionHandle,nSock,aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** 使用LMK分组对公钥和认证数据计算的MAC，4B ***/
    if(piMacLen)
    {
        *piMacLen = 4;
    }

    if(pucMac)
    {
        memcpy(pucMac, p, 4);
    }
    
    p += 4;

    if(piDerPublicKeyLen){
        *piDerPublicKeyLen =(int) (iRspLen - 4);
    }
    
     if(puDerPublicKey){
        memcpy(puDerPublicKey,p,*piDerPublicKeyLen);
    }
  
    return HAR_OK;
}

/*
 * HSM_RSA_ExportSymmetricKey, 由RSA公钥加密保护导出一条对称密钥
 * pcKeyType                        IN        被导出密钥的密钥类型
 * iKeyIndex                           IN        被导出密钥的索引。<=0, 使用pcKey_Lmk参数；否则使用索引指定的密钥
 * pcKey_Lmk                        IN        LMK加密的被导出密钥的密文。当iKeyIndex<=0时有效
 * iKeyDiversifyNumber           IN        被导出密钥的分散级数
 * pcKeyDiversifyData              IN        被导出密钥的分散因子，每级32H
 * iRsaKeyIndex                    IN        作为保护密钥的RSA密钥索引，<=0或=9999时标识使用pucDerPublicKey参数
 * pucDerPublicKey              IN        作为保护密钥的DER编码的RSA公钥，仅当iRsaKeyIndex<=0或=9999时有效
 * iDerPublicKeyLen             IN        作为保护密钥的DER编码的RSA公钥长度，仅当iRsaKeyIndex<=0或=9999时有效
 * pucAuthData                       IN        作为保护密钥的公钥鉴别数据，不能带';'字符
 * iAuthDataLen                      IN        作为保护密钥的公钥鉴别数据长度
 * pucMac                                IN        作为保护密钥的RSA公钥的MAC值
 * iMacLen                               IN        作为保护密钥的RSA公钥的MAC值长度
 * pucCipherKey                     OUT       RSA密钥加密的被导出密钥密文
 * piCipherKeyLen                 OUT       RSA密钥加密的被导出密钥密文长度
 * pcKeyCv                              OUT       被导出密钥的校验值
 */
int HSM_RSA_ExportSymmetricKey(
    void *hSessionHandle,int nSock,
    char *pcKeyType, int iKeyIndex, char *pcKey_Lmk,
    int iKeyDiversifyNumber, char *pcKeyDiversifyData,
    int iRsaKeyIndex,
    unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucAuthData, int iAuthDataLen,
    unsigned char *pucMac,
    unsigned char *pucCipherKey/*out*/, int *piCipherKeyLen/*out*/,
    char *pcKeyCv/*out*/ )
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = SOCKET_MAXDATALEN;
    unsigned char aucCmd[SOCKET_MAXDATALEN] = {0};
    unsigned char aucRsp[SOCKET_MAXDATALEN] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "TV" ***/
    *p ++ = 'T';
    *p ++ = 'V';

    /*** 填充模式, 2N, 01–PKCS#1 v1.5 ***/
    *p ++ = '0';
    *p ++ = '1';

    /*** 被导出密钥的密钥类型 ***/
    memcpy(p, pcKeyType, 3);
    p += 3;

    /*** 被导出密钥 ***/
    rv = Tools_AddFieldKey(iKeyIndex, pcKey_Lmk, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("Parameter: iKeyIndex = [%d] is invalid.", iKeyIndex);
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** 被导出密钥分散级数及分散因子, 2H+n*32H ***/
    rv = Tools_AddFieldDiversifyData(1, iKeyDiversifyNumber, pcKeyDiversifyData, p);
    if (rv == HAR_PARAM_Diversify_DATA)
    {
        LOG_ERROR("Parameter: pcKeyDiversifyData's length = [%d] is invalid.", strlen(pcKeyDiversifyData) );
        return HAR_PARAM_Diversify_DATA;
    }
    p += rv;

    /*** 密钥索引, 4N ***/
    if (iRsaKeyIndex <= 0)
    {
        iRsaKeyIndex = 9999;
    }

    TASS_SPRINTF((char*)p, 6, "K%04d", iRsaKeyIndex);
    p += 5;

    if(iRsaKeyIndex == 9999)
    {
        /*** DER编码的RSA公钥, nB ***/
        memcpy(p, pucDerPublicKey, iDerPublicKeyLen);
        p += iDerPublicKeyLen;

        /*** 用于计算公钥MAC的额外的数据（不能包含字符’;’）, nB ***/
        memcpy(p, pucAuthData, iAuthDataLen);
        p += iAuthDataLen;

        /*** 认证数据分隔符,';' ***/
        *p ++ = ';';

        /*** 公钥MAC, 4B ***/
        memcpy(p, pucMac, 4);
        p += 4;
    }

    iCmdLen = (int)(p - aucCmd);
    //Tools_PrintBuf("cmd",aucCmd,iCmdLen);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, nSock, aucCmd, iCmdLen, aucRsp, &iRspLen);
    //Tools_PrintBuf("iRspLen",aucRsp,iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** RSA密钥加密的被导出密钥密文长度, 4N ***/
   // len = Tools_ConvertDecBuf2Int(p, 4);
    len = Tools_ConvertHexBuf2Int(p,4);
    p += 4;
    if(piCipherKeyLen)
    {
        *piCipherKeyLen = len;
    }

    /*** RSA密钥加密的被导出密钥密文, nB ***/
    if(pucCipherKey)
    {
        memcpy(pucCipherKey, p, len);
    }
    
    p += len;

    /*** 被导出密钥的校验值 ***/
    if(pcKeyCv)
    {
        strncpy(pcKeyCv, p, 16);
    }

    return HAR_OK;
}

/*
 * HSM_RSA_ExportSymmetricKey2, 由RSA公钥加密保护导出一条对称密钥
 * hSessionHandle              IN        会话句柄
 * pcKeyType                   IN        被导出密钥的密钥类型
 * iKeyFlag                    IN        对称密钥标记：0：单倍长度，8字节，1：双倍长度,16字节，2：三倍长度，24字节
 * pcKey_Lmk                   IN        LMK加密的被导出密钥的密文。当iKeyIndex<=0时有效
 * iKeyLen_Lmk                 IN        LMK加密的密钥的长度
 * pcKeyCv                     IN        对称密钥的校验值
 * pucMac                      IN        作为保护密钥的RSA公钥的MAC值
 * iMacLen                     IN        作为保护密钥的RSA公钥的MAC值长度            IN        被导出密钥的分散因子，每级32H
 * pucDerPublicKey             IN        作为保护密钥的DER编码的RSA公钥，仅当iRsaKeyIndex<=0或=9999时有效
 * iDerPublicKeyLen            IN        作为保护密钥的DER编码的RSA公钥长度，仅当iRsaKeyIndex<=0或=9999时有效
 * pucAuthData                 IN        作为保护密钥的公钥鉴别数据，不能带';'字符
 * iAuthDataLen                IN        作为保护密钥的公钥鉴别数据长度
 * pucInitIV                   OUT       对称密钥的初始化值IV
 * pucCipherKey                OUT       RSA密钥加密的被导出密钥密文
 * piCipherKeyLen              OUT       RSA密钥加密的被导出密钥密文长度
 * pcKeyCv                     OUT       被导出密钥的校验值
 */
int HSM_RSA_ExportSymmetricKey2(
    void *hSessionHandle,int nSock,
    int pcKeyType, int iKeyFlag, 
	char *pcKey_Lmk, int iKeyLen_Lmk,
    char *pcKeyCv,  int iKeyCvLen,
	unsigned char *pucMac,int iMacLen,
    unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucAuthData,	int iAuthDataLen,
    unsigned char *pucInitIV /**out*/,
    unsigned char *pucCipherKey/*out*/,
	int *piCipherKeyLen/*out*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = SOCKET_MAXDATALEN;
    unsigned char aucCmd[SOCKET_MAXDATALEN] = {0};
    unsigned char aucRsp[SOCKET_MAXDATALEN] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "GK" ***/
    *p ++ = 'G';
    *p ++ = 'K';
	
	/*** 加密标识 01-RSA ***/
	*p ++ = '0';
	*p ++ = '1';

    /*** 填充模式, 2N, 01–PKCS#1 v1.5 ***/
    *p ++ = '0';
    *p ++ = '1';

    /*** 被导出密钥的密钥类型 ***/
    TASS_SPRINTF((char*)p, 5, "%04d", pcKeyType);
    p += 4;
	
	/***对称密钥标记***/
	*p ++ = '0' + iKeyFlag;

    /*** 被导出密钥,16H/1A+32H/1A+48H ***/
    memcpy(p, pcKey_Lmk, iKeyLen_Lmk);
	p += iKeyLen_Lmk;

    /*** 对称密钥的校验值,16H，不足在右边补0 ***/
	if(strlen(pcKeyCv) > 16){
		LOG_ERROR("pcKeyCv length = [%d] is invalid",strlen(pcKeyCv));
		return HAR_PARAM_LEN;
	}
    memcpy(p, pcKeyCv, 16);
	p += 16;

	/*** 对于公钥和证明数据的MAC,用LMK计算***/
    memcpy(p, pucMac, iMacLen);
	p += iMacLen;
	
  
    /*** DER编码的RSA公钥, nB ***/
    memcpy(p, pucDerPublicKey, iDerPublicKeyLen);
    p += iDerPublicKeyLen;

    /*** 用于计算公钥MAC的额外的数据（不能包含字符’;’）, nB ***/
    memcpy(p, pucAuthData, iAuthDataLen);
    p += iAuthDataLen;

    iCmdLen = (int)(p - aucCmd);
    //Tools_PrintBuf("cmd",aucCmd,iCmdLen);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, nSock, aucCmd, iCmdLen, aucRsp, &iRspLen);
    //Tools_PrintBuf("iRspLen",aucRsp,iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;
	/*** 初始化值 ***/
	if(pucInitIV)
    {
        memcpy(pucInitIV, p, 16);
    }
	p += 16;
	
    /*** RSA密钥加密的被导出密钥密文长度, 4N ***/
    len = Tools_ConvertDecBuf2Int(p, 4);
    //len = Tools_ConvertHexBuf2Int(p,4);
    p += 4;
    if(piCipherKeyLen)
    {
        *piCipherKeyLen = len;
    }

    /*** RSA密钥加密的被导出密钥密文, nB ***/
    if(pucCipherKey)
    {
        memcpy(pucCipherKey, p, len);
    }
    
    p += len;
   

    return HAR_OK;
}

/*
 * HSM_RSA_ImportSymmetricKey, 由RSA公钥加密保护导入一条对称密钥
 * pcKeyType               IN        被导入密钥的密钥类型
 * cKeyScheme              IN        被导入密钥的算法标识：Z/X/Y/U/T/P/L/R
 * iKeyIndex               IN        被导入密钥的索引。<=0, 标识密钥不存储到内部
 * pcKeyLabel              IN        被导入密钥的标签。当iKeyIndex>0时有效
 * iRsaKeyIndex            IN        作为保护密钥的RSA密钥索引，<=0或=9999时标识使用pucPrivateKey_Lmk参数
 * pucPrivateKey_Lmk       IN        作为保护密钥的RSA私钥密文，仅当iRsaKeyIndex<=0或=9999时有效
 * iPrivateKeyLen_Lmk      IN        作为保护密钥的RSA私钥密文长度，仅当iRsaKeyIndex<=0或=9999时有效
 * pucCipherKey            IN        RSA公钥加密的被导入密钥密文
 * iCipherKeyLen           IN        RSA公钥加密的被导入密钥密文长度
 * pcKey_Lmk               OUT       LMK下加密的被导入密钥密文
 * pcKeyCv                 OUT       被导入密钥的校验值
 */
int HSM_RSA_ImportSymmetricKey(
    char *pcKeyType, char cKeyScheme,
    int iKeyIndex, char *pcKeyLabel,
    int iRsaKeyIndex,
    unsigned char *pucPrivateKey_Lmk, int iPrivateKeyLen_Lmk,
    unsigned char *pucCipherKey, int iCipherKeyLen, 
    char *pcKey_Lmk/*out*/, char *pcKeyCv/*out*/ )
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = SOCKET_MAXDATALEN;
    unsigned char aucCmd[SOCKET_MAXDATALEN] = {0};
    unsigned char aucRsp[SOCKET_MAXDATALEN] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "TW" ***/
    *p ++ = 'T';
    *p ++ = 'W';

    /*** 填充模式, 2N, 01–PKCS#1 v1.5 ***/
    *p ++ = '0';
    *p ++ = '1';

    /*** 被导入密钥的密钥类型 ***/
    memcpy( p, pcKeyType, 3 );
    p += 3;

    /*** 被导入密钥的算法标识：Z/X/Y/U/T/P/L/R ***/
    *p ++ = cKeyScheme;

    /*** 内部存储的密钥, 密钥索引、标签长度、标签 ***/
    rv = Tools_AddFieldSavedKey(iKeyIndex, pcKeyLabel, (char*)p);
    if(rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("Parameter: pcKeyLabel's length = [%d] is invalid.", strlen(pcKeyLabel));
        return rv;
    }
    p += rv;

    /*** 导入密钥的校验值, 16H, 全0则不校验，直接完成导入工作； ***/
    memset(p, '0', 16);
    p += 16;

    /*** RSA公钥加密的被导入密钥密文长度, 4H ***/
    TASS_SPRINTF((char*)p, 5, "%04X", iCipherKeyLen);
    p += 4;

    /*** RSA公钥加密的被导入密钥密文, nB ***/
    memcpy(p, pucCipherKey, iCipherKeyLen);
    p += iCipherKeyLen;

    /*** 密钥索引, 4N ***/
    if(iRsaKeyIndex<=0)
    {
        iRsaKeyIndex = 9999;
    }

    TASS_SPRINTF((char*)p, 6, "K%04d", iRsaKeyIndex);
    p += 5;

    if(iRsaKeyIndex == 9999)
    {
        /*** 私钥长度, 4N ***/
        TASS_SPRINTF((char*)p, 5, "%04d", iPrivateKeyLen_Lmk);
        p += 4;

        /*** LMK加密的密文私钥数据, nB ***/
        memcpy(p, pucPrivateKey_Lmk, iPrivateKeyLen_Lmk);
        p += iPrivateKeyLen_Lmk;
    }

    iCmdLen = (int)(p - aucCmd);
    //rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** LMK下加密的被导入密钥密文 ***/
    len = Tools_GetFieldKeyLength((char *)p);
    if (pcKey_Lmk)
    {
        memcpy(pcKey_Lmk, p, len);
    }
    p += len;

    /*** 校验值, 16H ***/
    if (pcKeyCv)
    {
        strncpy(pcKeyCv, (char *)p, 16);
    }

    return HAR_OK;
}

/*
 * HSM_RSA_ExportRSAKey     保护密钥（对称）加密导入一对RSA密钥
 * iMode                    加密算法模式  2 H  00 – ECB 01 – CBC
 * pcTkType                 用于加密保护RSA密钥的保护密钥类型 000 – KEK;   109 – MDK;
 * iTkIndex                 用于加密保护RSA的保护密钥索引
 * pcTk_Lmk                 用于加密保护RSA的保护密钥密文
 * iTkDiversifyNumber          保护密钥分散级数
 * pcTkDiversifyData           保护密钥分散因子
 * iRsaKeyIndex             被导出密钥索引号
 * pucPrivateKey            被导出密钥私钥数据
 * iPrivateKeyLen           被导出密钥私钥长度
 * pcExpandFlg              扩展标识
 * pcPADFlg                 标识被导出的各私钥分量的填充规则
 * iOutPublicKeyFlg         公钥输出格式,0 - 明文DER格式输出， ASN.1 格式DER 编码（模，指数序列） 1 - m及e采用分量密文形式输出
 * pcIV                     初始化向量
 */

int HSM_RSA_ExportRSAKey(void *hSessionHandle,int nSock,
    int iMode,  char *pcTkType,
    int iTkIndex, char *pcTk_Lmk,
    int iTkDiversifyNumber, char *pcTkDiversifyData,
    int iRsaKeyIndex,
    unsigned char *pucPrivateKey, int iPrivateKeyLen,
    char *pcExpandFlg, char *pcPADFlg,
    int iOutPublicKeyFlg, char *pcIV,
    unsigned char *pucDerPublicKey/*OUT*/, int *piDerPublicKeyLen/*OUT*/,
    unsigned char *pucPublicKey_m/*OUT*/, int *piPublicKey_mLen/*OUT*/,
    unsigned char *pucPublicKey_e/*OUT*/, int *piPublicKey_eLen/*OUT*/,
    unsigned char *pucPrivateKey_d/*OUT*/, int *piPrivateKey_dLen/*OUT*/,
    unsigned char *pucPrivateKey_p/*OUT*/, int *piPrivateKey_pLen/*OUT*/,
    unsigned char *pucPrivateKey_q/*OUT*/, int *piPrivateKey_qLen/*OUT*/,
    unsigned char *pucPrivateKey_dp/*OUT*/, int *piPrivateKey_dpLen/*OUT*/,
    unsigned char *pucPrivateKey_dq/*OUT*/, int *piPrivateKey_dqLen/*OUT*/,
    unsigned char *pucPrivateKey_qInv/*OUT*/, int *piPrivateKey_qInvLen/*OUT*/,
    unsigned char *pucDerPrivateKey/*OUT*/, int *piDerPrivateKeyLen/*OUT*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = SOCKET_MAXDATALEN;
    unsigned char aucCmd[SOCKET_MAXDATALEN] = {0};
    unsigned char aucRsp[SOCKET_MAXDATALEN] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "TR" ***/
    *p ++ = 'T';
    *p ++ = 'R';

    /*** 加密算法模式 ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iMode);
    p += 2;

    /*** 被导出密钥的密钥类型 ***/
    memcpy(p, pcTkType, 3);
    p += 3;

    /*** 保护密钥密钥 ***/
    rv = Tools_AddFieldKey(iTkIndex, pcTk_Lmk, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("Parameter: iTkIndex = [%d] is invalid.", iTkIndex);
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** 保护密钥分散级数及分散因子, 2H+n*32H ***/
    rv = Tools_AddFieldDiversifyData(1, iTkDiversifyNumber, pcTkDiversifyData, (char*)p);
    if (rv == HAR_PARAM_Diversify_DATA)
    {
        LOG_ERROR("Parameter: pcTkDiversifyData's length = [%d] is invalid.", strlen(pcTkDiversifyData));
        return HAR_PARAM_Diversify_DATA;
    }
    p += rv;

    /*** 被导出密钥索引, 4N ***/
    if(iRsaKeyIndex <= 0)
    {
        iRsaKeyIndex = 9999;
    }

    TASS_SPRINTF((char*)p, 6, "K%04d", iRsaKeyIndex);
    p += 5;

    if(iRsaKeyIndex == 9999)
    {
	/*** 被导出的RSA私钥字节数 ***/
    	TASS_SPRINTF((char*)p, 5, "%04d", iPrivateKeyLen);
    	p += 4;

        /*** 被导出的RSA私钥, nB ***/
        memcpy(p, pucPrivateKey, iPrivateKeyLen);
        p += iPrivateKeyLen;
    }

    if(!strcmp(pcExpandFlg, "P"))
    {
        /*** 扩展标识 ***/
        memcpy(p, pcExpandFlg, 1);
        p += 1;

        /*** PAD标识 ***/
        memcpy(p, pcPADFlg, 2);
        p += 2;

        /*** 0 - 明文DER格式输出， ASN.1 格式DER 编码（模，指数序列） 1 - m及e采用分量密文形式输出 ***/
        TASS_SPRINTF((char*)p, 2, "%d", iOutPublicKeyFlg);
        p += 1;

        /*** IV ***/
        memcpy(p, pcIV, strlen(pcIV));
        p += strlen(pcIV);
    }

    iCmdLen = (int)(p - aucCmd);

    rv = TCP_CommunicateHsm_ex(hSessionHandle, nSock, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }
    /*** Response Buffer ***/
    p = aucRsp;

    if(iOutPublicKeyFlg == 0 || strcmp(pcExpandFlg, "P")) /*** 公钥明文Der格式输出 ***/
    {
        /*** DER编码公钥, nB ***/
        len = Tools_GetFieldDerBufLength(p);
        if(piDerPublicKeyLen)
        {
            *piDerPublicKeyLen = len;
        }
        if(pucDerPublicKey)
        {
            memcpy(pucDerPublicKey, p, len);
        }
        p += len;
    }
    else if(iOutPublicKeyFlg == 1 && (!strcmp(pcExpandFlg, "P")))/***  m及e采用分量密文形式输出的公钥 ***/
    {
        /*** 公钥模m密文长度  ***/
        len = Tools_ConvertDecBuf2Int(p, 4);
        p += 4;
        if (piPublicKey_mLen)
        {
	    //printf("m len = [%d]\n", len);
            *piPublicKey_mLen = len;
        }

        /*** 公钥模m密文  ***/
        if(pucPublicKey_m)
        {
            memcpy(pucPublicKey_m, p, len);
        }
        p += len;

        /*** 公钥指数e密文长度 ***/
        len = Tools_ConvertDecBuf2Int(p, 4);
        p += 4;
        if (piPublicKey_eLen)
        {
	    //printf("e len = [%d]\n", len);
            *piPublicKey_eLen = len;
        }

        /*** 公钥指数e密文 ***/
        if(pucPublicKey_e)
        {
            memcpy(pucPublicKey_e, p, len);
        }
        p += len;
    }else if(iOutPublicKeyFlg == 2 && (!strcmp(pcExpandFlg, "P"))){ /*** 公钥明文DER编码格式输出，私钥密文输出 ***/

         /*** DER编码公钥, nB ***/
        len = Tools_GetFieldDerBufLength(p);
        if(len == HAR_DER_DECODE){
            LOG_ERROR("GetFieldDerBufLength is error,return [%d]",HAR_DER_DECODE);
        }
        if(piDerPublicKeyLen)
        {

            *piDerPublicKeyLen = len;
        }
        if(pucDerPublicKey)
        {
            memcpy(pucDerPublicKey, p, len);
        }
        p += len;
        len = Tools_ConvertDecBuf2Int(p, 4);
        p += 4;
        if (piDerPrivateKeyLen)
        {
        //printf("e len = [%d]\n", len);
            *piDerPrivateKeyLen = len;
        }
        if(pucDerPrivateKey){
            memcpy(pucDerPrivateKey, p, len);
        }
        p += len;
        return rv;
    }

    /*** 私钥指数d密文长度 ***/
    len = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;
    if (piPrivateKey_dLen)
    {
        *piPrivateKey_dLen = len;
    }

    /*** 私钥指数d密文 ***/
    if (pucPrivateKey_d)
    {
        memcpy(pucPrivateKey_d, p, len);
    }
    p += len;

    /*** 私钥分量P密文长度 ***/
    len = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;
    if (piPrivateKey_pLen)
    {
        *piPrivateKey_pLen = len;
    }

    /*** 私钥分量P密文 ***/
    if(pucPrivateKey_p)
    {
        memcpy(pucPrivateKey_p, p, len);
    }
    p += len;

    /*** 私钥分量Q密文长度 ***/
    len = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;
    if (piPrivateKey_qLen)
    {
        *piPrivateKey_qLen = len;
    }

    /*** 私钥分量Q密文 ***/
    if(pucPrivateKey_q)
    {
        memcpy(pucPrivateKey_q, p, len);
    }
    p += len;

    /*** 私钥分量dP 密文长度 ***/
    len = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;
    if (piPrivateKey_dpLen)
    {
        *piPrivateKey_dpLen = len;
    }

    /*** 私钥分量dP密文 ***/
    if (pucPrivateKey_dp)
    {
        memcpy(pucPrivateKey_dp, p, len);
    }
    p += len;

    /*** 私钥分量dQ 密文长度 ***/
    len = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;
    if(piPrivateKey_dqLen)
    {
        *piPrivateKey_dqLen = len;
    }

    /*** 私钥分量dQ密文 ***/
    if(pucPrivateKey_dq)
    {
        memcpy(pucPrivateKey_dq, p, len);
    }
    p += len;

    /*** 私钥分量qInv 密文长度 ***/
    len = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;
    if(piPrivateKey_qInvLen)
    {
        *piPrivateKey_qInvLen = len;
    }

    /*** 私钥分量qInv密文 ***/
    if(pucPrivateKey_qInv)
    {
        memcpy(pucPrivateKey_qInv, p, len);
    }

    return rv;
}

/*
 * HSM_RSA_ImportByTk     保护密钥（对称）加密导入一对RSA密钥
 * iMode                    加密算法模式  2 H  00 – ECB 01 – CBC
 * pcTkType                 用于加密保护RSA密钥的保护密钥类型 000 – KEK;   109 – MDK;
 * iTkIndex                 用于加密保护RSA的保护密钥索引
 * pcTk_Lmk                 用于加密保护RSA的保护密钥密文
 * iTkDiversifyNumber          保护密钥分散级数
 * pcTkDiversifyData           保护密钥分散因子
 * iRsaKeyIndex             被导出密钥索引号
 * pucRsaKeyTag             RSA密钥标签
 * iRsaKeyTagLen            RSA密钥标签长度
 * pucPublicKey             公钥， ASN.1 格式DER 编码（模，指数序列)
 * iPublicKeyLen            公钥数据长度
 * pucPrivateKey_d          私钥指数d  n B  私钥指数d密文
 * iPrivateKey_dLen         私钥指数d长度  4 N  私钥指数d密文长度，字节数
 * pucPrivateKey_p          私钥分量P  n B  私钥分量p密文
 * iPrivateKey_pLen         私钥分量P长度  4 N  私钥分量p密文长度，字节数
 * pucPrivateKey_q          私钥分量Q  n B  私钥分量q密文
 * iPrivateKey_qLen         私钥分量Q长度  4 N  私钥分量q密文长度，字节数
 * pucPrivateKey_dp         私钥分量dP  n B  私钥分量dP密文
 * iPrivateKey_dpLen        私钥分量dP长度  4 N  私钥分量dP密文长度，字节数
 * pucPrivateKey_dq         私钥分量dQ  n B  私钥分量dQ密文
 * iPrivateKey_dqLen        私钥分量dQ长度  4 N  私钥分量dQ密文长度，字节数
 * pucPrivateKey_qInv       私钥分量qInv  n B  私钥分量qInv密文
 * iPrivateKey_qInvLen      私钥分量qInv长度  4 N  私钥分量qInv密文长度，字节数
 */

int HSM_RSA_ImportByTk(
    int iMode,  char *pcTkType,
    int iTkIndex, char *pcTk_Lmk,
    int iTkDiversifyNumber, char *pcTkDiversifyData,
    int iRsaKeyIndex,
    unsigned char *pucRsaKeyTag, int iRsaKeyTagLen,
    unsigned char *pucPublicKey, int iPublicKeyLen,
    unsigned char *pucPrivateKey_d, int iPrivateKey_dLen,
    unsigned char *pucPrivateKey_p, int iPrivateKey_pLen,
    unsigned char *pucPrivateKey_q, int iPrivateKey_qLen,
    unsigned char *pucPrivateKey_dp, int iPrivateKey_dpLen,
    unsigned char *pucPrivateKey_dq, int iPrivateKey_dqLen,
    unsigned char *pucPrivateKey_qInv, int iPrivateKey_qInvLen,
    unsigned char *pucPrivateKey_Lmk/*out*/, int *piPrivateKeyLen_Lmk/*out*/ )
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = SOCKET_MAXDATALEN;
    unsigned char aucCmd[SOCKET_MAXDATALEN] = {0};
    unsigned char aucRsp[SOCKET_MAXDATALEN] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "TS" ***/
    *p ++ = 'T';
    *p ++ = 'S';

    /*** 加密算法模式 ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iMode);
    p += 2;

    /*** 保护密钥的密钥类型 ***/
    memcpy(p, pcTkType, 3);
    p += 3;

    /*** 保护密钥密钥 ***/
    rv = Tools_AddFieldKey(iTkIndex, pcTk_Lmk, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("Parameter: iTkIndex = [%d] is invalid.", iTkIndex);
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** 保护密钥分散级数及分散因子, 2H+n*32H ***/
    rv = Tools_AddFieldDiversifyData( 1, iTkDiversifyNumber, pcTkDiversifyData, (char*)p );
    if (rv == HAR_PARAM_Diversify_DATA)
    {
        LOG_ERROR("Parameter: pcTkDiversifyData length = [%d] is invalid.", strlen(pcTkDiversifyData));
        return HAR_PARAM_Diversify_DATA;
    }
    p += rv;

    /*** 被导入的密钥索引, 4N ***/
    if (iRsaKeyIndex<=0)
    {
        iRsaKeyIndex = 9999;
    }

    TASS_SPRINTF((char*)p, 6, "K%04d", iRsaKeyIndex);
    p += 5;

    if (iRsaKeyIndex != 9999)
    {
        TASS_SPRINTF((char *)p, 3, "%02d", iRsaKeyTagLen);
        p += 2;

        /*** RSA密钥标签  ***/
        memcpy(p, pucRsaKeyTag, iRsaKeyTagLen);
        p += iRsaKeyTagLen;
    }

    /*** 要导入的RSA密钥的公钥明文, ASN.1 格式DER 编码（模，指数序列）***/
    memcpy(p, pucPublicKey, iPublicKeyLen);
    p += iPublicKeyLen;

    TASS_SPRINTF((char *)p, 5, "%04d", iPrivateKey_dLen);
    p += 4;

    /*** 私钥指数d ***/
    memcpy(p, pucPrivateKey_d, iPrivateKey_dLen);
    p += iPrivateKey_dLen;

    /*** 私钥分量P ***/
    TASS_SPRINTF((char *)p, 5, "%04d", iPrivateKey_pLen);
    p += 4;
    memcpy(p, pucPrivateKey_p, iPrivateKey_pLen);
    p += iPrivateKey_pLen;

    /*** 私钥分量Q ***/
    TASS_SPRINTF((char *)p, 5, "%04d", iPrivateKey_qLen);
    p += 4;
    memcpy(p, pucPrivateKey_q, iPrivateKey_qLen);
    p += iPrivateKey_qLen;

    /*** 私钥分量dP ***/
    TASS_SPRINTF((char *)p, 5, "%04d", iPrivateKey_dpLen);
    p += 4;
    memcpy(p, pucPrivateKey_dp, iPrivateKey_dpLen);
    p += iPrivateKey_dpLen;

    /*** 私钥分量dQ ***/
    TASS_SPRINTF((char *)p, 5, "%04d", iPrivateKey_dqLen);
    p += 4;
    memcpy(p, pucPrivateKey_dq, iPrivateKey_dqLen);
    p += iPrivateKey_dqLen;

    /*** 私钥分量qInv ***/
    TASS_SPRINTF((char *)p, 5, "%04d", iPrivateKey_qInvLen);
    p += 4;
    memcpy(p, pucPrivateKey_qInv, iPrivateKey_qInvLen);
    p += iPrivateKey_qInvLen;

    iCmdLen = (int)(p - aucCmd);
    //rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** 私钥长度 ***/
    len = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;
    if(piPrivateKeyLen_Lmk)
    {
        *piPrivateKeyLen_Lmk = len;
    }

    /*** 私钥数据  ***/
    if(pucPrivateKey_Lmk)
    {
        memcpy(pucPrivateKey_Lmk, p, len);
    }

    return HAR_OK;
}



