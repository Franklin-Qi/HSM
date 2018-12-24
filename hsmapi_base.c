/*----------------------------------------------------------------------|
|    hsmapi_ic.h                                                        |
|    Version :     1.0                                                  |
|    Author:       Wen H                                                |
|    Description:  农行定制SJJ1310密码机扩展指令接口                    |
|                                                                       |
|    Copyright :   Beijing JN TASS Technology Co., Ltd.                 |
|    data:         2017-03-09. Create                                   |
|-----------------------------------------------------------------------|
|    Modify History:                                                    |
|----------------------------------------------------------------------*/
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <string.h>

#include "hsmapi_define.h"
#include "hsmapi_log.h"
#include "hsmapi_tools.h"
#include "hsmapi_init.h"
#include "hsmapi_base.h"
#include "hsmsocket.h"

#ifdef _MSC_VER
#include <windows.h>
#pragma warning(disable:4996)
#endif

int HSM_BASE_UO_GenerateSM2KeyPair(
    void *hSessionHandle,int nSock,
    int iKeyLength/*密钥长度*/,
    char cKeyUse/*密钥用途*/,
    int iSM2Idx/*SM2密钥索引*/,
    char cSeparator/*分隔符*/,
    char cKEKSymmAlg/*保护密钥算法*/,
    int iKEKMode/*保护密钥模式*/,
    int iKEKIdx/*保护密钥索引*/,
    char *pcKEKCipherByHMK/*保护密钥密文*/,
    char *pcKeyPassword/*密钥口令*/,
    unsigned char *pucPubKeyX/*公钥X明文 out*/,
    unsigned char *pucPubKeyY/*公钥Y明文 out*/,
    unsigned char *pucPriKeyCipherByHMK/*HMK加密的私钥密文 out*/,
    unsigned char *pucPriKeyCipherByKEK/*KEK加密的私钥密文 out*/)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 512;
    unsigned char aucCmd[512] = { 0 };
    unsigned char aucRsp[512] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code  "UO" ***/
    *p++ = 'U';
    *p++ = 'O';

    /*** 密钥长度 4N ***/
    TASS_SPRINTF(p, 5, "%04d", iKeyLength);
    p += strlen(p);

    /*** 密钥用途 1A ***/
    *p++ = cKeyUse;

    /*** SM2密钥索引 2N ***/
    TASS_SPRINTF(p, 3, "%02d", iSM2Idx);
    p += strlen(p);

    if (cSeparator == ';')
    {
        /*** 分隔符 1A ***/
        *p++ = cSeparator;
        /*** KEK算法类型 1A ***/
        *p++ = cKEKSymmAlg;
        /*** KEK算法模式 1N ***/
        TASS_SPRINTF(p, 2, "%d", iKEKMode);
        p += strlen(p);
        /*** KEK索引或密文 K+4N/16H/1A+32H/1A+48H ***/
        rv = Tools_AddFieldKey(iKEKIdx, pcKEKCipherByHMK, p);
        if (rv == HAR_PARAM_VALUE)
        {
            LOG_ERROR("Parameter: iKEKIdx or pcKEKCipherByHMK is invalid.",
                (pcKeyPassword == NULL) ? 0 : strlen(pcKeyPassword));
            return HAR_PARAM_VALUE;
        }
        p += rv;
    }

    /*** 密钥口令 8A ***/
    if (iSM2Idx != 0)
    {
        memcpy(p, pcKeyPassword, 8);
        p += 8;
    }

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, nSock, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if (rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** 公钥X 32B***/
    memcpy(pucPubKeyX, p, 32);
    p += 32;

    /*** 公钥Y 32B***/
    memcpy(pucPubKeyY, p, 32);
    p += 32;

    /*** HMK加密的私钥密文 40B***/
    memcpy(pucPriKeyCipherByHMK, p, 40);
    p += 40;

    /*** KEK加密的私钥密文 32B***/
    if (cSeparator == ';')
        memcpy(pucPriKeyCipherByKEK, p, 32);

    return HAR_OK;
}

int HSM_BASE_UY_ConvertSM2PriKeyCipherByHMKToKEK(
    void *hSessionHandle,int nSock,
    char cSymmAlg/*算法类型*/,
    unsigned char *pucPriKeyCipherByHMK/*HMK加密的私钥密文*/,
    int iKEKIdx/*保护密钥索引*/,
    char *pcKEKCipherByHMK/*保护密钥密文*/,
    char cMode/*模式*/,
    char *pcIV/*初始向量*/,
    unsigned char *pucPriKeyCipherByKEK/*KEK加密的私钥密文 out*/)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 512;
    unsigned char aucCmd[512] = { 0 };
    unsigned char aucRsp[512] = { 0 };
    unsigned char *p = aucCmd;
    int len;

    /*** Command Code  "UY" ***/
    *p++ = 'U';
    *p++ = 'Y';

    /*** 算法类型 1A ***/
    *p++ = cSymmAlg;

    /*** HMK加密的SM2私钥密文 40B ***/
    memcpy(p, pucPriKeyCipherByHMK, 40);

    /*** 保护密钥索引或密文 K+4N/16H/1A+32H/1A+48H ***/
    rv = Tools_AddFieldKey(iKEKIdx, pcKEKCipherByHMK, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iKEKIdx or pcKEKCipherByHMK is invlaid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** 算法模式 1A ***/
    *p++ = cMode;
    if (cMode == '1')
    {
        /*** 初始向量IV 16/32H ***/
        len = (cSymmAlg == '3') ? 16 : 32;
        memcpy(p, pcIV, len);
        p += len;
    }
    
    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, nSock, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if (rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    memcpy(pucPriKeyCipherByKEK, p, 32);

    return HAR_OK;
}

int HSM_BASE_UU_SM2PubKeyEncrypt(
    void *hSessionHandle,int nSock,
    int iKeyIdx/*密钥索引*/,
    unsigned char *pucPubKeyX/*公钥X明文*/,
    unsigned char *pucPubKeyY/*公钥Y明文*/,
    int iDataLength/*数据长度*/,
    unsigned char *pucData/*数据*/,
    int *piCipherLength/*密文长度 out*/,
    unsigned char *pucCipher/*密文 out*/)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code  "UU" ***/
    *p++ = 'U';
    *p++ = 'U';
    
    /*** 密钥索引 2N ***/
    TASS_SPRINTF(p, 3, "%02d", iKeyIdx);
    p += strlen(p);
    if (iKeyIdx == 0)
    {
        /*** 公钥X 32B ***/
        memcpy(p, pucPubKeyX, 32);
        p += 32;
        /*** 公钥Y 32B ***/
        memcpy(p, pucPubKeyY, 32);
        p += 32;
    }
    /*** 明文长度 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iDataLength);
    p += strlen(p);

    /*** 明文 nB ***/
    memcpy(p, pucData, iDataLength);
    p += iDataLength;
    
    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, nSock, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if (rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** 密文长度 4N ***/
    *piCipherLength = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;

    /*** 密文 nB ***/
    memcpy(pucCipher, p, *piCipherLength);

    return HAR_OK;
}

int HSM_BASE_UW_SM2PriKeyDecrypt(
    void *hSessionHandle,int nSock,
    int iKeyIdx/*密钥索引*/,
    char *pcKeyPassword/*密钥口令*/,
    unsigned char *pucPriKeyCipherByHMK/*私钥密文*/,
    int iCipherLength/*密文长度*/,
    unsigned char *pucCipher/*密文*/,
    int *piDataLength/*数据长度 out*/,
    unsigned char *pucData/*数据 out*/)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code  "UW" ***/
    *p++ = 'U';
    *p++ = 'W';

    /*** 密钥索引 2N ***/
    TASS_SPRINTF(p, 3, "%02d", iKeyIdx);
    p += strlen(p);

    if (iKeyIdx != 0)
    {
        /*** 密钥口令 8A ***/
        memcpy(p, pcKeyPassword, 8);
        p += strlen(p);
    }
    else
    {
        /*** 私钥密文 40B ***/
        memcpy(p, pucPriKeyCipherByHMK, 40);
        p += 40;
    }
    /*** 密文长度 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iCipherLength);
    p += strlen(p);

    /*** 密文 nB ***/
    memcpy(p, pucCipher, iCipherLength);
    p += iCipherLength;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, nSock, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if (rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }
    /*** Response Buffer ***/
    p = aucRsp;

    /*** 明文长度 4N ***/
    *piDataLength = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;

    /*** 明文 nB ***/
    memcpy(pucData, p, *piDataLength);

    return HAR_OK;
}

int HSM_BASE_UQ_SM2Signature(
    void *hSessionHandle,int nSock,
    int iKeyIdx/*密钥索引*/,
    char *pcKeyPassword/*密钥口令*/,
    unsigned char *pucPriKeyCipherByHMK/*私钥密文*/,
    int iDigestAlg/*摘要算法*/,
    int iUserIDLength/*用户标识长度*/,
    unsigned char *pucUserID/*用户标识*/,
    unsigned char *pucPubKey/*公钥*/,
    int iDataLength/*数据长度*/,
    unsigned char *pucData/*数据*/,
    unsigned char *pucSignatureR/*签名R部分 out*/,
    unsigned char *pucSignatureS/*签名S部分 out*/)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code  "UQ" ***/
    *p++ = 'U';
    *p++ = 'Q';

    /*** 密钥索引 2N ***/
    TASS_SPRINTF(p, 3, "%02d", iKeyIdx);
    p += strlen(p);

    if (iKeyIdx != 00)
    {
        /*** 密钥口令 8A ***/
        memcpy(p, pcKeyPassword, 8);
        p += strlen(p);
    }
    else
    {
        /*** 私钥密文 40B ***/
        memcpy(p, pucPriKeyCipherByHMK, 40);
        p += 40;
    }
    /*** 摘要算法 2N ***/
    TASS_SPRINTF(p, 3, "%02d", iDigestAlg);
    p += strlen(p);
    if (iDigestAlg == 2)
    {
        /*** 用户标识长度 4N ***/
        TASS_SPRINTF((char*)p, 5, "%04d", iUserIDLength);
        p += strlen(p);

        /*** 用户标识, nB ***/
        memcpy(p, pucUserID, iUserIDLength);
        p += iUserIDLength;

        /*** 公钥, 64B ***/
        if (iKeyIdx != 0)
        {
            memcpy(p, pucPubKey, 64);
            p += 64;
        }
    }

    /*** 数据长度 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iDataLength);
    p += strlen(p);

    /*** 数据 nB ***/
    memcpy(p, pucData, iDataLength);
    p += iDataLength;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, nSock, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if (rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** 签名R 32B***/
    memcpy(pucSignatureR, p, 32);
    p += 32;

    /*** 签名S 32B***/
    memcpy(pucSignatureS, p, 32);

    return HAR_OK;
}

int HSM_BASE_US_SM2Verify(
    void *hSessionHandle,int nSock,
    int iKeyIdx/*密钥索引*/,
    unsigned char *pucPubKeyX/*公钥X明文*/,
    unsigned char *pucPubKeyY/*公钥Y明文*/,
    unsigned char *pucSignatureR/*签名R部分 out*/,
    unsigned char *pucSignatureS/*签名S部分 out*/,
    int iDigestAlg,
    int iUserIDLength/*用户标识长度*/,
    unsigned char *pucUserID/*用户标识*/,
    int iDataLength/*数据长度*/,
    unsigned char *pucData/*数据*/)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code  "US" ***/
    *p++ = 'U';
    *p++ = 'S';

    /*** 密钥索引 2N ***/
    TASS_SPRINTF(p, 3, "%02d", iKeyIdx);
    p += strlen(p);
    if (iKeyIdx == 00)
    {
        memcpy(p, pucPubKeyX, 32);
        p += 32;
        memcpy(p, pucPubKeyY, 32);
        p += 32;
    }
    /*** 签名R 32B ***/
    memcpy(p, pucSignatureR, 32);
    p += 32;
    /*** 签名S 32B ***/
    memcpy(p, pucSignatureS, 32);
    p += 32;
    /*** 摘要算法 2N ***/
    TASS_SPRINTF(p, 3, "%02d", iDigestAlg);
    p += strlen(p);
    if (iDigestAlg == 2)
    {
        /*** 用户标识长度 4N ***/
        TASS_SPRINTF((char*)p, 5, "%04d", iUserIDLength);
        p += strlen(p);

        /*** 用户标识, nB ***/
        memcpy(p, pucUserID, iUserIDLength);
        p += iUserIDLength;
    }

    /*** 数据长度 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iDataLength);
    p += strlen(p);

    /*** 输入数据 nB ***/
    memcpy(p, pucData, iDataLength);
    p += iDataLength;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, nSock, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if (rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    return HAR_OK;
}

int HSM_BASE_GM_CalculateDigest(
    void *hSessionHandle,int nSock,
    int iAlgType/*算法类型*/,
    char cSeperator/*分隔符*/,
    int iDataLength/*数据长度*/,
    unsigned char *pucData/*数据*/,
    int *piDigestLength/*摘要长度*/,
    unsigned char *pucDigest/*摘要*/)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code  "GM" ***/
    *p++ = 'G';
    *p++ = 'M';

    /*** 算法类型 2A ***/
    TASS_SPRINTF(p, 3, "%02d", iAlgType);
    p += strlen(p);

    /*** 分隔符 1A ***/
    *p++ = ';';

    /*** 数据长度 5N ***/
    TASS_SPRINTF((char*)p, 6, "%05d", iDataLength);
    p += strlen(p);

    /*** 输入数据 nB ***/
    memcpy(p, pucData, iDataLength);
    p += iDataLength;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, nSock, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if (rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** 摘要长度 4N ***/
    *piDigestLength = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;

    /*** 摘要 nB ***/
    memcpy(pucDigest, p, *piDigestLength);

    return HAR_OK;
}