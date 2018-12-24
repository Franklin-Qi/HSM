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
#include "hsmapi_rsa.h"
#include "hsmsocket.h"

#ifdef _MSC_VER
#include <windows.h>
#pragma warning(disable:4996)
#endif

int HSM_RSA_EI_GenerateRSAKeyPair(
    void *hSessionHandle,int nSock,
    char cMode/*模式*/,
    int iKeyLength/*密钥长度*/,
    int iKeyEncode/*公私钥编码*/,
    int iRSAIdx/*RSA密钥索引*/,
    char *pcKeyPassword/*密钥口令*/,
    char cKeyUse/*密钥用途*/,
    int iKEKFlag/*KEK导出标识*/,
    char cKEKSymmAlg/*保护密钥算法*/,
    int iKEKMode/*保护密钥模式*/,
    int iKEKIdx/*保护密钥索引*/,
    char *pcKEKCipherByHMK/*保护密钥密文*/,
    char cSeparator/*分隔符*/,
    int iExpLength/*指数长度*/,
    int iExp/*指数*/,
    int *piPubKeyLength/*公钥长度 out*/,
    unsigned char *pucPubKey/*公钥 out*/,
    int *piPriKeyCipherByHMKLength/*HMK加密的私钥密文长度 out*/,
    unsigned char *pucPriKeyCipherByHMK/*HMK加密的私钥密文 out*/,
    int *piPriKeyCipherByKEKLength/*KEK加密的私钥密文长度 out*/,
    unsigned char *pucPriKeyCipherByKEK/*KEK加密的私钥密文 out*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code    "EI" ***/
    *p++ = 'E';
    *p++ = 'I';

    /*** 密钥模式 1A ***/
    *p++ = cMode;

    /*** 密钥长度 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iKeyLength);
    p += strlen(p);

    if (cMode != 3)
    {
        /*** 公私钥编码 2N ***/
        TASS_SPRINTF((char*)p, 3, "%02d", iKeyEncode);
        p += strlen(p);
    }

    /*** RSA索引编码 2N ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iRSAIdx);
    p += strlen(p);

    if (iRSAIdx != 00)
    {
        /*** 密钥口令 8A ***/
        memcpy(p, pcKeyPassword, 8);
        p += 8;
    }

    if ((cMode == '0') || (cMode == '1') || (cMode == '3'))
    {
        /*** 密钥用途 1N ***/
        if((cKeyUse >= '1' && cKeyUse <= '3'))
            *p++ = cKeyUse;
    }
    if ((cMode == '1') || (cMode == '2'))
    {
        /*** KEK导出标识 1N ***/
        TASS_SPRINTF((char*)p, 2, "%d", iKEKFlag);
        p += strlen(p);

        if (iKEKFlag == 1)
        {
            /*** KEK算法类型 1A ***/
            *p++ = cKEKSymmAlg;

            /*** KEK算法模式 1N ***/
            TASS_SPRINTF((char*)p, 2, "%d", iKEKMode);
            p += strlen(p);

            /*** KEK索引或密文 K+4N/16H/1A+32H/1A+48H ***/
            rv = Tools_AddFieldKey(iKEKIdx, pcKEKCipherByHMK, p);
            if (rv == HAR_PARAM_VALUE)
            {
                LOG_ERROR("Parameter: iKEKIdx or pcKEKCipherByHMK is invalid.",0);
                return HAR_PARAM_VALUE;
            }
            p += rv;
        }
    }

    if (cSeparator == ';')
    {
        /*** 分隔符 1A ***/
        *p++ = ';';

        /*** 指数长度 4N ***/
        TASS_SPRINTF(p, 5, "%04d", iExpLength);
        p += strlen(p);

        /*** 指数 nN ***/
        TASS_SPRINTF(p, 16, "%d", iExp);
        p += strlen(p);
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

    if (cMode != '3')
    {
        /*** 公钥长度 4N ***/
        *piPubKeyLength = Tools_ConvertDecBuf2Int(p, 4);
        p += 4;

        /*** 公钥 nB ***/
        memcpy(pucPubKey, p, *piPubKeyLength);
        p += *piPubKeyLength;

        if (cMode != '0')
        {
            /*** HMK加密私钥密文长度 4N ***/
            *piPriKeyCipherByHMKLength = Tools_ConvertDecBuf2Int(p, 4);
            p += 4;

            /*** HMK加密私钥密文 nB ***/
            memcpy(pucPriKeyCipherByHMK, p, *piPriKeyCipherByHMKLength);
            p += *piPriKeyCipherByHMKLength;

            if (iKEKFlag == 1)
            {
                /*** KEK加密私钥密文长度 4N ***/
                *piPriKeyCipherByKEKLength = Tools_ConvertDecBuf2Int(p, 4);
                p += 4;

                /*** KEK加密私钥密文 nB ***/
                memcpy(pucPriKeyCipherByKEK, p, *piPriKeyCipherByKEKLength);
            }
        }
    }

    return HAR_OK;
}

int HSM_RSA_EW_Singature(
    void *hSessionHandle,int nSock,
    int iHASHAlg,/*HASH算法标识*/
    int iPadMode/*填充模式*/,
    int iMGF/*MGF*/,
    int iMGFHASHAlg/*MGF哈希算法*/,
    int iOAEPParamLength/*OAEP参数长度*/,
    unsigned char *pucOAEPParam/*OAEP参数*/,
    int iDataLength/*数据长度*/,
    unsigned char *pucData/*数据*/,
    char cSeperator/*分隔符*/,
    int iRSAIdx,/*RSA索引*/
    char *pcKeyPassword,/*密钥口令*/
    int iPriKeyCipherByHMKLength,/*私钥密文长度*/
    unsigned char *pucPriKeyCipherByHMK,/*私钥密文*/
    int *piSignatureLength,/*签名长度 out*/
    unsigned char *pucSignature/*签名 out*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[SOCKET_MAXDATALEN] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code "EW" ***/
    *p++ = 'E';
    *p++ = 'W';

    /*** HASH算法标识 2N ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iHASHAlg);
    p += strlen(p);

    /*** 填充模式标识 2N ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iPadMode);
    p += strlen(p);

    if (iPadMode == 2)
    {
        /*** MGF 2N ***/
        TASS_SPRINTF((char*)p, 3, "%02d", iMGF);
        p += strlen(p);

        /*** MGF HASH算法 2N ***/
        TASS_SPRINTF((char*)p, 3, "%02d", iMGFHASHAlg);
        p += strlen(p);

        /*** OAEP编码参数长度 2N ***/
        TASS_SPRINTF((char*)p, 3, "%02d", iOAEPParamLength);
        p += strlen(p);

        /*** OAEP编码参数 nB ***/
        memcpy(p, pucOAEPParam, iOAEPParamLength);
        p += iOAEPParamLength;
    }

    /*** 数据长度 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iDataLength);
    p += strlen(p);

    /*** 数据 nB ***/
    memcpy(p, pucData, iDataLength);
    p += iDataLength;

    /*** 分隔符 1A ***/
    *p++ = cSeperator;

    /*** 密钥索引 2N ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iRSAIdx);
    p += strlen(p);

    /*** 密钥口令 8A ***/
    if (iRSAIdx != 00)
    {
        memcpy(p, pcKeyPassword, 8);
        p += 8;
    }
    else
    {
        /*** 私钥长度, 4N ***/
        TASS_SPRINTF((char*)p, 5, "%04d", iPriKeyCipherByHMKLength);
        p += strlen(p);

        /*** 私钥密文 nB ***/
        memcpy(p, pucPriKeyCipherByHMK, iPriKeyCipherByHMKLength);
        p += iPriKeyCipherByHMKLength;
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

    /*** 数字签名长度 4N ***/
    *piSignatureLength = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;

    /*** 签名 nB ***/
    memcpy(pucSignature, p, *piSignatureLength);

    return HAR_OK;
}

int HSM_RSA_EY_Verify(
    void *hSessionHandle,int nSock,
    int iHASHAlg,/*HASH算法标识*/
    int iPadMode/*填充模式*/,
    int iMGF/*MGF*/,
    int iMGFHASHAlg/*MGF哈希算法*/,
    int iOAEPParamLength/*OAEP参数长度*/,
    unsigned char *pucOAEPParam/*OAEP参数*/,
    int iSignatureLength/*签名长度*/,
    unsigned char *pucSignature/*签名*/,
    char cSeperator1/*分隔符1*/,
    int iDataLength/*数据长度*/,
    unsigned char *pucData/*数据*/,
    char cSeperator2/*分隔符2*/,
    int iRSAIdx,/*RSA索引*/
    int iPubKeyEncode/*公钥编码格式*/,
    int iPubKeyLength/*公钥长度*/,
    unsigned char *pucPubKey/*私钥密文*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[SOCKET_MAXDATALEN] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code "EY" ***/
    *p++ = 'E';
    *p++ = 'Y';

    /*** HASH算法标识 2N ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iHASHAlg);
    p += strlen(p);

    /*** 填充模式标识 2N ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iPadMode);
    p += strlen(p);

    if (iPadMode == 2)
    {
        /*** MGF 2N ***/
        TASS_SPRINTF((char*)p, 3, "%02d", iMGF);
        p += strlen(p);

        /*** MGF HASH算法 2N ***/
        TASS_SPRINTF((char*)p, 3, "%02d", iMGFHASHAlg);
        p += strlen(p);

        /*** OAEP编码参数长度 2N ***/
        TASS_SPRINTF((char*)p, 3, "%02d", iOAEPParamLength);
        p += strlen(p);

        /*** OAEP编码参数 nB ***/
        memcpy(p, pucOAEPParam, iOAEPParamLength);
        p += iOAEPParamLength;
    }

    /*** 签名长度 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iSignatureLength);
    p += strlen(p);

    /*** 签名 nB ***/
    memcpy(p, pucSignature, iSignatureLength);
    p += iSignatureLength;

    /*** 分隔符 1A ***/
    *p++ = cSeperator1;

    /*** 数据长度 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iDataLength);
    p += strlen(p);

    /*** 数据 nB ***/
    memcpy(p, pucData, iDataLength);
    p += iDataLength;

    /*** 分隔符 1A ***/
    *p++ = cSeperator2;

    /*** 密钥索引 2N ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iRSAIdx);
    p += strlen(p);

    if (iRSAIdx == 00)
    {
        /*** 公钥长度 4N ***/
        TASS_SPRINTF((char*)p, 5, "%04d", iPubKeyLength);
        p += strlen(p);

        /*** 公钥 nB ***/
        memcpy(p, pucPubKey, iPubKeyLength);
        p += iPubKeyLength;
    }

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, nSock, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if (rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    return HAR_OK;
}

int HSM_RSA_UK_PublicKeyOperation(
    void *hSessionHandle,int nSock,
    int iEnDecryptFlag/*加解密标识*/,
    int iPadMode/*填充模式*/,
    int iMGF/*MGF*/,
    int iMGFHASHAlg/*MGF哈希算法*/,
    int iOAEPParamLength/*OAEP参数长度*/,
    unsigned char *pucOAEPParam/*OAEP参数*/,
    int iMsgType/*消息类型*/,
    int iRSAIdx,/*RSA索引*/
    int iPubKeyEncode/*公钥编码格式*/,
    int iPubKeyLength/*公钥长度*/,
    unsigned char *pucPubKey/*公钥*/,
    int iDataInLength/*输入数据长度*/,
    unsigned char *pucDataIn/*输入数据*/,
    int *piDataOutLength/*输出数据长度 out*/,
    unsigned char *pucDataOut/*输出数据 out*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 4096 * 2;
    unsigned char aucCmd[SOCKET_MAXDATALEN] = { 0 };
    unsigned char aucRsp[4096 * 2] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code    "VA" ***/
    *p++ = 'V';
    *p++ = 'A';

    /*** 加解密标识 1N ***/
    TASS_SPRINTF((char*)p, 2, "%d", iEnDecryptFlag);
    p += strlen(p);

    /*** 填充模式标识 1N, ***/
    TASS_SPRINTF((char*)p, 2, "%d", iPadMode);
    p += strlen(p);

    if (iPadMode == 2)
    {
        /*** MGF 2N ***/
        TASS_SPRINTF((char*)p, 3, "%02d", iMGF);
        p += strlen(p);

        /*** MGF HASH算法 2N ***/
        TASS_SPRINTF((char*)p, 3, "%02d", iMGFHASHAlg);
        p += strlen(p);

        /*** OAEP编码参数长度 2N ***/
        TASS_SPRINTF((char*)p, 3, "%02d", iOAEPParamLength);
        p += strlen(p);

        /*** OAEP编码参数 nB ***/
        memcpy(p, pucOAEPParam, iOAEPParamLength);
        p += iOAEPParamLength;
    }

    /*** 密钥索引 2N ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iRSAIdx);
    p += strlen(p);

    if (iRSAIdx == 0)
    {
        /*** 公钥编码 1N ***/
        TASS_SPRINTF((char*)p, 2, "%d", iPubKeyEncode);
        p += strlen(p);

        /*** 公钥长度 4N ***/
        TASS_SPRINTF((char*)p, 5, "%04d", iPubKeyLength);
        p += strlen(p);

        /*** 公钥 nB***/
        memcpy(p, pucPubKey, iPubKeyLength);
        p += iPubKeyLength;
    }

    /*** 数据长度 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iDataInLength);
    p += strlen(p);

    if (iMsgType)
    {
        /*** 数据 nH ***/
        strncpy(p, pucDataIn, iDataInLength * 2);
        p += strlen(p);
    }
    else
    {
        /*** 数据 nB ***/
        memcpy(p, pucDataIn, iDataInLength);
        p += iDataInLength;
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

    /*** 输出数据长度, 4N ***/
    *piDataOutLength = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;

    /*** 输出数据, nB ***/
    memcpy(pucDataOut, p, iDataInLength);

    return HAR_OK;
}

int HSM_RSA_VA_PrivateKeyOperation(
    void *hSessionHandle,int nSock,
    int iEnDecryptFlag/*加解密标识*/,
    int iPadMode/*填充模式*/,
    int iMGF/*MGF*/,
    int iMGFHASHAlg/*MGF哈希算法*/,
    int iOAEPParamLength/*OAEP参数长度*/,
    unsigned char *pucOAEPParam/*OAEP参数*/,
    int iRSAIdx/*私钥索引*/,
    char *pcKeyPassword/*私钥口令*/,
    int iPriKeyCipherByHMKLength/*私钥密文长度*/,
    unsigned char *pucPriKeyCipherByHMK/*私钥密文*/,
    int iDataInLength/*输入数据长度*/,
    unsigned char *pucDataIn/*输入数据*/,
    int *piDataOutLength/*输出数据长度 out*/,
    unsigned char *pucDataOut/*输出数据 out*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 4096 * 2;
    unsigned char aucCmd[SOCKET_MAXDATALEN] = { 0 };
    unsigned char aucRsp[4096 * 2] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code    "VA" ***/
    *p++ = 'V';
    *p++ = 'A';

    /*** 加解密标识, 2N, ***/
    TASS_SPRINTF((char*)p, 2, "%d", iEnDecryptFlag);
    p += strlen(p);

    /*** 填充模式标识, 2N, ***/
    TASS_SPRINTF((char*)p, 2, "%d", iPadMode);
    p += strlen(p);

    if (iPadMode == 2)
    {
        /*** MGF, 2N, ***/
        TASS_SPRINTF((char*)p, 3, "%02d", iMGF);
        p += strlen(p);

        /*** MGF HASH算法, 2N, ***/
        TASS_SPRINTF((char*)p, 3, "%02d", iMGFHASHAlg);
        p += strlen(p);

        /*** OAEP编码参数长度, 2N, ***/
        TASS_SPRINTF((char*)p, 3, "%02d", iOAEPParamLength);
        p += strlen(p);

        /*** OAEP编码参数 ***/
        memcpy(p, pucOAEPParam, iOAEPParamLength);
        p += iOAEPParamLength;
    }

    /*** 密钥索引, 2N ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iRSAIdx);
    p += strlen(p);

    /*** 密钥口令 8A ***/
    if (iRSAIdx != 00)
    {
        memcpy(p, pcKeyPassword, 8);
        p += 8;
    }
    else
    {
        /*** 私钥长度, 4N ***/
        TASS_SPRINTF((char*)p, 5, "%04d", iPriKeyCipherByHMKLength);
        p += strlen(p);

        /*** 私钥密文 nB ***/
        memcpy(p, pucPriKeyCipherByHMK, iPriKeyCipherByHMKLength);
        p += iPriKeyCipherByHMKLength;
    }

    /*** 数据长度 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iDataInLength);
    p += strlen(p);

    /*** 数据 nB ***/
    memcpy(p, pucDataIn, iDataInLength);
    p += iDataInLength;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, nSock, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if (rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** 输出数据长度 4N ***/
    *piDataOutLength = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;

    /*** 输出数据 nB ***/
    memcpy(pucDataOut, p, *piDataOutLength);

    return HAR_OK;
}

int HSM_RSA_UA_SeparatePrivateKeyCipherByHMKToKEK(
    void *hSessionHandle,int nSock,
    char cKEKSymmAlg/*算法类型*/,
    int iKEKIdx/*保护密钥索引*/,
    char *pcKEKCipherByHMK/*保护密钥密文*/,
    char cKEKDiversifyTime/*保护密钥分散次数*/,
    char *pcKEKDiversifyData/*保护密钥分散数据*/,
    int iPriKeyCipherByHMKLength/*私钥密文长度*/,
    unsigned char *pucPriKeyCipherByHMK/*私钥密文*/,
    int *piModeLength/*模长度 out*/,
    unsigned char *pucMode/*模 out*/,
    int *piELength/*指数长度 out*/,
    unsigned char *pucE/*指数 out*/,
    int *piDLength/*D长度 out*/,
    unsigned char *pucD/*D out*/,
    int *piPrime1Length/*Prime1长度 out*/,
    unsigned char *pucPrime1/*Prime1 out*/,
    int *piPrime2Length/*Prime2长度 out*/,
    unsigned char *pucPrime2/*Prime2 out*/,
    int *piPexp1Length/*Pexp1长度 out*/,
    unsigned char *pucPexp1/*Pexp1 out*/,
    int *piPexp2Length/*Pexp2长度 out*/,
    unsigned char *pucPexp2/*Pexp2 out*/,
    int *piCoefLength/*coef长度 out*/,
    unsigned char *pucCoef/*coef out*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code    "UA" ***/
    *p++ = 'U';
    *p++ = 'A';

    /*** KEK算法类型 1A ***/
    *p++ = cKEKSymmAlg;

    /*** KEK索引或密文 K+4N/16H/1A+32H/1A+48H ***/
    rv = Tools_AddFieldKey(iKEKIdx, pcKEKCipherByHMK, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("Parameter: iKEKIdx or pcKEKCipherByHMK is invalid.", 0);
        return HAR_PARAM_VALUE;
    }
    p += rv;

    /*** KEK分散次数 1A ***/
    if ((cKEKDiversifyTime < '0') || (cKEKDiversifyTime > '3'))
    {
        LOG_ERROR("%s", "Parameter: cKEKDiversifyTime is invalid.");
        return HAR_PARAM_LEN;
    }
    *p++ = cKEKDiversifyTime;
    p += strlen(p);

    if (cKEKDiversifyTime != '0')
    {
        /*** KEK分散数据 n*16H ***/
        len = (cKEKDiversifyTime & 0x0f) * 16;
        memcpy(p, pcKEKDiversifyData, len);
        p += len;
    }

    /*** 私钥长度, 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iPriKeyCipherByHMKLength);
    p += strlen(p);

    /*** 私钥密文 nB ***/
    memcpy(p, pucPriKeyCipherByHMK, iPriKeyCipherByHMKLength);
    p += iPriKeyCipherByHMKLength;
    
    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, nSock, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if (rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** 模长度 4N ***/
    *piModeLength = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;

    /*** 模 nB ***/
    memcpy(pucMode, p, *piModeLength);
    p += *piModeLength;

    /*** E长度 4N ***/
    *piELength = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;

    /*** E nB ***/
    memcpy(pucE, p, *piELength);
    p += *piELength;

    /*** D长度 4N ***/
    *piDLength = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;

    /*** D nB ***/
    memcpy(pucD, p, *piDLength);
    p += *piDLength;

    /*** Prime1长度 4N ***/
    *piPrime1Length = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;

    /*** Prime1 nB ***/
    memcpy(pucPrime1, p, *piPrime1Length);
    p += *piPrime1Length;

    /*** Prime2长度 4N ***/
    *piPrime2Length = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;

    /*** Prime2 nB ***/
    memcpy(pucPrime2, p, *piPrime2Length);
    p += *piPrime2Length;

    /*** Pexp1长度 4N ***/
    *piPexp1Length = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;

    /*** Pexp1 nB ***/
    memcpy(pucPexp1, p, *piPexp1Length);
    p += *piPexp1Length;

    /*** Pexp2长度 4N ***/
    *piPexp2Length = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;

    /*** Pexp2 nB ***/
    memcpy(pucPexp2, p, *piPexp2Length);
    p += *piPexp2Length;

    /*** coef长度 4N ***/
    *piCoefLength = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;

    /*** coef nB ***/
    memcpy(pucCoef, p, *piCoefLength);

    return HAR_OK;
}