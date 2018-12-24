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
#include "hsmapi_magnet.h"
#include "hsmsocket.h"

#ifdef _MSC_VER
#include <windows.h>
#pragma warning(disable:4996)
#endif

int HSM_MGT_X0_GenerateKey(
    void *hSessionHandle,int nSock,
    char cMode/*模式*/,
    int  iMediaType/*介质类型*/,
    char cSymmAlg/*算法类型*/,
    char cCompCount/*分量个数*/,
    int iKeyLength/*密钥长度*/,
    int iDataKeyIdx/*密钥索引*/,
    char *pcDataKeyCipherByHMK/*密钥密文*/,
    char cDiversifyTime/*分散次数*/,
    char *pcDiversifyData/*分散数据*/,
    int iInnerIndex/*内部索引*/,
    int iPubKeyLength/*公钥长度*/,
    unsigned char *pucPubKey/*公钥*/,
    char cKEKSymmAlg/*算法类型*/,
    int iKEKIdx/*保护密钥索引*/,
    char *pcKEKCipherByHMK/*保护密钥密文*/,
    char *pcPrintInfo/*打印相关信息*/,
    char *pcKeyCipherByHMK/*HMK加密密钥密文 out*/,
    int *piKeyCipherByPubKeyLength/*公钥加密密钥密文长度 out*/,
    unsigned char *pucKeyCipherByPubKey/*公钥加密密钥密文 out*/,
    char *pcKeyCipherByKEK/*KEK加密密钥密文 out*/,
    char *pcKCV/*密钥校验值 out*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code    "X0" ***/
    *p++ = 'X';
    *p++ = '0';

    /*** 密钥模式 1A ***/
    *p++ = cMode;

    /*** 介质类型 1A ***/
    TASS_SPRINTF(p, 3, "%02d", iMediaType);
    p += strlen(p);

    /*** 算法类型 1A ***/
    *p++ = cSymmAlg;

    /*** 分量个数 1A ***/
    *p++ = cCompCount;
    
    if (cMode == '0')
    {
        /*** 密钥长度 4A ***/
        TASS_SPRINTF(p, 5, "%04d", iKeyLength);
        p += strlen(p);
    }
    else
    {
        /*** 数据密钥索引或密文 K+4N/16H/1A+32H/1A+48H ***/
        len = Tools_AddFieldKey(iDataKeyIdx, pcDataKeyCipherByHMK, p);
        if (len == HAR_PARAM_VALUE)
        {
            LOG_ERROR("%s", "Parameter: iDataKeyIdx or pcDataKeyCipherByHMK is invalid.");
            return HAR_PARAM_LEN;
        }
        p += len;
        /*** 分散次数和分散因子 1A + n*16H***/
        if ((cDiversifyTime < '1') || (cDiversifyTime > '3'))
        {
            LOG_ERROR("%s", "Parameter: cDiversifyTime is invalid.");
            return HAR_PARAM_LEN;
        }
        *p++ = cDiversifyTime;
        p += strlen(p);
        len = (cDiversifyTime & 0x0f) * 16;
        memcpy(p, pcDiversifyData, len);
        p += len;
    }
    if (iInnerIndex != 0)
    {
        /*** 内部索引 K+4N ***/
        TASS_SPRINTF(p, 6, "K%04d", iInnerIndex);
        p += strlen(p);
    }
    if ((iMediaType == 12) || (iMediaType == 13))
    {
        /*** 公钥长度 4A ***/
        TASS_SPRINTF(p, 5, "%04d", iPubKeyLength);
        p += strlen(p);
        /*** 公钥 nB ***/
        memcpy(p, pucPubKey, iPubKeyLength);
        p += iPubKeyLength;
    }
    if (iMediaType == 14)
    {
        /*** KEK算法类型 1A ***/
        *p++ = cKEKSymmAlg;
        /*** KEK密钥索引或密文 K+4N/16H/1A+32H/1A+48H ***/
        len = Tools_AddFieldKey(iKEKIdx, pcKEKCipherByHMK, p);
        if (len == HAR_PARAM_VALUE)
        {
            LOG_ERROR("%s","Parameter: iKEKIdx or pcKEKCipherByHMK is invalid.");
            return HAR_PARAM_LEN;
        }
        p += len;
    }
    /*** 打印信息 nA ***/
    sprintf(p, "%s", pcPrintInfo == NULL ? "" : pcPrintInfo);
    p += strlen(p);

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, nSock, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if (rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** HMK加密的密钥密文 16H/1A+32H/1A+48H ***/
    len = Tools_GetFieldKeyLength(p);
    strncpy(pcKeyCipherByHMK, p, len);
    *(pcKeyCipherByHMK + len) = '\0';
    p += len;
    /*** 公钥加密的密钥密文及长度 4N + nB ***/
    if ((iMediaType == 12) || (iMediaType == 13))
    {
        *piKeyCipherByPubKeyLength = Tools_ConvertDecBuf2Int(p, 4);
        p += 4;
        memcpy(pucKeyCipherByPubKey, p, *piKeyCipherByPubKeyLength * 2);
        *(pucKeyCipherByPubKey + *piKeyCipherByPubKeyLength) = '\0';
        p += *piKeyCipherByPubKeyLength;
    }
    /*** KEK加密的密钥密文 16H/1A+32H/1A+48H ***/
    if (iMediaType == 14)
    {
        len = Tools_GetFieldKeyLength(p);
        strncpy(pcKeyCipherByKEK, p, len);
        *(pcKeyCipherByKEK + len) = '\0';
        p += len;
    }
    /*** KCV 16H ***/
    strncpy(pcKCV, p, 16);
    *(pcKCV + 16) = '\0';
    return HAR_OK;
}

int HSM_MGT_A6_ImportKey(
    void *hSessionHandle,int nSock,
    char cSymmAlg/*算法类型*/,
    int iKEKIdx/*保护密钥索引*/,
    char *pcKEKCipherByHMK/*保护密钥密文*/,
    char *pcKeyCipherByKEK/*KEK加密密钥密文*/,
    char cHMKScheme/*HMK密钥方案*/,
    int iInnerIndex/*内部索引*/,
    char cSeparator/*分隔符*/,
    char *pcKCVIn/*密钥校验值*/,
    char *pcKeyCipherByHMK/*KEK加密密钥密文 out*/,
    char *pcKCVOut/*密钥校验值 out*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code    "A6" ***/
    *p++ = 'A';
    *p++ = '6';

    /*** 算法类型 1A***/
    *p++ = cSymmAlg;

    /*** KEK密钥索引或密文 K+4N/16H/1A+32H/1A+48H ***/
    len = Tools_AddFieldKey(iKEKIdx, pcKEKCipherByHMK, p);
    if (len == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iKEKIdx or pcKEKCipherByHMK is invalid.");
        return HAR_PARAM_LEN;
    }
    p += len;

    /*** 被导入密钥密文 16H/1A+32H/1A+48H ***/
    len = Tools_AddFieldKey(0, pcKeyCipherByKEK, p);
    if (len == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: pcKeyCipherByKEK is invalid.");
        return HAR_PARAM_LEN;
    }
    p += len;

    /*** HMK密钥方案 1A ***/
    *p++ = cHMKScheme;

    if (iInnerIndex != 0)
    {
        /*** 内部索引 K+4N **/
        TASS_SPRINTF(p, 6, "K%04d", iInnerIndex);
        p += strlen(p);
    }

    if (cSeparator == ';')
    {
        /*** 分隔符 1A ***/
        *p++ = cSeparator;
        /*** KCV 8H ***/
        memcpy(p, pcKCVIn, 8);
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

    /*** HMK加密的密钥密文 16H/1A+32H/1A+48H ***/
    len = Tools_GetFieldKeyLength(p);
    strncpy(pcKeyCipherByHMK, p, len);
    *(pcKeyCipherByHMK + len) = '\0';
    p += len;
    /*** KCV 16H ***/
    strncpy(pcKCVOut, p, 16);
    *(pcKCVOut + 16) = '\0';
    return HAR_OK;
}

int HSM_MGT_A8_ExportKey(
    void *hSessionHandle,int nSock,
    char cSymmAlg/*算法类型*/,
    int iKEKIdx/*保护密钥索引*/,
    char *pcKEKCipherByHMK/*保护密钥密文*/,
    int iKeyIdx/*被导出密钥索引*/,
    char *pcKeyCipherByHMK/*被导出密钥密文*/,
    char cKEKScheme/*KEK密钥方案*/,
    char *pcKeyCipherByKEK/*KEK加密密钥密文 out*/,
    char *pcKCV/*密钥校验值 out*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code    "A8" ***/
    *p++ = 'A';
    *p++ = '8';

    /*** 算法类型 1A***/
    *p++ = cSymmAlg;

    /*** KEK密钥索引或密文 K+4N/16H/1A+32H/1A+48H ***/
    len = Tools_AddFieldKey(iKEKIdx, pcKEKCipherByHMK, p);
    if (len == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iKEKIdx or pcKEKCipherByHMK is invalid.");
        return HAR_PARAM_LEN;
    }
    p += len;

    /*** 被导出密钥索引或密文 K+4N/16H/1A+32H/1A+48H ***/
    len = Tools_AddFieldKey(iKeyIdx, pcKeyCipherByHMK, p);
    if (len == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iKeyIdx or pcKeyCipherByHMK is invalid.");
        return HAR_PARAM_LEN;
    }
    p += len;

    /*** KEK密钥方案 1A ***/
    *p++ = cKEKScheme;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, nSock, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if (rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** KEK加密的密钥密文 16H/1A+32H/1A+48H ***/
    len = Tools_GetFieldKeyLength(p);
    strncpy(pcKeyCipherByKEK, p, len);
    *(pcKeyCipherByKEK + len) = '\0';
    p += len;
    /*** KCV 16H ***/
    strncpy(pcKCV, p, 16);
    *(pcKCV + 16) = '\0';
    return HAR_OK;
}

int HSM_MGT_GG_CompoundKEK(
    void *hSessionHandle,int nSock,
    char cSymmAlg/*算法类型*/,
    char *pcKEKComponent1CipherByHMK/*KEK分量1密文*/,
    char *pcKEKComponent2CipherByHMK/*KEK分量2密文*/,
    char *pcKEKComponent3CipherByHMK/*KEK分量3密文*/,
    char *pcKEKCipherByHMK/*HMK加密KEK密文 out*/,
    char *pcKCV/*密钥校验值 out*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code    "GG" ***/
    *p++ = 'G';
    *p++ = 'G';

    /*** 算法类型 1A***/
    *p++ = cSymmAlg;

    /*** KEK分量1密文 16H/1A+32H/1A+48H ***/
    len = Tools_AddFieldKey(0, pcKEKComponent1CipherByHMK, p);
    if (len == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: pcKEKComponent1CipherByHMK is invalid.");
        return HAR_PARAM_LEN;
    }
    p += len;

    /*** KEK分量2密文 16H/1A+32H/1A+48H ***/
    len = Tools_AddFieldKey(0, pcKEKComponent2CipherByHMK, p);
    if (len == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: pcKEKComponent2CipherByHMK is invalid.");
        return HAR_PARAM_LEN;
    }
    p += len;

    /*** KEK分量2密文 16H/1A+32H/1A+48H ***/
    len = Tools_AddFieldKey(0, pcKEKComponent3CipherByHMK, p);
    if (len == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: pcKEKComponent3CipherByHMK is invalid.");
        return HAR_PARAM_LEN;
    }
    p += len;
    
    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, nSock, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if (rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** KEK加密的密钥密文 16H/1A+32H/1A+48H ***/
    len = Tools_GetFieldKeyLength(p);
    strncpy(pcKEKCipherByHMK, p, len);
    *(pcKEKCipherByHMK + len) = '\0';
    p += len;

    /*** KCV 16H ***/
    strncpy(pcKCV, p, 16);
    *(pcKCV + 16) = '\0';
    return HAR_OK;
}

int HSM_MGT_X2_HMKEncryptKey(
    void *hSessionHandle,int nSock,
    char cSymmAlg/*算法类型*/,
    int iKeyIdx/*待加密密钥索引*/,
    char *pcKeyCipherByHMK/*HMK加密密钥密文 out*/,
    char *pcKCV/*密钥校验值 out*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;
    int kcvLen = 16;

    /*** Command Code    "X2" ***/
    *p++ = 'X';
    *p++ = '2';

    /*** 算法类型 1A***/
    *p++ = cSymmAlg;

    /*** 密钥索引 K+4N ***/
    len = Tools_AddFieldKey(iKeyIdx, NULL, p);
    if (len == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iKeyIdx is invalid.");
        return HAR_PARAM_LEN;
    }
    p += len;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, nSock, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if (rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** HMK加密的密钥密文 16H/1A+32H/1A+48H ***/
    len = Tools_GetFieldKeyLength(p);
    strncpy(pcKeyCipherByHMK, p, len);
    *(pcKeyCipherByHMK + len) = '\0';
    p += len;

    /*** KCV 16H ***/
    strncpy(pcKCV, p, kcvLen);
    *(pcKCV + kcvLen) = '\0';
    return HAR_OK;
}

int HSM_MGT_KA_GenerateKCV(
    void *hSessionHandle,int nSock,
    char cSymmAlg/*算法类型*/,
    int iKeyIdx/*待加密密钥索引*/,
    char cSeparator/*分隔符*/,
    char cKCVType/*KCV类型*/,
    char *pcKCV/*密钥校验值 out*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;
    int kcvLen = 16;

    /*** Command Code    "KA" ***/
    *p++ = 'K';
    *p++ = 'A';

    /*** 算法类型 1A***/
    *p++ = cSymmAlg;

    /*** 密钥索引 K+4N ***/
    len = Tools_AddFieldKey(iKeyIdx, NULL, p);
    if (len == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iKeyIdx is invalid.");
        return HAR_PARAM_LEN;
    }
    p += len;

    if (cSeparator == ';')
    {
        /*** 分隔符 1A ***/
        *p++ = cSeparator;
        /*** KCV类型 1A ***/
        *p++ = cKCVType;
        if (cKCVType == '1')
            kcvLen = 6;
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

    /*** KCV 16/6H ***/
    strncpy(pcKCV, p, kcvLen);
    *(pcKCV + kcvLen) = '\0';
    return HAR_OK;
}

int HSM_MGT_JA_GenerateRandomPIN(
    void *hSessionHandle,int nSock,
    char *pcPAN/*PAN*/,
    int iPINLength/*PIN长度*/,
    char *pcPINCipherByHMK/*HMK加密PIN密文 out*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code    "JA" ***/
    *p++ = 'J';
    *p++ = 'A';

    /*** PAN 12N ***/
    memcpy(p, pcPAN, 12);
    p += 12;

    /*** PIN长度 2N ***/
    TASS_SPRINTF(p, 3, "%02d", iPINLength);
    p += strlen(p);

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, nSock, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if (rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** PIN密文 13H ***/
    strncpy(pcPINCipherByHMK, p, 13);
    *(pcPINCipherByHMK + 13) = '\0';
    return HAR_OK;
}

int HSM_MGT_BA_EncryptPIN(
    void *hSessionHandle,int nSock,
    char *pcPIN/*PIN*/,
    char *pcPAN/*PAN*/,
    char *pcPINCipherByHMK/*HMK加密PIN密文 out*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code    "BA" ***/
    *p++ = 'B';
    *p++ = 'A';

    /*** PIN 13H ***/
    memcpy(p, pcPIN, 13);
    p += 13;

    /*** PAN 12N ***/
    memcpy(p, pcPAN, 12);
    p += 12;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, nSock, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if (rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** PIN密文 13H ***/
    strncpy(pcPINCipherByHMK, p, 13);
    *(pcPINCipherByHMK + 13) = '\0';
    return HAR_OK;
}

int HSM_MGT_BE_VerifyPIN(
    void *hSessionHandle,int nSock,
    char cSymmAlg/*算法类型*/,
    int iPIKIdx/*保护密钥索引*/,
    char *pcPIKCipherByHMK/*保护密钥密文*/,
    char *pcPINBlockByPIK/*PIK加密PIN密文*/,
    int iPINFormat/*PIN格式*/,
    char *pcPAN/*PAN*/,
    char *pcPINCipherByHMK/*HMK加密PIN密文*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code    "BE" ***/
    *p++ = 'B';
    *p++ = 'E';

    /*** 算法类型 1A***/
    *p++ = cSymmAlg;

    /*** PIK密钥索引或密文 K+4N/16H/1A+32H/1A+48H ***/
    len = Tools_AddFieldKey(iPIKIdx, pcPIKCipherByHMK, p);
    if (len == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iPIKIdx or pcPIKCipherByHMK is invalid.");
        return HAR_PARAM_LEN;
    }
    p += len;

    /*** PIN块 16/32H ***/
    len = ((cSymmAlg == '3') ? 16 : 32);
    memcpy(p, pcPINBlockByPIK, len);
    p += len;

    /*** PIN格式 2N ***/
    TASS_SPRINTF(p, 3, "%02d", iPINFormat);
    p += strlen(p);

    /*** PAN 12N ***/
    memcpy(p, pcPAN, 12);
    p += 12;

    /*** PIN密文 13H ***/
    memcpy(p, pcPINCipherByHMK, 13);
    p += 13;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, nSock, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if (rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    return HAR_OK;
}

int HSM_MGT_JC_ConvertPINBlockByPIKToHMK(
    void *hSessionHandle,int nSock,
    char cSymmAlg/*算法类型*/,
    int iPIKIdx/*保护密钥索引*/,
    char *pcPIKCipherByHMK/*保护密钥密文*/,
    char *pcPINBlockByPIK/*PIK加密PIN密文*/,
    int iPINFormat/*PIN格式*/,
    char *pcPAN/*PAN*/,
    char *pcPINCipherByHMK/*HMK加密PIN密文 out*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code    "JC" ***/
    *p++ = 'J';
    *p++ = 'C';

    /*** 算法类型 1A***/
    *p++ = cSymmAlg;

    /*** PIK密钥索引或密文 K+4N/16H/1A+32H/1A+48H ***/
    len = Tools_AddFieldKey(iPIKIdx, pcPIKCipherByHMK, p);
    if (len == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iPIKIdx or pcPIKCipherByHMK is invalid.");
        return HAR_PARAM_LEN;
    }
    p += len;

    /*** PIN块 16/32H ***/
    len = ((cSymmAlg == '3') ? 16 : 32);
    memcpy(p, pcPINBlockByPIK, len);
    p += len;

    /*** PIN格式 2N ***/
    TASS_SPRINTF(p, 3, "%02d", iPINFormat);
    p += strlen(p);

    /*** PAN 12N ***/
    memcpy(p, pcPAN, 12);
    p += 12;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, nSock, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if (rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** PIN密文 ***/
    strncpy(pcPINCipherByHMK, p, 13);
    *(pcPINCipherByHMK + 13) = '\0';

    return HAR_OK;
}

/*PIN块从HMK到PIK*/
int HSM_MGT_JG_ConvertPINCipherByHMKToPIK(
    void *hSessionHandle,int nSock,
    char cSymmAlg/*算法类型*/,
    int iPIKIdx/*保护密钥索引*/,
    char *pcPIKCipherByHMK/*保护密钥密文*/,
    int iPINFormat/*PIN格式*/,
    char *pcPAN/*PAN*/,
    char *pcPINCipherByHMK/*HMK加密PIN密文*/,
    char *pcPINBlockByPIK/*PIK加密PIN密文 out*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code    "JG" ***/
    *p++ = 'J';
    *p++ = 'G';

    /*** 算法类型 1A***/
    *p++ = cSymmAlg;

    /*** PIK密钥索引或密文 K+4N/16H/1A+32H/1A+48H ***/
    len = Tools_AddFieldKey(iPIKIdx, pcPIKCipherByHMK, p);
    if (len == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iPIKIdx or pcPIKCipherByHMK is invalid.");
        return HAR_PARAM_LEN;
    }
    p += len;

    /*** PIN格式 2N ***/
    TASS_SPRINTF(p, 3, "%02d", iPINFormat);
    p += strlen(p);

    /*** PAN 12N ***/
    memcpy(p, pcPAN, 12);
    p += 12;

    /*** PIN密文 13H ***/
    memcpy(p, pcPINCipherByHMK, 13);
    p += 13;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, nSock, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if (rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** PIN块 16/32H ***/
    strncpy(pcPINBlockByPIK, p, iRspLen);
    *(pcPINBlockByPIK + iRspLen) = '\0';

    return HAR_OK;
}

int HSM_MGT_CC_ConvertPINBlockByPIK1ToPIK2(
    void *hSessionHandle,int nSock,
    char cSymmAlg1/*算法类型1*/,
    char cSymmAlg2/*算法类型2*/,
    int iPIK1Idx/*PIK1索引*/,
    char *pcPIK1CipherByHMK/*PIK1密文*/,
    int iPIK2Idx/*PIK2索引*/,
    char *pcPIK2CipherByHMK/*PIK2密文*/,
    int iMaxPINLength/*最大PIN长度*/,
    char *pcPINBlockByPIK1/*PIK1加密PIN密文*/,
    int iPINFormat1/*PIN格式1*/,
    int iPINFormat2/*PIN格式2*/,
    char *pcPAN/*PAN*/,
    char *pcPINBlockByPIK2/*PIK2加密PIN密文*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code    "CC" ***/
    *p++ = 'C';
    *p++ = 'C';

    /*** 算法类型1 1A***/
    *p++ = cSymmAlg1;

    /*** 算法类型2 1A***/
    *p++ = cSymmAlg2;

    /*** PIK1密钥索引或密文 K+4N/16H/1A+32H/1A+48H ***/
    len = Tools_AddFieldKey(iPIK1Idx, pcPIK1CipherByHMK, p);
    if (len == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iPIK1Idx or pcPIK1CipherByHMK is invalid.");
        return HAR_PARAM_LEN;
    }
    p += len;

    /*** PIK2密钥索引或密文 K+4N/16H/1A+32H/1A+48H ***/
    len = Tools_AddFieldKey(iPIK2Idx, pcPIK2CipherByHMK, p);
    if (len == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iPIK2Idx or pcPIK2CipherByHMK is invalid.");
        return HAR_PARAM_LEN;
    }
    p += len;

    /*** 最大PIN长度 2N ***/
    TASS_SPRINTF(p, 3, "%02d", iMaxPINLength);
    p += strlen(p);

    /*** PIN块 16/32H ***/
    len = ((cSymmAlg1 == '3') ? 16 : 32);
    memcpy(p, pcPINBlockByPIK1, len);
    p += len;

    /*** PIN格式1 2N ***/
    TASS_SPRINTF(p, 3, "%02d", iPINFormat1);
    p += strlen(p);

    /*** PIN格式2 2N ***/
    TASS_SPRINTF(p, 3, "%02d", iPINFormat2);
    p += strlen(p);

    /*** PAN 12H ***/
    memcpy(p, pcPAN, 12);
    p += 12;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, nSock, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if (rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** PIN块2 16/32H ***/
    len = ((cSymmAlg2 == '3') ? 16 : 32);
    strncpy(pcPINBlockByPIK2, p, len);
    *(pcPINBlockByPIK2 + len) = '\0';

    return HAR_OK;
}

int HSM_MGT_MS_GenerateMAC(
    void *hSessionHandle,int nSock,
    char cDataBlockFlag/*数据块标识*/,
    char cMACAlog/*数据块标识*/,
    char cSymmAlg/*算法类型*/,
    int iMAKIdx/*MAK索引*/,
    char *pcMAKCipherByHMK/*MAK密文*/,
    char *pcIV/*IV*/,
    int iDataLength,/*MAC数据长度*/
    unsigned char *pucData,/*MAC数据*/
    char *pcMAC/*MAC*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code    "MS" ***/
    *p++ = 'M';
    *p++ = 'S';

    /*** 数据块标识 1A ***/
    *p++ = cDataBlockFlag;

    /*** MACAlog 1A ***/
    *p++ = cMACAlog;

    /*** 算法类型 1A***/
    *p++ = cSymmAlg;

    /*** MAK索引或密文 K+4N/16H/1A+32H/1A+48H ***/
    len = Tools_AddFieldKey(iMAKIdx, pcMAKCipherByHMK, p);
    if (len == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iDataKeyIdx or pcDataKeyCipherByHMK is invalid.");
        return HAR_PARAM_LEN;
    }
    p += len;

    /*** IV 16/32H***/
    len = ((cSymmAlg == '3') ? 16 : 32);
    memcpy(p, pcIV, len);
    p += len;

    /*** 数据长度 4N ***/
    TASS_SPRINTF(p, 5, "%04d", iDataLength);
    p += strlen(p);

    /*** 数据 nB***/
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

    /*** MAC 16/32H ***/
    strncpy(pcMAC, p, iRspLen);
    *(pcMAC + iRspLen) = '\0';

    return HAR_OK;
}

int HSM_MGT_MC_VerifyMAC(
    void *hSessionHandle,int nSock,
    char cMACAlog/*数据块标识*/,
    char cSymmAlg/*算法类型*/,
    int iMAKIdx/*MAK索引*/,
    char *pcMAKCipherByHMK/*MAK密文*/,
    char *pcMAC/*MAC*/,
    char *pcIV/*IV*/,
    int iDataLength/*MAC数据长度*/,
    unsigned char *pucData/*MAC数据*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code    "MC" ***/
    *p++ = 'M';
    *p++ = 'C';

    /*** MACAlog 1A ***/
    *p++ = cMACAlog;

    /*** 算法类型 1A***/
    *p++ = cSymmAlg;

    /*** MAK索引或密文 K+4N/16H/1A+32H/1A+48H ***/
    len = Tools_AddFieldKey(iMAKIdx, pcMAKCipherByHMK, p);
    if (len == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iDataKeyIdx or pcDataKeyCipherByHMK is invalid.");
        return HAR_PARAM_LEN;
    }
    p += len;

    /*** MAC 16/32H ***/
    len = ((cSymmAlg == '3') ? 16 : 32);
    memcpy(p, pcMAC, len);
    p += len;

    /*** IV 16/32H ***/
    memcpy(p, pcIV, len);
    p += len;

    /*** 数据长度 4N ***/
    TASS_SPRINTF(p, 5, "%04d", iDataLength);
    p += strlen(p);

    /*** 数据 nB***/
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

int HSM_MGT_CW_GenerateCVV(
    void *hSessionHandle,int nSock,
    char cSymmAlg/*算法类型*/,
    int iCVK_A_BIdx/*CVK_A/B索引*/,
    char *pcCVK_A_BCipherByHMK/*CVK_A/B密文*/,
    char *pcAccountNo/*主账号*/,
    char cSeparator/*分隔符*/,
    char *pcCardValidityDate/*卡有效期*/,
    char *pcCardServiceCode/*卡服务代码*/,
    char *pcCVV/*CVV out*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code    "CW" ***/
    *p++ = 'C';
    *p++ = 'W';

    /*** 算法类型 1A***/
    *p++ = cSymmAlg;

    /*** CVK_A/B索引或密文 K+4N/16H/1A+32H/1A+48H ***/
    len = Tools_AddFieldKey(iCVK_A_BIdx, pcCVK_A_BCipherByHMK, p);
    if (len == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iCVK_A_BIdx or pcCVK_A_BCipherByHMK is invalid.");
        return HAR_PARAM_LEN;
    }
    p += len;

    /*** 主账号 12-19N ***/
    len = strlen(pcAccountNo);
    if ((len < 12) || (len > 19))
    {
        LOG_ERROR("%s", "Parameter: pcAccountNo is invalid.");
        return HAR_PARAM_LEN;
    }
    memcpy(p, pcAccountNo, len);
    p += len;

    /*** Delimiter 16/32H ***/
    *p++ = cSeparator;

    /*** 卡有效期 4N ***/
    memcpy(p, pcCardValidityDate, 4);
    p += 4;

    /*** 卡服务代码 3N ***/
    memcpy(p, pcCardValidityDate, 3);
    p += 3;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, nSock, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if (rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** CVV 16/32H ***/
    strncpy(pcCVV, p, 3);
    *(pcCVV + 3) = '\0';

    return HAR_OK;
}

int HSM_MGT_CY_VerifyCVV(
    void *hSessionHandle,int nSock,
    char cSymmAlg/*算法类型*/,
    int iCVK_A_BIdx/*CVK_A/B索引*/,
    char *pcCVK_A_BCipherByHMK/*CVK_A/B密文*/,
    char *pcCVV/*CVV*/,
    char *pcAccountNo/*主账号*/,
    char cSeparator/*分隔符*/,
    char *pcCardValidityDate/*卡有效期*/,
    char *pcCardServiceCode/*卡服务代码*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code    "CY" ***/
    *p++ = 'C';
    *p++ = 'Y';

    /*** 算法类型 1A***/
    *p++ = cSymmAlg;

    /*** CVK_A/B索引或密文 K+4N/16H/1A+32H/1A+48H ***/
    len = Tools_AddFieldKey(iCVK_A_BIdx, pcCVK_A_BCipherByHMK, p);
    if (len == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iCVK_A_BIdx or pcCVK_A_BCipherByHMK is invalid.");
        return HAR_PARAM_LEN;
    }
    p += len;

    /*** CVV 3N ***/
    memcpy(p, pcCVV, 3);
    p += 3;

    /*** 主账号 12-19N ***/
    len = strlen(pcAccountNo);
    if ((len < 12) || (len > 19))
    {
        LOG_ERROR("%s", "Parameter: pcAccountNo is invalid.");
        return HAR_PARAM_LEN;
    }
    memcpy(p, pcAccountNo, len);
    p += len;

    /*** Delimiter 16/32H ***/
    *p++ = cSeparator;

    /*** 卡有效期 4N ***/
    memcpy(p, pcCardValidityDate, 4);
    p += 4;

    /*** 卡服务代码 3N ***/
    memcpy(p, pcCardValidityDate, 3);
    p += 3;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, nSock, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if (rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    return HAR_OK;
}

int HSM_MGT_PA_DefinePrintFormat(
    void *hSessionHandle,int nSock,
    char *pcFormatData/*打印格式数据*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code    "CY" ***/
    *p++ = 'C';
    *p++ = 'Y';

    /*** 打印格式数据 nA ***/
    len = strlen(pcFormatData);
    memcpy(p, pcFormatData, len);
    p += len;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, nSock, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if (rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    return HAR_OK;
}