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

#ifdef _MSC_VER
#include <windows.h>
#pragma warning(disable:4996)
#endif

#include "hsmapi_define.h"
#include "hsmapi_log.h"
#include "hsmapi_tools.h"
#include "hsmapi_init.h"
#include "hsmapi_extend.h"
#include "hsmsocket.h"

int HSM_EXT_BG_EncryptPIN(
    void *hSessionHandle,int nSock,
    char cSymmAlg/*密钥类型*/,
    int iPIKIdx/*密钥索引*/,
    char *pcPIKCipherByHMK/*密钥密文*/,
    char *pcPIN/*PIN明文*/,
    char *pcPAN/*PAN*/,
    char *pcPINCipher/*PIN密文 out */)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code  "BG" ***/
    *p++ = 'B';
    *p++ = 'G';

    /*** 密钥类型 ***/
    *p++ = cSymmAlg;

    /*** 密钥索引或密文 ***/
    rv = Tools_AddFieldKey(iPIKIdx, pcPIKCipherByHMK, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iKeyIdx or pcPIKCipherByHMK is invlaid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** PIN明文 ***/
    memcpy(p, pcPIN, 13);
    p += 13;

    /*** PAN ***/
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

    /*** Response Buffer ***/
    strncpy(pcPINCipher, p, iRspLen);
    *(pcPINCipher + iRspLen) = '\0';

    return HAR_OK;
}

int HSM_EXT_BC_DecryptPIN(
    void *hSessionHandle,int nSock,
    char cSymmAlg/*密钥类型*/,
    int iPIKIdx/*密钥索引*/,
    char *pcPIKCipherByHMK/*密钥密文*/,
    char *pcPINCipher/*PIN密文*/,
    char *pcPAN/*PAN*/,
    char *pcPIN/*PIN明文 out */)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;
    int len;

    /*** Command Code  "BC" ***/
    *p++ = 'B';
    *p++ = 'C';

    /*** 密钥类型 ***/
    *p++ = cSymmAlg;

    /*** 密钥索引或密文 ***/
    rv = Tools_AddFieldKey(iPIKIdx, pcPIKCipherByHMK, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iKeyIdx or pcPIKCipherByHMK is invlaid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** PIN密文 ***/
    len = cSymmAlg == '3' ? 16 : 32;
    memcpy(p, pcPINCipher, len);
    p += len;

    /*** PAN ***/
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
    /*** Response Buffer ***/
    strncpy(pcPIN, p, iRspLen);
    *(pcPIN + iRspLen) = '\0';

    return HAR_OK;
}

int HSM_EXT_EN_ConvertPINBlockByPIKSrcToPIKDst_DoublePAN(
    void *hSessionHandle,int nSock,
    int iSymmAlgConvertType/*算法转换类型*/,
    int iPIKSrcIdx/*源PIK索引*/,
    char *pcPIKSrcCipherByHMK/*源PIK密文*/,
    int iPIKSrcDiversifyTime/*源PIK分散次数*/,
    char *pcPIKSrcDiversifyData/*源PIK分散数据*/,
    int iPIKDstIdx/*目的PIK索引*/,
    char *pcPIKDstCipherByHMK/*目的PIK密文*/,
    int iPIKDstDiversifyTime/*目的PIK分散次数*/,
    char *pcPIKDstDiversifyData/*目的PIK分散数据*/,
    int iPINFormatSrc/*源PIN格式*/,
    int iPINFormatDst/*目的PIN格式*/,
    char *pcPINCipherByPIKSrc/*源PIK加密的PIN密文*/,
    char *pcPANSrc/*源PAN*/,
    int iDstPANFlag/*目的PAN标识*/,
    char *pcPANDst/*目的PAN*/,
    char *pcPINCipherByPIKDst/*PIK2加密PIN密文 out*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code    "EN" ***/
    *p++ = 'E';
    *p++ = 'N';

    /*** 算法转换类型 1N ***/
    TASS_SPRINTF(p, 2, "%d", iSymmAlgConvertType);
    p += strlen(p);

    /*** 源PIK密钥索引或密文 K+4N/16H/1A+32H/1A+48H ***/
    len = Tools_AddFieldKey(iPIKSrcIdx, pcPIKSrcCipherByHMK, p);
    if (len == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iPIKSrcIdx or pcPIKSrcCipherByHMK is invalid.");
        return HAR_PARAM_LEN;
    }
    p += len;

    /*** 源PIK密钥分散次数 1N ***/
    if ((iPIKSrcDiversifyTime < 0) || (iPIKSrcDiversifyTime > 3))
    {
        LOG_ERROR("%s", "Parameter: iPIKSrcDiversifyTime is invalid.");
        return HAR_PARAM_LEN;
    }
    TASS_SPRINTF(p, 2, "%d", iPIKSrcDiversifyTime);
    p += strlen(p);

    if (iPIKSrcDiversifyTime != 0)
    {
        /*** 源PIK密钥分散数据 n*32H***/
        len = iPIKSrcDiversifyTime * 32;
        memcpy(p, pcPIKSrcDiversifyData, len);
        p += len;
    }

    /*** 目的PIK密钥分散次数 1N ***/
    if ((iPIKDstDiversifyTime < 0) || (iPIKDstDiversifyTime > 3))
    {
        LOG_ERROR("%s", "Parameter: iPIKDstDiversifyTime is invalid.");
        return HAR_PARAM_LEN;
    }
    TASS_SPRINTF(p, 2, "%d", iPIKDstDiversifyTime);
    p += strlen(p);

    if (iPIKDstDiversifyTime != 0)
    {
        /*** 目的PIK密钥分散数据 n*32H***/
        len = iPIKDstDiversifyTime * 32;
        memcpy(p, pcPIKDstDiversifyData, len);
        p += len;
    }

    /*** 源PIN格式 2N ***/
    TASS_SPRINTF(p, 3, "%02d", iPINFormatSrc);
    p += strlen(p);

    /*** 目的PIN格式 2N ***/
    TASS_SPRINTF(p, 3, "%02d", iPINFormatDst);
    p += strlen(p);

    /*** PIN块 16/32H ***/
    len = (((iSymmAlgConvertType == 1) || (iSymmAlgConvertType == 2)) ? 16 : 32);
    memcpy(p, pcPINCipherByPIKSrc, len);
    p += len;

    /*** 源PAN 12N ***/
    if (iPINFormatSrc != 7)
    {
        memcpy(p, pcPANSrc, 12);
        p += 12;
    }

    /*** 目的PAN标识 1N ***/
    TASS_SPRINTF(p, 1, "%d", iDstPANFlag);
    p += strlen(p);

    if (iDstPANFlag == 1)
    {
        /*** 目的PAN 12N ***/
        if (iPINFormatDst != 7)
        {
            len = ((iPINFormatDst == 50) ? 16 : 12);
            memcpy(p, pcPANDst, len);
            p += len;
        }
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

    /*** PIN密文 ***/
    strncpy(pcPINCipherByPIKDst, p, iRspLen);
    *(pcPINCipherByPIKDst + iRspLen) = '\0';

    return HAR_OK;
}

int HSM_EXT_DE_CalculatePINOffsetWithIBM3642Alg(
    void *hSessionHandle,int nSock,
    int iPVKIdx/*源PIK索引*/,
    char *pcPVKCipherByHMK/*源PIK密文*/,
    char cFlag/*标识位*/,
    int iPINLength/*PIN明文长度*/,
    char *pcPIN/*PIN明文*/,
    int iCheckLength/*检查长度*/,
    char *pcAccountNo/*账号*/,
    char *pcDecConvertTable/*十进制转换表*/,
    char *pcPINVerifyData/*PIN校验数据*/,
    char cTerminationMsgSeparator/*终止信息分隔符*/,
    char *pcPINOffset/*PINOffset out*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code    "DE" ***/
    *p++ = 'D';
    *p++ = 'E';

    /*** PVK索引或密文 K+4N/16H/1A+32H/1A+48H ***/
    len = Tools_AddFieldKey(iPVKIdx, pcPVKCipherByHMK, p);
    if (len == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iPVKIdx or pcPVKCipherByHMK is invalid.");
        return HAR_PARAM_LEN;
    }
    p += len;

    /*** 标识位 1A ***/
    *p++ = cFlag;

    /*** PIN明文长度 2N ***/
    TASS_SPRINTF(p, 3, "%02d", iPINLength);
    p += strlen(p);

    /*** PIN明文 nN ***/
    memcpy(p, pcPIN, iPINLength);
    p += iPINLength;

    /*** 检查长度 2N ***/
    TASS_SPRINTF(p, 3, "%02d", iCheckLength);
    p += strlen(p);

    /*** 账号 16N ***/
    memcpy(p, pcAccountNo, 16);
    p += 16;

    /*** 十进制转换表 16N ***/
    memcpy(p, pcDecConvertTable, 16);
    p += 16;

    /*** PIN校验数据 12A ***/
    memcpy(p, pcDecConvertTable, 12);
    p += 12;

    /*** 信息终止分隔符 1C ***/
    if (cTerminationMsgSeparator != '\0')
        *p++ = cTerminationMsgSeparator;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, nSock, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if (rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** PINOffset ***/
    strncpy(pcPINOffset, p, 12);
    *(pcPINOffset + 12) = '\0';

    return HAR_OK;
}

int HSM_EXT_DG_CalculatePVV(
    void *hSessionHandle,int nSock,
    int iPVK1Idx/*PIK1索引*/,
    char *pcPVK1CipherByHMK/*PVK1密文*/,
    int iPVK2Idx/*PVK2索引*/,
    char *pcPVK2CipherByHMK/*PVK2密文*/,
    char cFlag/*标识位*/,
    int iPINLength/*PIN明文长度*/,
    char *pcPIN/*PIN明文*/,
    char *pcAccountNo/*账号*/,
    int iPVKI/*PVKI*/,
    char cTerminationMsgSeparator/*终止信息分隔符*/,
    char *pcPVV/*PVV out*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code    "DG" ***/
    *p++ = 'D';
    *p++ = 'G';

    /*** PVK1索引或密文 K+4N/16H/1A+32H/1A+48H ***/
    len = Tools_AddFieldKey(iPVK1Idx, pcPVK1CipherByHMK, p);
    if (len == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iPVK1Idx or pcPVK1CipherByHMK is invalid.");
        return HAR_PARAM_LEN;
    }
    p += len;

    /*** PVK2索引或密文 K+4N/16H/1A+32H/1A+48H ***/
    len = Tools_AddFieldKey(iPVK2Idx, pcPVK2CipherByHMK, p);
    if (len == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iPVK2Idx or pcPVK2CipherByHMK is invalid.");
        return HAR_PARAM_LEN;
    }
    p += len;

    /*** 标识位 1A ***/
    *p++ = cFlag;

    /*** PIN明文长度 2N ***/
    TASS_SPRINTF(p, 3, "%02d", iPINLength);
    p += strlen(p);

    /*** PIN明文 nN ***/
    memcpy(p, pcPIN, iPINLength);
    p += iPINLength;

    /*** 账号 12N ***/
    memcpy(p, pcAccountNo, 12);
    p += 16;

    /*** PVKI 1H ***/
    TASS_SPRINTF(p, 2, "%X", iPVKI);
    p += strlen(p);

    /*** 信息终止分隔符 1C ***/
    if (cTerminationMsgSeparator != '\0')
        *p++ = cTerminationMsgSeparator;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, nSock, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if (rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** PINOffset ***/
    strncpy(pcPVV, p, 4);
    *(pcPVV + 4) = '\0';

    return HAR_OK;
}

int HSM_EXT_KE_Cover_RecoverData(
    void *hSessionHandle,int nSock,
    int iMode/*模式*/,
    int iStrInLength/*输入字符串长度*/,
    char *pcStrIn/*输入字符串*/,
    int *piStrOutLength/*输出字符串长度*/,
    char *pcStrOut/*输出字符串*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code    "KE" ***/
    *p++ = 'K';
    *p++ = 'E';

    /*** 模式 1H ***/
    TASS_SPRINTF(p, 2, "%X", iMode);
    p += strlen(p);

    /*** 字符串长度 4N ***/
    TASS_SPRINTF(p, 5, "%04d", iStrInLength);
    p += strlen(p);

    /*** 字符串 nA ***/
    memcpy(p, pcStrIn, iStrInLength);
    p += iStrInLength;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, nSock, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if (rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** 输出字符串长度 4N ***/
    *piStrOutLength = Tools_GetFieldKeyLength(p);
    p += 4;

    /*** 输出字符串 nA ***/
    strncpy(pcStrOut, p, *piStrOutLength);
    *(pcStrOut + *piStrOutLength) = '\0';

    return HAR_OK;
}

int HSM_EXT_ED_BignumExponentModuleOperation(
    void *hSessionHandle,int nSock,
    int iBaseLength/*底数长度*/,
    unsigned char *pucBase/*底数*/,
    int iExpLength/*指数长度*/,
    unsigned char *pucExp/*指数*/,
    int iModLength/*模数长度*/,
    unsigned char *pucMod/*模数*/,
    int *piResultLength/*结果长度 out*/,
    unsigned char *pucResult/*结果 out*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code    "ED" ***/
    *p++ = 'E';
    *p++ = 'D';

    /*** 底数长度 4N ***/
    TASS_SPRINTF(p, 5, "%04d", iBaseLength);
    p += strlen(p);

    /*** 底数 nA ***/
    memcpy(p, pucBase, iBaseLength);
    p += iBaseLength;

    /*** 指数长度 4N ***/
    TASS_SPRINTF(p, 5, "%04d", iExpLength);
    p += strlen(p);

    /*** 指数 nA ***/
    memcpy(p, pucExp, iExpLength);
    p += iExpLength;

    /*** 模数长度 4N ***/
    TASS_SPRINTF(p, 5, "%04d", iModLength);
    p += strlen(p);

    /*** 模数 nA ***/
    memcpy(p, pucMod, iModLength);
    p += iModLength;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, nSock, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if (rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** 输出字符串长度 4N ***/
    *piResultLength = Tools_GetFieldKeyLength(p);
    p += 4;

    /*** 结果 nB ***/
    memcpy(pucResult, p, *piResultLength);

    return HAR_OK;
}

int HSM_EXT_EF_GenerateBigPrimeNum(
    void *hSessionHandle,int nSock,
    int iPrimeNumLengthIn/*输入大素数长度*/,
    int *piPrimeNumLengthOut/*输出大素数长度 out*/,
    unsigned char *pucPrimeNum/*结果 out*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code    "EF" ***/
    *p++ = 'E';
    *p++ = 'F';

    /*** 输入大素数长度 4N ***/
    TASS_SPRINTF(p, 5, "%04d", iPrimeNumLengthIn);
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

    /*** 输出大素数长度 4N ***/
    *piPrimeNumLengthOut = Tools_GetFieldKeyLength(p);
    p += 4;

    /*** 大素数 nB ***/
    memcpy(pucPrimeNum, p, *piPrimeNumLengthOut);

    return HAR_OK;
}

int HSM_EXT_TE_GenerateRandom(
    void *hSessionHandle,int nSock,
    int iRandomLength/*随机数长度*/,
    unsigned char *pucRandom/*随机数 out*/)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 2048;
    unsigned char aucCmd[2048] = { 0 };
    unsigned char aucRsp[2048] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code  "TE" ***/
    *p++ = 'T';
    *p++ = 'E';

    /*** 随机数长度 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iRandomLength);
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

    /*** 随机数 nB ***/
    memcpy(pucRandom, p, iRspLen);

    return HAR_OK;
}

/*密机检查*/
int HSM_EXT_NC_CheckHSM(
    void *hSessionHandle,int nSock,
    char *pcHMKCV/*HMK校验值 out*/,
    char *pcVersion/*版本号 out*/)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 2048;
    unsigned char aucCmd[2048] = { 0 };
    unsigned char aucRsp[2048] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code  "NC" ***/
    *p++ = 'N';
    *p++ = 'C';

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, nSock, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if (rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }
    /*** Response Buffer ***/
    p = aucRsp;

    /*** HMK校验值 16H ***/
    strncpy(pcHMKCV, p, 16);
    p += 16;

    /*** 版本号 14A ***/
    strncpy(pcVersion, p, 14);
    p += 14;

    return HAR_OK;
}

int HSM_EXT_KG_ConvertKeyCipher_Enhance(
    void *hSessionHandle,int nSock,
    char cMode/*模式*/,
    int iAlg/*算法*/,
    int iKeyHeadLength/*密钥头长度*/,
    char *pcKeyHead/*密钥头*/,
    char *pcIV/*IV*/,
    int iKEKIdx/*保护密钥索引*/,
    char *pcKEKCipherByHMK/*HMK加密的保护密钥密文*/,
    int iKeyIdx/*待加密密钥索引*/,
    char *pcKeyCipherByHMK/*HMK加密的待加密密钥密文*/,
    int *piKeyCipherByKEKLength/*KEK加密的密钥密文长度 out*/,
    unsigned char *pucKeyCipherByKEK/*KEK加密的密钥密文 out*/)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;
    int len;

    /*** Command Code    "KG" ***/
    *p++ = 'K';
    *p++ = 'G';

    /*** 模式 1A ***/
    *p++ = cMode;

    /*** 算法 2N ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iAlg);
    p += strlen(p);

    /*** 密钥头长度 2N ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iKeyHeadLength);
    p += strlen(p);

    /*** 密钥头 nH ***/
    memcpy(p, pcKeyHead, iKeyHeadLength);
    p += iKeyHeadLength;

    if (iAlg == 2)
    {
        /*** IV nH ***/
        memcpy(p, pcIV, 16);
        p += 16;
    }

    /*** KEK密钥索引或密文 K+4N/16H/1A+32H/1A+48H ***/
    len = Tools_AddFieldKey(iKEKIdx, pcKEKCipherByHMK, p);
    if (len == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iKEKIdx or pcKEKCipherByHMK is invalid.");
        return HAR_PARAM_LEN;
    }
    p += len;

    /*** 待转加密密钥索引或密文 K+4N/16H/1A+32H/1A+48H ***/
    len = Tools_AddFieldKey(iKeyIdx, pcKeyCipherByHMK, p);
    if (len == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iKeyIdx or pcKeyCipherByHMK is invalid.");
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

    /*** KEK加密的密钥密文长度 4N ***/
    *piKeyCipherByKEKLength = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;

    /*** KEK加密的密钥密文 nH ***/
    memcpy(pucKeyCipherByKEK, p, (*piKeyCipherByKEKLength) * 2);

    return HAR_OK;
}

/*密钥转加密扩展型*/
int HSM_EXT_KH_ConvertKeyCipher_Extend(
    void *hSessionHandle,int nSock,
    int iAlg/*算法*/,
    int iKEKIdx/*保护密钥索引*/,
    char *pcKEKCipherByHMK/*HMK加密的保护密钥密文*/,
    int iKey1Length/*密钥1明文长度*/,
    unsigned char *pucKey1/*密钥1明文*/,
    int iKey2Length/*密钥2明文长度*/,
    unsigned char *pucKey2/*密钥2明文*/,
    int iKey3Length/*密钥3明文长度*/,
    unsigned char *pucKey3/*密钥3明文*/,
    int iKeyPrefixLength/*密钥前缀长度*/,
    unsigned char *pucKeyPrefix/*密钥前缀*/,
    char *pcIV/*IV*/,
    int *piKeyCipherByKEKLength/*KEK加密的密钥密文长度 out*/,
    unsigned char *pucKeyCipherByKEK/*KEK加密的密钥密文 out*/)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;
    int len;

    /*** Command Code    "KH" ***/
    *p++ = 'K';
    *p++ = 'H';

    /*** 算法 2N ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iAlg);
    p += strlen(p);

    /*** KEK密钥索引或密文 K+4N/16H/1A+32H/1A+48H ***/
    len = Tools_AddFieldKey(iKEKIdx, pcKEKCipherByHMK, p);
    if (len == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iKEKIdx or pcKEKCipherByHMK is invalid.");
        return HAR_PARAM_LEN;
    }
    p += len;

    /*** 密钥1长度 2N ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iKey1Length);
    p += strlen(p);

    /*** 密钥1 nB ***/
    memcpy(p, pucKey1, iKey1Length);
    p += iKey1Length;

    /*** 密钥2长度 2N ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iKey2Length);
    p += strlen(p);

    /*** 密钥2 nB ***/
    memcpy(p, pucKey2, iKey2Length);
    p += iKey2Length;

    /*** 密钥3长度 2N ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iKey3Length);
    p += strlen(p);

    /*** 密钥3 nB ***/
    memcpy(p, pucKey3, iKey3Length);
    p += iKey3Length;

    /*** 密钥前缀长度 2N ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iKeyPrefixLength);
    p += strlen(p);

    /*** 密钥前缀 nB ***/
    memcpy(p, pucKeyPrefix, iKeyPrefixLength);
    p += iKeyPrefixLength;

    if (iAlg == 2)
    {
        /*** IV nH ***/
        memcpy(p, pcIV, 16);
        p += 16;
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

    /*** KEK加密的密钥密文长度 4N ***/
    *piKeyCipherByKEKLength = Tools_ConvertDecBuf2Int(p, 2);
    p += 2;

    /*** KEK加密的密钥密文 nH ***/
    memcpy(pucKeyCipherByKEK, p, *piKeyCipherByKEKLength);

    return HAR_OK;
}

int HSM_EXT_UX_EncryptKeyWithHMK_Extend(
    void *hSessionHandle,int nSock,
    int iAlg/*算法*/,
    int iMode/*模式*/,
    int iKey1Length/*密钥1明文长度*/,
    unsigned char *pucKey1/*密钥1明文*/,
    int iKey2Length/*密钥2明文长度*/,
    unsigned char *pucKey2/*密钥2明文*/,
    int iKey3Length/*密钥3明文长度*/,
    unsigned char *pucKey3/*密钥3明文*/,
    char *pcIV/*IV*/,
    int *piKeyCipherByHMKLength/*HMK加密密钥密文长度 out*/,
    unsigned char *pucKeyCipherByHMK/*HMK加密密钥密文 out*/)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code    "UX" ***/
    *p++ = 'U';
    *p++ = 'X';

    /*** 算法 2N ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iAlg);
    p += strlen(p);

    /*** 模式 2N ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iMode);
    p += strlen(p);

    /*** 密钥1长度 2N ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iKey1Length);
    p += strlen(p);

    /*** 密钥1 nB ***/
    memcpy(p, pucKey1, iKey1Length);
    p += iKey1Length;

    if (iMode == 2)
    {
        /*** 密钥2长度 2N ***/
        TASS_SPRINTF((char*)p, 3, "%02d", iKey2Length);
        p += strlen(p);

        /*** 密钥2 nB ***/
        memcpy(p, pucKey2, iKey2Length);
        p += iKey2Length;

        /*** 密钥3长度 2N ***/
        TASS_SPRINTF((char*)p, 3, "%02d", iKey3Length);
        p += strlen(p);

        /*** 密钥3 nB ***/
        memcpy(p, pucKey3, iKey3Length);
        p += iKey3Length;
    }

    if (iAlg == 2)
    {
        /*** IV nH ***/
        memcpy(p, pcIV, 16);
        p += 16;
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

    /*** KEK加密的密钥密文长度 4N ***/
    *piKeyCipherByHMKLength = Tools_ConvertDecBuf2Int(p, 2);
    p += 2;

    /*** KEK加密的密钥密文 nB ***/
    memcpy(pucKeyCipherByHMK, p, *piKeyCipherByHMKLength);

    return HAR_OK;
}

int HSM_EXT_EO_DiversifyAndExportKey(
    void *hSessionHandle,int nSock,
    int iMode/*模式*/,
    int iDiversifySymmAlg/*分散算法*/,
    int iAlgMode/*算法模式*/,
    int iKeySrcIdx/*主控密钥索引*/,
    char *pcKeySrcCipherByHMK/*主控密钥密文*/,
    int iDiversifyMode/*分散模式*/,
    int iDiversifyTime/*分散次数*/,
    int iDiversifyDataLength/*分散因子长度*/,
    char *pcDiversifyData/*分散因子*/,
    int iExportSymmAlg/*导出算法*/,
    int iKEKIdx/*保护密钥索引*/,
    char *pcKEKCipherByHMK/*保护密钥密文*/,
    int iKEKDiversifyTime/*保护密钥分散次数*/,
    char *pcKEKDiversifyData/*保护密钥分散因子*/,
    char *pcIV/*IV_CBC*/,
    int *piKeyCipherByHMKLength/*HMK加密的密钥密文长度 out*/,
    unsigned char *pucKeyCipherByHMK/*HMK加密的密钥密文 out*/,
    int *piKeyCipherByKEKLength/*KEK加密的密钥密文长度 out*/,
    unsigned char *pucKeyCipherByKEK/*KEK加密的密钥密文 out*/,
    char *pcKCV/*密钥校验值 out*/)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;
    int len;

    /*** Command Code    "EO" ***/
    *p++ = 'E';
    *p++ = 'O';

    /*** 模式 2N ***/
    TASS_SPRINTF((char*)p, 2, "%d", iMode);
    p += strlen(p);

    /*** 分散算法 2N ***/
    TASS_SPRINTF((char*)p, 2, "%d", iDiversifySymmAlg);
    p += strlen(p);

    /*** 算法模式 2N ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iAlgMode);
    p += strlen(p);

    /*** 源密钥索引或密文 K+4N/16H/1A+32H/1A+48H ***/
    len = Tools_AddFieldKey(iKeySrcIdx, pcKeySrcCipherByHMK, p);
    if (len == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iKeySrcIdx or pcKeySrcCipherByHMK is invalid.");
        return HAR_PARAM_LEN;
    }
    p += len;

    /*** 分散模式 1N ***/
    TASS_SPRINTF((char*)p, 2, "%d", iDiversifyMode);
    p += strlen(p);

    if (iDiversifyMode == 1)
    {
        /*** 分散次数 1N ***/
        if ((iDiversifyTime < 0) || (iDiversifyTime > 2))
        {
            LOG_ERROR("%s", "Parameter: iDiversifyTime is invalid.");
            return HAR_PARAM_LEN;
        }
        TASS_SPRINTF((char*)p, 2, "%d", iDiversifyTime);
        p += strlen(p);
        len = iDiversifyTime * 32;
    }
    else
    {
        /*** 分散因子长度 4N ***/
        TASS_SPRINTF((char*)p, 5, "%4d", iDiversifyDataLength);
        p += strlen(p);
        len = iDiversifyDataLength;
    }
    /*** 分散数据 nH ***/
    memcpy(p, pcDiversifyData, len);
    p += len;

    if ((iMode == 2) || (iMode == 3))
    {
        /*** KEK算法 2N ***/
        TASS_SPRINTF((char*)p, 2, "%d", iExportSymmAlg);
        p += strlen(p);

        /*** KEK索引或密文 K+4N/16H/1A+32H/1A+48H ***/
        len = Tools_AddFieldKey(iKEKIdx, pcKEKCipherByHMK, p);
        if (len == HAR_PARAM_VALUE)
        {
            LOG_ERROR("%s", "Parameter: iKEKIdx or pcKEKCipherByHMK is invalid.");
            return HAR_PARAM_LEN;
        }
        p += len;

        /*** KEK分散次数 1N ***/
        if ((iKEKDiversifyTime < 0) || (iKEKDiversifyTime > 2))
        {
            LOG_ERROR("%s", "Parameter: iKEKDiversifyTime is invalid.");
            return HAR_PARAM_LEN;
        }
        TASS_SPRINTF((char*)p, 2, "%d", iKEKDiversifyTime);
        p += strlen(p);

        /*** KEK分散数据 n*32H ***/
        memcpy(p, pcKEKDiversifyData, iKEKDiversifyTime * 3);
        p += len;
    }

    /*** IV_CBC 32/16H ***/
    if ((iAlgMode == 2) && (iDiversifyTime != 0))
    {
        len = ((iDiversifySymmAlg == 3) ? 16 : 32);
        memcpy(p, pcIV, len);
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

    /*** HMK加密的密钥密文长度 4N ***/
    *piKeyCipherByHMKLength = Tools_ConvertDecBuf2Int(p, 2);
    p += 2;

    /*** HMK加密的密钥密文 nB ***/
    memcpy(pucKeyCipherByHMK, p, *piKeyCipherByHMKLength);
    p += *piKeyCipherByHMKLength;

    if ((iMode == 2) || (iMode == 3))
    {
        /*** KEK加密的密钥密文长度 4N ***/
        *piKeyCipherByHMKLength = Tools_ConvertDecBuf2Int(p, 2);
        p += 2;

        /*** KEK加密的密钥密文 nB ***/
        memcpy(pucKeyCipherByHMK, p, *piKeyCipherByHMKLength);
        p += *piKeyCipherByKEKLength;
    }

    /*** 密钥校验值 16H ***/
    strncpy(pcKCV, p, 16);

    return HAR_OK;
}

int HSM_EXT_UE_ConvertKeyCipherBetweenHMKAndRSA(
    void *hSessionHandle,int nSock,
    int iAlgConvertType/*算法转换类型*/,
    int iPadMode/*填充模式*/,
    int iMGF/*MGF*/,
    int iMGFHashAlg/*MGF哈希算发*/,
    int iOAEPCodeParamLength/*OAEP编码参数长度*/,
    unsigned char *pucOAEPCodeParam/*OAEP编码参数*/,
    int iKeyCipherInLength/*密钥密文长度*/,
    unsigned char *pucKeyCipherIn/*密钥密文*/,
    int iRSAIdx/*RSA密钥索引号*/,
    char *pcKeyPassword/*RSA密钥口令*/,
    int iPubKeyCodeFormat/*公钥编码格式*/,
    int iPubKeyLength/*公钥长度*/,
    unsigned char *pucPubKey/*公钥*/,
    int iPriKeyCipherLength/*私钥密文长度*/,
    unsigned char *pucPriKeyCipher/*私钥密文*/,
    int *piKeycCipherOutLength/*密文长度 out*/,
    unsigned char *pucKeyCipherOut/*密文 out*/)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;

    int iKEKFlag = 0;

    /*** Command Code  "UE" ***/
    *p++ = 'U';
    *p++ = 'E';

    /*** 算法转换类型 2N ***/
    TASS_SPRINTF(p, 3, "%02d", iAlgConvertType);
    p += strlen(p);

    /*** 填充模式 2N ***/
    TASS_SPRINTF(p, 3, "%02d", iPadMode);
    p += strlen(p);

    if (iPadMode == 2)
    {
        /*** MGF 2N ***/
        TASS_SPRINTF(p, 3, "%02d", iMGF);
        p += strlen(p);

        /*** MGF哈希算法 2N ***/
        TASS_SPRINTF(p, 3, "%02d", iMGFHashAlg);
        p += strlen(p);

        /*** OAEP编码参数长度 2N ***/
        TASS_SPRINTF(p, 3, "%02d", iOAEPCodeParamLength);
        p += strlen(p);

        /*** OAEP编码参数 nB ***/
        memcpy(p, pucOAEPCodeParam, iOAEPCodeParamLength);
        p += iOAEPCodeParamLength;
    }

    /*** 被加密密钥长度 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iKeyCipherInLength);
    p += strlen(p);

    /*** 被加密密钥 nB ***/
    memcpy(p, pucKeyCipherIn, iKeyCipherInLength);
    p += iKeyCipherInLength;

    /*** 密钥索引号 2N ***/
    TASS_SPRINTF(p, 3, "%02d", iRSAIdx);
    p += strlen(p);

    if ((iAlgConvertType == 02) && (iRSAIdx != 00))
    {
        /*** 密钥口令 8A ***/
        memcpy(p, pcKeyPassword, 8);
        p += strlen(p);
    }
    if (iRSAIdx == 00)
    {
        if (iAlgConvertType == 01)
        {
            /*** 公钥编码格式 1N ***/
            TASS_SPRINTF(p, 2, "%d", iPubKeyCodeFormat);
            p += strlen(p);

            /*** 公钥长度 4N ***/
            TASS_SPRINTF(p, 5, "%4d", iPubKeyLength);
            p += strlen(p);

            /*** 公钥 nB ***/
            memcpy(p, pucPubKey, iPubKeyLength);
            p += iPubKeyLength;
        }
        else if (iAlgConvertType == 02)
        {
            /*** 私钥密文长度 4N ***/
            TASS_SPRINTF(p, 5, "%4d", iPriKeyCipherLength);
            p += strlen(p);

            /*** 私钥密文 nB ***/
            memcpy(p, pucPriKeyCipher, iPriKeyCipherLength);
            p += iPriKeyCipherLength;
        }
        else
        {
            LOG_ERROR("Parameter: iAlgConvertType = [%d] is invalid, it must be 1 or 2.",
                iAlgConvertType);
            return HAR_PARAM_VALUE;
        }
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

    /*** 密文长度 4N ***/
    *piKeycCipherOutLength = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;

    /*** 密文 nB ***/
    memcpy(pucKeyCipherOut, p, *piKeycCipherOutLength);

    return HAR_OK;
}

int HSM_EXT_UC_SM2ConvertKeyCipher(
    void *hSessionHandle,int nSock,
    int iAlgConvertType/*算法转换类型*/,
    int iSrcKeyCipherLength/*被加密密钥长度*/,
    unsigned char *pucSrcKeyCipher/*被加密密钥*/,
    int iSM2Idx/*SM2密钥索引*/,
    char *pcKeyPassword/*密钥口令*/,
    unsigned char *pucPubKeyXY/*公钥*/,
    unsigned char *pucPriKeyCipherByHMK/*私钥密文*/,
    int *piDstKeyCipherLength/*密文长度 out*/,
    unsigned char *pucDstKeyCipher/*密文 out*/)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;

    int iKEKFlag = 0;

    /*** Command Code  "UC" ***/
    *p++ = 'U';
    *p++ = 'C';

    /*** 算法转换类型 2N ***/
    TASS_SPRINTF(p, 3, "%02d", iAlgConvertType);
    p += strlen(p);

    /*** 被加密密钥长度 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iSrcKeyCipherLength);
    p += strlen(p);

    /*** 被加密密钥 nB ***/
    memcpy(p, pucSrcKeyCipher, iSrcKeyCipherLength);
    p += iSrcKeyCipherLength;

    /*** 密钥索引 2N ***/
    TASS_SPRINTF(p, 3, "%02d", iSM2Idx);
    p += strlen(p);

    if ((iAlgConvertType == 02) && (iSM2Idx != 00))
    {
        /*** 密钥口令 8A ***/
        memcpy(p, pcKeyPassword, 8);
        p += strlen(p);
    }
    if (iSM2Idx == 00)
    {
        if (iAlgConvertType == 01)
        {
            /*** 公钥 ***/
            memcpy(p, pucPubKeyXY, 64);
            p += 64;
        }
        else if (iAlgConvertType == 02)
        {
            /*** 私钥密文 ***/
            memcpy(p, pucPriKeyCipherByHMK, 40);
            p += 40;
        }
        else
        {
            LOG_ERROR("Parameter: iAlgConvertType = [%d] is invalid, it must be 1 or 2.",
                iAlgConvertType);
            return HAR_PARAM_VALUE;
        }
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

    /*** 密文长度 4N ***/
    *piDstKeyCipherLength = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;

    /*** 密文 nB ***/
    memcpy(pucDstKeyCipher, p, *piDstKeyCipherLength);

    return HAR_OK;
}

int HSM_EXT_EG_DiversifyCardKey(
    void *hSessionHandle,int nSock,
    int iDiversifyMode/*分散模式*/,
    char cSymmAlg/*算法类型*/,
    char cICCardType/*IC卡类型*/,
    int iKEKIdx/*保护密钥索引*/,
    char *pcKEKCipherByHMK/*保护密钥密文*/,
    int iCardKeyIdx/*卡密钥索引*/,
    char *pcCardKeyCipherByHMK/*卡密钥密文*/,
    char *pcCardKeyDiversifyData/*卡片密钥分散因子*/,
    char *pcSessionKeyDiversifyData/*会话密钥分散因子*/,
    int *piKeyCipherByKEKLength/*保护密钥加密的密钥密文长度 out*/,
    unsigned char *pucKeyCipherByKEK/*保护密钥加密的密钥密文 out*/,
    char *pcKCV/*密钥校验值 out*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code    "EG" ***/
    *p++ = 'E';
    *p++ = 'G';

    /*** 分散模式 1N ***/
    TASS_SPRINTF((char*)p, 5, "%02d", iDiversifyMode);
    p += strlen(p);

    /*** 算法类型 1A ***/
    *p++ = cSymmAlg;

    /*** IC卡类型 1A ***/
    *p++ = cICCardType;

    /*** 保护密钥索引或密文 K+4N/16H/1A+32H/1A+48H ***/
    len = Tools_AddFieldKey(iKEKIdx, pcKEKCipherByHMK, p);
    if (len == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iKEKIdx or pcKEKCipherByHMK is invalid.");
        return HAR_PARAM_LEN;
    }
    p += len;

    /*** 卡密钥索引或密文 K+4N/16H/1A+32H/1A+48H ***/
    len = Tools_AddFieldKey(iCardKeyIdx, pcCardKeyCipherByHMK, p);
    if (len == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iKEKIdx or pcKEKCipherByHMK is invalid.");
        return HAR_PARAM_LEN;
    }
    p += len;

    /*** 卡片密钥分散因子 16/32B ***/
    len = ((cICCardType == '2') && (cSymmAlg == '3')) ? 8 : 16;
    memcpy(p, pcCardKeyDiversifyData, len);
    p += len;

    if ((iDiversifyMode != 1) && (cICCardType != '0'))
    {
        /*** 会话密钥分散因子 4/32H ***/
        len = ((cICCardType == '2') && (cSymmAlg == '3')) ? 2 : 16;
        memcpy(p, pcSessionKeyDiversifyData, len);
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

    /*** 子密钥或会话密钥 16B ***/
    memcpy(pucKeyCipherByKEK, (char *)p, 16);
    p += 16;

    /*** 子密钥或会话密钥 8H ***/
    memcpy(pcKCV, (char *)p, 8);

    return HAR_OK;
}

int HSM_EXT_EB_GenerateSM2PubKeyByPriKey(
    void *hSessionHandle,int nSock,
    unsigned char *pucPriKeyCipher/*私钥密文*/,
    int *piPubKeyLength/*公钥长度 out*/,
    unsigned char *pucPubKey/*公钥 out*/)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code  "EB" ***/
    *p++ = 'E';
    *p++ = 'B';
    /*** 私钥密文 40B ***/
    memcpy(p, pucPriKeyCipher, 40);
    p += 40;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, nSock, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if (rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }
    /*** Response Buffer ***/
    p = aucRsp;

    /*** 公钥长度 4N ***/
    *piPubKeyLength = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;

    /*** 公钥 nB ***/
    memcpy(pucPubKey, p, *piPubKeyLength);

    return HAR_OK;
}

int HSM_EXT_UD_DecryptSymmKeyCipherWithPriKeyAndPrint(
    void *hSessionHandle,int nSock,
    char cKeyScheme/*密钥方案*/,
    int iAsymmAlg/*非对称算法*/,
    int iPadMode/*填充模式*/,
    int iSymmKeyCipherByPubKeyLength/*公钥加密的对称密钥密文长度*/,
    unsigned char *pucSymmKeyCipherByPubKey/*公钥加密的对称密钥密文*/,
    char cSeperator/*分隔符*/,
    int iPriKeyIdx/*私钥索引*/,
    int iPriKeyCipherLength/*私钥密文长度*/,
    unsigned char *pucPriKeyCipher/*私钥密文*/,
    char *pcPrintInfo/*打印信息*/,
    char *pcSymmKeyCipherByHMK/*HMK加密的对称密钥密文 out*/,
    char *pcSymmKCV/*对称密钥校验值 out*/)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;
    int len;

    /*** Command Code  "UD" ***/
    *p++ = 'U';
    *p++ = 'D';

    /*** 密钥方案 1A ***/
    *p++ = cKeyScheme;

    /*** 非对称算法 2N ***/
    TASS_SPRINTF(p, 3, "%02d", iAsymmAlg);
    p += strlen(p);

    /*** 填充模式 2N ***/
    TASS_SPRINTF(p, 3, "%02d", iPadMode);
    p += strlen(p);

    /*** 公钥加密密钥长度 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iSymmKeyCipherByPubKeyLength);
    p += strlen(p);

    /*** 公钥加密密钥 nB ***/
    memcpy(p, pucSymmKeyCipherByPubKey, iSymmKeyCipherByPubKeyLength);
    p += iSymmKeyCipherByPubKeyLength;

    /*** 分隔符 1A ***/
    *p++ = cSeperator;

    /*** 私钥索引号 2N ***/
    TASS_SPRINTF(p, 3, "%02d", iPriKeyIdx);
    p += strlen(p);

    if (iPriKeyIdx == 00)
    {
        /*** 私钥密文长度 4N ***/
        TASS_SPRINTF(p, 5, "%4d", iPriKeyCipherLength);
        p += strlen(p);

        /*** 私钥密文 nB ***/
        memcpy(p, pucPriKeyCipher, iPriKeyCipherLength);
        p += iPriKeyCipherLength;
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

    /*** HMK加密的对称密钥密文 16H/1A+32H/1A+48H ***/
    len = Tools_GetFieldKeyLength(p);
    strncpy(pcSymmKeyCipherByHMK, p, len);
    *(pcSymmKeyCipherByHMK + len) = '\0';
    p += len;

    /*** KCV 16H ***/
    strncpy(pcSymmKCV, p, 16);
    *(pcSymmKCV + 16) = '\0';

    return HAR_OK;
}

int HSM_EXT_EJ_ExportRSAPubKey(
    void *hSessionHandle,int nSock,
    int iKeyType/*密钥类型*/,
    int iPubKeyCode/*公钥编码*/,
    int iKeyIdx/*密钥索引*/,
    char *pcKeyPassword/*密钥口令*/,
    unsigned char *pucPubKey/*公钥 out*/)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code  "EJ" ***/
    *p++ = 'E';
    *p++ = 'J';

    /*** 密钥类型 1N ***/
    TASS_SPRINTF((char*)p, 2, "%d", iKeyType);
    p += strlen(p);

    /*** 公钥编码 2N ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iPubKeyCode);
    p += strlen(p);

    /*** 密钥索引 2N ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iKeyIdx);
    p += strlen(p);

    /*** 密钥口令 8A ***/
    memcpy(p, pcKeyPassword, 8);
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
    
    /*** 公钥, n Byte ***/
    memcpy(pucPubKey, p, iRspLen);
    
    return HAR_OK;
}

int HSM_EXT_SJ_ExportSM2PubKey(
    void *hSessionHandle,int nSock,
    int iKeyType/*密钥类型*/,
    int iPubKeyCode/*公钥编码*/,
    int iKeyIdx/*密钥索引*/,
    char *pcKeyPassword/*密钥口令*/,
    unsigned char *pucPubKey/*公钥 out*/)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 512;
    unsigned char aucCmd[512] = { 0 };
    unsigned char aucRsp[512] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code  "SJ" ***/
    *p++ = 'S';
    *p++ = 'J';

    /*** 密钥类型 1N ***/
    TASS_SPRINTF((char*)p, 2, "%d", iKeyType);
    p += strlen(p);

    /*** 公钥编码 2N ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iPubKeyCode);
    p += strlen(p);

    /*** 密钥索引 2N ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iKeyIdx);
    p += strlen(p);

    /*** 密钥口令 8A ***/
    memcpy(p, pcKeyPassword, 8);
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

    /*** 公钥, n Byte ***/
    memcpy(pucPubKey, p, iRspLen);

    return HAR_OK;
}

int HSM_EXT_XG_SeparateHash(
    void *hSessionHandle,int nSock,
    int iSepFlag/*分步标识*/,
    int iAlgType/*算法类型*/,
    int iSM2PubKeyLength/*SM2公钥长度*/,
    unsigned char *pucSM2PubKey/*SM2公钥*/,
    int iUserIDLength/*USERID长度*/,
    unsigned char *pucUserID/*USERID*/,
    int iDataInputLength/*输入数据长度*/,
    unsigned char *pucDataInput/*输入数据*/,
    int iDataProcessLength/*过程数据长度*/,
    unsigned char *pucDataProcess/*过程数据*/,
    char cTerminationMsgSeparator/*终止信息分隔符*/,
    int *piDataOut_ProcessLength/*输出(过程)数据长度 out*/,
    unsigned char *pucDataOut_Process/*输出(过程)数据 out*/)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code  "XG" ***/
    *p++ = 'X';
    *p++ = 'G';

    /*** 分步标识 1N ***/
    TASS_SPRINTF(p, 2, "%d", iSepFlag);
    p += strlen(p);

    /*** 算法类型 1N ***/
    TASS_SPRINTF(p, 2, "%d", iAlgType);
    p += strlen(p);

    if ((iAlgType == 1) && ((iSepFlag == 0) || (iSepFlag == 1)))
    {
        /*** SM2公钥长度 4N ***/
        TASS_SPRINTF(p, 5, "%04d", iSM2PubKeyLength);
        p += strlen(p);

        /*** SM2公钥 nB ***/
        memcpy(p, pucSM2PubKey, iSM2PubKeyLength);
        p += iSM2PubKeyLength;

        /*** USERID长度 4N ***/
        TASS_SPRINTF(p, 5, "%04d", iUserIDLength);
        p += strlen(p);

        /*** USERID nB ***/
        memcpy(p, pucUserID, iUserIDLength);
        p += iUserIDLength;
    }

    if ((iSepFlag == 0) || (iSepFlag == 2))
    {
        /*** 输入数据长度 4N ***/
        TASS_SPRINTF(p, 5, "%04d", iDataInputLength);
        p += strlen(p);

        /*** 输入数据 nB ***/
        memcpy(p, pucDataInput, iDataInputLength);
        p += iDataInputLength;
    }
    if ((iSepFlag == 2) || (iSepFlag == 3))
    {
        /*** 过程数据长度 4N ***/
        TASS_SPRINTF(p, 5, "%04d", iDataProcessLength);
        p += strlen(p);

        /*** 输入数据 nB ***/
        memcpy(p, pucDataProcess, iDataProcessLength);
        p += iDataProcessLength;
    }

    /*** 信息终止分隔符 1C ***/
    if (cTerminationMsgSeparator != '\0')
        *p++ = cTerminationMsgSeparator;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, nSock, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if (rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }
    /*** Response Buffer ***/
    p = aucRsp;

    /*** 输出(过程)数据长度 4H ***/
    *piDataOut_ProcessLength = Tools_ConvertHexBuf2Int(p, 4);
    p += 4;

    /*** 输出(过程)数据 nB ***/
    memcpy(pucDataOut_Process, p, *piDataOut_ProcessLength);

    return HAR_OK;
}

int HSM_EXT_UG_GeneratePlainSM2KeyPair(
    void *hSessionHandle,int nSock,
    int iKeyLength/*密钥长度*/,
    unsigned char *pucPubKeyX/*公钥X明文 out*/,
    unsigned char *pucPubKeyY/*公钥Y明文 out*/,
    unsigned char *pucPriKey/*私钥 out*/)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 512;
    unsigned char aucCmd[512] = { 0 };
    unsigned char aucRsp[512] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code  "UG" ***/
    *p++ = 'U';
    *p++ = 'G';

    /*** 密钥长度 4N ***/
    TASS_SPRINTF(p, 5, "%04d", iKeyLength);
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

    /*** 公钥X 32B***/
    memcpy(pucPubKeyX, p, 32);
    p += 32;

    /*** 公钥Y 32B***/
    memcpy(pucPubKeyY, p, 32);
    p += 32;

    /*** 私钥 32B***/
    memcpy(pucPriKey, p, 32);

    return HAR_OK;
}

int HSM_EXT_UM_ConverSM2PriKeyPlainToCipher(
    void *hSessionHandle,int nSock,
    int iKeyLength/*密钥长度*/,
    unsigned char *pucPriKeyPlain/*私钥明文*/,
    unsigned char *pucPriKeyCipher/*私钥密文*/)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 512;
    unsigned char aucCmd[512] = { 0 };
    unsigned char aucRsp[512] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code  "UM" ***/
    *p++ = 'U';
    *p++ = 'M';

    /*** 密钥长度 4N ***/
    TASS_SPRINTF(p, 5, "%04d", iKeyLength);
    p += strlen(p);

    /*** 私钥明文 32B ***/
    memcpy(p, pucPriKeyPlain, 32);
    p += 32;

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle, nSock, aucCmd, iCmdLen, aucRsp, &iRspLen);
    if (rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** 私钥 40B***/
    memcpy(pucPriKeyCipher, p, 40);

    return HAR_OK;
}

int HSM_EXT_UI_GeneratePlainRSAKeyPair(
    void *hSessionHandle,int nSock,
    int iKeyLength/*密钥长度*/,
    int iKeyEnode/*公私钥编码*/,
    char cSeparator/*分隔符*/,
    int iExpLength/*指数长度*/,
    char *pcExp/*指数*/,
    int *piPubKeyLength/*公钥长度 out*/,
    unsigned char *pucPubKey/*公钥 out*/,
    int *piPriKeyLength/*私钥长度 out*/,
    unsigned char *pucPriKey/*私钥 out*/,
    unsigned char *pucPubAndPriKey/*公私钥 out*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code    "UI" ***/
    *p++ = 'U';
    *p++ = 'I';

    /*** 密钥长度 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iKeyLength);
    p += strlen(p);

    /*** 公私钥编码 2N ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iKeyEnode);
    p += strlen(p);

    if (cSeparator == ';')
    {
        /*** 分隔符 1A ***/
        *p++ = ';';

        /*** 指数长度 4N ***/
        TASS_SPRINTF(p, 5, "%04d", iExpLength);
        p += strlen(p);

        /*** 指数 nN ***/
        memcpy(p, pcExp, iExpLength);
        p += iExpLength;
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

    if (iKeyEnode != 1)
    {
        /*** 公钥长度 4N ***/
        *piPubKeyLength = Tools_ConvertDecBuf2Int(p, 4);
        p += 4;

        /*** 公钥 nB ***/
        memcpy(pucPubKey, p, *piPubKeyLength);
        p += *piPubKeyLength;

        /*** 私钥长度 4N ***/
        *piPriKeyLength = Tools_ConvertDecBuf2Int(p, 4);
        p += 4;

        /*** 私钥 nB ***/
        memcpy(pucPriKey, p, *piPriKeyLength);
        p += *piPriKeyLength;
    }
    else
    {
        /*** 公私钥 nB ***/
        memcpy(pucPubAndPriKey, p, iRspLen);
    }

    return HAR_OK;
}