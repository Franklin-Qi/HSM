/*----------------------------------------------------------------------|
|    hsmapi_ic.c                                                        |
|    Version :     1.0                                                  |
|    Author:       Luo Cangjian                                         |
|    Description:  SJJ1310密码机接口金融IC卡应用主机命令函数            |
|                                                                       |
|    Copyright :   Beijing JN TASS Technology Co., Ltd.                 |
|    data:         2015-06-03. Create                                   |
|-----------------------------------------------------------------------|
|    Modify History:                                                    |
|----------------------------------------------------------------------*/
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <stdarg.h>
#include <string.h>

#include "hsmapi_define.h"
#include "hsmapi_log.h"
#include "hsmapi_tools.h"
#include "hsmapi_init.h"
#include "hsmsocket.h"
#include "hsmapi_ic.h"

#ifdef _MSC_VER
#pragma warning(disable:4996)
#include <windows.h>
#endif

int HSM_IC_VC_DiversifyKey(
    void *hSessionHandle,int nSock,
    char cSymmAlg/*算法类型*/,
    int iMasterKeyIdx/*主控密钥索引*/,
    char *pcMasterKeyCipherByHMK/*主控密钥密文*/,
    char cMasterKeyDiversifyTime/*主控密钥分散次数*/,
    char cMasterKeyDiversifySymmAlg/*主控密钥分散算法*/,
    char *pcMasterKeyDiversifyData/*主控密钥分散数据*/,
    int iAppMasterKeyType_Tag/*应用主密钥索引*/,
    int iAppMasterKeyIdx/*应用主密钥索引*/,
    char *pcAppMasterKeyCipherByHMK/*应用主密钥密文*/,
    char cAppMasterKeyDiversifyTime/*应用主密钥分散次数*/,
    char cAppMasterKeyDiversifySymmAlg/*应用主密钥分散算法*/,
    char *pcAppMasterKeyDiversifyData/*应用主密钥分散数据*/,
    int *piKeyCipherLength/*密钥密文长度 out*/,
    char *pcKeyCipher/*密钥密文 out*/,
    char *pcKCV/*密钥校验值 out*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code    "VC" ***/
    *p++ = 'V';
    *p++ = 'C';

    /*** 算法类型 1A ***/
    *p++ = cSymmAlg;

    /*** 主控密钥索引或密文 K+4N/16H/1A+32H/1A+48H ***/
    len = Tools_AddFieldKey(iMasterKeyIdx, pcMasterKeyCipherByHMK, p);
    if (len == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iMasterKeyIdx or pcMasterKeyCipherByHMK is invalid.");
        return HAR_PARAM_LEN;
    }
    p += len;

    /*** 主控密钥分散次数 1A ***/
    if ((cMasterKeyDiversifyTime < '0') || (cMasterKeyDiversifyTime > '3'))
    {
        LOG_ERROR("%s", "Parameter: cMasterKeyDiversifyTime is invalid.");
        return HAR_PARAM_LEN;
    }
    *p++ = cMasterKeyDiversifyTime;
    p += strlen(p);

    if (cMasterKeyDiversifyTime != '0')
    {
        /*** 主控密钥分散算法 1A ***/
        *p++ = cMasterKeyDiversifySymmAlg;

        /*** 主控密钥分散数据 n*16H***/
        len = (cMasterKeyDiversifyTime & 0x0f) * 16;
        memcpy(p, pcMasterKeyDiversifyData, len);
        p += len;
    }

    /*** 应用主密钥类型/TAG 3A ***/
    TASS_SPRINTF(p, 4, "%03d", iAppMasterKeyType_Tag);
    p += strlen(p);

    /*** 应用主密钥索引或密文 K+4N/16H/1A+32H/1A+48H ***/
    len = Tools_AddFieldKey(iAppMasterKeyIdx, pcAppMasterKeyCipherByHMK, p);
    if (len == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iAppMasterKeyIdx or pcAppMasterKeyCipherByHMK is invalid.");
        return HAR_PARAM_LEN;
    }
    p += len;

    /*** 应用主密钥分散次数 1A ***/
    if ((cAppMasterKeyDiversifyTime < '0') || (cAppMasterKeyDiversifyTime > '3'))
    {
        LOG_ERROR("%s", "Parameter: cAppMasterKeyDiversifyTime is invalid.");
        return HAR_PARAM_LEN;
    }
    *p++ = cAppMasterKeyDiversifyTime;
    p += strlen(p);

    if (cAppMasterKeyDiversifyTime != '0')
    {
        /*** 应用主密钥分散算法 1A ***/
        *p++ = cAppMasterKeyDiversifySymmAlg;

        /*** 应用主密钥分散数据 n*16H***/
        len = (cAppMasterKeyDiversifyTime & 0x0f) * 16;
        memcpy(p, pcAppMasterKeyDiversifyData, len);
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

    /*** 密钥密文长度 2N ***/
    *piKeyCipherLength = Tools_ConvertHexBuf2Int(p, 2);
    p += 2;

    /*** 密钥密文 nH ***/
    strncpy(pcKeyCipher, p, *piKeyCipherLength);
    *(pcKeyCipher + *piKeyCipherLength) = '\0';
    p += *piKeyCipherLength;

    /*** KCV nH ***/
    strncpy(pcKCV, p, 16);
    *(pcKCV + 16) = '\0';

    return HAR_OK;
}

int HSM_IC_VM_VerifyARQC_GenerateARPC(
    void *hSessionHandle,int nSock,
    char cSymmAlg/*算法类型*/,
    char cICCardType/*IC卡类型*/,
    char cMode/*模式*/,
    int iKeyIdx/*密钥索引*/,
    char *pcKeyCipherByHMK/*密钥密文*/,
    char *pcCardKeyDiversifyData/*卡片密钥分散因子*/,
    char *pcSessionKeyDiversifyData/*会话密钥分散因子*/,
    char *pcARQC/*待验证ARQC*/,
    int iDataLength/*数据长度*/,
    unsigned char *pucData/*数据*/,
    char *pcARC/*ARC*/,
    char *pcARPC/*密钥校验值 out*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code    "VM" ***/
    *p++ = 'V';
    *p++ = 'M';

    /*** 算法类型 1A ***/
    *p++ = cSymmAlg;

    /*** IC卡类型 1A ***/
    *p++ = cICCardType;

    /*** 模式 1A ***/
    *p++ = cMode;

    /*** 密钥索引或密文 K+4N/16H/1A+32H/1A+48H ***/
    len = Tools_AddFieldKey(iKeyIdx, pcKeyCipherByHMK, p);
    if (len == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iKeyIdx or pcKeyCipherByHMK is invalid.");
        return HAR_PARAM_LEN;
    }
    p += len;
    
    /*** 卡片密钥分散因子 16/32H ***/
    len = ((cICCardType == '2') && (cSymmAlg == '3')) ? 16 : 32;
    memcpy(p, pcCardKeyDiversifyData, len);
    p += len;

    if (cICCardType != '0')
    {
        /*** 会话密钥分散因子 4/32H ***/
        len = ((cICCardType == '2') && (cSymmAlg == '3')) ? 4 : 32;
        memcpy(p, pcSessionKeyDiversifyData, len);
        p += len;
    }

    /*** 待验证ARQC 16/32H ***/
    len = ((cICCardType == '2') && (cSymmAlg != '3')) ? 32 : 16;
    memcpy(p, pcARQC, len);
    p += len;

    if (cMode != '2')
    {
        /*** 数据长度 4N ***/
        TASS_SPRINTF((char*)p, 5, "%04d", iDataLength);
        p += strlen(p);

        /*** 数据 nB ***/
        memcpy(p, pucData, iDataLength);
        p += iDataLength;
    }

    if (cMode != '0')
    {
        /*** ARC 4H ***/
        memcpy(p, pcARC, 4);
        p += 4;
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

    if (cMode != '0')
    {
        /*** ARPC 16H ***/
        strncpy(pcARPC, p, iRspLen);
        *(pcARPC + iRspLen) = '\0';
    }

    return HAR_OK;
}
    
int HSM_IC_VI_Encrypt_DecryptScript(
    void *hSessionHandle,int nSock,
    char cSymmAlg/*算法类型*/,
    char cEnDecryptFlag/*加解密标识*/,
    char cICCardType/*IC卡类型*/,
    char cMode/*加解密模式*/,
    int iMasterKeyIdx/*密钥索引*/,
    char *pcMasterKeyCipherByHMK/*密钥密文*/,
    char *pcCardKeyDiversifyData/*卡片密钥分散因子*/,
    char *pcSessionKeyDiversifyData/*会话密钥分散因子*/,
    char *pcIV/*初始向量IV*/,
    int iDataInLength/*输入数据长度*/,
    unsigned char *pucDataIn/*输入数据*/,
    int *piDataOutLength/*输出数据长度 out*/,
    unsigned char *pucDataOut/*输出数据 out*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code    "VI" ***/
    *p++ = 'V';
    *p++ = 'I';

    /*** 算法类型 1A ***/
    *p++ = cSymmAlg;

    /*** 操作类型 1A ***/
    *p++ = cEnDecryptFlag;

    /*** IC卡类型 1A ***/
    *p++ = cICCardType;

    /*** 模式 1A ***/
    *p++ = cMode;

    /*** 密钥索引或密文 K+4N/16H/1A+32H/1A+48H ***/
    len = Tools_AddFieldKey(iMasterKeyIdx, pcMasterKeyCipherByHMK, p);
    if (len == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iMasterKeyIdx or pcMasterKeyCipherByHMK is invalid.");
        return HAR_PARAM_LEN;
    }
    p += len;

    /*** 卡片密钥分散因子 16/32H ***/
    len = ((cICCardType == '2') && (cSymmAlg == '3')) ? 16 : 32;
    memcpy(p, pcCardKeyDiversifyData, len);
    p += len;

    /*** 会话密钥分散因子 4/32H ***/
    len = ((cICCardType == '2') && (cSymmAlg == '3')) ? 4 : 32;
    memcpy(p, pcSessionKeyDiversifyData, len);
    p += len;

    if (cMode == '1')
    {
        /*** 初始向量IV 16/32H ***/
        len =  (cSymmAlg == '3') ? 16 : 32;
        memcpy(p, pcIV, len);
        p += len;
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
    memcpy(pucDataOut, (char *)p, *piDataOutLength);

    return HAR_OK;
}

int HSM_IC_VK_CalculateScriptMAC(
    void *hSessionHandle,int nSock,
    char cSymmAlg/*算法类型*/,
    char cICCardType/*IC卡类型*/,
    int iMasterKeyIdx/*密钥索引*/,
    char *pcMasterKeyCipherByHMK/*密钥密文*/,
    char *pcCardKeyDiversifyData/*卡片密钥分散因子*/,
    char *pcSessionKeyDiversifyData/*会话密钥分散因子*/,
    int iDataLength/*数据长度*/,
    unsigned char *pucData/*数据*/,
    char *pcMAC/*MAC out*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 4096;
    unsigned char aucCmd[4096] = { 0 };
    unsigned char aucRsp[4096] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code    "VK" ***/
    *p++ = 'V';
    *p++ = 'K';

    /*** 算法类型 1A ***/
    *p++ = cSymmAlg;

    /*** IC卡类型 1A ***/
    *p++ = cICCardType;

    /*** 密钥索引或密文 K+4N/16H/1A+32H/1A+48H ***/
    len = Tools_AddFieldKey(iMasterKeyIdx, pcMasterKeyCipherByHMK, p);
    if (len == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iMasterKeyIdx or pcMasterKeyCipherByHMK is invalid.");
        return HAR_PARAM_LEN;
    }
    p += len;

    /*** 卡片密钥分散因子 16/32H ***/
    len = ((cICCardType == '2') && (cSymmAlg == '3')) ? 16 : 32;
    memcpy(p, pcCardKeyDiversifyData, len);
    p += len;

    /*** 会话密钥分散因子 4/32H ***/
    len = ((cICCardType == '2') && (cSymmAlg == '3')) ? 4 : 32;
    memcpy(p, pcSessionKeyDiversifyData, len);
    p += len;

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

    /*** MAC 16H ***/
    memcpy(pcMAC, (char *)p, 16);

    return HAR_OK;
}

int HSM_IC_VS_ConvertCipherByKey1ToKey2(
    void *hSessionHandle,int nSock,
    char cDeSymmAlg/*解密算法类型*/,
    int iDeKeyIdx/*解密密钥索引*/,
    char *pcDeKeyCipherByHMK/*解密密钥密文*/,
    char cDeMode/*解密模式*/,
    char *pcDeIV/*解密初始向量*/,
    char cEnSymmAlg/*加密算法类型*/,
    int iEnKeyIdx/*加密密钥索引*/,
    char *pcEnKeyCipherByHMK/*加密密钥密文*/,
    char cEnMode/*加密模式*/,
    char *pcEnIV/*加密初始向量*/,
    int iDataInLength/*输入数据长度*/,
    unsigned char *pucDataIn/*输入数据*/,
    int *piDataOutLength/*输出数据长度 out*/,
    unsigned char *pucDataOut/*输出数据 out*/)
{
    int rv = HAR_OK, len;
    int iDataOutLen = 0;
    int iCmdLen;
    int iRspLen = 4096 + 128;
    unsigned char aucCmd[4096 + 128] = { 0 };
    unsigned char aucRsp[4096 + 128] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code  "VS" ***/
    *p++ = 'V';
    *p++ = 'S';

    /*** 解密算法类型 1A ***/
    *p++ = cDeSymmAlg;

    /*** 解密密钥索引或密文 K+4N/16H/1A+32H/1A+48H ***/
    rv = Tools_AddFieldKey(iDeKeyIdx, pcDeKeyCipherByHMK, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iDeKeyIdx or pcDeKeyCipherByHMK is invlaid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** 解密算法模式 1A ***/
    *p++ = cDeMode;

    if (cDeMode == '1')
    {
        /*** 解密初始向量IV 16/32H ***/
        len = (cDeSymmAlg == '3') ? 16 : 32;
        memcpy(p, pcDeIV, len);
        p += len;
    }

    /*** 加密算法类型 1A ***/
    *p++ = cEnSymmAlg;

    /*** 加密密钥索引或密文 K+4N/16H/1A+32H/1A+48H ***/
    rv = Tools_AddFieldKey(iEnKeyIdx, pcEnKeyCipherByHMK, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iEnKeyIdx or pcEnKeyCipherByHMK is invlaid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** 加密算法模式 1A ***/
    *p++ = cEnMode;

    if (cEnMode == '1')
    {
        /*** 加密初始向量IV 16/32H ***/
        len = (cEnSymmAlg == '3') ? 16 : 32;
        memcpy(p, pcEnIV, len);
        p += len;
    }

    /*** 输入数据长度 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iDataInLength);
    p += strlen(p);

    /*** 输入数据 nB***/
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
    /*** 输出数据长度 ***/
    *piDataOutLength = Tools_ConvertDecBuf2Int(p, 4);
    p += 4;
    /*** 输出数据 ***/
    memcpy(pucDataOut, (char *)p, *piDataOutLength);

    return HAR_OK;
}

int HSM_IC_V2_Encrypt_DecryptData(
    void *hSessionHandle,int nSock,
    char cSymmAlg/*算法类型*/,
    int iKeyIdx/*密钥索引*/,
    char *pcKeyCipherByHMK/*密钥密文*/,
    char cDiversifyTime/*分散次数*/,
    char *pcDiversifyData/*分散因子*/,
    char cEnDecryptFlag/*加解密标识*/,
    char cMode/*加解密模式*/,
    char *pcIV/*初始向量*/,
    char cPadMode/*填充模式*/,
    int iDataInLength/*输入数据长度*/,
    unsigned char *pucDataIn/*输入数据*/,
    int *piDataOutLength/*输出数据长度 out*/,
    unsigned char *pucDataOut/*输出数据 out*/)
{
    int rv = HAR_OK, len;
    int iDataOutLen = 0;
    int iCmdLen;
    int iRspLen = 4096 + 128;
    unsigned char aucCmd[4096 + 128] = { 0 };
    unsigned char aucRsp[4096 + 128] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code  "V2" ***/
    *p++ = 'V';
    *p++ = '2';

    /*** 算法类型 1A ***/
    *p++ = cSymmAlg;

    /*** 密钥索引或密文 K+4N/16H/1A+32H/1A+48H ***/
    rv = Tools_AddFieldKey(iKeyIdx, pcKeyCipherByHMK, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iKeyIdx or pcKeyCipherByHMK is invlaid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** 主控密钥分散次数 1A ***/
    if ((cDiversifyTime < '0') || (cDiversifyTime > '2'))
    {
        LOG_ERROR("%s", "Parameter: cDiversifyTime is invalid.");
        return HAR_PARAM_LEN;
    }
    *p++ = cDiversifyTime;
    p += strlen(p);

    if (cDiversifyTime != '0')
    {
        /*** 密钥分散数据 n*16H ***/
        len = (cDiversifyTime & 0x0f) * 16;
        memcpy(p, pcDiversifyData, len);
        p += len;
    }

    /*** 加解密标识 1A ***/
    *p++ = cEnDecryptFlag;

    /*** 算法应用模式标识 1A ***/
    *p++ = cMode;
    if (cMode == '1')
    {
        /*** 初始向量IV 16/32H ***/
        len = (cSymmAlg == '3') ? 16 : 32;
        memcpy(p, pcIV, len);
        p += len;
    }

    /*** 填充模式 1A ***/
    *p++ = cPadMode;

    /*** 输入数据长度 4N ***/
    TASS_SPRINTF((char*)p, 5, "%04d", iDataInLength);
    p += strlen(p);

    /*** 输入数据 nB ***/
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

    /*** 输出数据 nB***/
    memcpy(pucDataOut, (char *)p, *piDataOutLength);

    return HAR_OK;
}

int HSM_IC_V4_CalculateMAC(
    void *hSessionHandle,int nSock,
    char cSymmAlg/*算法类型*/,
    int iKeyIdx/*密钥索引*/,
    char *pcKeyCipherByHMK/*密钥密文*/,
    char cMACAlog/*MAC算法标识*/,
    char cDiversifyTime/*分散次数*/,
    char *pcDiversifyData/*分散因子*/,
    char *pcIV/*初始向量*/,
    int iDataLength/*数据长度*/,
    unsigned char *pucData/*数据*/,
    char *pcMAC/*MAC out*/)
{
    int rv = HAR_OK, len;
    int iCmdLen;
    int iRspLen = 4096 + 128;
    unsigned char aucCmd[4096 + 128] = { 0 };
    unsigned char aucRsp[4096 + 128] = { 0 };
    unsigned char *p = aucCmd;

    /*** Command Code  "V4" ***/
    *p++ = 'V';
    *p++ = '4';

    /*** 算法类型 1A ***/
    *p++ = cSymmAlg;

    /*** 密钥索引或密文 K+4N/16H/1A+32H/1A+48H ***/
    rv = Tools_AddFieldKey(iKeyIdx, pcKeyCipherByHMK, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iKeyIdx or pcKeyCipherByHMK is invlaid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** MAC算法标识 1A ***/
    *p++ = cMACAlog;

    /*** 主控密钥分散次数 1A ***/
    if ((cDiversifyTime < '0') || (cDiversifyTime > '3'))
    {
        LOG_ERROR("%s", "Parameter: cDiversifyTime is invalid.");
        return HAR_PARAM_LEN;
    }
    *p++ = cDiversifyTime;
    p += strlen(p);

    if (cDiversifyTime != '0')
    {
        /*** 密钥分散数据 n*16H***/
        len = (cDiversifyTime & 0x0f) * 16;
        memcpy(p, pcDiversifyData, len);
        p += len;
    }

    /*** 初始向量IV 16/32H ***/
    len = (cSymmAlg == '3') ? 16 : 32;
    memcpy(p, pcIV, len);
    p += len;

    /*** 输入数据长度 4N***/
    TASS_SPRINTF((char*)p, 5, "%04d", iDataLength);
    p += strlen(p);

    /*** 输入数据 nB***/
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

    /*** MAC ***/
    strncpy(pcMAC, (char *)p, iRspLen);
    *(pcMAC + iRspLen) = '\0';
   return HAR_OK;
}