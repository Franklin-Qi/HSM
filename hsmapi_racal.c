/*----------------------------------------------------------------------|
|    hsmapi_racal.c                                                     |
|    Version :     1.0                                                  |
|    Author:       Luo Cangjian                                         |
|    Description:  SJJ1310密码机接口雷卡兼容主机命令函数                |
|                                                                       |
|    Copyright :   Beijing JN TASS Technology Co., Ltd.                 |
|    data:         2015-06-03. Create                                   |
|-----------------------------------------------------------------------|
|    Modify History:                                                    |
|----------------------------------------------------------------------*/
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>


#ifdef _MSC_VER
#include <windows.h>
#pragma warning(disable:4996)
#endif

#include "hsmapi_racal.h"
#include "hsmapi_define.h"
#include "hsmapi_log.h"
#include "hsmapi_tools.h"
#include "hsmsocket.h"

int HSM_RCL_GenerateRandomPin(char *pcPAN, int iPinLength, char *pcPinCipherByLmk/*out*/)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[128] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "JA" ***/
    *p ++ = 'J';
    *p ++ = 'A';

    /*** PAN ***/
    rv = Tools_AddFieldPan(PANFMT_PIN_LMK, pcPAN, p);
    if(rv == HAR_PARAM_PAN)
    {
        LOG_ERROR("Error: pcPAN = [%s] is invaild.", pcPAN);
        return rv;
    }
    p += rv;

    /*** Pin Length ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iPinLength);
    p += 2;

    iCmdLen = (int)(p - aucCmd);
    /*
     *rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
     */
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** PIN, LH ***/
    if(pcPinCipherByLmk)
    {
        strncpy(pcPinCipherByLmk, (char *)p, iRspLen);
    }

    return HAR_OK;
}

int HSM_RCL_EncryptPin_LMK(char *pcPlainPin, char *pcPAN, char *pcPinCipherByLmk/*out*/)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[128] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "BA" ***/
    *p ++ = 'B';
    *p ++ = 'A';

    /*** PIN ***/
    memcpy(p, pcPlainPin, strlen(pcPlainPin));
    p += strlen(pcPlainPin);
    *p ++ = 'F';

    /*** PAN ***/
    rv = Tools_AddFieldPan(PANFMT_PIN_LMK, pcPAN, p);
    if(rv == HAR_PARAM_PAN)
    {
        LOG_ERROR("Error: pcPAN = [%s] is invaild.", pcPAN);
        return rv;
    }
    p += rv;

    iCmdLen = (int)(p - aucCmd);
    //rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** PIN, LH ***/
    if(pcPinCipherByLmk)
    {
        strncpy(pcPinCipherByLmk, (char *)p, iRspLen);
    }

    return rv;
}

int HSM_RCL_DecryptPin_LMK(void *hSessionHandle,int nSock,char *pcPinCipherByLmk, char *pcPAN, char *pcPlainPin/*out*/)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[128] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "NG" ***/
    *p ++ = 'N';
    *p ++ = 'G';

    /*** PAN ***/
    rv = Tools_AddFieldPan(PANFMT_PIN_LMK, pcPAN, p);
    if(rv == HAR_PARAM_PAN)
    {
        LOG_ERROR("Error: pcPAN = [%s] is invaild.", pcPAN);
        return rv;
    }
    p += rv;

    /*** Cipher PIN ***/
    memcpy(p, pcPinCipherByLmk, strlen(pcPinCipherByLmk));
    p += strlen(pcPinCipherByLmk);

    iCmdLen = (int)(p - aucCmd);
    
    rv = TCP_CommunicateHsm_ex(hSessionHandle,aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }
   

    /*** Response Buffer ***/
    p = aucRsp;

    /*** PIN, LH ***/
    if(pcPlainPin)
    {
        strncpy(pcPlainPin, (char *)p, iRspLen);
    }

    return HAR_OK;
}

int HSM_RCL_ConvertCipherPin_Lmk2Zpk(void *hSessionHandle,int nSock,
    int iZpkIdx, char *pcZpkCipherByLmk, int iPinFmt,
    char *pcPAN, char *pcPinCipherByLmk, char *pcPinCipherByZpk/*out*/)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[128] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "JG" ***/
    *p ++ = 'J';
    *p ++ = 'G';

    /*** Dst ZPK ***/
    rv = Tools_AddFieldKey(iZpkIdx, pcZpkCipherByLmk, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Error: iZpkIdx or pcZpkCipherByLmk is invalid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** Pin Block Format ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iPinFmt);
    p += 2;

    /*** PAN ***/
    rv = Tools_AddFieldPan(iPinFmt, pcPAN, p);
    if(rv == HAR_PARAM_PAN)
    {
        LOG_ERROR("Error: pcPAN = [%s] is invaild.", pcPAN);
        return rv;
    }
    p += rv;

    /*** Cipher Pin_LMK ***/
    memcpy(p, pcPinCipherByLmk, strlen(pcPinCipherByLmk));
    p += strlen(pcPinCipherByLmk);

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle,aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** PIN, 16H/32H ***/
    if(pcPinCipherByZpk)
    {
        strncpy(pcPinCipherByZpk, (char *)p, iRspLen);
    }

    return HAR_OK;
}

int HSM_RCL_ConvertCipherPin_Zpk2Lmk(
    void *hSessionHandle,int nSock,
    int iZpkIdx, char *pcZpkCipherByLmk, int iPinFmt,
    char *pcPAN, char *pcPinCipherByZpk, char *pcPinCipherByLmk/*out*/)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[128] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "JE" ***/
    *p ++ = 'J';
    *p ++ = 'E';

    /*** Src ZPK ***/
    rv = Tools_AddFieldKey(iZpkIdx, pcZpkCipherByLmk, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Error: iZpkIdx or pcZpkCipherByLmk is invalid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** Cipher Pin_ZPK, 16H/32H ***/
    memcpy(p, pcPinCipherByZpk, strlen(pcPinCipherByZpk));
    p += strlen( pcPinCipherByZpk );

    /*** Pin Block Format ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iPinFmt);
    p += 2;

    /*** PAN ***/
    rv = Tools_AddFieldPan(iPinFmt, pcPAN, p);
    if(rv == HAR_PARAM_PAN)
    {
        LOG_ERROR("Error: pcPAN = [%s] is invaild.", pcPAN);
        return rv;
    }
    p += rv;

    iCmdLen = (int)(p - aucCmd);
  
    rv = TCP_CommunicateHsm_ex(hSessionHandle,aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }
  

    /*** Response Buffer ***/
    p = aucRsp;

    /*** PIN_Lmk, LH ***/
    if(pcPinCipherByLmk)
    {
        strncpy(pcPinCipherByLmk, (char *)p, iRspLen);
    }

    return HAR_OK;
}

int HSM_RCL_ConvertCipherPin_Zpk2Zpk(
    int iSrcZpkIdx, char *pcSrcZpkCipherByLmk, int iDstZpkIdx, char *pcDstZpkCipherByLmk,
    int iSrcPinFmt, int iDstPinFmt,
    char *pcSrcPAN, char *pcDstPAN,
    char *pcSrcPinCipherByZpk, char *pcDstPinCipherByZpk/*out*/ )
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[256] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "TI" ***/
    *p ++ = 'T';
    *p ++ = 'I';

    /*** Src Key Type, 1：TPK; 2：ZPK ***/
    *p ++ = '2';

    /*** Src ZPK ***/
    rv = Tools_AddFieldKey(iSrcZpkIdx, pcSrcZpkCipherByLmk, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Error: iSrcZpkIdx or pcSrcZpkCipherByLmk is invalid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** Dst Key Type, 1：TPK; 2：ZPK ***/
    *p ++ = '2';

    /*** Dst ZPK ***/
    rv = Tools_AddFieldKey(iDstZpkIdx, pcDstZpkCipherByLmk, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Error: iDstZpkIdx or pcDstZpkCipherByLmk is invalid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** Pin Length, "12" ***/
    TASS_SPRINTF((char*)p, 3, "%2d", 12);
    p += 2;

    /*** Cipher Pin_ZPK1, 16H/32H ***/
    memcpy(p, pcSrcPinCipherByZpk, strlen(pcSrcPinCipherByZpk));
    p += strlen(pcSrcPinCipherByZpk);

    /*** Pin Block Format 1 ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iSrcPinFmt);
    p += 2;

    /*** Src PAN ***/
    rv = Tools_AddFieldPan(iSrcPinFmt, pcSrcPAN, p);
    if(rv == HAR_PARAM_PAN)
    {
        LOG_ERROR("Error: pcSrcPAN = [%s] is invaild.", pcSrcPAN);
        return rv;
    }
    p += rv;

    /*** Pin Block Format 2 ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iDstPinFmt);
    p += 2;

    /*** Dst PAN ***/
    rv = Tools_AddFieldPan(iDstPinFmt, pcDstPAN, p);
    if(rv == HAR_PARAM_PAN)
    {
        LOG_ERROR("Error: pcDstPAN = [%s] is invaild.", pcDstPAN);
        return rv;
    }
    p += rv;

    iCmdLen = (int)(p - aucCmd);
    /*
     *rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
     */
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** PIN_Zpk2, 16H/32H ***/
    if(pcDstPinCipherByZpk)
    {
        strncpy(pcDstPinCipherByZpk, (char *)p, iRspLen);
    }

    return HAR_OK;
}

int HSM_RCL_GenerateIBMPinOffset(
    int iPvkIdx, char *pcPvkCipherByLmk,
    char *pcPinCipherByLmk, int iMinLength,
    char *pcPAN, char *pcDecimalTable, char *pcPinVerifyData,
    char *pcPinOffset/*out*/)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[128] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "DE" ***/
    *p ++ = 'D';
    *p ++ = 'E';

    /*** PVK ***/
    rv = Tools_AddFieldKey(iPvkIdx, pcPvkCipherByLmk, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Error: iPvkIdx or pcPvkCipherByLmk is invalid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** Cipher Pin_Lmk ***/
    memcpy(p, pcPinCipherByLmk, strlen(pcPinCipherByLmk));
    p += strlen(pcPinCipherByLmk);

    /*** PIN校验长度, 2N ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iMinLength);
    p += 2;

    /*** PAN ***/
    rv = Tools_AddFieldPan(PANFMT_PIN_LMK, pcPAN, p);
    if(rv == HAR_PARAM_PAN)
    {
        LOG_ERROR("Error: pcPAN = [%s] is invaild.", pcPAN);
        return rv;
    }
    p += rv;

    /*** 十进制转换表, 16N ***/
    memcpy(p, pcDecimalTable, 16);
    p += 16;

    /*** PIN校验数据, 12A ***/
    memcpy(p, pcPinVerifyData, 12);
    p += 12;

    iCmdLen = (int)(p - aucCmd);
    /*
     *rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
     */
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** PIN Offset, 12H ***/
    if(pcPinOffset)
    {
        strncpy(pcPinOffset, (char *)p, 12);
    }

    return HAR_OK;
}

int HSM_RCL_VerifyZonePinBlock_PinOffset(
    int iZpkIdx, char *pcZpkCipherByLmk,
    int iPvkIdx, char *pcPvkCipherByLmk,
    char *pcPinBlock_Zpk, int iPinFormat, int iMinLength,
    char *pcPAN, char *pcDecimalTable, char *pcPinVerifyData,
    char *pcPinOffset)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[256] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "EA" ***/
    *p ++ = 'E';
    *p ++ = 'A';

    /*** ZPK ***/
    rv = Tools_AddFieldKey(iZpkIdx, pcZpkCipherByLmk, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Error: iZpkIdx or pcZpkCipherByLmk is invalid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** PVK ***/
    rv = Tools_AddFieldKey(iPvkIdx, pcPvkCipherByLmk, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Error: iPvkIdx or pcPvkCipherByLmk is invalid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** PIN最大长度, 2N, 12 ***/
    *p ++ = '1';
    *p ++ = '2';

    /*** Cipher PinBlock_ZPK ***/
    memcpy(p, pcPinBlock_Zpk, strlen(pcPinBlock_Zpk));
    p += strlen( pcPinBlock_Zpk );

    /*** PIN格式代码, 2N ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iPinFormat);
    p += 2;

    /*** PIN校验长度, 2N ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iMinLength);
    p += 2;

    /*** PAN ***/
    rv = Tools_AddFieldPan(iPinFormat, pcPAN, p);
    if(rv == HAR_PARAM_PAN)
    {
        LOG_ERROR("Parameter: pcPAN = [%s] is invaild.", pcPAN);
        return rv;
    }
    p += rv;

    /*** 十进制转换表, 16N ***/
    memcpy(p, pcDecimalTable, 16);
    p += 16;

    /*** PIN校验数据, 12A ***/
    memcpy(p, pcPinVerifyData, 12);
    p += 12;

    /*** PIN Offset, 12H ***/
    memcpy(p, pcPinOffset, 12);
    p += 12;

    iCmdLen = (int)(p - aucCmd);
    /*
     *rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
     */
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}


int HSM_RCL_GeneratePVV(
    int iPvkIdx, char *pcPvkCipherByLmk, int iPvkID,
    char *pcPinCipherByLmk, char *pcPAN,
    char *pcPVV/*out*/)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[256] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "DG" ***/
    *p ++ = 'D';
    *p ++ = 'G';

    /*** PVK ***/
    rv = Tools_AddFieldKey(iPvkIdx, pcPvkCipherByLmk, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iPvkIdx or pcPvkCipherByLmk is invalid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** Cipher Pin_Lmk ***/
    memcpy(p, pcPinCipherByLmk, strlen(pcPinCipherByLmk));
    p += strlen(pcPinCipherByLmk);

    /*** PAN ***/
    rv = Tools_AddFieldPan(PANFMT_PIN_LMK, pcPAN, p);
    if(rv == HAR_PARAM_PAN)
    {
        LOG_ERROR("Parameter: pcPAN = [%s] is invaild.", pcPAN);
        return rv;
    }
    p += rv;

    /*** PVK ID ***/
    if (iPvkID < 10)
    {
        *p ++ = iPvkID + '0';
    }
    else if (iPvkID <= 15)
    {
        *p ++ = iPvkID-10 + 'A';
    }
    else
    {
        LOG_ERROR("Parameter: iPvkID[%d] is Invalid.", iPvkID);
        return HAR_PARAM_KEY_ID;
    }

    iCmdLen = (int)(p - aucCmd);
    /*
     *rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
     */
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** PVV, 4N ***/
    if(pcPVV)
    {
        strncpy(pcPVV, (char *)p, 4);
    }

    return HAR_OK;
}

int HSM_RCL_GenerateCVV(
    int iCvkIdx, char *pcCvk_Lmk,
    char *pcPAN, char *pcExpirationDate, char *pcServiceCode,
    char *pcCVV/*out*/)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[128] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "CW" ***/
    *p ++ = 'C';
    *p ++ = 'W';

    /*** CVK ***/
    rv = Tools_AddFieldKey(iCvkIdx, pcCvk_Lmk, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iCvkIdx or pcCvk_Lmk is invalid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** All PAN ***/
    memcpy(p, pcPAN, strlen(pcPAN));
    p += strlen(pcPAN);

    /*** ; ***/
    *p ++ = ';';

    /*** Valid Time ***/
    memcpy(p, pcExpirationDate, 4);
    p += 4;

    /*** Service Code ***/
    memcpy(p, pcServiceCode, 3);
    p += 3;

    iCmdLen = (int)(p - aucCmd);
    /*
     *rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
     */
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** CVV, 3N ***/
    if(pcCVV)
    {
        strncpy(pcCVV, (char *)p, 3);
    }

    return HAR_OK;
}

int HSM_RCL_VerifyCVV(
    int iCvkIdx, char *pcCvk_Lmk,
    char *pcPAN, char *pcExpirationDate, char *pcServiceCode,
    char *pcCVV)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[128] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "CY" ***/
    *p ++ = 'C';
    *p ++ = 'Y';

    /*** CVK ***/
    rv = Tools_AddFieldKey(iCvkIdx, pcCvk_Lmk, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iCvkIdx or pcCvk_Lmk is invalid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** 待校验的CVV, 3N ***/
    memcpy(p, pcCVV, 3);
    p += 3;

    /*** All PAN ***/
    memcpy(p, pcPAN, strlen(pcPAN));
    p += strlen( pcPAN );

    /*** ; ***/
    *p ++ = ';';

    /*** Valid Time, 4N ***/
    memcpy( p, pcExpirationDate, 4 );
    p += 4;

    /*** Service Code, 3N ***/
    memcpy(p, pcServiceCode, 3);
    p += 3;

    iCmdLen = (int)(p - aucCmd);
    /*
     *rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
     */
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

int HSM_RCL_EncryptData(
    int iBlockFlg, int iAlgoMode,
    int iZekIdx, char *pcZekCipherByLmk,
    unsigned char *pucIv/*in&out*/, int iIvLength,
    unsigned char *pucInput, int iInputLength,
    unsigned char *pucOutput/*out*/, int *piOutputLength/*out*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 1984 + 128;
    unsigned char aucCmd[1968 + 128] = {0};
    unsigned char aucRsp[1984 + 128] = {0};
    unsigned char *p = aucCmd;

    if(iInputLength > 1968)
    {
        LOG_ERROR("Parameter: iInputLength = [%d] is invalid, it must be less than 1968.", iInputLength);
        return HAR_PARAM_LEN;
    }

    /*** Command Code    "E0" ***/
    *p ++ = 'E';
    *p ++ = '0';

    /*** 报文块标识, 1N ***/
    *p ++ = (unsigned char)(iBlockFlg + '0');

    /*** 运算标识, 1N, 0 - 加密; 1 - 解密 ***/
    *p ++ = '0';

    /*** 算法标识, 1N, 1 - ECB; 2 - CBC ***/
    *p ++ = (unsigned char)(iAlgoMode + '0');

    /*** 密钥类型, 1N, 0 - ZEK ***/
    *p ++ = '0';

    /*** ZEK ***/
    rv = Tools_AddFieldKey(iZekIdx, pcZekCipherByLmk, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iZekIdx or pcZekCipherByLmk is invalid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** 输入数据格式, 1N, 0 – Binary模式, 1 – Expanded Hex模式 ***/
    *p ++ = '0';

    /*** 输出数据格式, 1N, 0 – Binary模式, 1 – Expanded Hex模式 ***/
    *p ++ = '0';

    /*** Pad 模式+Pad 字符+Pad 计数标识, 采用PBOC MAC（强制填充80模式）***/
    memcpy(p, "180000", 6);
    p += 6;

    /*** IV ***/
    if (iAlgoMode != ENCRYPT_MODE_ECB)
    {
        memcpy(p, pucIv, iIvLength);
        p += iIvLength;
    }

    /*** 数据长度, 3H ***/
    TASS_SPRINTF((char*)p, 4, "%03X", iInputLength);
    p += 3;

    /*** 输入数据，nB ***/
    memcpy(p, pucInput, iInputLength);
    p += iInputLength;

    iCmdLen = (int)(p - aucCmd);
    /*
     *rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
     */
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** 输出数据的格式, 1N, 0 – Binary模式, 1 – Expanded Hex模式 ***/
    p ++;

    /*** 输出数据长度, 3H ***/
    len = Tools_ConvertHexBuf2Int(p, 3);
    if(piOutputLength)
    {
        *piOutputLength = len;
    }
    p += 3;

    /*** 输出数据，nB ***/
    if(pucOutput)
    {
        memcpy(pucOutput, p, *piOutputLength);
    }
    p += *piOutputLength;

    /*** iv ***/
    if ((iAlgoMode != ENCRYPT_MODE_ECB) && (iBlockFlg==1 || iBlockFlg ==2))
    {
        if(pucIv)
        {
            memcpy(pucIv, p, iIvLength);
        }
    }

    return HAR_OK;
}

int HSM_RCL_DecryptData(
    int iBlockFlg, int iAlgoMode,
    int iZekIdx, char *pcZekCipherByLmk,
    unsigned char *pucIv/*in&out*/, int iIvLength,
    unsigned char *pucInput, int iInputLength,
    unsigned char *pucOutput/*out*/, int *piOutputLength/*out*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 1968 + 128;
    unsigned char aucCmd[1984 + 128] = {0};
    unsigned char aucRsp[1968 + 128] = {0};
    unsigned char *p = aucCmd;

    if(iInputLength > 1984)
    {
        LOG_ERROR("Parameter: iInputLength = [%d] is invalid, it must be less than 1984.", iInputLength);
        return HAR_PARAM_LEN;
    }

    /*** Command Code    "E0" ***/
    *p ++ = 'E';
    *p ++ = '0';

    /*** 报文块标识, 1N ***/
    *p ++ = (unsigned char)(iBlockFlg + '0');

    /*** 运算标识, 1N, 0 - 加密; 1 - 解密 ***/
    *p ++ = '1';

    /*** 算法标识, 1N, 1 - ECB; 2 - CBC ***/
    *p ++ = (unsigned char)(iAlgoMode + '0');

    /*** 密钥类型, 1N, 0 - ZEK ***/
    *p ++ = '0';

    /*** ZEK*/
    rv = Tools_AddFieldKey(iZekIdx, pcZekCipherByLmk, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iZekIdx or pcZekCipherByLmk is invalid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** 输入数据格式, 1N, 0 – Binary模式, 1 – Expanded Hex模式 ***/
    *p ++ = '0';

    /*** 输出数据格式, 1N, 0 – Binary模式, 1 – Expanded Hex模式 ***/
    *p ++ = '0';

    /*** Pad 模式+Pad 字符+Pad 计数标识, 采用PBOC MAC（强制填充80模式）***/
    memcpy(p, "180000", 6);
    p += 6;

    /*** IV ***/
    if (iAlgoMode != ENCRYPT_MODE_ECB)
    {
        memcpy(p, pucIv, iIvLength);
        p += iIvLength;
    }

    /*** 数据长度, 3H ***/
    TASS_SPRINTF((char*)p, 4, "%03X", iInputLength);
    p += 3;

    /*** 输入数据，nB ***/
    memcpy(p, pucInput, iInputLength);
    p += iInputLength;

    iCmdLen = (int)(p - aucCmd);
    /*
     *rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
     */
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** 输出数据的格式, 1N, 0 – Binary模式, 1 – Expanded Hex模式 ***/
    p ++;

    /*** 输出数据长度, 3H ***/
    len = Tools_ConvertHexBuf2Int(p, 3);
    if(piOutputLength)
    {
        *piOutputLength = len;
    }
    p += 3;

    /*** 输出数据，nB ***/
    if(pucOutput)
    {
        memcpy(pucOutput, p, *piOutputLength);
    }
    p += *piOutputLength;

    /*** iv ***/
    if ((iAlgoMode != ENCRYPT_MODE_ECB) && (iBlockFlg==1 || iBlockFlg ==2))
    {
        if(pucIv)
        {
            memcpy(pucIv, p, iIvLength);
        }
    }

    return HAR_OK;
}

int HSM_RCL_ZpkGenCbcMac(
    int iBlockFlg,
    int iZpkIdx, char *pcZpkCipherByLmk,
    unsigned char *pucIv/*in&out*/, int iIvLength,
    unsigned char *pucInput, int iInputLength,
    int iMacLen,
    char *pcOutput/*out*/)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[4095 + 128] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    if(iInputLength > 4095)
    {
        LOG_ERROR("Parameter: iInputLength = [%d] is invalid, it must be less than 4095.", iInputLength);
        return HAR_PARAM_LEN;
    }

    /*** Command Code    "UQ" ***/
    *p ++ = 'U';
    *p ++ = 'Q';

    /*** 报文块标识, 1N ***/
    *p ++ = (unsigned char)(iBlockFlg + '0');

    /*** ZPK ***/
    rv = Tools_AddFieldKey(iZpkIdx, pcZpkCipherByLmk, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iZpkIdx or pcZpkCipherByLmk is invalid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** IV ***/
    if(iBlockFlg == 2 || iBlockFlg == 3)
    {
        memcpy(p, pucIv, iIvLength);
        p += iIvLength;
    }

    /*** 数据长度, 3H ***/
    TASS_SPRINTF((char*)p, 4, "%03X", iInputLength);
    p += 3;

    /*** 输入数据，nB ***/
    memcpy(p, pucInput, iInputLength);
    p += iInputLength;

    /*** 输出的MAC长度, 2H ***/
    TASS_SPRINTF((char*)p, 3, "%02X", iMacLen);
    p += 2;

    iCmdLen = (int)(p - aucCmd);
    /*
     *rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
     */
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** 输出数据，n*2H ***/
    if(pcOutput)
    {
        strncpy(pcOutput, (char *)p, iRspLen);
    }

    return HAR_OK;
}

/**********************************
* 接口名称 ：ZAK/TAK 产生X9.9和X9.19的报文MAC
* 使用指令：MS
* 修改记录：
*         20140830 - 增加IV参数，并修改数据长度参数
*/
int HSM_RCL_ZakAndTakGenCbcMac(
            int iBlockFlg, int iKeyType,
            int iKeyLength,int iDataType,
            int iKeyIdx, char *pcKey_Lmk,
            unsigned char *pucIv, int iIvLength,
            unsigned char *pucInput, int iInputLength,
            unsigned char *pucOutput/*out*/, int *piOutputLength/*out*/)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 64;
    unsigned char aucCmd[4096 + 128] = {0};
    unsigned char aucRsp[64] = {0};
    unsigned char *p = aucCmd;

    if(iInputLength > 4096)
    {
        LOG_ERROR("Parameter: iInputLength = [%d] is invalid, it must be less than 4096.", iInputLength);
        return HAR_PARAM_LEN;
    }

    /*** Command Code    "MS" ***/
    *p ++ = 'M';
    *p ++ = 'S';

    /*** 报文块标识, 1N ***/
    *p ++ = (unsigned char)(iBlockFlg + '0');

    /*** 密钥类型, 1N,  0 – TAK    1 – ZAK ***/
    *p ++ = (unsigned char)(iKeyType + '0');

    /*** 密钥长度, 1N, 0 – 8字节，单长度DES密钥        1 – 16字节，双长度DES、SM1、SM4、AES密钥 ***/
    *p ++ = (unsigned char)(iKeyLength + '0');

    /*** 数据类型, 1N, 0 – 二进制            1 – 扩展十六进制 ***/
    *p ++ = (unsigned char)(iDataType + '0');

    /*** KEY ***/
    rv = Tools_AddFieldKey(iKeyIdx, pcKey_Lmk, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iKeyIdx or pcKey_Lmk is invalid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** IV ***/
    memcpy((char*)p, pucIv, iIvLength);
    p += iIvLength;

    /*** 数据长度, 4H ***/
    TASS_SPRINTF((char*)p, 5, "%04X", iInputLength);
    p += 4;

    /*** 输入数据，nB ***/
    memcpy(p, pucInput, iInputLength);
    p += iInputLength;

    iCmdLen = (int)(p - aucCmd);
    /*
     *rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
     */
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** 输出的数据长度 ***/
    if(piOutputLength)
    {
        *piOutputLength = iRspLen;
    }

    /*** 输出数据，nB ***/
    if(pucOutput)
    {
        memcpy(pucOutput, p, *piOutputLength);
    }

    return HAR_OK;
}


int HSM_RCL_GenWorkingKey(
    void *hSessionHandle,int nSock,
    int iGeneratMode, char *pcKeyType, char cKeyFlg_Lmk,
    int iZmkIdx, char *pcZmkCipher, char cKeyFlg_Zmk, char cKeyStorageFlg,
    int iKeyIdx, char *pcKeyTag, char *pcKeyCipherByLmk/*OUT*/,
    char *pcKeyCipherByZmk/*OUT*/, char *pcKeyCv/*OUT*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[128] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "A0" ***/
    *p ++ = 'A';
    *p ++ = '0';

    /*** 产生模式    0 - 产生密钥        1 - 产生密钥并在ZMK下加密 ***/
    *p ++= (unsigned char)(iGeneratMode + '0');

    /*** 工作密钥类型 ***/
    memcpy(p, pcKeyType, strlen(pcKeyType));
    p += strlen(pcKeyType);

    /*** 密钥标识 ***/
    *p ++ = cKeyFlg_Lmk;

    if(iGeneratMode == 1)
    {
        /*** ZMK密钥 ***/
        rv = Tools_AddFieldKey(iZmkIdx, pcZmkCipher, p);
        if (rv == HAR_PARAM_VALUE)
        {
            LOG_ERROR("%s", "Parameter: iZmkIdx or pcZmkCipher is invalid.");
            return HAR_PARAM_KEY_ID;
        }
        p += rv;

        /*** 密钥标识 ***/
        *p ++=  cKeyFlg_Zmk;
    }

    if(cKeyStorageFlg == 'K')
    {
        /*** 密钥存储标识 ***/
        *p ++= cKeyStorageFlg;

        /*** 密钥索引 ***/
        TASS_SPRINTF((char*)p, 5, "%04d", iKeyIdx);
        p += 4;

        /*** 密钥标签长度 ***/
        TASS_SPRINTF((char*)p, 3, "%02d", (int)strlen(pcKeyTag));
        p += 2;

        /*** 密钥标签 ***/
        memcpy(p, pcKeyTag, strlen(pcKeyTag));
        p += strlen(pcKeyTag);
    }

    iCmdLen = (int)(p - aucCmd);
    rv = TCP_CommunicateHsm_ex(hSessionHandle,aucCmd, iCmdLen, aucRsp, &iRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    if(iGeneratMode)
    {
        /*** LMK下加密的密文 ***/
        len = Tools_GetFieldKeyLength((char *)p);
        if(pcKeyCipherByLmk)
        {
            strncpy(pcKeyCipherByLmk, (char *)p, len);
        }
        p += len;

        /*** ZMK下加密的密文 ***/
        len = Tools_GetFieldKeyLength((char *)p);
        if(pcKeyCipherByZmk)
        {
            strncpy(pcKeyCipherByZmk, (char *)p, len);
        }
        p += len;
    }
    else
    {
        /*** LMK下加密的密文 ***/
        len = Tools_GetFieldKeyLength((char *)p);
        if(pcKeyCipherByLmk)
        {
            strncpy(pcKeyCipherByLmk, (char *)p, len);
        }
        p += len;
    }

    /*** 密钥校验值 ***/
    if(pcKeyCv)
    {
        strncpy(pcKeyCv, (char *)p, 16);
    }

    return HAR_OK;
}

int HSM_RCL_ImportKey_A6(
    void *hSessionHandle,int nSock,
    char *pcKeyType, int iZmkIdx, char *pcZmkCipher,
    char *pcKeyCipherByZmk, char cKeyFlg_Lmk, char cKeyStorageFlg,
    int iKeyIdx, char *pcKeyTag, char *pcKeyCipherByLmk/*OUT*/,
    char *pcKeyCv/*OUT*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[128] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "A6" ***/
    *p ++ = 'A';
    *p ++ = '6';

    /*** 工作密钥类型 ***/
    memcpy(p, pcKeyType, strlen(pcKeyType));
    p += strlen(pcKeyType);

    /*** ZMK密钥 ***/
    rv = Tools_AddFieldKey(iZmkIdx, pcZmkCipher, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iZmkIdx or pcZmkCipher is invalid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** ZMK下加密的密文 ***/
    memcpy(p, pcKeyCipherByZmk, strlen(pcKeyCipherByZmk));
    p += strlen(pcKeyCipherByZmk);

    /*** 密钥标识 ***/
    *p ++ = cKeyFlg_Lmk;

    if(cKeyStorageFlg == 'K')
    {
        rv = Tools_AddFieldSavedKey(iKeyIdx, pcKeyTag, p);
        if(rv == HAR_PARAM_VALUE)
        {
            LOG_ERROR("Parameter: pcKeyTag length = [%d] is invalid.", strlen(pcKeyTag));
            return rv;
        }
        p += rv;
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

    /*** LMK下加密的密文 ***/
    len = Tools_GetFieldKeyLength((char *)p);
    if(pcKeyCipherByLmk)
    {
        strncpy(pcKeyCipherByLmk, (char *)p, len);
    }
    p += len;

    /*** 密钥校验值 ***/
    if(pcKeyCv)
    {
        strncpy(pcKeyCv, (char *)p, 16);
    }

    return HAR_OK;
}

int HSM_RCL_ExportKey_A8(
    char *pcKeyType, int iZmkIdx, char *pcZmkCipher,
    int iKeyIdx, char *pcKeyCipherByLmk, char cKeyFlg_Zmk,
    char *pcKeyCipherByZmk/*OUT*/,
    char *pcKeyCv/*OUT*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[128] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "A8" ***/
    *p ++ = 'A';;
    *p ++ = '8';

    /*** 工作密钥类型 ***/
    memcpy(p, pcKeyType, strlen(pcKeyType));
    p += strlen(pcKeyType);

    /*** ZMK密钥 ***/
    rv = Tools_AddFieldKey(iZmkIdx, pcZmkCipher, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iZmkIdx or pcZmkCipher is invalid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** LMK下加密的密文 ***/
    rv = Tools_AddFieldKey(iKeyIdx, pcKeyCipherByLmk, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iKeyIdx or pcKeyCipherByLmk is invalid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** 密钥标识 ***/
    *p ++ = cKeyFlg_Zmk;

    iCmdLen = (int)(p - aucCmd);
    /*
     *rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
     */
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** ZMK下加密的密文 ***/
    len = Tools_GetFieldKeyLength((char *)p);
    if(pcKeyCipherByZmk)
    {
        strncpy(pcKeyCipherByZmk, (char *)p, len);
    }
    p += len;

    /*** 密钥校验值 ***/
    if(pcKeyCv)
    {
        strncpy(pcKeyCv, (char *)p, 16);
    }

    return HAR_OK;
}


int HSM_RCL_LoadFormatData(char* pcFormatData)
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[1024 + 2] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    if(pcFormatData == NULL)
    {
        LOG_ERROR("Parameter: pcFormatData = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcFormatData) > 1024)
    {
        LOG_ERROR("Parameter: pcFormatData length = [%d] is invalid.", strlen(pcFormatData));
        return HAR_PARAM_LEN;
    }

    /*** Command Code    "PA" ***/
    *p ++ = 'P';
    *p ++ = 'A';

    /*** 格式数据 ***/
    memcpy(p, pcFormatData, strlen(pcFormatData));
    p += strlen(pcFormatData);

    iCmdLen = (int)(p - aucCmd);
    /*
     *rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
     */
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}


int HSM_RCL_GenAndPrintKeyElement(char* pcKeyType, char cKeyFlg, char* pcPrintDomain, char* pcKeyCipherByLmk/*OUT*/, char* pcKCV/*OUT*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[1024 + 6] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    if(pcKeyType == NULL)
    {
        LOG_ERROR("Parameter: pcKeyType = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcKeyType) != 3)
    {
        LOG_ERROR("Parameter: pcKeyType length = [%d] is invalid.", strlen(pcKeyType));
        return HAR_PARAM_LEN;
    }

    if(pcPrintDomain == NULL)
    {
        LOG_ERROR("Parameter: pcPrintDomain = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcPrintDomain) > 1024)
    {
        LOG_ERROR("Parameter: pcPrintDomain = [%d] is invalid.", strlen(pcPrintDomain));
        return HAR_PARAM_ISNULL;
    }

    /*** Command Code    "A2" ***/
    *p ++ = 'A';
    *p ++ = '2';

    /*** 工作密钥类型 ***/
    memcpy(p, pcKeyType, strlen(pcKeyType));
    p += strlen(pcKeyType);

    /*** 密钥标识（LMK）***/
    *p++ = cKeyFlg;

    /*** 打印域 ***/
    memcpy(p, pcPrintDomain, strlen(pcPrintDomain));
    p += strlen(pcPrintDomain);

    iCmdLen = (int)(p - aucCmd);
    /*
     *rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
     */
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** 密钥密文(LMK) ***/
    len = Tools_GetFieldKeyLength((char *)p);
    if(pcKeyCipherByLmk)
    {
        strncpy(pcKeyCipherByLmk, (char *)p, len);
    }
    p += len;

    /*** 密钥校验值 ***/
    if(pcKCV)
    {
        strncpy(pcKCV, (char *)p, 8);
    }

    return HAR_OK;
}

int HSM_RCL_SyntheticKey_KeyCipher(int iElementNum, char* pcKeyType, char cKeyFlg,
    char* pcKeyElemnet, char* pcKeyCipherByLmk/*OUT*/, char* pcKCV/*OUT*/)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[1024 + 6] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    if(iElementNum < 2 || iElementNum > 8)
    {
        LOG_ERROR("Parameter: iElementNum = [%d] is invalid.It must be 2 -- 8.", iElementNum);
        return HAR_PARAM_ELEMENT_NUM;
    }

    if(pcKeyType == NULL)
    {
        LOG_ERROR("Parameter: pcKeyType = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcKeyType) != 3)
    {
        LOG_ERROR("Parameter: pcKeyType length = [%d] is invalid.", strlen(pcKeyType));
        return HAR_PARAM_LEN;
    }

    if(pcKeyElemnet == NULL)
    {
        LOG_ERROR("Parameter: pcKeyElemnet = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcKeyElemnet) > 1024)
    {
        LOG_ERROR("Parameter: pcKeyElemnet = [%d] is invalid.", strlen(pcKeyElemnet));
        return HAR_PARAM_ISNULL;
    }

    if(pcKeyCipherByLmk == NULL)
    {
        LOG_ERROR("Parameter: pcKeyCipherByLmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(pcKCV == NULL)
    {
        LOG_ERROR("Parameter: pcKCV = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    /*** Command Code    "A4" ***/
    *p ++ = 'A';
    *p ++ = '4';

    /*** 密钥成分 ***/
    *p ++ = iElementNum + '0';

    /*** 密钥类型 ***/
    memcpy(p, pcKeyType, strlen(pcKeyType));
    p += strlen(pcKeyType);

    /*** 密钥标识（LMK）***/
    *p++ = cKeyFlg;

    /*** 密钥成份 ***/
    memcpy(p, pcKeyElemnet, strlen(pcKeyElemnet));
    p += strlen(pcKeyElemnet);

    iCmdLen = (int)(p - aucCmd);
    /*
     *rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
     */
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** 密钥密文(LMK) ***/
    len = Tools_GetFieldKeyLength((char *)p);
    if(pcKeyCipherByLmk)
    {
        strncpy(pcKeyCipherByLmk, (char *)p, len);
    }
    p += len;

    /*** 密钥校验值 ***/
    if(pcKCV)
    {
        strncpy(pcKCV, (char *)p, 8);
    }

    return HAR_OK;
}

int HSM_RCL_KeyTypeConversion(
    void *hSessionHandle,int nSock,
    char *pcSrcKeyType,
    int  iSrcKeyIdx,
    char *pcSrcKeyCipherByLmk,
    char *pcDstKeyType,
    char cDstScheme,  /***算法标识***/
    char *pcDstKeyCipherByLmk/*OUT*/,
    char *pcDstKeyCv/*OUT*/ )
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[128] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "AN" ***/
    *p ++ = 'A';
    *p ++ = 'N';

    /*** 源密钥类型 ***/
    memcpy(p, pcSrcKeyType, strlen(pcSrcKeyType));
    p += strlen( pcSrcKeyType );

    /*** 源密钥 1A+32H/1A+16H/1A+48H***/
    rv = Tools_AddFieldKey(iSrcKeyIdx, pcSrcKeyCipherByLmk, p);
    if (rv == HAR_PARAM_VALUE)
    {
        LOG_ERROR("%s", "Parameter: iSrcKeyIdx or pcSrcKeyCipherByLmk is invalid.");
        return HAR_PARAM_KEY_ID;
    }
    p += rv;

    /*** 目的密钥类型 ***/
    memcpy(p, pcDstKeyType, strlen( pcDstKeyType ));
    p += strlen( pcDstKeyType );

    /*** 目的密钥算法标识 ***/
    *p ++ = cDstScheme;

    iCmdLen = (int)(p - aucCmd);

    rv = TCP_CommunicateHsm_ex(hSessionHandle,aucCmd, iCmdLen, aucRsp, &iRspLen);
     
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** LMK下加密的密文 1A+32H/1A+16H/1A+48H***/
    if(pcDstKeyCipherByLmk)
    {
        strncpy(pcDstKeyCipherByLmk, p, iRspLen - 16);
    }
    p += iRspLen - 16;

    /*** 密钥校验值 ***/
    strncpy(pcDstKeyCv, p + iRspLen - 16, 16);

    return HAR_OK;
}


int HSM_RCL_SynthesisKeyByPlaintext(
    char *pcKeyType,
    char cDstScheme,
    int  iElementCount,
    char *pcElement,
    int  iKeyIdx,
    char *pcKeyLabel,
    char *pcKeyCipherByLmk/*OUT*/,
    char *pcKeyCv/*OUT*/ )
{
    int rv = HAR_OK;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[1024] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "AM" ***/
    *p ++ = 'A';
    *p ++ = 'M';

    /*** 密钥类型 ***/
    memcpy(p, pcKeyType, strlen(pcKeyType));
    p += strlen(pcKeyType);

    /*** 密钥算法标识 ***/
    *p ++ = cDstScheme;

    /*** 密钥合成方式 ***/
    memcpy(p, "00", 2);
    p += 2;

    /*** 密钥成份个数 ***/
    TASS_SPRINTF((char*)p, 3, "%02d", iElementCount);
    p += 2;

    /*** 密钥成份 ***/
    memcpy(p, pcElement, strlen(pcElement));
    p += strlen(pcElement);

    /*** 密钥存储标识 ***/
    if(iKeyIdx)
    {
        rv = Tools_AddFieldSavedKey(iKeyIdx, pcKeyLabel, p);
        if(rv == HAR_PARAM_VALUE)
        {
            LOG_ERROR("Parameter: pcKeyLabel length = [%d] is invalid.", strlen(pcKeyLabel));
            return rv;
        }
        p += rv;
    }

    iCmdLen = (int)(p - aucCmd);
    /*
     *rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
     */
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    /*** LMK下加密的密文 ***/
    strncpy( pcKeyCipherByLmk, p, iRspLen - 16 );

    /*** 密钥校验值 ***/
    strncpy( pcKeyCv, p + iRspLen - 16, 16);

    return HAR_OK;
}

int HSM_RCL_GenAndPrintKey(int iGenMode,
                char *pcKeyType,
                char cKeyScheme,
                int  iKeyComponentLen,
                int  iKeyCvAlg,
                int  iGetKeyCvType,
                char *pcPrintDomain,
                char *pcKeyCipher,
                char *pcKeyCv)
{
    int rv = HAR_OK;
    int len = 0;
    int iCmdLen;
    int iRspLen = 128;
    unsigned char aucCmd[1024] = {0};
    unsigned char aucRsp[128] = {0};
    unsigned char *p = aucCmd;

    /*** Command Code    "A3" ***/
    *p ++ = 'A';
    *p ++ = '3';

    /*** 生成模式 ***/
    *p ++ = '0' + iGenMode;

    if(iGenMode)
    {
        /*** 密钥分量长度 ***/
        *p ++ = '0' + iKeyComponentLen;
    }
    else
    {
        /*** 密钥类型 ***/
        memcpy(p, pcKeyType, 3);
        p += 3;

        /*** 密钥算法标识 ***/
        *p ++ = cKeyScheme;
    }

    /*** 校验值算法标识 ***/
    TASS_SPRINTF((char *)p, 3, "%02d", iKeyCvAlg);
    p += 2;

    /*** 校验值取值方式 ***/
    TASS_SPRINTF((char *)p, 3, "%02d", iGetKeyCvType);
    p += 2;

    /*** 打印域 ***/
    memcpy(p, pcPrintDomain, (int)strlen(pcPrintDomain));
    p += strlen(pcPrintDomain);

    iCmdLen = (int)(p - aucCmd);
    /*
     *rv = TCP_CommunicateHsm(aucCmd, iCmdLen, aucRsp, &iRspLen);
     */
    if(rv)
    {
        LOG_ERROR("Communicate with Hsm error, return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    /*** Response Buffer ***/
    p = aucRsp;

    if(iGenMode)
    {
        /*** 密钥分量,长度由密钥分量长度域决定 ***/
        len = iKeyComponentLen * 2;
    }
    else
    {
        /*** 密钥分量密文（LMK） ***/
        len = Tools_GetFieldKeyLength((char*)p);

    }

    /*** 密钥分量密文 ***/
    if(pcKeyCipher)
    {
        strncpy(pcKeyCipher, (char *)p, len);
    }
    p += len;

    if(pcKeyCv)
    {
        /*** 密钥校验值 ***/
        strncpy(pcKeyCv, (char *)p, 16);
    }

    return HAR_OK;
}

