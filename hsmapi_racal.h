/*----------------------------------------------------------------------|
|    hsmapi_racal.h                                                     |
|    Version :     1.0                                                  |
|    Author:       Luo Cangjian                                         |
|    Description:  SJJ1310密码机接口雷卡兼容主机命令函数                |
|                                                                       |
|    Copyright :   Beijing JN TASS Technology Co., Ltd.                 |
|    data:         2015-06-03. Create                                   |
|-----------------------------------------------------------------------|
|    Modify History:                                                    |
|----------------------------------------------------------------------*/
#ifndef __HSM_API_RACAL_H__
#define __HSM_API_RACAL_H__

int HSM_RCL_GenerateRandomPin(char *pcPAN, int iPinLength, char *pcPinCipherByLmk/*out*/);

int HSM_RCL_EncryptPin_LMK(char *pcPlainPin, char *pcPAN, char *pcPinCipherByLmk/*out*/);

int HSM_RCL_DecryptPin_LMK(void *hSessionHandle,char *pcPinCipherByLmk, char *pcPAN, char *pcPlainPin/*out*/);

int HSM_RCL_TransferCipherPin_Lmk2Zpk(
    void *hSessionHandle,
    int iZpkIdx, char *pcZpkCipherByLmk, int iPinFmt,
    char *pcPAN, char *pcPinCipherByLmk, char *pcPinCipherByZpk/*out*/);

int HSM_RCL_TransferCipherPin_Zpk2Lmk(
    void *hSessionHandle,
    int iZpkIdx, char *pcZpkCipherByLmk, int iPinFmt,
    char *pcPAN, char *pcPinCipherByZpk, char *pcPinCipherByLmk/*out*/);

int HSM_RCL_TransferCipherPin_Zpk2Zpk(
    int iSrcZpkIdx, char *pcSrcZpkCipherByLmk, int iDstZpkIdx, char *pcDstZpkCipherByLmk,
    int iSrcPinFmt, int iDstPinFmt,
    char *pcSrcPAN, char *pcDstPAN,
    char *pcSrcPinCipherByZpk, char *pcDstPinCipherByZpk/*out*/ );

int HSM_RCL_GenerateIBMPinOffset(
    int iPvkIdx, char *pcPvkCipherByLmk,
    char *pcPinCipherByLmk, int iMinLength,
    char *pcPAN, char *pcDecimalTable, char *pcPinVerifyData,
    char *pcPinOffset/*out*/);

int HSM_RCL_VerifyZonePinBlock_PinOffset(
    int iZpkIdx, char *pcZpkCipherByLmk,
    int iPvkIdx, char *pcPvkCipherByLmk,
    char *pcPinBlock_Zpk, int iPinFormat, int iMinLength,
    char *pcPAN, char *pcDecimalTable, char *pcPinVerifyData,
    char *pcPinOffset);

int HSM_RCL_GeneratePVV(
    int iPvkIdx, char *pcPvkCipherByLmk, int iPvkID,
    char *pcPinCipherByLmk, char *pcPAN,
    char *pcPVV/*out*/);

int HSM_RCL_GenerateCVV(
    int iCvkIdx, char *pcCvk_Lmk,
    char *pcPAN, char *pcExpirationDate, char *pcServiceCode,
    char *pcCVV/*out*/);

int HSM_RCL_VerifyCVV(
    int iCvkIdx, char *pcCvk_Lmk,
    char *pcPAN, char *pcExpirationDate, char *pcServiceCode,
    char *pcCVV);

int HSM_RCL_EncryptData(
    int iBlockFlg, int iAlgoMode,
    int iZekIdx, char *pcZekCipherByLmk,
    unsigned char *pucIv/*in&out*/, int iIvLength,
    unsigned char *pucInput, int iInputLength,
    unsigned char *pucOutput/*out*/, int *piOutputLength/*out*/);

int HSM_RCL_DecryptData(
    int iBlockFlg, int iAlgoMode,
    int iZekIdx, char *pcZekCipherByLmk,
    unsigned char *pucIv/*in&out*/, int iIvLength,
    unsigned char *pucInput, int iInputLength,
    unsigned char *pucOutput/*out*/, int *piOutputLength/*out*/);

int HSM_RCL_ZpkGenCbcMac(
    int iBlockFlg,
    int iZpkIdx, char *pcZpkCipherByLmk,
    unsigned char *pucIv/*in&out*/, int iIvLength,
    unsigned char *pucInput, int iInputLength,
    int iMacLen,
    char *pcOutput/*out*/);

int HSM_RCL_ZakAndTakGenCbcMac(
            int iBlockFlg, int iKeyType,
            int iKeyLength,int iDataType,
            int iKeyIdx, char *pcKey_Lmk,
            unsigned char *pucIv, int iIvLength,
            unsigned char *pucInput, int iInputLength,
            unsigned char *pucOutput/*out*/, int *piOutputLength/*out*/);


int HSM_RCL_GenWorkingKey(
    void *hSessionHandle,
    int iGeneratMode, char *pcKeyType, char cKeyFlg_Lmk,
    int iZmkIdx, char *pcZmkCipher, char cKeyFlg_Zmk, char cKeyStorageFlg,
    int iKeyIdx, char *pcKeyTag, char *pcKeyCipherByLmk/*OUT*/,
    char *pcKeyCipherByZmk/*OUT*/, char *pcKeyCv/*OUT*/);

int HSM_RCL_ImportKey_A6(
    void *hSessionHandle,
    char *pcKeyType, int iZmkIdx, char *pcZmkCipher,
    char *pcKeyCipherByZmk, char cKeyFlg_Lmk, char cKeyStorageFlg,
    int iKeyIdx, char *pcKeyTag, char *pcKeyCipherByLmk/*OUT*/,
    char *pcKeyCv/*OUT*/);

int HSM_RCL_ExportKey_A8(
    char *pcKeyType, int iZmkIdx, char *pcZmkCipher,
    int iKeyIdx, char *pcKeyCipherByLmk, char cKeyFlg_Zmk,
    char *pcKeyCipherByZmk/*OUT*/,
    char *pcKeyCv/*OUT*/);

int HSM_RCL_LoadFormatData(char* pcFormatData);


int HSM_RCL_GenAndPrintKeyElement(char* pcKeyType, char cKeyFlg, char* pcPrintDomain, char* pcKeyCipherByLmk/*OUT*/, char* pcKCV/*OUT*/);

int HSM_RCL_SyntheticKey_KeyCipher(int iElementNum, char* pcKeyType, char cKeyFlg,
    char* pcKeyElemnet, char* pcKeyCipherByLmk/*OUT*/, char* pcKCV/*OUT*/);

int HSM_RCL_KeyTypeConversion(
    void *hSessionHandle,
    char *pcSrcKeyType,
    int  iSrcKeyIdx,
    char *pcSrcKeyCipherByLmk,
    char *pcDstKeyType,
    char cDstScheme,
    char *pcDstKeyCipherByLmk/*OUT*/,
    char *pcDstKeyCv/*OUT*/ );


int HSM_RCL_SynthesisKeyByPlaintext(
    char *pcKeyType,
    char cDstScheme,
    int  iElementCount,
    char *pcElement,
    int  iKeyIdx,
    char *pcKeyLabel,
    char *pcKeyCipherByLmk/*OUT*/,
    char *pcKeyCv/*OUT*/ );

int HSM_RCL_GenAndPrintKey(int iGenMode,
                char *pcKeyType,
                char cKeyScheme,
                int  iKeyComponentLen,
                int  iKeyCvAlg,
                int  iGetKeyCvType,
                char *pcPrintDomain,
                char *pcKeyCipher,
                char *pcKeyCv);

#endif /*__HSM_API_RACAL_H__*/
