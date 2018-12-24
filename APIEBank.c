/*----------------------------------------------------------------------|
|    hsmapi.c                                                           |
|    Version :     1.0                                                  |
|    Author:       Luo Cangjian                                         |
|    Description:  SJJ1310密码机金融交易通用接口                        |
|                                                                       |
|    Copyright :   Beijing JN TASS Technology Co., Ltd.                 |
|    data:         2015-06-05. Create                                   |
|-----------------------------------------------------------------------|
|    Modify History: TODO:密钥长度，以及数据长度的判断还需进一步检查。  |
|----------------------------------------------------------------------*/
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <string.h>
#include <stdbool.h>

#include "APIEBank.h"
#include "hsmapi_define.h"
#include "hsmapi_log.h"
#include "hsmapi_tools.h"
#include "hsmapi_init.h"
#include "hsmapi_ic.h"
#include "hsmapi_racal.h"
#include "hsmapi_asym.h"
#include "hsmapi_base.h"
#include "hsmapi_rsa.h"
#include "hsmapi_extend.h"
#include "hsmapi_magnet.h"
#include "hsmsocket.h"
#include "internal_structs.h"
#include "frmMutex.h"

#ifdef _MSC_VER
#pragma warning(disable:4996)
#endif

extern int g_iLogLevel;

FRMHANDLE_Mutex pstKeyPwdMutex;
int iKeyIdx = 0;
char pcKeyPassword[16] = { 0 };

FRMHANDLE_Mutex pstHashMutex;
int iHashAlgType = 0;
int iHashDataLength = 0;
unsigned char pucHashData[256] = { 0 };

typedef struct
{
    char cSymmAlg;
    int iKeyType_Tag;
    char pcKeyCipherByHMK[128];
    char pcKCV[32];
} _keyInfo;

/**
 * @brief   打开设备句柄，phDeviceHandle 由函数初始化并填写内容 
 *
 * @param   phDeviceHandle      [out]   返回设备句柄
 * @param   ipaddr              [in]    密码设备IP
 * @param   port 密码设备端口
 *
 * @return  0,成功
 */
int SDF_OpenDevice(
        void **phDeviceHandle,
        char *ipaddr,
        int port )
{
    int rt=0;
    Devicestruct *pDeviceStruct;
    char szLogLevel[64 + 1] = {0};

    if(ipaddr == NULL)
    {
        return HAR_PARAM_ISNULL;
    }

    if(port < 0)
    {
        return HAR_PARAM_VALUE;
    }

    if( *phDeviceHandle != NULL /*&& ((Devicestruct*)(*phDeviceHandle))->status == 1*/ )
    {
        SDF_CloseDevice( phDeviceHandle );
    }

    pDeviceStruct = (Devicestruct*)malloc( sizeof(Devicestruct) );

    memset( pDeviceStruct, 0, sizeof(Devicestruct) );
    strncpy( pDeviceStruct->ip, ipaddr, 16 );
    pDeviceStruct->port = port;

    pDeviceStruct->sockfd = TCP_ConnectHsm( pDeviceStruct->ip, pDeviceStruct->port );
    printf("pDeviceStruct->ip is %d, pDeviceStruct->port is %d \n",pDeviceStruct->status,pDeviceStruct->port);
  //  pDeviceStruct->sockfd = ConnectTcpServer(pDeviceStruct->ip, pDeviceStruct->port, &(pDeviceStruct->sockfd));  //zhaomx  2017-6-5
   
    if( (pDeviceStruct->sockfd) <= 0 )
    {
        LOG_ERROR( "%s, Error TCP_ConnectHsm return [%d].",
                __func__, pDeviceStruct->sockfd );
        rt = HAR_SOCK_CONNECT;
    }
    else
    {
        pDeviceStruct->status = 1;
        *phDeviceHandle = pDeviceStruct;
        printf("((Devicestruct*)(*phDeviceHandle))->status is %d, ((Devicestruct*)(*phDeviceHandle))->port is %d \n",((Devicestruct*)(*phDeviceHandle))->status,((Devicestruct*)(*phDeviceHandle))->port);

        rt = SDR_OK;
    }
    printf("2222222222222222222222222222\n");
    //获取环境变量中日志级别
    if(getenv("TASSDBGLEVEL") != NULL)
    {
        strcpy(szLogLevel, getenv("TASSDBGLEVEL"));
    }
    else
    {
        strcpy(szLogLevel, "error");
    }

    //判断日志级别
    if(!strcmp(szLogLevel, "trace"))
    {
        //trace日志
        g_iLogLevel = 1;
    }
    else
    {
        //错误日志
        g_iLogLevel = 0;
    }
    rt = tafrm_CreateMutex(&pstKeyPwdMutex);
    if (rt != 0 || pstKeyPwdMutex == NULL)
    {
        rt = HAR_MUTEX_CREATE;
    }


    iKeyIdx = 0;
    memset(pcKeyPassword, '\0', 16);
    rt = tafrm_CreateMutex(&pstHashMutex);
    if (rt != 0 || pstHashMutex == NULL)
    {
        rt = HAR_MUTEX_CREATE;
    }

    iHashDataLength = 0;
    memset(pucHashData, '\0', 16);
    printf("33333333333333333 %d\n",rt);
    return rt;
}

int SDF_CloseDevice(
        void *hDeviceHandle)
{
    int rt=0;
    Devicestruct *pDeviceStruct = (Devicestruct*)hDeviceHandle;

    if( pDeviceStruct != NULL && pDeviceStruct->status == 1 )
    {
        pDeviceStruct = (Devicestruct*)hDeviceHandle;
        TCP_DisconnectHsm( pDeviceStruct->sockfd );
       // DisconnectTcpServer(pDeviceStruct->sockfd);    //zhaomx   2017-06-05
        pDeviceStruct->status = 2;
        free(pDeviceStruct);
    }
    tafrm_DestroyMutex(pstKeyPwdMutex);
    pstKeyPwdMutex = NULL;
    return rt;
}

int SDF_OpenSession(
        void *hDeviceHandle,
        void **phSessionHandle)
{
    int rt=SDR_OK;
    Devicestruct* pDeviceStruct = (Devicestruct*)hDeviceHandle;
    Sessionstruct* pSessionStruct = NULL;

    printf("44444444444444444444444\n");
    
   /* if( pDeviceStruct == NULL || pDeviceStruct->status != 1 )
    {
        rt = HAR_DEVICEHANDLE_INVALID;
        LOG_ERROR( "%s, Error [%#X], DeviceHandle Inalid.", __func__, rt );
        return rt;
    }*/
    printf("44444444444444444444444\n");
    if( *phSessionHandle == NULL || ((Sessionstruct*)*phSessionHandle)->status != 1 )
    {
        pSessionStruct = (Sessionstruct*)malloc(sizeof(Sessionstruct));
        pSessionStruct->device = (Devicestruct*)hDeviceHandle;
        pSessionStruct->status = 1;
        pSessionStruct->hashCtx.m_uiMechanism = -1;
        *phSessionHandle = (void*)pSessionStruct;

    }
    if ( ((Sessionstruct*)*phSessionHandle)->status == 1 && ((Sessionstruct*)*phSessionHandle)->device != hDeviceHandle )
    {
        pSessionStruct->device = (Devicestruct*)hDeviceHandle;
    }

    return rt;
}

int SDF_CloseSession(
        void *hSessionHandle)
{
    int rt=SDR_OK;
    Sessionstruct* pSessionStruct = (Sessionstruct*)hSessionHandle;

    if( pSessionStruct != NULL && pSessionStruct->status == 1 )
    {
        if( pSessionStruct->hashCtx.m_uiMechanism != -1 )
        {
            free(pSessionStruct->hashCtx.pucData);
            free(pSessionStruct->hashCtx.pucHash);
            pSessionStruct->hashCtx.m_uiMechanism = -1;
        }
        pSessionStruct->status = 2;
        pSessionStruct->device = NULL;
        free(pSessionStruct);
    }

    return rt;
}

int SDF_Decrypt (
        void *hSessionHandle,
        void *hKeyHandle,
        unsigned int uiAlgID,
        unsigned char *pucIV,
        unsigned char *pucEncData,
        unsigned int uiEncDataLength,
        unsigned char *pucData,
        unsigned int *puiDataLength)
{
    // TODO 7.3.6 V2指令
    int rt;
    char cSymmAlg, cMode;
    char *pcData = NULL;
    char pcIv[33] = { 0 };
    int iIvLength;
    _keyInfo *pstKeyHandle;
    
    if ((uiAlgID & 0x90000400) == 0x90000400)//AES算法
        cSymmAlg = '4';
    else if (uiAlgID & 0x90000000)//DES算法
        cSymmAlg = '3';
    else if (uiAlgID & 0x00000100)//SM1算法
        cSymmAlg = '2';
    else if (uiAlgID & 0x00000400)//SM4算法
        cSymmAlg = '1';
    else
    {
        LOG_ERROR("%s", "uiAlgID is error, please check algorithm");
        return SDR_DECRYPT_ALGID;
    }
    if (uiAlgID & 0x00000001)//ECB
        cMode = '0';
    else if (uiAlgID & 0x00000002)//CBC
    {
        cMode = '1';
        if (pucIV == NULL)
        {
            LOG_ERROR("%s", "pucIV must not be NULL, when algorithm mode is CBC");
            return SDR_DECRYPT_IV;
        }
        iIvLength = (cSymmAlg == '3') ? 8 : 16;
        Tools_ConvertByte2HexStr(pucIV, iIvLength, pcIv);
    }
    else
    {
        LOG_ERROR("%s", "uiAlgID is error, please check algorithm mode");
        return SDR_DECRYPT_ALGID;
    }
    if ((uiEncDataLength % 8) || (uiEncDataLength > 4096))
    {
        LOG_ERROR("%s", "uiEncDataLength is error, it must be N*8 and less then 4096");
        return SDR_DECRYPT_ENCDATALENGTH;
    }
    if (pucData == NULL)
    {
        LOG_ERROR("%s", "pucData must not be NULL");
        return SDR_DECRYPT_DATA;
    }
    if (puiDataLength == NULL)
    {
        LOG_ERROR("%s", "puiDataLength must not be NULL");
        return SDR_DECRYPT_DATALENGTH;
    }
    pstKeyHandle = (_keyInfo*)hKeyHandle;
    pstKeyHandle->pcKeyCipherByHMK[0] = (cSymmAlg == '1') ? 'S' : ((cSymmAlg == '2') ? 'P' : ((cSymmAlg == '3') ? 'X' : 'L'));
    rt = HSM_IC_V2_Encrypt_DecryptData(
        hSessionHandle, 0,
        cSymmAlg,
        0,
        pstKeyHandle->pcKeyCipherByHMK,
        0, NULL,
        '0',
        cMode,
        pcIv,
        '3',
        uiEncDataLength,
        pucEncData,
        puiDataLength,
        pucData);
    if (rt)
    {
        free(pcData);
        LOG_ERROR("%s%02d", "HSM_IC_V2_DataEnDecrypt failed, error code: ", rt);
        return rt;
    }
    if (*puiDataLength < uiEncDataLength)
    {
        memset(pucData + *puiDataLength, 0, uiEncDataLength - *puiDataLength);
        *puiDataLength = uiEncDataLength;
        
    }
    if (cMode == '1')//CBC模式输出IV
        memcpy(pucIV, pucEncData + uiEncDataLength - iIvLength, iIvLength);
    return SDR_OK;
}

DLL int SDF_Encrypt(
    void *hSessionHandle,
    void *hKeyHandle,
    unsigned int uiAlgID,
    unsigned char *pucIV,
    unsigned char *pucData,
    unsigned int uiDataLength,
    unsigned char *pucEncData,
    unsigned int *puiEncDataLength)
{
    // TODO 7.3.6 V2指令
    int rt;
    char cSymmAlg, cMode;
    char *pcData = NULL;
    char pcIv[33] = { 0 };
    int iIvLength;
    _keyInfo *pstKeyHandle;

    if ((uiAlgID & 0x90000400) == 0x90000400)//AES算法
        cSymmAlg = '4';
    else if (uiAlgID & 0x90000000)//DES算法
        cSymmAlg = '3';
    else if (uiAlgID & 0x00000100)//SM1算法
        cSymmAlg = '2';
    else if (uiAlgID & 0x00000400)//SM4算法
        cSymmAlg = '1';
    else
    {
        LOG_ERROR("%s", "uiAlgID is error, please check algorithm");
        return SDR_DECRYPT_ALGID;
    }
    if (uiAlgID & 0x00000001)//ECB
        cMode = '0';
    else if (uiAlgID & 0x00000002)//CBC
    {
        cMode = '1';
        if (pucIV == NULL)
        {
            LOG_ERROR("%s", "pucIV must not be NULL, when algorithm mode is CBC");
            return SDR_DECRYPT_IV;
        }
        iIvLength = (cSymmAlg == '3') ? 8 : 16;
        Tools_ConvertByte2HexStr(pucIV, iIvLength, pcIv);
    }
    else
    {
        LOG_ERROR("%s", "uiAlgID is error, please check algorithm mode");
        return SDR_DECRYPT_ALGID;
    }
    if ((uiDataLength % 8) || (uiDataLength > 4096))
    {
        LOG_ERROR("%s", "uiDataLength is error, it must be N*8 and less then 4096");
        return SDR_DECRYPT_ENCDATALENGTH;
    }
    if (pucEncData == NULL)
    {
        LOG_ERROR("%s", "pucEncData must not be NULL");
        return SDR_DECRYPT_DATA;
    }
    if (puiEncDataLength == NULL)
    {
        LOG_ERROR("%s", "puiEncDataLength must not be NULL");
        return SDR_DECRYPT_DATALENGTH;
    }
    pstKeyHandle = (_keyInfo*)hKeyHandle;
    pstKeyHandle->pcKeyCipherByHMK[0] = (cSymmAlg == '1') ? 'S' : ((cSymmAlg == '2') ? 'P' : ((cSymmAlg == '3') ? 'X' : 'L'));
    rt = HSM_IC_V2_Encrypt_DecryptData(
        hSessionHandle, 0,
        cSymmAlg,
        0,
        pstKeyHandle->pcKeyCipherByHMK,
        0, NULL,
        '1',
        cMode,
        pcIv,
        '3',
        uiDataLength,
        pucData,
        puiEncDataLength,
        pucEncData);
    if (rt)
    {
        free(pcData);
        LOG_ERROR("%s%02d", "HSM_IC_V2_DataEnDecrypt failed, error code: ", rt);
        return rt;
    }
    if (cMode == '1')//CBC模式输出IV
        memcpy(pucIV, pucEncData + *puiEncDataLength - iIvLength, iIvLength);
    return SDR_OK;
}

DLL int SDF_DestoryKey(
        void *hSessionHandle,
        void *hKeyHandle)
{
    // TODO 销毁hKeyHandle指针内存中的临时密钥
    if (hKeyHandle!=NULL)
        free(hKeyHandle);
    hKeyHandle = NULL;
    return SDR_OK;
}

DLL int SDF_ExportEncPublicKey_ECC(
        void *hSessionHandle,int nSock,
        unsigned int uiKeyId,
        ECCrefPublicKey *pucPublicKey)
{
    // TODO 7.6.22 SJ指令，导出ECC加密公钥
    int rt;
    unsigned char pucPubKey[128] = { 0 };

    if (pucPublicKey == NULL)
    {
        LOG_ERROR("%s", "pucPublicKey must not be NULL");
        return SDR_EXPENCPUBKEYECC_PUBLICKEY;
    }
    rt = HSM_EXT_SJ_ExportSM2PubKey(
        hSessionHandle, 0,
        '2',
        2,
        uiKeyId,
        pcKeyPassword,
        pucPubKey);
    if (rt)
    {
        LOG_ERROR("%s%02d", "HSM_EXT_SJ_ExportSM2PubKey failed, error code: ", rt);
        return rt;
    }
    pucPublicKey->bits = 32 * 8;
    memcpy(pucPublicKey->x + ECCref_MAX_LEN - 32, pucPubKey, 32);
    memcpy(pucPublicKey->y + ECCref_MAX_LEN - 32, pucPubKey + 32, 32);

    return SDR_OK;
}

DLL int SDF_ExportSignPublicKey_ECC(
        void *hSessionHandle,int nSock,
        unsigned int uiKeyIndex,
        ECCrefPublicKey *pucPublicKey)
{
    // TODO 7.6.22 SJ指令，导出ECC签名公钥
    int rt;
    unsigned char pucPubKey[ECCref_MAX_LEN * 2] = { 0 };

    if (pucPublicKey == NULL)
    {
        LOG_ERROR("%s", "pucPublicKey must not be NULL");
        return SDR_EXPSIGNPUBKEYECC_PUBLICKEY;
    }
    memset(pucPublicKey, 0, sizeof(ECCrefPublicKey));
    rt = HSM_EXT_SJ_ExportSM2PubKey(
        hSessionHandle, 0,
        '1',
        2,
        uiKeyIndex,
        pcKeyPassword,
        pucPubKey);
    if (rt)
    {
        LOG_ERROR("%s%02d", "HSM_EXT_SJ_ExportSM2PubKey failed, error code: ", rt);
        return rt;
    }
    pucPublicKey->bits = 32 * 8;
    memset(pucPublicKey->x, 0, ECCref_MAX_LEN);
    memset(pucPublicKey->y, 0, ECCref_MAX_LEN);
    memcpy(pucPublicKey->x + ECCref_MAX_LEN - 32, pucPubKey, 32);
    memcpy(pucPublicKey->y + ECCref_MAX_LEN - 32, pucPubKey + 32, 32);

    return SDR_OK;
}

DLL int SDF_ExportSignPublicKey_RSA(
        void *hSessionHandle,int nSock,
        unsigned int uiKeyIndex,
        RSArefPublicKey *pucPublicKey)
{
    // TODO 7.6.21 EJ指令，导出RSA签名公钥
    int rt, iPubKeyMLength, iPubKeyELength;
    unsigned char pucPubKey[RSAref_MAX_LEN] = { 0 };
    char pcPubKey[1024] = { 0 };
    char pcPubKeyM[1024] = { 0 };
    char pcPubKeyE[1024] = { 0 };

    if (pucPublicKey == NULL)
    {
        LOG_ERROR("%s", "pucPublicKey must not be NULL");
        return SDR_EXPSIGNPUBKEYRSA_PUBLICKEY;
    }
    memset(pucPublicKey, 0, sizeof(RSArefPublicKey));
    rt = HSM_EXT_EJ_ExportRSAPubKey(
        hSessionHandle, 0,
        '1',
        1,
        uiKeyIndex,
        pcKeyPassword,
        pucPubKey);
    if (rt)
    {
        LOG_ERROR("%s%02d", "HSM_EXT_EJ_ExportRSAPubKey failed, error code: ", rt);
        return rt;
    }
    Tools_DDer(pucPubKey, pcPubKeyM, &iPubKeyMLength, pcPubKeyE, &iPubKeyELength);
    memset(pucPublicKey->m, 0, RSAref_MAX_LEN);
    memset(pucPublicKey->e, 0, RSAref_MAX_LEN);
    pucPublicKey->bits = iPubKeyMLength / 2 * 8;
    Tools_ConvertHexStr2Byte(pcPubKeyM, iPubKeyMLength, pucPublicKey->m + RSAref_MAX_LEN - iPubKeyMLength / 2);
    Tools_ConvertHexStr2Byte(pcPubKeyE, iPubKeyELength, pucPublicKey->e + RSAref_MAX_LEN - iPubKeyELength / 2);

    return SDR_OK;
}

DLL int SDF_ExternalDecrypt_ECC(
        void *hSessionHandle,int nSock,
        unsigned int uiAlgID,
        ECCrefPrivateKey *pucPrivateKey,
        ECCCipher *pucEncData,
        unsigned char *pucData,
        unsigned int *puiDataLength)
{
    // TODO 7.4.4 UW指令，外部私钥解密数据
    int rt;
    if ((uiAlgID != SGD_SM2) && (uiAlgID != SGD_SM2_3))
    {
        LOG_ERROR("%s", "uiAlgID is error, please check algorithm");
        return SDR_EXTDECRYPTECC_ALGID;
    }
    if (pucPrivateKey == NULL)
    {
        LOG_ERROR("%s", "pucPrivateKey must not be NULL");
        return SDR_EXTDECRYPTECC_PRIVATEKEY;
    }
    if (pucEncData == NULL)
    {
        LOG_ERROR("%s", "pucEncData must not be NULL");
        return SDR_EXTDECRYPTECC_ENCDATA;
    }
    if (pucData == NULL)
    {
        LOG_ERROR("%s", "pucData must not be NULL");
        return SDR_EXTDERYPTECC_DATA;
    }
    if (puiDataLength == NULL)
    {
        LOG_ERROR("%s", "puiDataLength must not be NULL");
        return SDR_EXTDECRYPTECC_DATALENGTH;
    }
    rt = HSM_BASE_UW_SM2PriKeyDecrypt(
        hSessionHandle, 0,
        0,
        pcKeyPassword,
        pucPrivateKey->K + ECCref_MAX_LEN - 32,
        pucEncData->L,
        pucEncData->C,
        puiDataLength,
        pucData);
    if (rt)
    {
        LOG_ERROR("%s%02d", "HSM_BASE_UW_SM2PriKeyDecrypt failed, error code: ", rt);
        return rt;
    }

    return SDR_OK;
}

DLL int SDF_ExternalEncrypt_ECC(
        void *hSessionHandle,int nSock,
        unsigned int uiAlgID,
        ECCrefPublicKey *pucPublicKey,
        unsigned char *pucData,
        unsigned int uiDataLength,
        ECCCipher *pucEncData)
{
    // TODO 7.4.3 UU指令，外部公钥加密数据
    int rt;
    if ((uiAlgID != SGD_SM2) && (uiAlgID != SGD_SM2_3))
    {
        LOG_ERROR("%s", "uiAlgID is error, please check algorithm");
        return SDR_EXTENCRYPTECC_ALGID;
    }
    if (pucPublicKey == NULL)
    {
        LOG_ERROR("%s", "pucPublicKey must not be NULL");
        return SDR_EXTENCRYPTECC_PUBLICKEY;
    }
    if (pucEncData == NULL)
    {
        LOG_ERROR("%s", "pucEncData must not be NULL");
        return SDR_EXTENCRYPTECC_ENCDATA;
    }
    memset(pucEncData, 0, sizeof(ECCCipher));
    rt = HSM_BASE_UU_SM2PubKeyEncrypt(
        hSessionHandle, 0,
        0,
        pucPublicKey->x + ECCref_MAX_LEN - 32,
        pucPublicKey->y + ECCref_MAX_LEN - 32,
        uiDataLength,
        pucData,
        &pucEncData->L,
        pucEncData->C);
    if (rt)
    {
        LOG_ERROR("%s%02d", "HSM_BASE_UU_SM2PubKeyEncrypt failed, error code: ", rt);
        return rt;
    }
    return SDR_OK;
}

DLL int SDF_ExternalSign_ECC(
        void *hSessionHandle,int nSock,
        unsigned int uiAlgID,
        ECCrefPrivateKey *pucPrivateKey,
        unsigned char *pucData,
        unsigned int uiDataLength,
        ECCSignature *pucSignature)
{
    // TODO 7.4.5 UQ指令，外部私钥签名运算，外部实现SM3摘要运算
    int rt;
    if ((uiAlgID != SGD_SM2) && (uiAlgID != SGD_SM2_1))
    {
        LOG_ERROR("%s", "uiAlgID is error, please check algorithm");
        return SDR_EXTSIGNECC_ALGID;
    }
    if (pucPrivateKey == NULL)
    {
        LOG_ERROR("%s", "pucPrivateKey must not be NULL");
        return SDR_EXTSIGNECC_PRIVATEKEY;
    }
    if (pucSignature == NULL)
    {
        LOG_ERROR("%s", "pucSignature must not be NULL");
        return SDR_EXTSIGNECC_SIGNATURE;
    }
    memset(pucSignature, 0, sizeof(ECCSignature));
    rt = HSM_BASE_UQ_SM2Signature(
        hSessionHandle, 0,
        0,
        pcKeyPassword,
        pucPrivateKey->K + ECCref_MAX_LEN - 32,
        1,
        0,
        NULL,
        NULL,
        uiDataLength,
        pucData,
        pucSignature->r + ECCref_MAX_LEN - 32,
        pucSignature->s + ECCref_MAX_LEN - 32);
    if (rt)
    {
        LOG_ERROR("%s%02d", "HSM_BASE_UQ_SM2Signature failed, error code: ", rt);
        return rt;
    }

    return SDR_OK;
}

DLL int SDF_ExternalVerify_ECC(
        void *hSessionHandle,int nSock,
        unsigned int uiAlgID,
        ECCrefPublicKey *pucPublicKey,
        unsigned char *pucDataInput,
        unsigned int uiInputLength,
        ECCSignature *pucSignature)
{
    // TODO 7.4.6 US指令，使用外部ECC公钥进行验签名运算
    int rt;
    if ((uiAlgID != SGD_SM2) && (uiAlgID != SGD_SM2_1))
    {
        LOG_ERROR("%s", "uiAlgID is error, please check algorithm");
        return SDR_EXTVERIFYECC_ALGID;
    }
    if (pucPublicKey == NULL)
    {
        LOG_ERROR("%s", "pucPublicKey must not be NULL");
        return SDR_EXTVERIFYECC_PUBLICKEY;
    }
    if (pucSignature == NULL)
    {
        LOG_ERROR("%s", "pucSignature must not be NULL");
        return SDR_EXTVERIFYECC_SIGNATURE;
    }
    rt = HSM_BASE_US_SM2Verify(
        hSessionHandle, 0,
        0,
        pucPublicKey->x + ECCref_MAX_LEN - 32,
        pucPublicKey->y + ECCref_MAX_LEN - 32,
        pucSignature->r + ECCref_MAX_LEN - 32,
        pucSignature->s + ECCref_MAX_LEN - 32,
        1,
        0,
        NULL,
        uiInputLength,
        pucDataInput);
    if (rt)
    {
        LOG_ERROR("%s%02d", "HSM_BASE_US_SM2Verify failed, error code: ", rt);
        return rt;
    }

    return SDR_OK;
}

DLL int SDF_GenerateKeyPair_ECC(
        void *hSessionHandle,int nSock,
        unsigned int uiAlgID,
        unsigned int uiKeyBits,
        ECCrefPublicKey *pucPublicKey,
        ECCrefPrivateKey *pucPrivateKey)
{
    // TODO 7.4.1 UO指令，产生SM2密钥对
    int rt;
    char cKeyType;
    switch (uiAlgID)
    {
    case SGD_SM2:
        cKeyType = '3';
        break;
    case SGD_SM2_1:
        cKeyType = '1';
        break;
    case SGD_SM2_3:
        cKeyType = '2';
        break;
    default:
        LOG_ERROR("%s", "uiAlgID is error, please check algorithm");
        return SDR_GENKEYPAIRECC_ALGID;
    }
    if (uiKeyBits != OSCCA_FP_256)
    {
        LOG_ERROR("%s", "uiKeyBits is error");
        return SDR_GENKEYPAIRECC_KEYBITS;
    }
    if (pucPublicKey == NULL)
    {
        LOG_ERROR("%s", "pucPublicKey must not be NULL");
        return SDR_GENKEYPAIRECC_PUBLICKEY;
    }
    memset(pucPublicKey, 0, sizeof(ECCrefPublicKey));
    if (pucPrivateKey == NULL)
    {
        LOG_ERROR("%s", "pucPrivateKey must not be NULL");
        return SDR_GENKEYPAIRECC_PRIVATEKEY;
    }
    memset(pucPrivateKey, 0, sizeof(ECCrefPrivateKey));
    rt = HSM_BASE_UO_GenerateSM2KeyPair(
        hSessionHandle, 0,
        256,
        cKeyType,
        0,
        '\0', '0', 0, 0, NULL, NULL,
        pucPublicKey->x + ECCref_MAX_LEN - 32,
        pucPublicKey->y + ECCref_MAX_LEN - 32,
        pucPrivateKey->K + ECCref_MAX_LEN - 32,
        NULL);
    if (rt)
    {
        LOG_ERROR("%s%02d", "HSM_BASE_UO_GenerateSM2KeyPair failed, error code: ", rt);
        return rt;
    }
    pucPublicKey->bits = 32 * 8;
    pucPrivateKey->bits = 32 * 8;

    return SDR_OK;
}

DLL int SDF_GenerateKeyPair_RSA(
        void *hSessionHandle,int nSock,
        unsigned int uiKeyBits,
        RSArefPublicKey *pucPublicKey,
        RSArefPrivateKey *pucPrivateKey)
{
    // TODO 7.5.1 EI指令，产生RSA密钥对，模式为2
    int rt;
    int iPubKeyLength, iPriKeyCipherByHMKLength, iPubKeyMLength, iPubKeyELength;
    unsigned char pucPubKeyDer[4096] = { 0 }, pucPubKeyCipherByHMK[4096] = { 0 };
    if (pucPublicKey == NULL)
    {
        LOG_ERROR("%s", "pucPublicKey must not be NULL");
        return SDR_GENKEYPAIRRSA_PUBLICKEY;
    }
    memset(pucPublicKey, 0, sizeof(RSArefPublicKey));
    if (pucPrivateKey == NULL)
    {
        LOG_ERROR("%s", "pucPrivateKey must not be NULL");
        return SDR_GENKEYPAIRRSA_PRIVATEKEY;
    }
    memset(pucPrivateKey, 0, sizeof(RSArefPrivateKey));
    rt = HSM_RSA_EI_GenerateRSAKeyPair(
        hSessionHandle, 0,
        '2',
        uiKeyBits,
        1,
        0,
        NULL,
        '3',
        0,
        '0',
        0, 0, NULL,
        '\0', 0, 0,
        &iPubKeyLength,
        pucPubKeyDer,
        &iPriKeyCipherByHMKLength,
        pucPrivateKey->d,
        NULL, NULL);
    if (rt)
    {
        LOG_ERROR("%s%02d", "HSM_RSA_EI_GenerateRSAKeyPair failed, error code: ", rt);
        return rt;
    }
    pucPublicKey->bits = uiKeyBits;
    pucPrivateKey->bits = uiKeyBits;
    Tools_DDer(pucPubKeyDer, pucPublicKey->m, &iPubKeyMLength, pucPublicKey->e, &iPubKeyELength);
    memcpy(pucPublicKey->m + ECCref_MAX_LEN - iPubKeyMLength, pucPublicKey->m, iPubKeyMLength);
    memcpy(pucPublicKey->e + ECCref_MAX_LEN - iPubKeyELength, pucPublicKey->e, iPubKeyELength);
    memset(pucPublicKey->m, 0, ECCref_MAX_LEN - iPubKeyMLength);
    memset(pucPublicKey->e, 0, ECCref_MAX_LEN - iPubKeyELength);
    memcpy(pucPrivateKey->m, pucPublicKey->m, ECCref_MAX_LEN);
    memcpy(pucPrivateKey->e, pucPublicKey->e, ECCref_MAX_LEN);
    return SDR_OK;
}

DLL int SDF_GenerateKeyWithEPK_ECC(
        void *hSessionHandle,int nSock,
        unsigned int uiKeyBits,
        unsigned int uiAlgID,
        ECCrefPublicKey *pucPublicKey,
        ECCCipher *pucKey,
        void **phKeyHandle)
{
    // TODO 7.2.1 X0指令，产生密钥，模式0介质12
    int rt;
    char cSymmAlg;
    unsigned char pucPubKey[128] = { 0 };
    int len;
    _keyInfo *pstKeyHandle;

    if ((uiAlgID & 0x90000400) == 0x90000400)//AES算法
        cSymmAlg = '4';
    else if (uiAlgID & 0x90000000)//DES算法
        cSymmAlg = '3';
    else if (uiAlgID & 0x00000100)//SM1算法
        cSymmAlg = '2';
    else if (uiAlgID & 0x00000400)//SM4算法
        cSymmAlg = '1';
    else
    {
        LOG_ERROR("%s", "uiAlgID is error, please check algorithm");
        return SDR_GENKEYWITHEPKECC_ALGID;
    }
    if (pucPublicKey == NULL)
    {
        LOG_ERROR("%s", "pucPublicKey must not be NULL");
        return SDR_GENKEYWITHEPKECC_PUBLICKEY;
    }
    len = Tools_ConvertHexStr2Byte(
        "3059301306072A8648CE3D020106082A811CCF5501822D03420004",
        strlen("3059301306072A8648CE3D020106082A811CCF5501822D03420004"),
        pucPubKey);
    memcpy(pucPubKey + len, pucPublicKey->x + ECCref_MAX_LEN - 32, 32);
    memcpy(pucPubKey + len + 32, pucPublicKey->y + ECCref_MAX_LEN - 32, 32);
    if (pucKey == NULL)
    {
        LOG_ERROR("%s", "pucKey must not be NULL");
        return SDR_GENKEYWITHEPKECC_KEY;
    }
    memset(pucKey, 0, sizeof(ECCCipher));
    *phKeyHandle = malloc(sizeof(_keyInfo));
    if (*phKeyHandle == NULL)
    {
        LOG_ERROR("%s", "phKeyHandle malloc memory error");
        return SDR_GENKEYWITHEPKECC_MALLOC;
    }
    memset(*phKeyHandle, 0, sizeof(_keyInfo));
    pstKeyHandle = (_keyInfo*)*phKeyHandle;
    pstKeyHandle->cSymmAlg = cSymmAlg;
    pstKeyHandle->pcKeyCipherByHMK[0] =
        ((cSymmAlg == '1') ? 'S' : ((cSymmAlg == '2') ? 'P' : ((cSymmAlg == '3') ? 'X' : 'L')));
    rt = HSM_MGT_X0_GenerateKey(
        hSessionHandle, 0,
        '0',
        12,
        pstKeyHandle->cSymmAlg,
        '1',
        uiKeyBits / 8,
        0, NULL, 0, NULL, 0,
        91,
        pucPubKey,
        0, 0, NULL, NULL,
        pstKeyHandle->pcKeyCipherByHMK,
        &pucKey->L, 
        pucKey->C,
        NULL,
        pstKeyHandle->pcKCV);
    if (rt)
    {
        LOG_ERROR("%s%02d", "HSM_MGT_X0_GenerateKey failed, error code: ", rt);
        free(*phKeyHandle);
        return rt;
    }
    memcpy(pucKey->x, pucPublicKey->x, ECCref_MAX_LEN);
    memcpy(pucKey->y, pucPublicKey->y, ECCref_MAX_LEN);

    return SDR_OK;
}

DLL int SDF_GenerateKeyWithKEK(
        void *hSessionHandle,int nSock,
        unsigned int uiKeyBits,
        unsigned int uiAlgID,
        unsigned int uiKEKIndex,
        unsigned char *pucKey,
        unsigned int *puiKeyLength,
        void **phKeyHandle)
{
    // TODO 7.2.1 X0指令，产生密钥，模式0介质14
    int rt;
    char cSymmAlg;
    char pcKey[128] = { 0 };
    _keyInfo *pstKeyHandle;

    if ((uiAlgID & 0x90000400) == 0x90000400)//AES算法
        cSymmAlg = '4';
    else if (uiAlgID & 0x90000000)//DES算法
        cSymmAlg = '3';
    else if (uiAlgID & 0x00000100)//SM1算法
        cSymmAlg = '2';
    else if (uiAlgID & 0x00000400)//SM4算法
        cSymmAlg = '1';
    else
    {
        LOG_ERROR("%s", "uiAlgID is error, please check algorithm");
        return SDR_GENKEYWITHKEK_ALGID;
    }
    if (pucKey == NULL)
    {
        LOG_ERROR("%s", "pucKey must not be NULL");
        return SDR_GENKEYWITHKEK_KEY;
    }
    if (puiKeyLength == NULL)
    {
        LOG_ERROR("%s", "puiKeyLength must not be NULL");
        return SDR_GENKEYWITHKEK_KEYLENGTH;
    }
    *phKeyHandle = malloc(sizeof(_keyInfo));
    if (*phKeyHandle == NULL)
    {
        LOG_ERROR("%s", "phKeyHandle malloc memory error");
        return SDR_GENKEYWITHKEK_MALLOC;
    }
    memset(*phKeyHandle, 0, sizeof(_keyInfo));
    pstKeyHandle = (_keyInfo*)*phKeyHandle;
    pstKeyHandle->cSymmAlg = cSymmAlg;
    pstKeyHandle->pcKeyCipherByHMK[0] =
        ((cSymmAlg == '1') ? 'S' : ((cSymmAlg == '2') ? 'P' : ((cSymmAlg == '3') ? 'X' : 'L')));

    rt = HSM_MGT_X0_GenerateKey(
        hSessionHandle, 0,
        '0',
        14,
        pstKeyHandle->cSymmAlg,
        '1',
        uiKeyBits / 8,
        0, NULL, 0, NULL, 0, 0, NULL,
        pstKeyHandle->cSymmAlg, 
        uiKEKIndex,
        NULL,
        NULL,
        pstKeyHandle->pcKeyCipherByHMK,
        NULL, NULL,
        pcKey,
        pstKeyHandle->pcKCV);
    if (rt)
    {
        LOG_ERROR("%s%02d", "HSM_MGT_X0_GenerateKey failed, error code: ", rt);
        free(*phKeyHandle);
        return rt;
    }
    *puiKeyLength = (strlen(pcKey) - 1) / 2;
    Tools_ConvertHexStr2Byte(pcKey + 1, *puiKeyLength * 2, pucKey);

    return SDR_OK;
}

DLL int SDF_GenerateRandom(
    void *hSessionHandle,int nSock,
    int iRandomLen,
    char *pcRandom)
{
    int     rt = SDR_OK;
    int     len = 0;
    unsigned char pucRandom[2048];

    if (pcRandom == NULL)
    {
        LOG_ERROR("%s", "pcRandom must not be NULL");
        return SDR_GENRANDOM_RANDOM;
    }
    rt = HSM_EXT_TE_GenerateRandom(hSessionHandle, 0, iRandomLen, pucRandom);
    if (rt)
    {
        LOG_ERROR("%s%02d", "HSM_EXT_TE_GenerateRandom failed, error code: ", rt);
        return rt;
    }
    Tools_ConvertByte2HexStr(pucRandom, iRandomLen, pcRandom);

    return SDR_OK;
}

DLL int SDF_GetPrivateKeyAccessRight(
    void *hSessionHandle,int nSock,
    unsigned int uiKeyIndex,
    unsigned char *pucPassword,
    unsigned int uiPwdLength)
{
    if ((uiKeyIndex < 1) || (uiKeyIndex>50))
    {
        LOG_ERROR("%s", "uiKeyIndex is invalid, uiKeyIndex must be 1-50");
        return SDR_GETPRIKEYACCRIGHT_KEYINDEX;
    }
    if ((uiPwdLength != 8) || (pucPassword == NULL) || (strlen(pucPassword) < uiPwdLength))
    {
        LOG_ERROR("%s", "uiPwdLength or pucPassword is invalid, uiPwdLength and strlen(pucPassword) must be 8");
        return SDR_GETPRIKEYACCRIGHT_PWDORLENGTH;
    }
    tafrm_LockMutex(pstKeyPwdMutex);
    iKeyIdx = uiKeyIndex;
    strncpy(pcKeyPassword, pucPassword, uiPwdLength);
    return SDR_OK;
}

DLL int SDF_ReleasePrivateKeyAccessRight(
    void *hSessionHandle,int nSock,
    unsigned int uiKeyIndex)
{
    if ((uiKeyIndex < 1) || (uiKeyIndex>50))
    {
        LOG_ERROR("%s", "uiKeyIndex is invalid, uiKeyIndex must be 1-50");
        return SDR_RELPRIKEYACCRIGHT_KEYINDEX;
    }
    iKeyIdx = 0;
    memset(pcKeyPassword, '\0', 16);
    tafrm_UnlockMutex(pstKeyPwdMutex);

    return SDR_OK;
}

DLL int SDF_HashInit(
    void *hSessionHandle,int nSock,
    unsigned int uiAlgID,
    ECCrefPublicKey *pucPublicKey,
    unsigned char *pucID,
    unsigned int uiIDLength)
{
    int rt;
    int len;
    unsigned char pucPubKey[128] = { 0 };
    tafrm_LockMutex(pstHashMutex);
    switch (uiAlgID)
    {
        case SGD_SM3: iHashAlgType = 1; break;
        case SGD_SHA1: iHashAlgType = 2; break;
        case SGD_SHA256: iHashAlgType = 3; break;
        case SGD_SHA512: iHashAlgType = 4; break;
        case SGD_SHA384: iHashAlgType = 5; break;
        case SGD_SHA224: iHashAlgType = 6; break;
        case SGD_MD5: iHashAlgType = 7; break;
        default:
        {
            LOG_ERROR("%s", "uiAlgID is invalid");
            tafrm_UnlockMutex(pstHashMutex);
            return SDR_HASHINIT_ALGID;
        }
    }
    if (uiAlgID == 1)
    {
        if (pucPublicKey == NULL)
        {
            LOG_ERROR("%s", "pucPublicKey must not be NULL");
            tafrm_UnlockMutex(pstHashMutex);
            return SDR_HASHINIT_PUBLICKEY;
        }
        len = Tools_ConvertHexStr2Byte(
            "3059301306072A8648CE3D020106082A811CCF5501822D03420004",
            strlen("3059301306072A8648CE3D020106082A811CCF5501822D03420004"),
            pucPubKey);
        memcpy(pucPubKey + len, pucPublicKey->x + ECCref_MAX_LEN - 32, 32);
        memcpy(pucPubKey + len + 32, pucPublicKey->y + ECCref_MAX_LEN - 32, 32);
        if (pucID == NULL)
        {
            LOG_ERROR("%s", "pucID must not be NULL");
            tafrm_UnlockMutex(pstHashMutex);
            return SDR_HASHINIT_ID;
        }
        
    }
    rt = HSM_EXT_XG_SeparateHash(
        hSessionHandle, 0,
        1,
        iHashAlgType,
        64,
        pucPubKey,
        uiIDLength,
        pucID,
        0,
        NULL,
        0,
        NULL,
        '\0',
        &iHashDataLength,
        pucHashData);
    if (rt)
    {
        LOG_ERROR("%s%02d", "HSM_EXT_XG_SeparateHash failed, error code: ", rt);
        tafrm_UnlockMutex(pstHashMutex);
        return rt;
    }

    return SDR_OK;
}

DLL int SDF_HashUpdate(
    void *hSessionHandle,int nSock,
    unsigned char *pucData,
    unsigned int uiDataLength)
{
    int rt;
    rt = HSM_EXT_XG_SeparateHash(
        hSessionHandle, 0,
        2,
        iHashAlgType,
        0,
        NULL,
        0,
        NULL,
        uiDataLength,
        pucData,
        iHashDataLength,
        pucHashData,
        '\0',
        &iHashDataLength,
        pucHashData);
    if (rt)
    {
        LOG_ERROR("%s%02d", "HSM_EXT_XG_SeparateHash failed, error code: ", rt);
        tafrm_UnlockMutex(pstHashMutex);
        return rt;
    }

    return SDR_OK;
}

DLL int SDF_HashFinal(
    void *hSessionHandle,int nSock,
    unsigned char *pucHash,
    unsigned int *puiHashLength)
{
    int rt;
    if (pucHash == NULL)
    {
        LOG_ERROR("%s", "pucHash must not be NULL");
        tafrm_UnlockMutex(pstHashMutex);
        return SDR_HASHFINAL_HASH;
    }
    if (puiHashLength == NULL)
    {
        LOG_ERROR("%s", "puiHashLength must not be NULL");
        tafrm_UnlockMutex(pstHashMutex);
        return SDR_HASHFINAL_HASHLENGTH;
    }
    rt = HSM_EXT_XG_SeparateHash(
        hSessionHandle, 0,
        3,
        iHashAlgType,
        0,
        NULL,
        0,
        NULL,
        0,
        NULL,
        iHashDataLength,
        pucHashData,
        '\0',
        puiHashLength,
        pucHash);
    if (rt)
    {
        LOG_ERROR("%s%02d", "HSM_EXT_XG_SeparateHash failed, error code: ", rt);
        tafrm_UnlockMutex(pstHashMutex);
        return rt;
    }
    tafrm_UnlockMutex(pstHashMutex);
    return SDR_OK;
}

DLL int SDF_ImportKey(
    void *hSessionHandle,
    unsigned char *pucKey,
    unsigned int uiKeyLength,
    void **phKeyHandle)
{
    int rt, len;
    unsigned char pucKeyCipher[64] = { 0 };
    _keyInfo *pstKeyHandle;
    *phKeyHandle = malloc(sizeof(_keyInfo));

    if (*phKeyHandle == NULL)
    {
        LOG_ERROR("%s", "phKeyHandle malloc memory error");
        return SDR_IMPORTKEY_MALLOC;
    }
    memset(*phKeyHandle, 0, sizeof(_keyInfo));
    pstKeyHandle = (_keyInfo*)*phKeyHandle;
    pstKeyHandle->cSymmAlg = '1';
    pstKeyHandle->pcKeyCipherByHMK[0] = 'S';
    
    rt = HSM_EXT_UX_EncryptKeyWithHMK_Extend(
        hSessionHandle, 0,
        01,
        01,
        uiKeyLength,
        pucKey,
        0, NULL, 0, NULL,
        NULL,
        &len,
        pucKeyCipher);
    if (rt)
    {
        LOG_ERROR("%s%02d", "HSM_EXT_UX_HSMEncryptKeyExt failed, error code: ", rt);
        return rt;
    }
    Tools_ConvertByte2HexStr(pucKeyCipher, len, pstKeyHandle->pcKeyCipherByHMK + 1);
    return SDR_OK;
}

DLL int SDF_ImportKeyWithISK_ECC(
    void *hSessionHandle,int nSock,
    unsigned int uiISKIndex,
    ECCCipher *pucKey,
    void **phKeyHandle)
{
    int rt, len;
    unsigned char pcKeyCipher[64] = { 0 };
    _keyInfo *pstKeyHandle;
    if (pucKey == NULL)
    {
        LOG_ERROR("%s", "pucKey must not be NULL");
        return SDR_IMPORTKEYWITHEPKECC_KEY;
    }
    *phKeyHandle = malloc(sizeof(_keyInfo));
    if (*phKeyHandle == NULL)
    {
        LOG_ERROR("%s", "phKeyHandle malloc memory error");
        return SDR_IMPORTKEYWITHEPKECC_MALLOC;
    }
    memset(*phKeyHandle, 0, sizeof(_keyInfo));
    pstKeyHandle = (_keyInfo*)*phKeyHandle;
    pstKeyHandle->pcKeyCipherByHMK[0] = 'S';
    pstKeyHandle->cSymmAlg = '1';
    rt = HSM_EXT_UC_SM2ConvertKeyCipher(
        hSessionHandle, 0,
        02,
        pucKey->L,
        pucKey->C,
        uiISKIndex,
        pcKeyPassword,
        NULL, NULL,
        &len,
        pcKeyCipher);
    if (rt)
    {
        LOG_ERROR("%s%02d", "HSM_EXT_UC_SM2_SymmAlgConvertKeyCipher failed, error code: ", rt);
        return rt;
    }
    Tools_ConvertByte2HexStr(pcKeyCipher, len, pstKeyHandle->pcKeyCipherByHMK + 1);

    return SDR_OK;
}

DLL int SDF_InternalPrivateKeyOperation_RSA(
    void *hSessionHandle,int nSock,
    unsigned int uiKeyIndex,
    unsigned char *pucDataInput,
    unsigned int uiInputLength,
    unsigned char *pucDataOutput,
    unsigned int *puiOutputLength)
{
    int rt;
    if (uiKeyIndex <= 0)
    {
        LOG_ERROR("%s", "uiKeyIndex <= 0, it should be 1-50");
        return SDR_INPRIOPT_KEYINDEX;
    }
    if (pucDataOutput == NULL)
    {
        LOG_ERROR("%s", "pucDataOutput must not be NULL");
        return SDR_INPRIOPT_DATAOUTPUT;
    }
    if (puiOutputLength == NULL)
    {
        LOG_ERROR("%s", "puiOutputLength must not be NULL");
        return SDR_INPRIOPT_DATAOUTPUTLENGTH;
    }
    rt = HSM_RSA_EW_Singature(
        hSessionHandle, 0,
        04,
        00,
        0, 0, 0, NULL,
        uiInputLength,
        pucDataInput,
        ';',
        uiKeyIndex,
        pcKeyPassword,
        0, NULL,
        puiOutputLength,
        pucDataOutput);
    if (rt)
    {
        LOG_ERROR("%s%02d", "HSM_RSA_EW_Singature failed, error code: ", rt);
        return rt;
    }

    return SDR_OK;
}

DLL int SDF_InternalPublicKeyOperation_RSA(
    void *hSessionHandle,int nSock,
    unsigned int uiKeyIndex,
    unsigned char *pucDataInput,
    unsigned int uiInputLength,
    unsigned char *pucDataOutput,
    unsigned int *puiOutputLength)
{
    int rt;
    if (uiKeyIndex <= 0)
    {
        LOG_ERROR("%s", "uiKeyIndex <= 0, it should be 1-50");
        return SDR_INPUBOPT_KEYINDEX;
    }
    if (pucDataOutput == NULL)
    {
        LOG_ERROR("%s", "pucDataOutput must not be NULL");
        return SDR_INPUBOPT_DATAOUTPUT;
    }
    if (puiOutputLength == NULL)
    {
        LOG_ERROR("%s", "puiOutputLength must not be NULL");
        return SDR_INPUBOPT_DATAOUTPUTLENGTH;
    }
    rt = HSM_RSA_EW_Singature(
        hSessionHandle, 0,
        04,
        00,
        0, 0, 0, NULL,
        uiInputLength,
        pucDataInput,
        ';',
        uiKeyIndex,
        pcKeyPassword,
        0, NULL,
        puiOutputLength,
        pucDataOutput);
    if (rt)
    {
        LOG_ERROR("%s%02d", "HSM_RSA_EW_Singature failed, error code: ", rt);
        return rt;
    }

    return SDR_OK;
}

DLL int SDF_InternalSign_ECC(
    void *hSessionHandle,int nSock, unsigned int uiISKIndex,
    unsigned char *pucData,
    unsigned int uiDataLength,
    ECCSignature *pucSignature)
{
    // TODO 7.4.5 UQ指令，外部私钥签名运算，外部实现SM3摘要运算
    int rt;
    if (uiISKIndex <= 0)
    {
        LOG_ERROR("%s", "uiISKIndex <= 0, it should be 1-50");
        return SDR_INSIGNECC_ISKINDEX;
    }
    if (pucSignature == NULL)
    {
        LOG_ERROR("%s", "pucSignature must not be NULL");
        return SDR_INSIGNECC_SIGNATURE;
    }
    memset(pucSignature, 0, sizeof(ECCSignature));
    rt = HSM_BASE_UQ_SM2Signature(
        hSessionHandle, 0,
        uiISKIndex,
        pcKeyPassword,
        NULL,
        02,
        16,
        "1234567812345678",
        NULL,
        uiDataLength,
        pucData,
        pucSignature->r + ECCref_MAX_LEN - 32,
        pucSignature->s + ECCref_MAX_LEN - 32);
    if (rt)
    {
        LOG_ERROR("%s%02d", "HSM_BASE_UQ_SM2Signature failed, error code: ", rt);
        return rt;
    }

    return SDR_OK;
}

DLL int SDF_InternalVerify_ECC(
    void *hSessionHandle,int nSock,
    unsigned int uiISKIndex,
    unsigned char *pucData,
    unsigned int uiDataLength,
    ECCSignature *pucSignature)
{
    // TODO 7.4.6 US指令，使用外部ECC公钥进行验签名运算
    int rt;
    if (uiISKIndex <= 0)
    {
        LOG_ERROR("%s", "uiISKIndex <= 0, it should be 1-50");
        return SDR_INVERIFYECC_ISKINDEX;
    }
    if (pucSignature == NULL)
    {
        LOG_ERROR("%s", "pucSignature must not be NULL");
        return SDR_INVERIFYECC_SIGNATURE;
    }
    rt = HSM_BASE_US_SM2Verify(
        hSessionHandle, 0,
        uiISKIndex,
        NULL,
        NULL,
        pucSignature->r + ECCref_MAX_LEN - 32,
        pucSignature->s + ECCref_MAX_LEN - 32,
        02,
        16,
        "1234567812345678",
        uiDataLength,
        pucData);
    if (rt)
    {
        LOG_ERROR("%s%02d", "HSM_BASE_US_SM2Verify failed, error code: ", rt);
        return rt;
    }

    return SDR_OK;
}

DLL int Tass_DecryptTrackData(
    void *hSessionHandle,int nSock,
    int iKeyIdx,
    char *pcKey_LMK,
    char *pcTrackCipher,
    int iTrackTextLen,
    int iAlgId,
    int iPadFlg,
    char *pcIV,
    char *pcTrackText)
{
    int rt = SDR_OK;
    int len = 0;
    int i = 0,count=0,tail=0;
    char *pCipher = pcTrackCipher, *pPlain = pcTrackText;
    unsigned char pTmpBuf[4906] = { 0 };
    char pIv[64] = { 0 };
    char cSymmAlg;
    if (pcKey_LMK == NULL)
    {
        LOG_ERROR("%s", "pcKey_LMK must not be NULL");
        return HAR_PARAM_VALUE;
    }
    if(pcTrackCipher == NULL)
    {
        LOG_ERROR("%s", "pcTrackCipher must not be NULL");
        return HAR_PARAM_VALUE;
    }
    if (pcTrackText == NULL)
    {
        LOG_ERROR("%s", "pcTrackText must not be NULL");
        return HAR_PARAM_VALUE;
    }
    if (iAlgId == 1 && ((pcIV == NULL) || (strlen(pcIV) != 16 && strlen(pcIV) != 32)))
    {
        LOG_ERROR("pcIV length = %d, should be 16 or 32.", pcIV == NULL ? 0 : strlen(pcIV));
        return HAR_PARAM_IV;
    }
    tail = iTrackTextLen % 4096;
    count = iTrackTextLen / 4096;
    if (tail)
        ++count;
    cSymmAlg = 
        (*pcKey_LMK == 'S' ? '1' : (*pcKey_LMK == 'P' ? '2' : (*pcKey_LMK == 'L' ? '4' : '3')));
    if (iAlgId == 1)
        strncpy(pIv, pcIV, strlen(pcIV));
    for (i = 0; i < count; ++i)
    {
        memset(pTmpBuf, 0, sizeof(pTmpBuf));
        len = (((i == count - 1) && tail) ? tail : 4096) * 2;
        Tools_ConvertHexStr2Byte(pCipher, len, pTmpBuf);
        pCipher += len;
        rt = HSM_IC_V2_Encrypt_DecryptData(
            hSessionHandle, 0,
            cSymmAlg,
            0,
            pcKey_LMK,
            '0',
            NULL,
            '0',
            iAlgId == 0 ? '0' : '1',
            pIv,
            iPadFlg == 0 ? '3' : (iPadFlg == 1 ? '5' : '2'),
            len / 2,
            pTmpBuf,
            &len,
            pTmpBuf);
        if (rt)
        {
            LOG_ERROR("%s%02d", "HSM_IC_V2_DataEnDecrypt failed, error code: ", rt);
            return rt;
        }
        Tools_ConvertByte2HexStr(pTmpBuf, len, pPlain);
        pPlain += len * 2;
        if (iAlgId == 1)
            strncpy(pIv, pCipher - strlen(pcIV), strlen(pcIV));
    }
    
    return rt;
}

DLL int Tass_EncryptTrackData(
    void *hSessionHandle,int nSock,
    int iKeyIdx,
    char *pcKey_LMK,
    char *pcTrackText,
    int iTrackTextLen,
    int iAlgId,
    int iPadFlg,
    char *pcIV,
    char *pcTrackCipher)
{
    int rt = SDR_OK;
    int len = 0;
    int i = 0, count = 0, tail = 0;
    char *pCipher = pcTrackCipher, *pPlain = pcTrackText;
    unsigned char pTmpBuf[4906] = { 0 };
    char pIv[64] = { 0 };
    char cSymmAlg;
    if (pcKey_LMK == NULL)
    {
        LOG_ERROR("%s", "pcKey_LMK must not be NULL");
        return HAR_PARAM_VALUE;
    }
    if (pcTrackCipher == NULL)
    {
        LOG_ERROR("%s", "pcTrackCipher must not be NULL");
        return HAR_PARAM_VALUE;
    }
    if (pcTrackText == NULL)
    {
        LOG_ERROR("%s", "pcTrackText must not be NULL");
        return HAR_PARAM_VALUE;
    }
    if (iAlgId == 1 && ((pcIV == NULL) || (strlen(pcIV) != 16 && strlen(pcIV) != 32)))
    {
        LOG_ERROR("pcIV length = %d, should be 16 or 32.", pcIV == NULL ? 0 : strlen(pcIV));
        return HAR_PARAM_IV;
    }
    tail = iTrackTextLen % 4096;
    count = iTrackTextLen / 4096;
    if (tail)
        ++count;
    cSymmAlg =
        (*pcKey_LMK == 'S' ? '1' : (*pcKey_LMK == 'P' ? '2' : (*pcKey_LMK == 'L' ? '4' : '3')));
    if (iAlgId==1)
        strncpy(pIv, pcIV, strlen(pcIV));
    for (i = 0; i < count; ++i)
    {
        memset(pTmpBuf, 0, sizeof(pTmpBuf));
        len = (((i == count - 1) && tail) ? tail : 4096) * 2;
        Tools_ConvertHexStr2Byte(pPlain, len, pTmpBuf);
        pPlain += len;
        rt = HSM_IC_V2_Encrypt_DecryptData(
            hSessionHandle, 0,
            cSymmAlg,
            0,
            pcKey_LMK,
            '0',
            NULL,
            '1',
            iAlgId == 0 ? '0' : '1',
            pIv,
            iPadFlg == 0 ? '3' : (iPadFlg == 1 ? '5' : '2'),
            len / 2,
            pTmpBuf,
            &len,
            pTmpBuf);
        if (rt)
        {
            LOG_ERROR("%s%02d", "HSM_IC_V2_DataEnDecrypt failed, error code: ", rt);
            return rt;
        }
        Tools_ConvertByte2HexStr(pTmpBuf, len, pCipher);
        pCipher += len * 2;
        if (iAlgId == 1)
            strncpy(pIv, pCipher - strlen(pcIV), strlen(pcIV));
    }

    return rt;
}

DLL int Tass_Decrypt_PIN(
    void *hSessionHandle,int nSock,
    int iKeyIdx,
    char *pcKeyCipherByLmk,
    char *pcPinBlkCipher,
    int iPinBlkFmt,
    char *pcPan,
    char *pcPinText)
{
    int rt;
    char cSymmAlg = '1';
    if ((iKeyIdx == 0) && (pcKeyCipherByLmk == NULL))
    {
        LOG_ERROR("%s", "pcKeyCipherByLmk must not be NULL, when iKeyIdx = 0");
        return HAR_PARAM_VALUE;
    }
    if (pcPinBlkCipher == NULL)
    {
        LOG_ERROR("%s", "pcPinBlkCipher must not be NULL");
        return HAR_PARAM_VALUE;
    }
    if (pcPan == NULL)
    {
        LOG_ERROR("%s", "pcPan must not be NULL");
        return HAR_PARAM_VALUE;
    }
    if (pcPinText == NULL)
    {
        LOG_ERROR("%s", "pcPinText must not be NULL");
        return HAR_PARAM_VALUE;
    }
    if (iKeyIdx==0)
        cSymmAlg =
        (*pcKeyCipherByLmk == 'S' ? '1' : (*pcKeyCipherByLmk == 'P' ? '2' : (*pcKeyCipherByLmk == 'L' ? '4' : '3')));
    rt = HSM_EXT_BC_DecryptPIN(
        hSessionHandle, 0,
        cSymmAlg,
        iKeyIdx,
        pcKeyCipherByLmk,
        pcPinBlkCipher,
        pcPan,
        pcPinText);
    if (rt)
    {
        LOG_ERROR("%s%02d", "HSM_EXT_BC_DecryptPIN failed, error code: ", rt);
        return rt;
    }

    return SDR_OK;
}

DLL int Tass_DeriveKeyExportedByRsa(
    void *hSessionHandle,int nSock,
    char *pcZmkCipher_Lmk,
    char *pcPublicKey,
    char *pcDisData,
    char *pcKeyType,//无意义
    char *pcSubKeyCipher_TK,
    char *pcSubKeyCipher_Lmk,
    char *pcSubKeyCv)
{
    int rt, len;
    char cSymmAlg;
    unsigned char pucPubKey[4096] = { 0 };

    if (pcZmkCipher_Lmk == NULL)
    {
        LOG_ERROR("%s", "pucPublicKey must not be NULL");
        return HAR_PARAM_VALUE;
    }
    if (pcPublicKey == NULL)
    {
        LOG_ERROR("%s", "pcPublicKey must not be NULL");
        return HAR_PARAM_VALUE;
    }
    if (pcDisData == NULL)
    {
        LOG_ERROR("%s", "pcDisData malloc memory error");
        return HAR_PARAM_VALUE;
    }
    if (pcSubKeyCipher_TK == NULL)
    {
        LOG_ERROR("%s", "pcSubKeyCipher_TK malloc memory error");
        return HAR_PARAM_VALUE;
    }
    if (pcSubKeyCipher_Lmk == NULL)
    {
        LOG_ERROR("%s", "pcSubKeyCipher_Lmk malloc memory error");
        return HAR_PARAM_VALUE;
    }
    if (pcSubKeyCv == NULL)
    {
        LOG_ERROR("%s", "pcSubKeyCv malloc memory error");
        return HAR_PARAM_VALUE;
    }

    cSymmAlg = 
        (*pcZmkCipher_Lmk == 'S' ? '1' : (*pcZmkCipher_Lmk == 'P' ? '2' : (*pcZmkCipher_Lmk == 'L' ? '4' : '3')));
    Tools_ConvertHexStr2Byte(pcPublicKey, strlen(pcPublicKey), pucPubKey);
    rt = HSM_MGT_X0_GenerateKey(
        hSessionHandle, 0,
        '1',
        13,
        cSymmAlg,
        '1',
        0,
        0, pcZmkCipher_Lmk,
        '0', pcDisData,
        0,
        strlen(pcPublicKey)/2,
        pucPubKey,
        '0', 0, NULL, NULL,
        pcSubKeyCipher_Lmk,
        &len,
        pucPubKey,
        NULL,
        pcSubKeyCv);
    if (rt)
    {
        LOG_ERROR("%s%02d", "HSM_MGT_X0_GenerateKey failed, error code: ", rt);
        return rt;
    }
    Tools_ConvertByte2HexStr(pucPubKey, len, pcSubKeyCipher_TK);
    return SDR_OK;
}

DLL int  Tass_DeriveKeyExportedByZMK(
    void *hSessionHandle,int nSock,
    char *pcKeyCipher_Lmk,
    char *pcZmkCipher_Lmk,
    char *pcDisData,
    char *pcKeyType,
    char *pcSubKeyCipher_ZMK,
    char *pcSubKeyCipher_Lmk,
    char *pcSubKeyCv)
{
    int rt, iKeyType;
    char cSymmAlgSrc, cSymmAlgKEK;
    unsigned char pucPubKey[4096] = { 0 };

    if (pcKeyCipher_Lmk == NULL)
    {
        LOG_ERROR("%s", "pucPublicKey must not be NULL");
        return HAR_PARAM_VALUE;
    }
    if (pcZmkCipher_Lmk == NULL)
    {
        LOG_ERROR("%s", "pcPublicKey must not be NULL");
        return HAR_PARAM_VALUE;
    }
    if (pcDisData == NULL)
    {
        LOG_ERROR("%s", "pcDisData malloc memory error");
        return HAR_PARAM_VALUE;
    }
    if (pcKeyType == NULL)
    {
        LOG_ERROR("%s", "pcKeyType malloc memory error");
        return HAR_PARAM_VALUE;
    }
    sscanf(pcKeyType, "%d", &iKeyType);
    if (pcSubKeyCipher_ZMK == NULL)
    {
        LOG_ERROR("%s", "pcSubKeyCipher_ZMK malloc memory error");
        return HAR_PARAM_VALUE;
    }
    if (pcSubKeyCipher_Lmk == NULL)
    {
        LOG_ERROR("%s", "pcSubKeyCipher_Lmk malloc memory error");
        return HAR_PARAM_VALUE;
    }
    if (pcSubKeyCv == NULL)
    {
        LOG_ERROR("%s", "pcSubKeyCv malloc memory error");
        return HAR_PARAM_VALUE;
    }

    cSymmAlgSrc =
        (*pcKeyCipher_Lmk == 'S' ? '1' : (*pcKeyCipher_Lmk == 'P' ? '2' : (*pcKeyCipher_Lmk == 'L' ? '4' : '3')));
    cSymmAlgKEK =
        (*pcZmkCipher_Lmk == 'S' ? '1' : (*pcZmkCipher_Lmk == 'P' ? '2' : (*pcZmkCipher_Lmk == 'L' ? '4' : '3')));
    rt = HSM_MGT_X0_GenerateKey(
        hSessionHandle, 0,
        '1',
        14,
        cSymmAlgSrc,
        '1',
        0,
        0, pcKeyCipher_Lmk,
        (strlen(pcDisData) / 16) & 0x30, pcDisData,
        0,
        0, NULL,
        cSymmAlgKEK,
        0, pcZmkCipher_Lmk,
        NULL,
        pcSubKeyCipher_Lmk,
        NULL,
        NULL,
        pcSubKeyCipher_ZMK,
        pcSubKeyCv);
    if (rt)
    {
        LOG_ERROR("%s%02d", "HSM_MGT_X0_GenerateKey failed, error code: ", rt);
        return rt;
    }

    return SDR_OK;
}

DLL int Tass_Disper_Zmk(
    void *hSessionHandle,int nSock,
    int iKeyIdx,
    char *pcKey_LMK,
    char *pcDisData,
    int iZmkIdx,
    char *pcZmkKey_LMK,
    char *pcZmk_ZMK,
    char *pcZmk_LMK,
    char *pcZmkCv)
{
    int rt;
    char cSymmAlgSrc, cSymmAlgKEK;
    unsigned char pucPubKey[4096] = { 0 };

    if (iKeyIdx != 0)
    {
        LOG_ERROR("%s", "iKeyIdx must be 0");
        return HAR_PARAM_VALUE;
    }
    if (pcKey_LMK == NULL)
    {
        LOG_ERROR("%s", "pcKey_LMK must not be NULL");
        return HAR_PARAM_VALUE;
    }
    if (pcDisData == NULL)
    {
        LOG_ERROR("%s", "pcDisData malloc memory error");
        return HAR_PARAM_VALUE;
    }
    if (pcZmk_LMK == NULL)
    {
        LOG_ERROR("%s", "pcZmk_LMK malloc memory error");
        return HAR_PARAM_VALUE;
    }
    if (pcZmkCv == NULL)
    {
        LOG_ERROR("%s", "pcZmkCv malloc memory error");
        return HAR_PARAM_VALUE;
    }

    cSymmAlgKEK =
        (*pcKey_LMK == 'S' ? '1' : (*pcKey_LMK == 'P' ? '2' : (*pcKey_LMK == 'L' ? '4' : '3')));
    if (iZmkIdx != 0)
        cSymmAlgSrc = cSymmAlgKEK;
    else
        cSymmAlgSrc =
            (*pcZmkKey_LMK == 'S' ? '1' : (*pcZmkKey_LMK == 'P' ? '2' : (*pcZmkKey_LMK == 'L' ? '4' : '3')));
    rt = HSM_MGT_X0_GenerateKey(
        hSessionHandle, 0,
        '1',
        14,
        cSymmAlgSrc,
        '1',
        0,
        iZmkIdx, pcZmkKey_LMK,
        (strlen(pcDisData) / 16) & 0x30, pcDisData,
        0,
        0, NULL,
        cSymmAlgKEK,
        0,
        pcKey_LMK,
        NULL,
        pcZmk_LMK,
        NULL, NULL,
        pcZmk_ZMK,
        pcZmkCv);
    if (rt)
    {
        LOG_ERROR("%s%02d", "HSM_MGT_X0_GenerateKey failed, error code: ", rt);
        return rt;
    }

    return SDR_OK;
}

DLL int Tass_GenRSAKey(
    void *hSessionHandle,int nSock,
    int RsaIndex,
    char *RsaTag,
    int RsaLen, int pub_E,
    int zmkIndex,
    char *zmk_Lmk,
    char *zmk_disData,
    int mode,
    char *pucDerPublicKey,
    char *pucDerPrivateKey)
{
    int rt = SDR_OK;
    char cSymmAlg = '1';
    int KEKIndex;
    char KEKCipher[64] = { 0 }, KCV[32] = { 0 };
    int KEKFlag = 1;
    int iPubKeyLength, iPriKeyLength_LMK, iPriKeyLength_KEK;
    char pcExp[8] = { 0 };
    unsigned char pucDerPubKey[4096] = { 0 };
    unsigned char pucDerPriKey_LMK[4096] = { 0 };
    unsigned char pucDerPriKey_KEK[4096] = { 0 };
    if (zmk_Lmk != NULL)
        cSymmAlg =
        (*zmk_Lmk == 'S' ? '1' : (*zmk_Lmk == 'P' ? '2' : (*zmk_Lmk == 'L' ? '4' : '3')));
    if ((!((zmkIndex == 0) && (zmk_Lmk == NULL))) && (zmk_disData != NULL))
    {
        rt = HSM_MGT_X0_GenerateKey(
            hSessionHandle, 0,
            '1',
            00,
            cSymmAlg,
            '1',
            0,
            zmkIndex,
            zmk_Lmk,
            strlen(zmk_disData)/16, zmk_disData,
            0, 0, NULL, '0', 0, NULL, NULL,
            KEKCipher,
            NULL, NULL, NULL,
            KCV);
        if (rt)
        {
            LOG_ERROR("%s", "HSM_MGT_X0_GenerateKey is error");
            return rt;
        }
        KEKIndex = 0;
    }
    else
    {
        KEKIndex = zmkIndex;
        if (zmk_Lmk != NULL)
            strcpy(KEKCipher, zmk_Lmk);
    }
    if ((KEKIndex == 0) && (KEKCipher[0] == 0))
        KEKFlag = 0;
    sprintf(pcExp, "%d", pub_E);
    rt = HSM_RSA_EI_GenerateRSAKeyPair(
        hSessionHandle, 0,
        RsaIndex != 0 ? '1' : '2',
        RsaLen,
        1,
        RsaIndex,
        pcKeyPassword,
        '3',
        KEKFlag,
        cSymmAlg,
        mode,
        KEKFlag ? KEKIndex : 0,
        KEKFlag ? KEKCipher : NULL,
        ';',
        strlen(pcExp),
        pub_E,
        &iPubKeyLength,
        pucDerPubKey,
        &iPriKeyLength_LMK,
        pucDerPriKey_LMK,
        &iPriKeyLength_KEK,
        pucDerPriKey_KEK);
    if (rt)
    {
        LOG_ERROR("%s", "HSM_RSA_EI_GenerateRSAKeyPair is error");
        return rt;
    }
    if (KEKFlag)
        Tools_ConvertByte2HexStr(pucDerPriKey_KEK, iPriKeyLength_KEK, pucDerPrivateKey);
    else
        Tools_ConvertByte2HexStr(pucDerPriKey_LMK, iPriKeyLength_LMK, pucDerPrivateKey);
    Tools_ConvertByte2HexStr(pucDerPubKey, iPubKeyLength, pucDerPublicKey);

    return SDR_OK;
}

DLL int Tass_GenSm2Key(
    void *hSessionHandle,int nSock,
    int zmkIndex,
    char *zmk_Lmk,
    char *zmk_disData,
    int mode,
    char *SM2_D_ZMK,
    char * SM2_PUBKEY,
    char * SM2_LMK)
{
    int rt = SDR_OK;
    char cSymmAlg = '1';
    int KEKIndex;
    char KEKCipher[64] = { 0 }, KCV[32] = { 0 };
    int KEKFlag = 1;
    unsigned char pucPubKey[512] = { 0 };
    unsigned char pucPriKey_LMK[512] = { 0 };
    unsigned char pucPriKey_KEK[512] = { 0 };
    if (zmk_Lmk != NULL)
        cSymmAlg =
        (*zmk_Lmk == 'S' ? '1' : (*zmk_Lmk == 'P' ? '2' : (*zmk_Lmk == 'L' ? '4' : '3')));
    if ((!((zmkIndex == 0) && (zmk_Lmk == NULL))) && (zmk_disData != NULL))
    {
        rt = HSM_MGT_X0_GenerateKey(
            hSessionHandle, 0,
            '1',
            00,
            cSymmAlg,
            '1',
            0,
            zmkIndex,
            zmk_Lmk,
            (strlen(zmk_disData) / 16) & 0x30,
            zmk_disData,
            0, 0, NULL, '0', 0, NULL, NULL,
            KEKCipher,
            NULL, NULL, NULL,
            KCV);
        if (rt)
        {
            LOG_ERROR("%s", "HSM_MGT_X0_GenerateKey is error");
            return rt;
        }
        KEKIndex = 0;
    }
    else
    {
        KEKIndex = zmkIndex;
        if (zmk_Lmk != NULL)
            strcpy(KEKCipher, zmk_Lmk);
    }
    if ((KEKIndex == 0) && (KEKCipher[0] == 0))
        KEKFlag = 0;
    rt = HSM_BASE_UO_GenerateSM2KeyPair(
        hSessionHandle, 0,
        256,
        '3',
        0,
        KEKFlag ? ';' : '\0',
        cSymmAlg,
        mode,
        KEKFlag ? KEKIndex : 0,
        KEKFlag ? KEKCipher : NULL,
        NULL,
        pucPubKey,
        pucPubKey + 32,
        pucPriKey_LMK,
        pucPriKey_KEK);
    if (rt)
    {
        LOG_ERROR("%s", "HSM_BASE_UO_GenerateSM2KeyPair is error");
        return rt;
    }
    if (KEKFlag)
        Tools_ConvertByte2HexStr(pucPriKey_KEK, 32, SM2_D_ZMK);
    Tools_ConvertByte2HexStr(pucPriKey_LMK, 40, SM2_LMK);
    Tools_ConvertByte2HexStr(pucPubKey, 64, SM2_PUBKEY);
    return SDR_OK;
}

DLL int Tass_Gen_ANSI_Mac(
    void *hSessionHandle,int nSock,
    int iKeyIdx,
    char *pcKeyCipherByLmk,
    int iInDataLen,
    unsigned char *pcInData,
    char *pcMac)
{
    int rt = SDR_OK;
    char cSymmAlg;
    unsigned char pucData[4096] = { 0 };
    if (iKeyIdx != 0)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] is invalid, when iKeyIdx = 0.", iKeyIdx);
        return HAR_PARAM_VALUE;
    }
    if (pcKeyCipherByLmk == NULL)
    {
        LOG_ERROR("Parameter pcKeyCipherByLmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_VALUE;
    }
    if ((strlen(pcInData) != iInDataLen * 2) || (iInDataLen > 4096))
    {
        LOG_ERROR("Parameter length pcKeyCipherByLmk = [%d] or iInDataLen = [%d] is invalid, must be less than %d.",
            strlen(pcKeyCipherByLmk), iInDataLen, 4096);
        return HAR_PARAM_LEN;
    }
    if (pcMac == NULL)
    {
        LOG_ERROR("Parameter pcMac = [%s] is invalid.", "NULL");
        return HAR_PARAM_VALUE;
    }
    cSymmAlg = 
        (*pcKeyCipherByLmk == 'S' ?  '1' : (*pcKeyCipherByLmk == 'P' ? '2' : (*pcKeyCipherByLmk == 'L' ? '4' : '3')));
    Tools_ConvertHexStr2Byte(pcInData, strlen(pcInData), pucData);
    rt = HSM_IC_V4_CalculateMAC(
        hSessionHandle, 0,
        cSymmAlg,
        iKeyIdx,
        pcKeyCipherByLmk,
        '1',
        '0', NULL,
        cSymmAlg == '3' ? "0000000000000000" : "00000000000000000000000000000000",
        strlen(pcInData) / 2,
        pucData,
        pcMac);
    if (rt)
    {
        LOG_ERROR("%s%02d", "HSM_IC_V4_CalculateMAC failed, error code: ", rt);
        return rt;
    }

    return SDR_OK;
}

DLL int Tass_Generate_Mak(
    void *hSessionHandle,int nSock,
    int iKeyIdx,
    char *pcKeyCipherByLmk,
    char cMakScheme,
    char *pcMakCipherByZmk,
    char *pcMakCipherByLmk,
    char *pcMakCv)
{
    int rt;
    char cSymmAlg1, cSymmAlg2;
    if (iKeyIdx != 0)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] is invalid, when iKeyIdx = 0.", iKeyIdx);
        return HAR_PARAM_VALUE;
    }
    if (pcKeyCipherByLmk == NULL)
    {
        LOG_ERROR("Parameter pcKeyCipherByLmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_VALUE;
    }
    if (pcMakCipherByZmk == NULL)
    {
        LOG_ERROR("Parameter pcMakCipherByZmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_VALUE;
    }
    if (pcMakCipherByLmk == NULL)
    {
        LOG_ERROR("Parameter pcMakCipherByLmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_VALUE;
    }
    if (pcMakCv == NULL)
    {
        LOG_ERROR("Parameter pcMakCv = [%s] is invalid.", "NULL");
        return HAR_PARAM_VALUE;
    }

    cSymmAlg1 =
        (cMakScheme == 'S' ? '1' : (cMakScheme == 'P' ? '2' : (cMakScheme == 'L' ? '4' : '3')));
    cSymmAlg2 =
        (*pcKeyCipherByLmk == 'S' ? '1' : (*pcKeyCipherByLmk == 'P' ? '2' : (*pcKeyCipherByLmk == 'L' ? '4' : '3')));
    rt = HSM_MGT_X0_GenerateKey(
        hSessionHandle, 0,
        '0',
        14,
        cSymmAlg1,
        '1',
        16,
        0, NULL, '0', NULL, 0, 0, NULL,
        cSymmAlg2,
        iKeyIdx,
        pcKeyCipherByLmk,
        NULL,
        pcMakCipherByLmk,
        NULL,
        NULL,
        pcMakCipherByZmk,
        pcMakCv);
    if (rt)
    {
        LOG_ERROR("%s%02d", "HSM_MGT_X0_GenerateKey failed, error code: ", rt);
        return rt;
    }

    return SDR_OK;
}

DLL int Tass_Generate_Pik(
    void *hSessionHandle,int nSock,
    int iKeyIdx,
    char *pcKeyCipherByLmk,
    char cPikScheme,
    char *pcPikCipherByZmk,
    char *pcPikCipherByLmk,
    char *pcPikCv)
{
    int rt;
    char cSymmAlg1, cSymmAlg2;
    if (iKeyIdx != 0)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] is invalid, when iKeyIdx = 0.", iKeyIdx);
        return HAR_PARAM_VALUE;
    }
    if (pcKeyCipherByLmk == NULL)
    {
        LOG_ERROR("Parameter pcKeyCipherByLmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_VALUE;
    }
    if (pcPikCipherByZmk == NULL)
    {
        LOG_ERROR("Parameter pcPikCipherByZmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_VALUE;
    }
    if (pcPikCipherByLmk == NULL)
    {
        LOG_ERROR("Parameter pcPikCipherByLmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_VALUE;
    }
    if (pcPikCv == NULL)
    {
        LOG_ERROR("Parameter pcPikCv = [%s] is invalid.", "NULL");
        return HAR_PARAM_VALUE;
    }

    cSymmAlg1 =
        (cPikScheme == 'S' ? '1' : (cPikScheme == 'P' ? '2' : (cPikScheme == 'L' ? '4' : '3')));
    cSymmAlg2 =
        (*pcKeyCipherByLmk == 'S' ? '1' : (*pcKeyCipherByLmk == 'P' ? '2' : (*pcKeyCipherByLmk == 'L' ? '4' : '3')));
    rt = HSM_MGT_X0_GenerateKey(
        hSessionHandle, 0,
        '0',
        14,
        cSymmAlg1,
        '1',
        16,
        0, NULL, '0', NULL, 0, 0, NULL,
        cSymmAlg2,
        iKeyIdx,
        pcKeyCipherByLmk,
        NULL,
        pcPikCipherByLmk,
        NULL,
        NULL,
        pcPikCipherByZmk,
        pcPikCv);
    if (rt)
    {
        LOG_ERROR("%s%02d", "HSM_MGT_X0_GenerateKey failed, error code: ", rt);
        return rt;
    }

    return SDR_OK;
}

DLL int Tass_Generate_Zek(
    void *hSessionHandle,int nSock,
    int iKeyIdx,
    char *pcKeyCipherByLmk,
    char cZekScheme, char *pcZekCipherByZmk,
    char *pcZekCipherByLmk,
    char *pcZekCv)
{
    int rt;
    char cSymmAlg1, cSymmAlg2;
    if (iKeyIdx != 0)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] is invalid, when iKeyIdx = 0.", iKeyIdx);
        return HAR_PARAM_VALUE;
    }
    if (pcKeyCipherByLmk == NULL)
    {
        LOG_ERROR("Parameter pcKeyCipherByLmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_VALUE;
    }
    if (pcZekCipherByZmk == NULL)
    {
        LOG_ERROR("Parameter pcZekCipherByZmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_VALUE;
    }
    if (pcZekCipherByLmk == NULL)
    {
        LOG_ERROR("Parameter pcZekCipherByLmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_VALUE;
    }
    if (pcZekCv == NULL)
    {
        LOG_ERROR("Parameter pcZekCv = [%s] is invalid.", "NULL");
        return HAR_PARAM_VALUE;
    }

    cSymmAlg1 =
        (cZekScheme == 'S' ? '1' : (cZekScheme == 'P' ? '2' : (cZekScheme == 'L' ? '4' : '3')));
    cSymmAlg2 =
        (*pcKeyCipherByLmk == 'S' ? '1' : (*pcKeyCipherByLmk == 'P' ? '2' : (*pcKeyCipherByLmk == 'L' ? '4' : '3')));
    rt = HSM_MGT_X0_GenerateKey(
        hSessionHandle, 0,
        '0',
        14,
        cSymmAlg1,
        '1',
        16,
        0, NULL, '0', NULL, 0, 0, NULL,
        cSymmAlg2,
        iKeyIdx,
        pcKeyCipherByLmk,
        NULL,
        pcZekCipherByLmk,
        NULL,
        NULL,
        pcZekCipherByZmk,
        pcZekCv);
    if (rt)
    {
        LOG_ERROR("%s%02d", "HSM_MGT_X0_GenerateKey failed, error code: ", rt);
        return rt;
    }

    return SDR_OK;
}

DLL int Tass_Generate_Zmk(
    void *hSessionHandle,int nSock,
    int iKeyIdx,
    char *pcKeyCipherByLmk,
    char cZmkScheme,
    char *pcZmkCipherByZmk,
    char *pcZmkCipherByLmk,
    char *pcZmkCv)
{
    int rt;
    char cSymmAlg1, cSymmAlg2;
    if (iKeyIdx != 0)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] is invalid, when iKeyIdx = 0.", iKeyIdx);
        return HAR_PARAM_VALUE;
    }
    if (pcKeyCipherByLmk == NULL)
    {
        LOG_ERROR("Parameter pcKeyCipherByLmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_VALUE;
    }
    if (pcZmkCipherByZmk == NULL)
    {
        LOG_ERROR("Parameter pcZmkCipherByZmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_VALUE;
    }
    if (pcZmkCipherByLmk == NULL)
    {
        LOG_ERROR("Parameter pcZmkCipherByLmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_VALUE;
    }
    if (pcZmkCv == NULL)
    {
        LOG_ERROR("Parameter pcZmkCv = [%s] is invalid.", "NULL");
        return HAR_PARAM_VALUE;
    }

    cSymmAlg1 =
        (cZmkScheme == 'S' ? '1' : (cZmkScheme == 'P' ? '2' : (cZmkScheme == 'L' ? '4' : '3')));
    cSymmAlg2 =
        (*pcKeyCipherByLmk == 'S' ? '1' : (*pcKeyCipherByLmk == 'P' ? '2' : (*pcKeyCipherByLmk == 'L' ? '4' : '3')));
    rt = HSM_MGT_X0_GenerateKey(
        hSessionHandle, 0,
        '0',
        14,
        cSymmAlg1,
        '1',
        16,
        0, NULL, '0', NULL, 0, 0, NULL,
        cSymmAlg2,
        iKeyIdx,
        pcKeyCipherByLmk,
        NULL,
        pcZmkCipherByLmk,
        NULL,
        NULL,
        pcZmkCipherByZmk,
        pcZmkCv);
    if (rt)
    {
        LOG_ERROR("%s%02d", "HSM_MGT_X0_GenerateKey failed, error code: ", rt);
        return rt;
    }

    return SDR_OK;
}

DLL int Tass_PRIVATE_Oper(
    void *hSessionHandle,int nSock,
    int keytype,
    char *Rsa_LMK,
    char *SM2_LMK,
    char *indata,
    char *outdata)
{
    int rt = SDR_OK;
    char buf[4096] = { 0 },priKey[4096];
    int len;
    if (indata == NULL)
    {
        LOG_ERROR("%s", "Parameter indata must not be NULL.");
        return HAR_PARAM_VALUE;
    }
    if (outdata == NULL)
    {
        LOG_ERROR("%s", "Parameter outdata must not be NULL.");
        return HAR_PARAM_VALUE;
    }
    len = Tools_ConvertHexStr2Byte(indata, strlen(indata), buf);
    if (len == -1)
    {
        LOG_ERROR("%s", "Parameter indata has no-hexadecimal charactor.");
        return HAR_PARAM_VALUE;
    }
    if (keytype == 0)
    {
        if (Rsa_LMK == NULL)
        {
            LOG_ERROR("%s", "Parameter Rsa_LMK must not be NULL.");
            return HAR_PARAM_VALUE;
        }
        len = Tools_ConvertHexStr2Byte(Rsa_LMK, strlen(Rsa_LMK), priKey);
        if (len == -1)
        {
            LOG_ERROR("%s", "Parameter SM2_LMK has no-hexadecimal charactor.");
            return HAR_PARAM_VALUE;
        }
        rt = HSM_RSA_VA_PrivateKeyOperation(
            hSessionHandle, 0,
            0,
            0,
            0, 0, 0, NULL, 0, NULL,
            strlen(Rsa_LMK) / 2,
            priKey,
            strlen(indata) / 2,
            buf,
            &len,
            outdata);
        if (rt)
        {
            LOG_ERROR("%s%02d", "HSM_RSA_VA_PrivateKeyOperation failed, error code: ", rt);
            return rt;
        }
    }
    else if (keytype == 1)
    {
        if (SM2_LMK == NULL)
        {
            LOG_ERROR("%s", "Parameter SM2_LMK must not be NULL.");
            return HAR_PARAM_VALUE;
        }
        len = Tools_ConvertHexStr2Byte(SM2_LMK, strlen(SM2_LMK), priKey);
        if (len == -1)
        {
            LOG_ERROR("%s", "Parameter SM2_LMK has no-hexadecimal charactor.");
            return HAR_PARAM_VALUE;
        }
        rt = HSM_BASE_UW_SM2PriKeyDecrypt(
            hSessionHandle, 0,
            0, NULL,
            priKey,
            strlen(indata) / 2,
            buf,
            &len,
            buf);
        if (rt)
        {
            LOG_ERROR("%s%02d", "HSM_BASE_UW_SM2PriKeyDecrypt failed, error code: ", rt);
            return rt;
        }
        Tools_ConvertByte2HexStr(buf, len, outdata);
    }
    else
    {
        LOG_ERROR("%s", "Parameter keytype is invalid, it should be 0 or 1.");
        return HAR_PARAM_VALUE;
    }

    return rt;
}

DLL int Tass_PubKey_Oper(
    void *hSessionHandle,int nSock,
    int keytype,
    char *indata,
    char *RSAPubKeyE,
    char *RSAPubKeyN,
    char *SM2PubKey,
    char *outdata)
{
    int   rt = SDR_OK;
    char buf[4096] = { 0 }, pubKey[128] = { 0 };
    int len;
    if (indata == NULL)
    {
        LOG_ERROR("%s", "Parameter indata must not be NULL.");
        return HAR_PARAM_VALUE;
    }
    if (outdata == NULL)
    {
        LOG_ERROR("%s", "Parameter outdata must not be NULL.");
        return HAR_PARAM_VALUE;
    }
    if (keytype == 0)
    {
        if ((RSAPubKeyE == NULL) || (RSAPubKeyN == NULL))
        {
            LOG_ERROR("%s", "Parameter RSAPubKeyE and RSAPubKeyN must not be NULL.");
            return HAR_PARAM_VALUE;
        }
        Tools_Der(RSAPubKeyN, RSAPubKeyE, buf, &len);
        len = Tools_ConvertHexStr2Byte(buf, len, buf);
        rt = HSM_RSA_UK_PublicKeyOperation(
            hSessionHandle, 0,
            1,
            0,
            0, 0, 0, NULL,
            1,
            0,
            1,
            len,
            buf,
            strlen(indata) / 2,
            (char *)indata,
            &len,
            buf);
        if (rt)
        {
            LOG_ERROR("%s%02d", "HSM_RSA_UK_PublicKeyOperation failed, error code: ", rt);
            return rt;
        }
        Tools_ConvertByte2HexStr(buf, len, outdata);
    }
    else if (keytype == 1)
    {
        if (SM2PubKey == NULL)
        {
            LOG_ERROR("%s", "Parameter SM2PubKey must not be NULL.");
            return HAR_PARAM_VALUE;
        }
        len = Tools_ConvertHexStr2Byte(indata, strlen(indata), buf);
        if (len == -1)
        {
            LOG_ERROR("%s", "Parameter indata has no-hexadecimal charactor.");
            return HAR_PARAM_VALUE;
        }
        len = Tools_ConvertHexStr2Byte(SM2PubKey, strlen(SM2PubKey), pubKey);
        if (len == -1)
        {
            LOG_ERROR("%s", "Parameter SM2PubKey has no-hexadecimal charactor.");
            return HAR_PARAM_VALUE;
        }
        rt = HSM_BASE_UU_SM2PubKeyEncrypt(
            hSessionHandle, 0,
            0,
            pubKey,
            pubKey + 32,
            strlen(indata) / 2,
            buf,
            &len,
            buf);
        if (rt)
        {
            LOG_ERROR("%s%02d", "HSM_BASE_UU_SM2PubKeyEncrypt failed, error code: ", rt);
            return rt;
        }
        Tools_ConvertByte2HexStr(buf, len, outdata);
    }
    else
    {
        LOG_ERROR("%s", "Parameter keytype  is invalid, it should be 0 or 1.");
        return HAR_PARAM_VALUE;
    }

    return rt;
}

#ifdef ZEOR
/***************************************************************************
* Subroutine: Tass_VerifyARQC
* Function:   验证ARQC/TC
* Input:
*    @iKeyIdx               密钥索引
*    @pcKeyCipherByLmk      密钥密文
*    @pcPan                 PAN
*    @pcATC                 ATC
*    @pcTransData           交易数据
*    @pcARQC                待验证的ARQC
* Output:
*    无
*
* Return:      成功返回0，其他表示失败
* Description: 分散MDK源密钥产生卡片主密钥UDK，根据ATC值计算交易会话密钥SDK；
*              填充交易数据，使用SDK计算其MAC值，与输入的ARQC对比。
*
* Author:       Luo Cangjian
* Date:         2015.06.05
* ModifyRecord:
* *************************************************************************/
HSMAPI int
Tass_VerifyARQC(
        int     iKeyIdx,
        char    *pcKeyCipherByLmk,
        char    *pcPan,
        char    *pcATC,
        char    *pcTransData,
        char    *pcARQC)
{
    int     rv = SDR_OK;
    char    szKeyCipher[49 + 1] = {0};

    rv = Tools_CheckKeyValidity(iKeyIdx, pcKeyCipherByLmk, szKeyCipher);
    if(rv)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] or pcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iKeyIdx, pcKeyCipherByLmk, rv);
        return rv;
    }

    if(pcPan == NULL)
    {
        LOG_ERROR("Parameter pcPan = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcPan) != 16)
    {
        LOG_ERROR("Parameter pcPan'length = [%d] is invalid. It must be 16 characters.", strlen(pcPan));
        return HAR_PARAM_LEN;
    }

    if(pcATC == NULL)
    {
        LOG_ERROR("Parameter pcATC = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcATC) != 4)
    {
        LOG_ERROR("Parameter pcATC'length = [%s] is invalid. It must be 4 characters.", strlen(pcATC));
        return HAR_PARAM_LEN;
    }

    if(pcTransData == NULL)
    {
        LOG_ERROR( "Parameter pcTransData = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcTransData) % 2 != 0)
    {
        LOG_ERROR("Parameter pcTransData'length = [%d], Its length is a multiple of 2.", strlen(pcTransData));
        return HAR_PARAM_LEN;
    }

    if(strlen(pcTransData) < 2 || strlen(pcTransData) > 255 * 2)
    {
        LOG_ERROR("Parameter pcTransData'length = [%d] is ivnalid. Its length must be 2 -- 510 characters.", strlen(pcTransData));
        return HAR_PARAM_LEN;
    }

    if(pcARQC == NULL)
    {
        LOG_ERROR("Parameter pcARQC = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcARQC) != 16)
    {
        LOG_ERROR("Parameter pcARQC'length = [%d] is invalid. It must be 16 characters.", strlen(pcARQC));
        return HAR_PARAM_LEN;
    }

    rv = HSM_IC_VerifyArqc(iKeyIdx,
                    szKeyCipher,
                    pcPan,
                    pcATC,
                    pcTransData,
                    pcARQC);
    if(rv)
    {
         LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/**
 * @brief   TODO:不在本次任务中   
 *
 * @param   iKeyIdx
 * @param   pcKeyCipherByLmk
 * @param   pcPan
 * @param   pcATC
 * @param   pcARQC
 * @param   pcARC
 * @param   pcARPC
 *
 * @return  
 */
DLL int Tass_GenARPC(
        int     iKeyIdx,
        char    *pcKeyCipherByLmk,
        char    *pcPan,
        char    *pcATC,
        char    *pcARQC,
        char    *pcARC,
        char    *pcARPC)
{
    int     rv = SDR_OK;
    char    szKeyCipher[49 + 1] = {0};

    rv = Tools_CheckKeyValidity(iKeyIdx, pcKeyCipherByLmk, szKeyCipher);
    if(rv)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] or pcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iKeyIdx, pcKeyCipherByLmk, rv);
        return rv;
    }

    if(pcPan == NULL)
    {
        LOG_ERROR("Parameter pcPan = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcPan) != 16)
    {
        LOG_ERROR("Parameter pcPan'length = [%d] is invalid. It must be 16 characters.", strlen(pcPan));
        return HAR_PARAM_LEN;
    }

    if(pcATC == NULL)
    {
        LOG_ERROR("Parameter pcATC = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcATC) != 4)
    {
        LOG_ERROR("Parameter pcATC'length = [%s] is invalid. It must be 4 characters.", strlen(pcATC));
        return HAR_PARAM_LEN;
    }

    if(pcARQC == NULL)
    {
        LOG_ERROR("Parameter pcARQC = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcARQC) != 16)
    {
        LOG_ERROR("Parameter pcARQC'length = [%d] is invalid. It must be 16 characters.", strlen(pcARQC));
        return HAR_PARAM_LEN;
    }

    if(pcARC == NULL)
    {
        LOG_ERROR("Parameter pcARC = [%d] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcARC) != 4)
    {
        LOG_ERROR("Parameter pcARC'length = [%d] is invalid. It must be 4 characters.", strlen(pcARC));
        return HAR_PARAM_LEN;
    }

    if(pcARPC == NULL)
    {
        LOG_ERROR("Parameter pcARPC = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    /*** 该函数模式标志应该为2 ***/
    rv = HSM_IC_GenerateArpc(
            iKeyIdx,
            szKeyCipher,
            pcPan,
            pcATC,
            pcARQC,
            pcARC,
            pcARPC/*out*/);
    if(rv)
    {
         LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/**
 * @brief   TOOD: 不在本次任务
 *
 * @param   iKeyIdx
 * @param   pcKeyCipherByLmk
 * @param   pcPan
 * @param   pcATC
 * @param   pcTransData
 * @param   pcARQC
 * @param   pcARC
 * @param   pcARPC
 *
 * @return  
 */
DLL int Tass_VerifyARQC_GenARPC(
        int     iKeyIdx,
        char    *pcKeyCipherByLmk,
        char    *pcPan,
        char    *pcATC,
        char    *pcTransData,
        char    *pcARQC,
        char    *pcARC,
        char    *pcARPC/*out*/)
{
    int     rv = SDR_OK;
    char    szKeyCipher[49 + 1] = {0};

    rv = Tools_CheckKeyValidity(iKeyIdx, pcKeyCipherByLmk, szKeyCipher);
    if(rv)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] or pcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iKeyIdx, pcKeyCipherByLmk, rv);
        return rv;
    }

    if(pcPan == NULL)
    {
        LOG_ERROR("Parameter pcPan = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcPan) != 16)
    {
        LOG_ERROR("Parameter pcPan'length = [%d] is invalid. It must be 16 characters.", strlen(pcPan));
        return HAR_PARAM_LEN;
    }

    if(pcATC == NULL)
    {
        LOG_ERROR("Parameter pcATC = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcATC) != 4)
    {
        LOG_ERROR("Parameter pcATC'length = [%s] is invalid. It must be 4 characters.", strlen(pcATC));
        return HAR_PARAM_LEN;
    }

    if(pcTransData == NULL)
    {
        LOG_ERROR("Parameter pcTransData = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcTransData) % 2 != 0)
    {
        LOG_ERROR("Parameter pcTransData'length = [%d], Its length is a multiple of 2.", strlen(pcTransData));
        return HAR_PARAM_LEN;
    }

    if(strlen(pcTransData) < 2 || strlen(pcTransData) > 255 * 2)
    {
        LOG_ERROR("Parameter pcTransData'length = [%d] is ivnalid. Its length must be 2 -- 510 characters.", strlen(pcTransData));
        return HAR_PARAM_LEN;
    }

    if(pcARQC == NULL)
    {
        LOG_ERROR("Parameter pcARQC = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcARQC) != 16)
    {
        LOG_ERROR("Parameter pcARQC'length = [%d] is invalid. It must be 16 characters.", strlen(pcARQC));
        return HAR_PARAM_LEN;
    }

    if(pcARC == NULL)
    {
        LOG_ERROR("Parameter pcARC = [%d] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcARC) != 4)
    {
        LOG_ERROR("Parameter pcARC'length = [%d] is invalid. It must be 4 characters.", strlen(pcARC));
        return HAR_PARAM_LEN;
    }

    if(pcARPC == NULL)
    {
        LOG_ERROR( "Parameter pcARPC = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    /*** 该函数模式标志应该为1 ***/
    rv = HSM_IC_VerifyArqc_GenARPC(
            iKeyIdx,
            szKeyCipher,
            pcPan,
            pcATC,
            pcTransData,
            pcARQC,
            pcARC,
            pcARPC);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);

        if(rv == 1)
        {
            LOG_ERROR("authentication failed, ARQC = [%s].", pcARPC);
        }
    }

    return rv;
}


/**
 * @brief   TODO: 不在本次开发任务
 *
 * @param   iKeyIdx
 * @param   pcKeyCipherByLmk
 * @param   pcPan
 * @param   pcATC
 * @param   pcTransData
 * @param   pcDataCipher
 *
 * @return  
 */
DLL int Tass_ScriptEncrypt(
        int     iKeyIdx,
        char    *pcKeyCipherByLmk,
        char    *pcPan,
        char    *pcATC,
        char    *pcTransData,
        char    *pcDataCipher/*out*/)
{
    int     rv = SDR_OK;
    char    szKeyCipher[49 + 1] = {0};

    rv = Tools_CheckKeyValidity(iKeyIdx, pcKeyCipherByLmk, szKeyCipher);
    if(rv)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] or pcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iKeyIdx, pcKeyCipherByLmk, rv);
        return rv;
    }

    if(pcPan == NULL)
    {
        LOG_ERROR("Parameter pcPan = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcPan) != 16)
    {
        LOG_ERROR("Parameter pcPan'length = [%d] is invalid. It must be 16 characters.", strlen(pcPan));
        return HAR_PARAM_LEN;
    }

    if(pcATC == NULL)
    {
        LOG_ERROR("Parameter pcATC = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcATC) != 4)
    {
        LOG_ERROR("Parameter pcATC'length = [%s] is invalid. It must be 4 characters.", strlen(pcATC));
        return HAR_PARAM_LEN;
    }

    if(pcTransData == NULL)
    {
        LOG_ERROR( "Parameter pcTransData = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcTransData) % 2 != 0)
    {
        LOG_ERROR("Parameter pcTransData'length = [%d], Its length is a multiple of 2.", strlen(pcTransData));
        return HAR_PARAM_LEN;
    }

    if(strlen(pcTransData) < 2 || strlen(pcTransData) > 984 * 2)
    {
        LOG_ERROR("Parameter pcTransData'length = [%d] is ivnalid. Its length must be 2 -- %d characters.",
                strlen(pcTransData), 984 * 2);
        return HAR_PARAM_LEN;
    }

    if(pcDataCipher == NULL)
    {
        LOG_ERROR("Parameter pcDataCipher = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    /*** 脚本加密 ***/
    rv = HSM_IC_EncryptPbocScript(
            iKeyIdx,
            szKeyCipher,
            pcPan,
            pcATC,
            pcTransData,
            pcDataCipher);
    if(rv)
    {
         LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}


/**
 * @brief   TODO: 不在本次开发任务
 *
 * @param   iKeyIdx
 * @param   pcKeyCipherByLmk
 * @param   pcPan
 * @param   pcATC
 * @param   pcTransData
 * @param   pcMAC
 *
 * @return  
 */
DLL int Tass_ScriptMAC(
        int     iKeyIdx,
        char    *pcKeyCipherByLmk,
        char    *pcPan,
        char    *pcATC,
        char    *pcTransData,
        char    *pcMAC)
{
    int     rv = SDR_OK;
    char    szKeyCipher[49 + 1] = {0};

    rv = Tools_CheckKeyValidity(iKeyIdx, pcKeyCipherByLmk, szKeyCipher);
    if(rv)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] or pcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iKeyIdx, pcKeyCipherByLmk, rv);
        return rv;
    }

    if(pcPan == NULL)
    {
        LOG_ERROR("Parameter pcPan = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcPan) != 16)
    {
        LOG_ERROR("Parameter pcPan'length = [%d] is invalid. It must be 16 characters.", strlen(pcPan));
        return HAR_PARAM_LEN;
    }

    if(pcATC == NULL)
    {
        LOG_ERROR("Parameter pcATC = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcATC) != 4)
    {
        LOG_ERROR("Parameter pcATC'length = [%s] is invalid. It must be 4 characters.", strlen(pcATC));
        return HAR_PARAM_LEN;
    }

    if(pcTransData == NULL)
    {
        LOG_ERROR("Parameter pcTransData = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcTransData) % 2 != 0)
    {
        LOG_ERROR("Parameter pcTransData'length = [%d], Its length is a multiple of 2.", strlen(pcTransData));
        return HAR_PARAM_LEN;
    }

    if(strlen(pcTransData) < 2 || strlen(pcTransData) > 984 * 2)
    {
        LOG_ERROR("Parameter pcTransData'length = [%d] is ivnalid. Its length must be 2 -- %d characters.",
                strlen(pcTransData), 984 * 2);
        return HAR_PARAM_LEN;
    }

    if(pcMAC == NULL)
    {
        LOG_ERROR("Parameter pcMAC = [%s] is invalid..", "NULL");
        return HAR_PARAM_ISNULL;
    }

    /*** 计算脚本MAC ***/
    rv = HSM_IC_GeneratePbocScriptMac(
            iKeyIdx,
            szKeyCipher,
            pcPan,
            pcATC,
            pcTransData,
            pcMAC);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/**
 * @brief   TODO: 不在本次开发任务
 *
 * @param   hSessionHandle
 * @param   iKeyIdx
 * @param   pcKeyCipherByLmk
 * @param   iEncMode
 * @param   iDiversifyNum
 * @param   pcDiversifyData
 * @param   iSessionKeyMode
 * @param   pcSessionKeyData
 * @param   iPaddingMode
 * @param   pcInData
 * @param   pcIv
 * @param   pcOutData
 *
 * @return  
 */
DLL int Tass_EncryptICData(
        void    *hSessionHandle,
        int     iKeyIdx,
        char    *pcKeyCipherByLmk,
        int     iEncMode,
        int     iDiversifyNum,
        char    *pcDiversifyData,
        int     iSessionKeyMode,
        char    *pcSessionKeyData,
        int     iPaddingMode,
        char    *pcInData,
        char    *pcIv,
        char    *pcOutData)
{
    int     rv = SDR_OK;
    int     iOutDataLen = 0;
    int     iInDataLen = 0;
    unsigned char aucInData[1024 * 2] = {0};
    unsigned char aucOutData[1024 * 4] = {0};
    char    szKeyCipher[49 + 1] = {0};

    rv = Tools_CheckKeyValidity(iKeyIdx, pcKeyCipherByLmk, szKeyCipher);
    if(rv)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] or pcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iKeyIdx, pcKeyCipherByLmk, rv);
        return rv;
    }

    if(iEncMode != 0 && iEncMode != 1)
    {
        LOG_ERROR("Parameter iEncMode = [%d] is invalid. It must be 0 or 1.", iEncMode);
        return HAR_PARAM_ENC_MODE;
    }

    if(iDiversifyNum < 0 || iDiversifyNum > 3)
    {
        LOG_ERROR("Parameter iDiversifyNum = [%d] is invalid. It must be 0-3.", iDiversifyNum);
        return HAR_PARAM_Diversify_NUM;
    }

    if(iDiversifyNum != 0)
    {
        if(pcDiversifyData == NULL)
        {
            LOG_ERROR("Parameter pcDiversifyData = [%s] is invalid.", "NULL");
            return HAR_PARAM_ISNULL;
        }

        if((int)strlen(pcDiversifyData) != 32 * iDiversifyNum)
        {
            LOG_ERROR("Parameter pcDiversifyData'length = [%d] is invalid. It must be %d characters.",
                    strlen(pcDiversifyData),  32 * iDiversifyNum);
            return HAR_PARAM_LEN;
        }
    }

    rv = Tools_CheckSessionKeyDataValidity(iSessionKeyMode, pcSessionKeyData);
    if(rv)
    {
        LOG_ERROR("Parameter iSessionKeyMode or pcSessionKeyData is invalid, return code = [%#010X].", rv);
        return rv;
    }

    rv = Tools_CheckPaddingModeValidity(iPaddingMode);
    if(rv)
    {
        LOG_ERROR("Parameter iPaddingMode = [%d] is invalid.", iPaddingMode);
        return rv;
    }

    if(pcInData == NULL)
    {
        LOG_ERROR("Parameter pcInData = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if((int)strlen(pcInData) > 2048)
    {
        LOG_ERROR("Parameter pcInData'length = [%d] is invalid. It must be less than 2048 characters.", strlen(pcInData));
        return HAR_PARAM_LEN;
    }

    if(iEncMode == 1)
    {
        if(pcIv == NULL)
        {
            LOG_ERROR("Parameter pcIv = [%s] is invalid.", "NULL");
            return HAR_PARAM_ISNULL;
        }

        if(strlen(pcIv) != 16 && strlen(pcIv) != 32)
        {
            LOG_ERROR("Parameter pcIv'length = [%d] is invalid. It must be 16 or 32 characters.", strlen(pcIv));
            return HAR_PARAM_LEN;
        }
    }

    if(pcOutData == NULL)
    {
        LOG_ERROR("Parameter pcOutData = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    iInDataLen = Tools_ConvertHexStr2Byte(pcInData, strlen(pcInData), aucInData);
    if(iInDataLen == -1)
    {
        LOG_ERROR("%s", "Parameter [pcInData] hexadecimal string conversion to byte array failed");
        return HAR_HEX_TO_BYTE;
    }

    rv = HSM_IC_SymmKeyEncryptData(
            hSessionHandle, 
            iEncMode,               /*** 加密算法模式 ***/
            "109",                  /*** 密钥类型 ***/
            iKeyIdx,                /*** 密钥索引 ***/
            szKeyCipher,            /*** 密钥密文 ***/
            pcDiversifyData,           /*** 密钥分散因子 ***/
            iSessionKeyMode,        /*** 会话密钥产生模式 ***/
            pcSessionKeyData,       /*** 会话密钥因子 ***/
            iPaddingMode,           /*** 数据填充模式 ***/
            pcIv,                   /*** 初始化向量 ***/
            aucInData,              /*** 待加密的数据 ***/
            iInDataLen,             /*** 待加密的数据长度 ***/
            aucOutData,             /*** 输出的密钥密文 ***/
            &iOutDataLen);          /*** 输出的密钥密文字节数 ***/
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    rv = Tools_ConvertByte2HexStr(aucOutData, iOutDataLen, pcOutData);
    if(rv == -1)
    {
        LOG_ERROR("%s", "Byte data conversion to hexadecimalstring failure.");
        rv = HAR_BYTE_TO_HEX;
    }

    return rv;
}


/**
 * @brief   TODO: 不在本次开发任务
 *
 * @param   iKeyIdx
 * @param   pcKeyCipherByLmk
 * @param   iMode
 * @param   iMacType
 * @param   iDiversifyNum
 * @param   pcDiversifyData
 * @param   iSessionKeyMode
 * @param   pcSessionKeyData
 * @param   iPaddingMode
 * @param   pcInData
 * @param   iInDataLen
 * @param   pcIv
 * @param   pcMac
 *
 * @return  
 */
DLL int Tass_GenerateICMac(
        int     iKeyIdx,
        char    *pcKeyCipherByLmk,
        int     iMode,
        int     iMacType,
        int     iDiversifyNum,
        char    *pcDiversifyData,
        int     iSessionKeyMode,
        char    *pcSessionKeyData,
        int     iPaddingMode,
        char    *pcInData,
        int     iInDataLen,
        char    *pcIv,
        char    *pcMac/*out*/)
{
    int     rv = SDR_OK;
    char    szKeyCipher[49 + 1] = {0};
    char    szMacCiher[16 + 1] = {0};
    unsigned char aucInData[1968] = {0};

    rv = Tools_CheckKeyValidity(iKeyIdx, pcKeyCipherByLmk, szKeyCipher);
    if(rv)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] or pcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iKeyIdx, pcKeyCipherByLmk, rv);
        return rv;
    }

    if(iMode != 1 && iMode != 3)
    {
        LOG_ERROR("Parameter iMode = [%d] is invalid. It must be 1 or 3.", iMode);
        return HAR_PARAM_MAC_MODE;
    }

    if(iDiversifyNum < 0 || iDiversifyNum > 3)
    {
        LOG_ERROR("Parameter iDiversifyNum = [%d] is invalid. It must be 0 - 3.", iDiversifyNum);
        return HAR_PARAM_Diversify_NUM;
    }

    if(pcDiversifyData == NULL)
    {
        LOG_ERROR("Parameter pcDiversifyData = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if((int)strlen(pcDiversifyData) != 32 * iDiversifyNum)
    {
        LOG_ERROR("Parameter pcDiversifyData'length = [%d] is invalid.", strlen(pcDiversifyData));
        return HAR_PARAM_Diversify_NUM;
    }

    rv = Tools_CheckSessionKeyDataValidity(iSessionKeyMode, pcSessionKeyData);
    if(rv)
    {
        LOG_ERROR("Parameter iSessionKeyMode or pcSessionKeyData is invalid, return code = [%#010X].", rv);
        return rv;
    }

    rv = Tools_CheckPaddingModeValidity(iPaddingMode);
    if(rv)
    {
        LOG_ERROR("Parameter iPaddingMode = [%d] is invalid.", iPaddingMode);
        return rv;
    }

    if(pcInData == NULL)
    {
        LOG_ERROR("Parameter pcInData = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(iInDataLen > 1968 * 2)
    {
        LOG_ERROR("Parameter pucInData'length = [%d] is invalid. It must be less than %d.", iInDataLen, 1968 * 2);
        return HAR_PARAM_LEN;
    }

    if(pcIv == NULL)
    {
        LOG_ERROR("Parameter pcIv = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcIv) != 16 && strlen(pcIv) != 32)
    {
        LOG_ERROR("Parameter pcIv'length = [%d] is invalid. It must be 16 or 32 characters.", strlen(pcIv));
        return HAR_PARAM_LEN;
    }

    if(pcMac == NULL)
    {
        LOG_ERROR("Parameter pcMac = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    iInDataLen = Tools_ConvertHexStr2Byte(pcInData, strlen(pcInData), aucInData);
    if(iInDataLen == -1)
    {
        LOG_ERROR("%s", "Parameter [pcInData] hexadecimal string conversion to byte array failed");
        return HAR_HEX_TO_BYTE;
    }

    /*** 该函数的MAC取值方式固定为8；***/
    rv = HSM_IC_GeneralGenerateMac(
            iMode,                          /*** MAC算法模式 ***/
            iMacType,                       /*** MAC取值方式 ***/
            "008",                          /*** 密钥类型 ***/
            iKeyIdx,                        /*** 密钥索引 ***/
            szKeyCipher,                    /*** 密钥密文 ***/
            pcDiversifyData,                   /*** 分散因子 ***/
            iSessionKeyMode,                /*** 会话密钥产生模式 ***/
            pcSessionKeyData,               /*** 会话密钥因子 ***/
            iPaddingMode,                   /*** 数据填充模式 ***/
            aucInData,                      /*** 待计算MAC的数据 ***/
            iInDataLen,                     /*** 待计算MAC的数据长度 ***/
            pcIv,                           /*** 初始化向量 ***/
            pcMac,                          /*** 输出的MAC ***/
            szMacCiher);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}


/**
 * @brief   TODO: 不在本次开发任务
 *
 * @param   iKeyIdx
 * @param   pcKeyCipherByLmk
 * @param   iMode
 * @param   pcPan
 * @param   pcValidity
 * @param   pcServiceCode
 * @param   pcCvn
 *
 * @return  
 */
DLL int Tass_GenVerifyCvn(
        int  iKeyIdx,
        char *pcKeyCipherByLmk,
        int  iMode,
        char *pcPan,
        char *pcValidity,
        char *pcServiceCode,
        char *pcCvn/*in&out*/)
{
    int rv = SDR_OK;

    if(iKeyIdx < 0 || iKeyIdx > 2048)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] is invalid. It must be 0-2048.", iKeyIdx);
        return HAR_PARAM_KEY_ID;
    }

    if(iKeyIdx == 0)
    {
        if(pcKeyCipherByLmk == NULL)
        {
            LOG_ERROR("Parameter pcKeyCipherByLmk = [%s] is invalid.", "NULL");
            return HAR_PARAM_ISNULL;
        }

        if(strlen(pcKeyCipherByLmk) != 33)
        {
            LOG_ERROR("Parameter pcKeyCipherByLmk'length = [%d] is invalid. It must be 33 characters.", strlen(pcKeyCipherByLmk));
            return HAR_PARAM_LEN;
        }
    }

    if(iMode != 0 && iMode != 1)
    {
        LOG_ERROR("Parameter iMode = [%d] is invalid. It must be 0 or 1.", iMode);
        return HAR_PARAM_VALUE;
    }

    if(pcPan == NULL)
    {
        LOG_ERROR("Parameter pcPan = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(pcValidity == NULL)
    {
        LOG_ERROR("Parameter pcValidity = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcValidity) != 4)
    {
        LOG_ERROR("Parameter pcValidity'length = [%d] is invalid. It must be 4 characters.", pcValidity);
        return HAR_PARAM_LEN;
    }

    if(pcServiceCode == NULL)
    {
        LOG_ERROR("Parameter pcServiceCode = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcServiceCode) != 3)
    {
        LOG_ERROR("Parameter pcServiceCode'length = [%d] is invalid. It must be 3 characters.", strlen(pcServiceCode));
        return HAR_PARAM_LEN;
    }

    if(pcCvn == NULL)
    {
        LOG_ERROR("Parameter pcCvn = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    /*** 产生CVV,call CW  ***/
    if(iMode == 0)
    {
        rv = HSM_RCL_GenerateCVV(iKeyIdx, pcKeyCipherByLmk, pcPan, pcValidity, pcServiceCode, pcCvn);
        if(rv)
        {
            LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
        }

    }/*** 校验时候为传入参数,校验CVV,call CY ***/
    else
    {
        if(strlen(pcCvn) != 3)
        {
            LOG_ERROR("Parameter pcCvn'length = [%d] is invalid. It must be 3 characters.", pcCvn);
            return HAR_PARAM_LEN;
        }

        rv = HSM_RCL_VerifyCVV(iKeyIdx, pcKeyCipherByLmk, pcPan, pcValidity, pcServiceCode, pcCvn);
        if(rv)
        {
            LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
        }
    }

    return rv;
}


/**
 * @brief   TODO: 不在本次开发任务
 *
 * @param   hSessionHandle
 * @param   iKeyIdx
 * @param   pcKeyCipherByLmk
 * @param   iInDataLen
 * @param   pcInData
 * @param   pcMac
 *
 * @return  
 */
DLL int Tass_GenUnionMac(
        void *hSessionHandle,int nSock,
        int     iKeyIdx,
        char    *pcKeyCipherByLmk,
        int     iInDataLen,
        char    *pcInData,
        char    *pcMac)
{
    int     rv = SDR_OK;
    int     iDataLen = 0;
    unsigned char aucInData[1024 * 2] = {0};
    char    szKeyCipher[50] = {0};

    rv = Tools_CheckKeyValidity(iKeyIdx, pcKeyCipherByLmk, szKeyCipher);
    if(rv)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] or pcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iKeyIdx, pcKeyCipherByLmk, rv);
        return rv;
    }

    if(pcInData == NULL)
    {
        LOG_ERROR("Parameter pcInData = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if((int)strlen(pcInData) != iInDataLen)
    {
        LOG_ERROR("Parameter iInDataLen = [%d] is invalid.", iInDataLen);
        return HAR_PARAM_LEN;
    }

    iDataLen = Tools_ConvertHexStr2Byte(pcInData, strlen(pcInData), aucInData);
    if(iDataLen == -1)
    {
        LOG_ERROR("%s", "Parameter [pcInData] hexadecimal string conversion to byte array failed");
        return HAR_HEX_TO_BYTE;
    }

    //Tools_PrintBuf("InData", aucInData, iDataLen);
    if(pcMac == NULL)
    {
        LOG_ERROR("Parameter pcMac = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    /*** 该函数的MAC取值方式固定为8 ***/
    rv =  HSM_IC_GenerateMac(
                hSessionHandle,
                1,
                "008",
                iKeyIdx,
                szKeyCipher,
                "",
                0,                       /*** 会话模式 ***/
                "",                      /*** 会话因子 ***/
                2,
                aucInData,               /*** 输入的数据 ***/
                iDataLen,                /*** 输入的数据长度 ***/
                "0000000000000000",
                pcMac);

    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}


/**
 * @brief   TODO: 不在本次开发任务
 *
 * @param   iKeyIdx
 * @param   pcKeyCipherByLmk
 * @param   iInDataLen
 * @param   pcInData
 * @param   pcMac
 *
 * @return  
 */
DLL int Tass_GenZPKMac(
        int     iKeyIdx,
        char    *pcKeyCipherByLmk,
        int     iInDataLen,
        char    *pcInData,
        char    *pcMac/*out*/)
{
    int     rv = 0;
    unsigned char aucInData[1024 * 2] = {0};

    if(iKeyIdx < 0 || iKeyIdx > 2048)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] is invalid, it must be 0-2048.", iKeyIdx);
        return HAR_PARAM_KEY_ID;
    }

    if(iKeyIdx == 0)
    {
        if(pcKeyCipherByLmk == NULL)
        {
            LOG_ERROR("Parameter pcKeyCipherByLmk = [%s] is invalid.", "NULL");
            return HAR_PARAM_ISNULL;
        }

        if(strlen(pcKeyCipherByLmk) != 16 && strlen(pcKeyCipherByLmk) != 33)
        {
            LOG_ERROR("Parameter pcKeyCipherByLmk'length = [%d] is invalid. It must be 16 or 33 characters.",
                    strlen(pcKeyCipherByLmk));
            return HAR_PARAM_LEN;
        }
    }

    if(pcInData == NULL)
    {
        LOG_ERROR("Parameter pcInData = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    iInDataLen = Tools_ConvertHexStr2Byte(pcInData, strlen(pcInData), aucInData);
    if(iInDataLen == -1)
    {
        LOG_ERROR("%s", "Parameter [pcInData] hexadecimal string conversion to byte array failed");
        return HAR_HEX_TO_BYTE;
    }

    if(pcMac == NULL)
    {
        LOG_ERROR("Parameter ERROR, pcMac = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    /*** 该函数的MAC取值方式固定为8 ***/
    rv = HSM_RCL_ZpkGenCbcMac(
                0,
                iKeyIdx,
                pcKeyCipherByLmk,
                (unsigned char*)"0000000000000000",
                16,
                aucInData,
                iInDataLen,
                8,
                pcMac);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}


/**
 * @brief   TODO: 不在本次开发任务
 *
 * @param   iSrcKeyIdx
 * @param   pcSrcpcKeyCipherByLmk
 * @param   iDstKeyIdx
 * @param   pcDstpcKeyCipherByLmk
 * @param   pcSrcPan
 * @param   pcDstPan
 * @param   iSrcPinBlkFmt
 * @param   iDstPinBlkFmt
 * @param   pcSrcPinBlkCipher
 * @param   pcDstPinBlkCipher
 *
 * @return  
 */
DLL int Tass_TranslatePin(
        int     iSrcKeyIdx,
        char    *pcSrcpcKeyCipherByLmk,
        int     iDstKeyIdx,
        char    *pcDstpcKeyCipherByLmk,
        char    *pcSrcPan,
        char    *pcDstPan,
        int     iSrcPinBlkFmt,
        int     iDstPinBlkFmt,
        char    *pcSrcPinBlkCipher,
        char    *pcDstPinBlkCipher/*out*/)
{
    int rv = SDR_OK;

    rv = Tools_CheckKeyValidity_1(iSrcKeyIdx, pcSrcpcKeyCipherByLmk);
    if(rv)
    {
        LOG_ERROR("Parameter iSrcKeyIdx = [%d] or pcSrcpcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iSrcKeyIdx, pcSrcpcKeyCipherByLmk, rv);
        return rv;
    }

    rv = Tools_CheckKeyValidity_1(iDstKeyIdx, pcDstpcKeyCipherByLmk);
    if(rv)
    {
        LOG_ERROR("Parameter iDstKeyIdx = [%d] or pcDstpcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iDstKeyIdx, pcDstpcKeyCipherByLmk, rv);
        return rv;
    }

    if(pcSrcPan == NULL)
    {
        LOG_ERROR("Parameter pcSrcPan = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcSrcPan) != 12 && strlen(pcSrcPan) != 18)
    {
        LOG_ERROR("Parameter pcSrcPan'length = [%d] is invalid. It must be 12 or 18 characters.", strlen(pcSrcPan));
        return HAR_PARAM_LEN;
    }

    if(pcDstPan == NULL)
    {
        LOG_ERROR("Parameter pcDstPan = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcDstPan) != 12 && strlen(pcDstPan) != 18)
    {
        LOG_ERROR("Parameter pcDstPan'length = [%d] is invalid. It must be 12 or 18 characters.", strlen(pcDstPan));
        return HAR_PARAM_LEN;
    }

    if(pcSrcPinBlkCipher == NULL)
    {
        LOG_ERROR("Parameter pcSrcPinBlkCipher = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcSrcPinBlkCipher) != 16 && strlen(pcSrcPinBlkCipher) != 32)
    {
        LOG_ERROR("Parameter pcSrcPinBlkCipher'length = [%d] is invalid. It must be 16 or 32 characters.",
                strlen(pcSrcPinBlkCipher));
        return HAR_PARAM_LEN;
    }

    if(pcDstPinBlkCipher == NULL)
    {
        LOG_ERROR("Parameter pcDstPinBlkCipher = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    /*** 调用转加密指令函数 ***/
    rv = HSM_RCL_ConvertCipherPin_Zpk2Zpk(
            iSrcKeyIdx,                 /*** 源密钥索引 ***/
            pcSrcpcKeyCipherByLmk,      /*** 源密钥密文 ***/
            iDstKeyIdx,                 /*** 目的密钥索引 ***/
            pcDstpcKeyCipherByLmk,      /*** 目的密钥密文 ***/
            iSrcPinBlkFmt,              /*** 源PINBLOCK格式 ***/
            iDstPinBlkFmt,              /*** 目标PINBLOCK格式 ***/
            pcSrcPan,                   /*** 源账号 ***/
            pcDstPan,                   /*** 目的账号 ***/
            pcSrcPinBlkCipher,          /*** 源PINBLOCK密文 ***/
            pcDstPinBlkCipher);         /*** 目标PINBLOCK密文 ***/
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}


/**
 * @brief   TODO: 不在本次开发任务
 *
 * @param   hSessionHandle
 * @param   iKeyIdx
 * @param   pcKeyCipherByLmk
 * @param   pcPinText
 * @param   iPinBlkFmt
 * @param   pcPan
 * @param   pcPinBlkCipher
 *
 * @return  
 */
DLL int Tass_EncryptPIN(
        void    *hSessionHandle,
        int     iKeyIdx,
        char    *pcKeyCipherByLmk,
        char    *pcPinText,
        int     iPinBlkFmt,
        char    *pcPan,
        char    *pcPinBlkCipher/*out*/)
{
    int     rv = SDR_OK;
    char    szLmkPin[129] = {0};
    char    szPinText[16] = {0};

    rv = Tools_CheckKeyValidity_1(iKeyIdx, pcKeyCipherByLmk);
    if(rv)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] or pcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iKeyIdx, pcKeyCipherByLmk, rv);
        return rv;
    }

    if(pcPinText == NULL)
    {
        LOG_ERROR("Parameter pcPinText = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcPinText) != 6)
    {
        LOG_ERROR("Parameter pcPinText length = [%d] is invalid. It must be 6 characters.", strlen(pcPinText));
        return HAR_PARAM_LEN;
    }
    memcpy(szPinText, pcPinText, 6);

    if(pcPan == NULL)
    {
        LOG_ERROR("Parameter pcPan = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcPan) != 12 && strlen(pcPan) != 18 && strlen(pcPan) != 0)
    {
        LOG_ERROR("Parameter pcPan = [%s] is invalid, Its length must be 0 or 12 or 18.", pcPan);
        return HAR_PARAM_LEN;
    }

    if(pcPinBlkCipher == NULL)
    {
        LOG_ERROR("Parameter pcPinBlkCipher = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    /*** call BA LMK加密一个明文PIN码 ***/
    rv = HSM_RCL_EncryptPin_LMK(szPinText, pcPan, szLmkPin);
    if(rv)
    {
        LOG_ERROR("HSM_RCL_EncryptPin_LMK failed, return code = [%d].", rv);
        return rv;
    }

    /*** call JG 将PIN由LMK加密转换为ZPK加密 ***/
    rv = HSM_RCL_ConvertCipherPin_Lmk2Zpk(hSessionHandle, iKeyIdx, pcKeyCipherByLmk, iPinBlkFmt, pcPan, szLmkPin, pcPinBlkCipher);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/**
 * @brief   随机生成ZMK密钥，并使用一个保护ZMK加密导出
 *
 * @param   hSessionHandle      [in]    与设备建立的会话句柄
 * @param   iKeyIdx             [in]    保护ZMK的密钥索引
 * @param   pcKeyCipherByLmk    [in]    保护ZMK在LMK下加密的密文，长度为1A+32H
 * @param   cZmkScheme          [in]    生成ZMK密钥的算法标识
 * @param   pcZmkCipherByZmk    [out]   保护ZMK加密的新生成ZMK密钥的密文
 * @param   pcZmkCipherByLmk    [out]   LMK加密的新生成ZMK密钥的密文
 * @param   pcZmkCv             [out]   生成ZMK密钥的校验值
 *
 * @return  
 */
DLL int Tass_Generate_Zmk(
        void *hSessionHandle,int nSock,
        int iKeyIdx,
        char *pcKeyCipherByLmk,
        char cZmkScheme,
        char *pcZmkCipherByZmk,
        char *pcZmkCipherByLmk,
        char *pcZmkCv)
{
    int     rv = SDR_OK;
    char    szKeyCipher[33 + 1] = {0};

    rv = Tools_CheckKeyValidity_3(iKeyIdx, pcKeyCipherByLmk, szKeyCipher);
    if(rv)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] or pcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iKeyIdx, pcKeyCipherByLmk, rv);
        return rv;
    }

    /*** 判断算法标识是否正确 ***/
    rv = Tools_CheckSchemeValidity(cZmkScheme);
    if(rv)
    {
        LOG_ERROR("Parameter cZmkScheme = [%c] is invalid.", cZmkScheme);
        return rv;
    }

    if(pcZmkCipherByZmk == NULL)
    {
        LOG_ERROR("Parameter pcZmkCipherByZmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(pcZmkCipherByLmk == NULL)
    {
        LOG_ERROR("Parameter pcZmkCipherByLmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(pcZmkCv == NULL)
    {
        LOG_ERROR("Parameter pcZmkCv = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    rv = HSM_RCL_GenWorkingKey(
            hSessionHandle,
            1,
            "000",
            cZmkScheme,
            iKeyIdx,
            szKeyCipher,
            cZmkScheme,
            '0',
            0,
            NULL,
            pcZmkCipherByLmk,
            pcZmkCipherByZmk,
            pcZmkCv);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/**
 * @brief   随机产生指定密钥使用机构的PIN加密工作密钥，输出分发和应用系统存储的密钥和校验值
 *
 * @param   hSessionHandle      [in]    与设备建立的会话句柄
 * @param   iKeyIdx             [in]    保护ZMK的密钥索引
 * @param   pcKeyCipherByLmk    [in]    保护ZMK在LMK下加密的密文
 * @param   cPikScheme          [in]    生成PIK密钥的算法标识
 * @param   pcPikCipherByZmk    [out]   保护ZMK加密的新生成PIK密钥的密文
 * @param   pcPikCipherByLmk    [out]   LMK加密的新生成PIK密钥的密文
 * @param   pcPikCv             [out]   生成PIK密钥的校验值
 *
 * @return  
 */
DLL int Tass_Generate_Pik(
        void *hSessionHandle,int nSock,
        int iKeyIdx,
        char *pcKeyCipherByLmk,
        char cPikScheme,
        char *pcPikCipherByZmk,
        char *pcPikCipherByLmk,
        char *pcPikCv)
{

    int     rv = SDR_OK;
    char    szKeyCipher[33 + 1] = {0};

    rv = Tools_CheckKeyValidity_3(iKeyIdx, pcKeyCipherByLmk, szKeyCipher);
    if(rv)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] or pcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iKeyIdx, pcKeyCipherByLmk, rv);
        return rv;
    }

    /*** 判断算法标识是否正确 ***/
    rv = Tools_CheckSchemeValidity(cPikScheme);
    if(rv)
    {
        LOG_ERROR("Parameter cPikScheme = [%c] is invalid.", cPikScheme);
        return rv;
    }

    if(pcPikCipherByZmk == NULL)
    {
        LOG_ERROR("Parameter pcPikCipherByZmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(pcPikCipherByLmk == NULL)
    {
        LOG_ERROR("Parameter pcPikCipherByLmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(pcPikCv == NULL)
    {
        LOG_ERROR("Parameter pcPikCv = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    rv = HSM_RCL_GenWorkingKey(
            hSessionHandle,
            1,
            "001",
            cPikScheme,
            iKeyIdx,
            szKeyCipher,
            cPikScheme,
            '0',
            0,
            NULL,
            pcPikCipherByLmk,
            pcPikCipherByZmk,
            pcPikCv);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}


/**
 * @brief   随机产生指定机构的MAC工作密钥，输出分发和应用系统存储（如需要）的密钥和校验值
 *
 * @param   hSessionHandle      [in]    与设备建立的会话句柄
 * @param   iKeyIdx             [in]    保护ZMK的密钥索引
 * @param   pcKeyCipherByLmk    [in]    保护ZMK在LMK下加密的密钥密文
 * @param   cMakScheme          [in]    生成MAK密钥的算法标识
 * @param   pcMakCipherByZmk    [out]   保护ZMK加密的新生成MAK密钥的密文
 * @param   pcMakCipherByLmk    [out]   LMK加密的新生成MAK密钥的密文
 * @param   pcMakCv             [out]   生成MAK密钥的校验值
 *
 * @return  
 */
DLL int Tass_Generate_Mak (
        void *hSessionHandle,int nSock,
        int iKeyIdx,
        char *pcKeyCipherByLmk,
        char cMakScheme,
        char *pcMakCipherByZmk,
        char *pcMakCipherByLmk,
        char *pcMakCv)
{
    int     rv = SDR_OK;
    char    szKeyCipher[33 + 1] = {0};

    rv = Tools_CheckKeyValidity_3(iKeyIdx, pcKeyCipherByLmk, szKeyCipher);
    if(rv)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] or pcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iKeyIdx, pcKeyCipherByLmk, rv);
        return rv;
    }

    /*** 判断算法标识是否正确 ***/
    rv = Tools_CheckSchemeValidity(cMakScheme);
    if(rv)
    {
        LOG_ERROR("Parameter cMakScheme = [%c] is invalid.", cMakScheme);
        return rv;
    }

    if(pcMakCipherByZmk == NULL)
    {
        LOG_ERROR("Parameter pcMakCipherByZmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(pcMakCipherByLmk == NULL)
    {
        LOG_ERROR("Parameter pcMakCipherByLmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(pcMakCv == NULL)
    {
        LOG_ERROR("Parameter pcMakCv = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    rv = HSM_RCL_GenWorkingKey(
            hSessionHandle,
            1,
            "008",
            cMakScheme,
            iKeyIdx,
            szKeyCipher,
            cMakScheme,
            '0',
            0,
            NULL,
            pcMakCipherByLmk,
            pcMakCipherByZmk,
            pcMakCv);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/**
 * @brief   随机产生指定机构的ZEK工作密钥，输出分发和应用系统存储（如需要）的密钥和校验值
 *
 * @param   hSessionHandle      [in]    与设备建立的会话句柄
 * @param   iKeyIdx             [in]    保护ZMK的密钥索引
 * @param   pcKeyCipherByLmk    [in]    保护ZMK在LMK下加密的密文
 * @param   cZekScheme          [in]    生成ZEK密钥的算法标识
 * @param   pcZekCipherByZmk    [out]   保护ZMK加密的新生成ZEK密钥的密文
 * @param   pcZekCipherByLmk    [out]   LMK加密的新生成ZEK密钥的密文
 * @param   pcZekCv             [out]   生成ZEK密钥的校验值
 *
 * @return  
 */
DLL int Tass_Generate_Zek(
        void *hSessionHandle,int nSock,
        int iKeyIdx,
        char *pcKeyCipherByLmk,
        char cZekScheme,
        char *pcZekCipherByZmk,
        char *pcZekCipherByLmk,
        char *pcZekCv)
{
    int     rv = SDR_OK;
    char    szKeyCipher[33 + 1] = {0};

    rv = Tools_CheckKeyValidity_3(iKeyIdx, pcKeyCipherByLmk, szKeyCipher);
    if(rv)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] or pcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iKeyIdx, pcKeyCipherByLmk, rv);
        return rv;
    }

    /*** 判断算法标识是否正确 ***/
    rv = Tools_CheckSchemeValidity(cZekScheme);
    if(rv)
    {
        LOG_ERROR("Parameter cZekScheme = [%c] is invalid.", cZekScheme);
        return rv;
    }

    if(pcZekCipherByZmk == NULL)
    {
        LOG_ERROR("Parameter pcZekCipherByZmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(pcZekCipherByLmk == NULL)
    {
        LOG_ERROR("Parameter pcZekCipherByLmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(pcZekCv == NULL)
    {
        LOG_ERROR("Parameter pcZekCv = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    rv = HSM_RCL_GenWorkingKey(
            hSessionHandle,
            1,
            "00A",
            cZekScheme,
            iKeyIdx,
            szKeyCipher,
            cZekScheme,
            '0',
            0,
            NULL,
            pcZekCipherByLmk,
            pcZekCipherByZmk,
            pcZekCv);

    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/**
 * @brief   TODO: 不在本次开发任务
 *
 * @param   hSessionHandle
 * @param   iKeyIdx
 * @param   pcKeyCipherByLmk
 * @param   cPikScheme
 * @param   pcPikCipherByZmk
 * @param   pcPikCipherByLmk
 * @param   pcPikCv
 *
 * @return  
 */
DLL int Tass_ImportPik(
        void    *hSessionHandle,
        int     iKeyIdx,
        char    *pcKeyCipherByLmk,
        char    cPikScheme,
        char    *pcPikCipherByZmk,
        char    *pcPikCipherByLmk/*OUT*/,
        char    *pcPikCv/*OUT*/ )
{
    int     rv = SDR_OK;
    char    szKeyCipher[33 + 1] = {0};
    char    szPikCipher[33 + 1] = {0};

    rv = Tools_CheckKeyValidity_3(iKeyIdx, pcKeyCipherByLmk, szKeyCipher);
    if(rv)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] or pcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iKeyIdx, pcKeyCipherByLmk, rv);
        return rv;
    }

    /*** 判断算法标识是否正确 ***/
    rv = Tools_CheckSchemeValidity(cPikScheme);
    if(rv)
    {
        LOG_ERROR("Parameter cPikScheme = [%c] is invalid.", cPikScheme);
        return rv;
    }

    if(pcPikCipherByZmk == NULL)
    {
        LOG_ERROR("Parameter pcPikCipherByZmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_KEY_CIPHER;
    }

    if((strlen(pcPikCipherByZmk) != 16) && (strlen(pcPikCipherByZmk) != 32) && (strlen(pcPikCipherByZmk) != 33))
    {
        LOG_ERROR("Parameter pcPikCipherByZmk length = [%d] is invalid.", strlen(pcPikCipherByZmk));
        return HAR_PARAM_KEY_CIPHER;
    }

    if(strlen(pcPikCipherByZmk) == 16)
    {
        memcpy(szPikCipher, pcPikCipherByZmk, 16);
    }
    else if(strlen(pcPikCipherByZmk) == 32)
    {
        memcpy(szPikCipher, "X", 1);
        memcpy(szPikCipher + 1, pcPikCipherByZmk, 32);
    }
    else if(strlen(pcPikCipherByZmk) == 33)
    {
        memcpy(szPikCipher, pcPikCipherByZmk, 33);
    }

    if(pcPikCipherByLmk == NULL)
    {
        LOG_ERROR("Parameter pcPikCipherByLmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(pcPikCv == NULL)
    {
        LOG_ERROR("Parameter pcPikCv = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    rv = HSM_RCL_ImportKey_A6(hSessionHandle,"001", iKeyIdx, szKeyCipher, szPikCipher, cPikScheme, '0', 0, NULL, pcPikCipherByLmk, pcPikCv);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}


/**
 * @brief   TODO: 不在本次开发任务
 *
 * @param   hSessionHandle
 * @param   iKeyIdx
 * @param   pcKeyCipherByLmk
 * @param   cMakScheme
 * @param   pcMakCipherByZmk
 * @param   pcMakCipherByLmk
 * @param   pcMakCv
 *
 * @return  
 */
DLL int Tass_ImportMak(
        void    *hSessionHandle,
        int     iKeyIdx,
        char    *pcKeyCipherByLmk,
        char    cMakScheme,
        char    *pcMakCipherByZmk,
        char    *pcMakCipherByLmk/*OUT*/,
        char    *pcMakCv/*OUT*/)
{
    int     rv = SDR_OK;
    char    szKeyCipher[33 + 1] = {0};
    char    szMakCipher[33 + 1] = {0};

    rv = Tools_CheckKeyValidity_3(iKeyIdx, pcKeyCipherByLmk, szKeyCipher);
    if(rv)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] or pcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iKeyIdx, pcKeyCipherByLmk, rv);
        return rv;
    }

    /*** 判断算法标识是否正确 ***/
    rv = Tools_CheckSchemeValidity(cMakScheme);
    if(rv)
    {
        LOG_ERROR("Parameter cMakScheme = [%c] is invalid.", cMakScheme);
        return rv;
    }

    if(pcMakCipherByZmk == NULL)
    {
        LOG_ERROR("Parameter pcMakCipherByZmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_KEY_CIPHER;
    }

    if((strlen(pcMakCipherByZmk) != 16) && (strlen(pcMakCipherByZmk) != 32) && (strlen(pcMakCipherByZmk) != 33))
    {
        LOG_ERROR("Parameter pcMakCipherByZmk length = [%d] is invalid.", strlen(pcMakCipherByZmk));
        return HAR_PARAM_KEY_CIPHER;
    }

    if(strlen(pcMakCipherByZmk) == 16)
    {
        memcpy(szMakCipher, pcMakCipherByZmk, 16);
    }
    else if(strlen(pcMakCipherByZmk) == 32)
    {
        memcpy(szMakCipher, "X", 1 );
        memcpy(szMakCipher + 1, pcMakCipherByZmk, 32);
    }
    else if(strlen(pcMakCipherByZmk) == 33)
    {
        memcpy(szMakCipher, pcMakCipherByZmk, 33);
    }

    if(pcMakCipherByLmk == NULL)
    {
        LOG_ERROR("Parameter pcMakCipherByLmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(pcMakCv == NULL)
    {
        LOG_ERROR("Parameter pcMakCv = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    rv = HSM_RCL_ImportKey_A6(hSessionHandle, "008", iKeyIdx, szKeyCipher, szMakCipher, cMakScheme, '0', 0, NULL, pcMakCipherByLmk, pcMakCv);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}


/**
 * @brief   TODO: 不在本次开发任务
 *
 * @param   hSessionHandle
 * @param   iKeyIdx
 * @param   pcKeyCipherByLmk
 * @param   iEncMode
 * @param   iDiversifyNum
 * @param   pcDiversifyData
 * @param   iSessionKeyMode
 * @param   pcSessionKeyData
 * @param   iPaddingMode
 * @param   pcInData
 * @param   pcIv
 * @param   pcOutData
 *
 * @return  
 */
DLL int Tass_EncryptData(
        void    *hSessionHandle,
        int     iKeyIdx,
        char    *pcKeyCipherByLmk,
        int     iEncMode,
        int     iDiversifyNum,
        char    *pcDiversifyData,
        int     iSessionKeyMode,
        char    *pcSessionKeyData,
        int     iPaddingMode,
        char    *pcInData,
        char    *pcIv,
        char    *pcOutData)
{
    int     rv = SDR_OK;
    int     iOutDataLen = 0;
    int     iInDataLen = 0;
    unsigned char aucInData[1024 * 2] = {0};
    unsigned char aucOutData[1024 * 4] = {0};

    if(iKeyIdx < 0 || iKeyIdx > 2048)
    {
        LOG_ERROR( "Parameter iKeyIdx[%d] Invalid, Must be 0-2048.", iKeyIdx );
        return HAR_PARAM_KEY_ID;
    }

    if(iKeyIdx == 0)
    {
        if(pcKeyCipherByLmk == NULL)
        {
            LOG_ERROR("Parameter pcKeyCipherByLmk = [%s] is invalid.", "NULL");
            return HAR_PARAM_ISNULL;
        }

        if(strlen(pcKeyCipherByLmk) != 16
                && strlen(pcKeyCipherByLmk) != 17
                && strlen(pcKeyCipherByLmk) != 33
                && strlen(pcKeyCipherByLmk) != 49)
        {
            LOG_ERROR("Parameter pcKeyCipherByLmk'length = [%d] is invalid. It must be 16, 17, 33 or 49.", strlen(pcKeyCipherByLmk));
            return HAR_PARAM_LEN;
        }
    }

    if(iEncMode != 0 && iEncMode != 1)
    {
        LOG_ERROR("Parameter iEncMode = [%d] is invalid. It must be 0 or 1.", iEncMode);
        return HAR_PARAM_ENC_MODE;
    }

    if(iDiversifyNum < 0 || iDiversifyNum > 3)
    {
        LOG_ERROR("Parameter iDiversifyNum = [%d] is invalid. It must be 0-3.", iDiversifyNum);
        return HAR_PARAM_Diversify_NUM;
    }

    if(iDiversifyNum != 0)
    {
        if(pcDiversifyData == NULL)
        {
            LOG_ERROR("Parameter pcDiversifyData = [%s] is invalid.", "NULL");
            return HAR_PARAM_ISNULL;
        }

        if((int)strlen(pcDiversifyData) != 32 * iDiversifyNum)
        {
            LOG_ERROR("Parameter pcDiversifyData'length = [%d] is invalid. It must be %d characters.", 32 * iDiversifyNum);
            return HAR_PARAM_LEN;
        }
    }

    rv = Tools_CheckSessionKeyDataValidity(iSessionKeyMode, pcSessionKeyData);
    if(rv)
    {
        LOG_ERROR("Parameter iSessionKeyMode or pcSessionKeyData is invalid, return code = [%#010X].", rv);
        return rv;
    }

    rv = Tools_CheckPaddingModeValidity(iPaddingMode);
    if(rv)
    {
        LOG_ERROR("Parameter iPaddingMode = [%d] is invalid.", iPaddingMode);
        return rv;
    }

    if(pcInData == NULL)
    {
        LOG_ERROR("Parameter error: pcInData = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    iInDataLen = Tools_ConvertHexStr2Byte(pcInData, strlen(pcInData), aucInData);
    if(iInDataLen == -1)
    {
        LOG_ERROR("%s", "Parameter [pcInData] hexadecimal string conversion to byte array failed.");
        return HAR_HEX_TO_BYTE;
    }

    if(iEncMode == 1)
    {
        if(pcIv == NULL)
        {
            LOG_ERROR("Parameter error: pcIv = [%s] is invalid.", "NULL");
            return HAR_PARAM_ISNULL;
        }

        if((strlen(pcIv) != 16 && strlen(pcIv) != 32))
        {
            LOG_ERROR("Parameter error, pcIv'length = [%d] is invalid. It must be 16 or 32 characters", pcIv);
            return HAR_PARAM_VALUE;
        }
    }

    if(pcOutData == NULL)
    {
        LOG_ERROR("Parameter error: pcOutData = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    rv = HSM_IC_SymmKeyEncryptData(
            hSessionHandle,
            iEncMode,
            "00A",
            iKeyIdx,
            pcKeyCipherByLmk,
            pcDiversifyData,
            iSessionKeyMode,
            pcSessionKeyData,
            iPaddingMode,
            pcIv,
            aucInData,
            iInDataLen,
            aucOutData,
            &iOutDataLen);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    rv = Tools_ConvertByte2HexStr(aucOutData, iOutDataLen, pcOutData);
    if(rv == -1)
    {
        LOG_ERROR("%s", "Byte data conversion to hexadecimalstring failure.");
        return HAR_BYTE_TO_HEX;
    }

    return rv;
}


/**
 * @brief   不在本次开发任务
 *
 * @param   hSessionHandle
 * @param   iKeyIdx
 * @param   pcKeyCipherByLmk
 * @param   iEncMode
 * @param   iDiversifyNum
 * @param   pcDiversifyData
 * @param   iSessionKeyMode
 * @param   pcSessionKeyData
 * @param   iPaddingMode
 * @param   pcInData
 * @param   pcIv
 * @param   pcOutData
 *
 * @return  
 */
DLL int Tass_DecryptData(
        void    *hSessionHandle,
        int     iKeyIdx,
        char    *pcKeyCipherByLmk,
        int     iEncMode,
        int     iDiversifyNum,
        char    *pcDiversifyData,
        int     iSessionKeyMode,
        char    *pcSessionKeyData,
        int     iPaddingMode,
        char    *pcInData,
        char    *pcIv,
        char    *pcOutData)
{
    int     rv = SDR_OK;
    int     iOutDataLen = 0;
    int     iDataLen = 0;
    unsigned char aucInData[1024 * 2] = {0};
    unsigned char aucOutData[1024 * 4] = {0};

    if(iKeyIdx < 0|| iKeyIdx > 2048)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] is invaild, it must be 0 - 2048.", iKeyIdx);
        return HAR_PARAM_KEY_ID;
    }

    if(iKeyIdx == 0)
    {
        if(pcKeyCipherByLmk == NULL)
        {
            LOG_ERROR("pcKeyCipherByLmk = [%s] is invalid.", "NULL");
            return HAR_PARAM_ISNULL;
        }

        if(strlen(pcKeyCipherByLmk) != 17 && strlen(pcKeyCipherByLmk) != 33 && strlen(pcKeyCipherByLmk) != 49)
        {
            LOG_ERROR("pcKeyCipherByLmk = [%s] is invalid.Its length must be 17, 33 or 49.", pcKeyCipherByLmk);
            return HAR_PARAM_LEN;
        }
    }

    if(iEncMode != 0 && iEncMode != 1)
    {
        LOG_ERROR("iEncMode = [%d] invalid, It must be 0 or 1.", iEncMode);
        return HAR_PARAM_ENC_MODE;
    }

    if(iDiversifyNum < 0 || iDiversifyNum > 3)
    {
        LOG_ERROR("iDiversifyNum = [%d] invalid, DispCnt must be 0-3.", iDiversifyNum);
        return HAR_PARAM_Diversify_NUM;
    }

    if(iDiversifyNum != 0)
    {
        if(pcDiversifyData == NULL || (int)strlen(pcDiversifyData) != 32 * iDiversifyNum)
        {
            LOG_ERROR("pcDiversifyData = [%s] invalid, pcDiversifyData'length must be %d.", pcDiversifyData, 32 * iDiversifyNum);
            return HAR_PARAM_Diversify_NUM;
        }
    }

    rv = Tools_CheckSessionKeyDataValidity(iSessionKeyMode, pcSessionKeyData);
    if(rv)
    {
        LOG_ERROR("Parameter iSessionKeyMode or pcSessionKeyData is invalid, return code = [%#010X].", rv);
        return rv;
    }

    rv = Tools_CheckPaddingModeValidity(iPaddingMode);
    if(rv)
    {
        LOG_ERROR("Parameter iPaddingMode = [%d] is invalid.", iPaddingMode);
        return rv;
    }

    if(pcInData == NULL)
    {
        LOG_ERROR("pcInData = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcInData) % 2 != 0)
    {
        LOG_ERROR("Parameter ERROR, pcInData'length = [%d] is invalid. Its length must be multiples of 2.", strlen(pcInData));
        return HAR_PARAM_LEN;
    }

    /*** 数据转换 ***/
    iDataLen = Tools_ConvertHexStr2Byte(pcInData, strlen(pcInData), aucInData);
    if(iDataLen == -1)
    {
        LOG_ERROR("%s", "Parameter [pcInData] hexadecimal string conversion to byte array failed");
        return HAR_HEX_TO_BYTE;
    }

    if(iEncMode == 1)
    {
        if(pcIv == NULL)
        {
            LOG_ERROR("pcIv = [%s] is invalid.", "NULL");
            return HAR_PARAM_ISNULL;
        }

        if((strlen(pcIv) != 16 && strlen(pcIv) != 32))
        {
            LOG_ERROR("pcIv = [%s] is invalid.", pcIv);
            return HAR_PARAM_VALUE;
        }
    }

    if(pcOutData == NULL)
    {
        LOG_ERROR( "pcOutData = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    rv = HSM_IC_SymmKeyDecryptData(
            hSessionHandle,
            iEncMode,
            "00A",
            iKeyIdx,
            pcKeyCipherByLmk,
            pcDiversifyData,
            iSessionKeyMode,
            pcSessionKeyData,
            iPaddingMode,
            pcIv,
            aucInData,
            iDataLen,
            aucOutData/*out*/,
            &iOutDataLen/*out*/);

    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
        return rv;
    }
    rv = Tools_ConvertByte2HexStr(aucOutData, iOutDataLen, pcOutData);
    if(rv == -1)
    {
        LOG_ERROR("%s", "Byte data conversion to hexadecimalstring failure.");
        return HAR_BYTE_TO_HEX;
    }

    return 0;
}


/**
 * @brief   TODO: 不在本次开发任务
 *
 * @param   hSessionHandle
 * @param   iKeyIdx
 * @param   pcKeyCipherByLmk
 * @param   pcPinBlkCipher
 * @param   iPinBlkFmt
 * @param   pcPan
 * @param   pcPinText
 *
 * @return  
 */
DLL int Tass_Decrypt_PIN(
        void    *hSessionHandle,
        int     iKeyIdx,
        char    *pcKeyCipherByLmk,
        char    *pcPinBlkCipher,
        int     iPinBlkFmt,
        char    *pcPan,
        char    *pcPinText/*out*/)
{
    int     rv = SDR_OK;
    char    szLmkPin[129] = {0};
    char    szPin[129] = {0};

    rv = Tools_CheckKeyValidity_1(iKeyIdx, pcKeyCipherByLmk);
    if(rv)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] or pcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iKeyIdx, pcKeyCipherByLmk, rv);
        return rv;
    }
   

    if(pcPinBlkCipher == NULL)
    {
        LOG_ERROR("Parameter pcPinBlkCipher = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(pcPan == NULL)
    {
        LOG_ERROR("Parameter pcPan = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcPan) != 12 && strlen(pcPan) != 18)
    {
        LOG_ERROR("Parameter pcPan[%s] Invalid, pcPan'length must be 12 or 18.", pcPan);
        return HAR_PARAM_LEN;
    }

    /*** call JE 转加密 ***/
    rv = HSM_RCL_ConvertCipherPin_Zpk2Lmk(hSessionHandle,iKeyIdx, pcKeyCipherByLmk, iPinBlkFmt, pcPan, pcPinBlkCipher, szLmkPin/*out*/);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code1 = [%d], [%#010X].", rv, rv);
        return rv;
    }
    /*** call NG 解密PIN码 ***/
    rv = HSM_RCL_DecryptPin_LMK(hSessionHandle,szLmkPin, pcPan, pcPinText/*out*/);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code2 = [%d], [%#010X].", rv, rv);
        return rv;
    }

    return rv;
}

/**
 * @brief   TODO: 不在本次开发任务
 *
 * @param   iKeyIdx
 * @param   pcKeyCipherByLmk
 * @param   pcIV
 * @param   iMacDataLen
 * @param   pcMacData
 * @param   pcMac
 *
 * @return  
 */
DLL int Tass_GenUnionMac_IV(
        int     iKeyIdx,
        char    *pcKeyCipherByLmk,
        char    *pcIV,
        int     iMacDataLen,
        char    *pcMacData,
        char    *pcMac/*out*/)
{
    int     rv = SDR_OK;
    int     iDataLen = 0;
    char    szKeyCipher[49 + 1] = {0};
    unsigned char aucData[1024 * 4] = {0};
    char    szIV[32 + 1] = {0};
    char    szKeyType[3 + 1] = {0};
    char    szKeyScheme[1 + 1] = {0};
    char    szKeyCv[16 + 1] = {0};
    char    szKeyLabel[16 + 1] = {0};
    char    szTime[64 + 1] = {0};

    rv = Tools_CheckKeyValidity(iKeyIdx, pcKeyCipherByLmk, szKeyCipher);
    if(rv)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] or pcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iKeyIdx, pcKeyCipherByLmk, rv);
        return rv;
    }

    if(pcMacData == NULL)
    {
        LOG_ERROR("Parameter pcMacdata = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(iMacDataLen != (int)strlen(pcMacData))
    {
        LOG_ERROR("Parameter iMacDataLen = [%d] is invalid.", iMacDataLen);
        return HAR_PARAM_LEN;
    }

    iDataLen = Tools_ConvertHexStr2Byte(pcMacData, strlen(pcMacData), aucData);
    if(iDataLen == -1)
    {
        LOG_ERROR("%s", "Parameter [pcMacData] hexadecimal string conversion to byte array failed");
        return HAR_HEX_TO_BYTE;
    }

    if(pcMac == NULL)
    {
        LOG_ERROR("Parameter pcMac = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(iKeyIdx > 0)
    {
        rv = HSM_IC_GetKeyInfo(
                    iKeyIdx,
                    szKeyType,
                    szKeyScheme,
                    szKeyCv,
                    szKeyLabel,
                    szTime);
        if(rv)
        {
            LOG_ERROR("HSM_IC_GetKeyInfo failed, error code = [%d].", rv);
            return rv;
        }

        if(!strcmp(szKeyScheme, "P") || !strcmp(szKeyScheme, "L") || !strcmp(szKeyScheme, "R"))
        {
            if(pcIV == NULL)
            {
                strcpy(szIV, "00000000000000000000000000000000");
            }
            else
            {
                if(strlen(pcIV) != 32)
                {
                    LOG_ERROR("Parameter pcIV length = [%d] is invalid. It must be 32 characters.", strlen(pcIV));
                    return HAR_PARAM_LEN;
                }

                strcpy(szIV, pcIV);
            }
        }
        else
        {
            if(pcIV == NULL)
            {
                strcpy(szIV, "0000000000000000");
            }
            else
            {
                if(strlen(pcIV) != 16)
                {
                    LOG_ERROR("Parameter pcIV length = [%d] is invalid. It must be 16 characters.", strlen(pcIV));
                    return HAR_PARAM_LEN;
                }

                strcpy(szIV, pcIV);
            }
        }
    }
    else
    {
        if(szKeyCipher[0] == 'P' || szKeyCipher[0] == 'L' || szKeyCipher[0] == 'R')
        {
            if(pcIV == NULL)
            {
                strcpy(szIV, "00000000000000000000000000000000");
            }
            else
            {
                if(strlen(pcIV) != 32)
                {
                    LOG_ERROR("pcIV length = [%d] is invalid. It must be 32 characters.", strlen(pcIV));
                    return HAR_PARAM_LEN;
                }

                strcpy(szIV, pcIV);
            }
        }
        else
        {
            if(pcIV == NULL)
            {
                strcpy(szIV, "0000000000000000");
            }
            else
            {
                if(strlen(pcIV) != 16)
                {
                    LOG_ERROR("Parameter pcIV length = [%d] is invalid. It must be 16 characters.", strlen(pcIV));
                    return HAR_PARAM_LEN;
                }

                strcpy(szIV, pcIV);
            }
        }
    }

    rv =  HSM_IC_GenerateMac_SM4(
                1,
                "008",
                iKeyIdx,
                szKeyCipher,
                "",
                0,                  /*** 会话模式 ***/
                "",                 /*** 会话因子 ***/
                2,
                aucData,            /*** 输入的数据 ***/
                iDataLen,           /*** 输入的数据长度 ***/
                szIV,
                pcMac);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/**
 * @brief   TODO: 不在本次开发任务
 *
 * @param   hSessionHandle
 * @param   iZmkIdx
 * @param   pcZmkCipherByLmk
 * @param   pcKeyType
 * @param   cScheme
 * @param   pcKeyCipherByZmk
 * @param   pcKeyCipherByLmk
 * @param   pcCkv
 *
 * @return  
 */
DLL int Tass_GenerateKey(
        void *hSessionHandle,int nSock,
        int     iZmkIdx,
        char    *pcZmkCipherByLmk,
        char    *pcKeyType,
        char    cScheme,
        char    *pcKeyCipherByZmk/*out*/,
        char    *pcKeyCipherByLmk/*out*/,
        char    *pcCkv/*out*/)
{
    int rv = SDR_OK;

    rv = Tools_CheckKeyValidity_1(iZmkIdx, pcZmkCipherByLmk);
    if(rv)
    {
        LOG_ERROR("Parameter iZmkIdx = [%d] or pcZmkCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iZmkIdx, pcZmkCipherByLmk, rv);
        return rv;
    }

    rv = Toos_CheckKeyType(pcKeyType);
    if(rv)
    {
        LOG_ERROR("Parameter pcKeyType = [%s] is invalid.", pcKeyType);
        return rv;
    }

    /*** 判断算法标识是否正确 ***/
    rv = Tools_CheckSchemeValidity(cScheme);
    if(rv)
    {
        LOG_ERROR("Parameter cScheme = [%c] is invalid.", cScheme);
        return rv;
    }

    if(pcKeyCipherByZmk == NULL)
    {
        LOG_ERROR("pcKeyCipherByZmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(pcKeyCipherByLmk == NULL)
    {
        LOG_ERROR("pcKeyCipherByLmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(pcCkv == NULL)
    {
        LOG_ERROR("pcCkv = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    rv = HSM_RCL_GenWorkingKey(
        hSessionHandle,
        1,                  /*** 密钥产生模式 ***/
        pcKeyType,
        cScheme,
        iZmkIdx,
        pcZmkCipherByLmk,
        cScheme,
        'N',               /*** 密钥存储标识 ***/
        0,
        "",                /*** 密钥标签 ***/
        pcKeyCipherByLmk/*out*/,
        pcKeyCipherByZmk/*out*/,
        pcCkv/*out*/);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}


/**
 * @brief   TODO: 不在本次开发任务
 *
 * @param   hSessionHandle
 * @param   iZmkIdx
 * @param   pcZmkCipherByLmk
 * @param   pcKeyCipherByZmk
 * @param   pcKeyType
 * @param   cScheme
 * @param   pcKeyCipherByLmk
 * @param   pcCkv
 *
 * @return  
 */
DLL int Tass_AcceptKey(
        void    *hSessionHandle,
        int     iZmkIdx,
        char    *pcZmkCipherByLmk,
        char    *pcKeyCipherByZmk,
        char    *pcKeyType,
        char    cScheme,
        char    *pcKeyCipherByLmk/*out*/,
        char    *pcCkv/*out*/)
{
    int rv = SDR_OK;

    rv = Tools_CheckKeyValidity_1(iZmkIdx, pcZmkCipherByLmk);
    if(rv)
    {
        LOG_ERROR("Parameter iZmkIdx = [%d] or pcZmkCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iZmkIdx, pcZmkCipherByLmk, rv);
        return rv;
    }

    if(pcKeyCipherByZmk == NULL)
    {
        LOG_ERROR("Parameter pcKeyCipherByZmk = [%s] is  invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcKeyCipherByZmk) != 16 && strlen(pcKeyCipherByZmk) != 33 && strlen(pcKeyCipherByZmk) != 49)
    {
        LOG_ERROR("Parameter pcKeyCipherByZmk length = [%d] is invalid. It must be 16, 33 or 49 characters.", strlen(pcKeyCipherByZmk));
        return HAR_PARAM_LEN;
    }

    rv = Toos_CheckKeyType(pcKeyType);
    if(rv)
    {
        LOG_ERROR("Parameter pcKeyType = [%s] is invalid.", pcKeyType);
        return rv;
    }

    /*** 判断算法标识是否正确 ***/
    rv = Tools_CheckSchemeValidity(cScheme);
    if(rv)
    {
        LOG_ERROR("Parameter cScheme = [%c] is invalid.", cScheme);
        return rv;
    }

    if(pcKeyCipherByLmk == NULL)
    {
        LOG_ERROR("Parameter pcKeyCipherByLmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(pcCkv == NULL)
    {
        LOG_ERROR("Parameter pcCkv = [%s] invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    rv = HSM_RCL_ImportKey_A6(
            hSessionHandle,
            pcKeyType,
            iZmkIdx,
            pcZmkCipherByLmk,
            pcKeyCipherByZmk,
            cScheme,
            'N',
            0,
            "",
            pcKeyCipherByLmk/*OUT*/,
            pcCkv/*OUT*/ );
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/**
 * @brief   TODO: 不在本次开发任务
 *
 * @param   iZmkIdx
 * @param   pcZmkCipherByLmk
 * @param   pcKeyType
 * @param   iKeyIdx
 * @param   pcKeyCipherByLmk
 * @param   cScheme
 * @param   pcKeyCipherByZmk
 * @param   pcKcv
 *
 * @return  
 */
DLL int Tass_ExportKey(
        int     iZmkIdx,
        char    *pcZmkCipherByLmk,
        char    *pcKeyType,
        int     iKeyIdx,
        char    *pcKeyCipherByLmk,
        char    cScheme,
        char    *pcKeyCipherByZmk/*out*/,
        char    *pcKcv/*out*/)
{
    int rv = SDR_OK;

    rv = Tools_CheckKeyValidity_1(iZmkIdx, pcZmkCipherByLmk);
    if(rv)
    {
        LOG_ERROR("Parameter iZmkIdx = [%d] or pcZmkCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iZmkIdx, pcZmkCipherByLmk, rv);
        return rv;
    }

    rv = Toos_CheckKeyType(pcKeyType);
    if(rv)
    {
        LOG_ERROR("Parameter pcKeyType = [%s] is invalid.", pcKeyType);
        return rv;
    }

    rv = Tools_CheckKeyValidity_1(iKeyIdx, pcKeyCipherByLmk);
    if(rv)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] or pcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iKeyIdx, pcKeyCipherByLmk, rv);
        return rv;
    }

    /*** 判断算法标识是否正确 ***/
    rv = Tools_CheckSchemeValidity(cScheme);
    if(rv)
    {
        LOG_ERROR("Parameter cScheme = [%c] is invalid.", cScheme);
        return rv;
    }

    if(pcKeyCipherByZmk == NULL)
    {
        LOG_ERROR("Parameter pcKeyCipherByZmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(pcKcv == NULL)
    {
        LOG_ERROR("Parameter pcKcv = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    rv = HSM_RCL_ExportKey_A8(
        pcKeyType,
        iZmkIdx,
        pcZmkCipherByLmk,
        iKeyIdx,
        pcKeyCipherByLmk,
        cScheme,
        pcKeyCipherByZmk/*out*/,
        pcKcv/*out*/);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/**
 * @brief   TODO: 不在本次开发任务
 *
 * @param   iSrcKeyIdx
 * @param   pcSrcKeyCipherByLmk
 * @param   iSrcEncMode
 * @param   iSrcDispCnt
 * @param   pcSrcDispData
 * @param   iSrcSessionKeyMode
 * @param   pcSrcSessionKeyData
 * @param   iSrcPaddingMode
 * @param   pcSrcIv
 * @param   pcSrcCipher
 * @param   iDstKeyIdx
 * @param   pcDstKeyCipherByLmk
 * @param   iDstEncMode
 * @param   iDstDispCnt
 * @param   pcDstDispData
 * @param   iDstSessionKeyMode
 * @param   pcDstSessionKeyData
 * @param   iDstPaddingMode
 * @param   pcDstIv
 * @param   pcDstCipher
 *
 * @return  
 */
DLL int Tass_ConvertCipher(
        int     iSrcKeyIdx,
        char    *pcSrcKeyCipherByLmk,
        int     iSrcEncMode,
        int     iSrcDispCnt,
        char    *pcSrcDispData,
        int     iSrcSessionKeyMode,
        char    *pcSrcSessionKeyData,
        int     iSrcPaddingMode,
        char    *pcSrcIv,
        char    *pcSrcCipher,
        int     iDstKeyIdx,
        char    *pcDstKeyCipherByLmk,
        int     iDstEncMode,
        int     iDstDispCnt,
        char    *pcDstDispData,
        int     iDstSessionKeyMode,
        char    *pcDstSessionKeyData,
        int     iDstPaddingMode,
        char    *pcDstIv,
        char    *pcDstCipher/*out*/)
{
    int     rv = SDR_OK;
    int     iSrcCipherLen = 0;
    int     iDstCipherLen = 0;
    unsigned char aucSrcCipher[2048] = {0};
    unsigned char aucDstCipher[2048] = {0};

    rv = Tools_CheckKeyValidity_1(iSrcKeyIdx, pcSrcKeyCipherByLmk);
    if(rv)
    {
        LOG_ERROR("Parameter iSrcKeyIdx = [%d] or pcSrcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iSrcKeyIdx, pcSrcKeyCipherByLmk, rv);
        return rv;
    }

    if(iSrcEncMode < 0 || iSrcEncMode > 3)
    {
        LOG_ERROR("Parameter iSrcEncMode = [%d] is invalid. It must be 0, 1, 2 or 3.", iSrcEncMode);
        return HAR_PARAM_VALUE;
    }

    if(iSrcDispCnt < 0 || iSrcDispCnt > 8)
    {
        LOG_ERROR("Parameter iSrcDispCnt = [%d] is invalid. It must be 0 -- 8.", iSrcDispCnt);
        return HAR_PARAM_VALUE;
    }

    if(pcSrcDispData == NULL)
    {
        LOG_ERROR("Parameter pcSrcDispData = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcSrcDispData) % 32 != 0 || (32 * iSrcDispCnt != (int)strlen(pcSrcDispData)))
    {
        LOG_ERROR("Parameter pcSrcDispData length = [%d] is invalid. It must be multiple of 32.", strlen(pcSrcDispData));
        return HAR_PARAM_LEN;
    }

    rv = Tools_CheckSessionKeyDataValidity(iSrcSessionKeyMode, pcSrcSessionKeyData);
    if(rv)
    {
        LOG_ERROR("Parameter iSrcSessionKeyMode or pcSrcSessionKeyData is invalid, return code = [%#010X].", rv);
        return rv;
    }

    rv = Tools_CheckPaddingModeValidity(iSrcPaddingMode);
    if(rv)
    {
        LOG_ERROR("Parameter iSrcPaddingMode = [%d] is invalid.", iSrcPaddingMode);
        return rv;
    }

    if(iSrcEncMode)
    {
        if(pcSrcIv == NULL)
        {
            LOG_ERROR("Parameter pcSrcIv = [%s] is invalid.", "NULL");
            return HAR_PARAM_ISNULL;
        }
        if(strlen(pcSrcIv) != 16 && strlen(pcSrcIv) != 32)
        {
            LOG_ERROR("Parameter pcSrcIv length = [%d] is invalid. It must be 16 or 32 characters.", strlen(pcSrcIv));
            return HAR_PARAM_LEN;
        }
    }

    if(pcSrcCipher == NULL)
    {
        LOG_ERROR("Parameter pcSrcCipher = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcSrcCipher) % 2 != 0)
    {
        LOG_ERROR("Parameter pcSrcCipher length = [%d] is invalid.", strlen(pcSrcCipher));
        return HAR_PARAM_LEN;
    }

    if(strlen(pcSrcCipher) > 4096)
    {
        LOG_ERROR("Parameter pcSrcCipher length = [%d] is invalid. It must be less than 4096.", strlen(pcSrcCipher));
        return HAR_PARAM_LEN;
    }

    rv = Tools_CheckHex(pcSrcCipher);
    if(rv)
    {
        LOG_ERROR("Parameter pcSrcCipher = [%s] is invalid. It must be hex string.", pcSrcCipher);
        return HAR_PARAM_VALUE;
    }

    rv = Tools_CheckKeyValidity_1(iDstKeyIdx, pcDstKeyCipherByLmk);
    if(rv)
    {
        LOG_ERROR("Parameter iDstKeyIdx = [%d] or pcDstKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iDstKeyIdx, pcDstKeyCipherByLmk, rv);
        return rv;
    }

    if(iDstEncMode < 0 || iDstEncMode > 3)
    {
        LOG_ERROR("Parameter iDstEncMode = [%d] is invalid. It must be 0, 1, 2 or 3.", iDstEncMode);
        return HAR_PARAM_VALUE;
    }

    if(iDstDispCnt < 0 || iDstDispCnt > 8)
    {
        LOG_ERROR("Parameter iDstDispCnt = [%d] is invalid. It must be 0 -- 8.", iDstDispCnt);
        return HAR_PARAM_VALUE;
    }

    if(pcDstDispData == NULL)
    {
        LOG_ERROR("Parameter pcDstDispData = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcDstDispData) % 32 != 0 || (32 * iDstDispCnt != (int)strlen(pcDstDispData)))
    {
        LOG_ERROR("Parameter pcDstDispData length = [%d] is invalid. It must be multiple of 32.", strlen(pcDstDispData));
        return HAR_PARAM_LEN;
    }

    rv = Tools_CheckSessionKeyDataValidity(iDstSessionKeyMode, pcDstSessionKeyData);
    if(rv)
    {
        LOG_ERROR("Parameter iDstSessionKeyMode or pcDstSessionKeyData is invalid, return code = [%#010X].", rv);
        return rv;
    }

    rv = Tools_CheckPaddingModeValidity(iDstPaddingMode);
    if(rv)
    {
        LOG_ERROR("Parameter iDstPaddingMode = [%d] is invalid.", iDstPaddingMode);
        return rv;
    }

    if(iDstEncMode)
    {
        if(pcDstIv == NULL)
        {
            LOG_ERROR("Parameter pcDstIv = [%s] is invalid.", "NULL");
            return HAR_PARAM_ISNULL;
        }
        if(strlen(pcDstIv) != 16 && strlen(pcDstIv) != 32)
        {
            LOG_ERROR("Parameter pcDstIv length = [%d] is invalid. It must be 16 or 32 characters.", strlen(pcDstIv));
            return HAR_PARAM_LEN;
        }
    }

    if(pcDstCipher == NULL)
    {
        LOG_ERROR("Parameter pcDstCipher = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    rv = Tools_ConvertHexStr2Byte(pcSrcCipher, strlen(pcSrcCipher), aucSrcCipher);
    if(rv == -1)
    {
        LOG_ERROR("%s", "Parameter [pcSrcCipher] hexadecimal string conversion to byte array failed");
        return HAR_HEX_TO_BYTE;
    }

    rv = HSM_IC_SymmKeyConvertCipher(
        iSrcEncMode,
        "00A",
        iSrcKeyIdx,
        pcSrcKeyCipherByLmk,
        pcSrcDispData,
        iSrcSessionKeyMode,
        pcSrcSessionKeyData,
        iSrcPaddingMode,
        pcSrcIv,
        iDstEncMode,
        "00A",
        iDstKeyIdx,
        pcDstKeyCipherByLmk,
        pcDstDispData,
        iDstSessionKeyMode,
        pcDstSessionKeyData,
        iDstPaddingMode,
        pcDstIv,
        aucSrcCipher,
        iSrcCipherLen,
        aucDstCipher/*out*/,
        &iDstCipherLen/*out*/);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    rv = Tools_ConvertByte2HexStr(aucDstCipher, iDstCipherLen, pcDstCipher);
    if(rv == -1)
    {
        LOG_ERROR("%s", "Byte data conversion to hexadecimalstring failure.");
        rv = HAR_BYTE_TO_HEX;
    }

    return rv;
}



/**
 * @brief   TODO: 不在本次开发任务
 *
 * @param   iKeyIdx
 * @param   pcKeyCipherByLmk
 * @param   pcPan
 * @param   pcAtc
 * @param   pcPlaintextPin
 * @param   pcCipherPin
 *
 * @return  
 */
DLL int Tass_Encrypt_OfflinePin(
        int     iKeyIdx,
        char    *pcKeyCipherByLmk,
        char    *pcPan,
        char    *pcAtc,
        char    *pcPlaintextPin,
        char    *pcCipherPin/*out*/)
{
    int rv = SDR_OK;

    rv = Tools_CheckKeyValidity_1(iKeyIdx, pcKeyCipherByLmk);
    if(rv)
    {
        LOG_ERROR("Parameter iKeyIdx = [%d] or pcKeyCipherByLmk = [%s] is invalid, return code = [%#010X].",
                iKeyIdx, pcKeyCipherByLmk);
        return rv;
    }

    if(pcPan == NULL)
    {
        LOG_ERROR("Parameter pcPan = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcPan) != 16)
    {
        LOG_ERROR("Parameter pcPan'length = [%d] is invalid. It must be 16 characters.", strlen(pcPan));
        return HAR_PARAM_LEN;
    }

    if(pcAtc == NULL)
    {
        LOG_ERROR("Parameter pcAtc = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcAtc) != 4)
    {
        LOG_ERROR("Parameter pcAtc'length = [%d] is invalid. It must be 4 characters.", strlen(pcAtc));
        return HAR_PARAM_LEN;
    }

    if(pcPlaintextPin == NULL)
    {
        LOG_ERROR("Parameter pcPlaintextPin = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(strlen(pcPlaintextPin) < 4 || strlen(pcPlaintextPin) > 12)
    {
        LOG_ERROR("Parameter pcPlaintextPin'length = [%d] is invalid. It must be 4 -- 12 characters.", strlen(pcPlaintextPin));
        return HAR_PARAM_LEN;
    }

    if(pcCipherPin == NULL)
    {
        LOG_ERROR("Parameter pcCipherPin = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    /*** 调用底层指令接口 ***/
    rv = HSM_IC_OfflinePin_PlaintextPin(
                iKeyIdx,
                pcKeyCipherByLmk,
                pcPan,
                pcAtc,
                "41",
                pcPlaintextPin,     /*** PIN明文 ***/
                "",
                "000000000000",
                pcCipherPin/*out*/);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/***************************************************************************
* Subroutine: Tass_KeyTypeConversion
* Function:   密钥类型转换
* Input:
*   @iSrcKeyIdx            源密钥索引
*   @pcSrcKeyCipherByLmk   源密钥密文，仅当密钥索引值为0时该参数有效
*   @pcSrcKeyType          源密钥类型
*   @pcDstKeyType          目的密钥类型
* Output:
*   @pcDstKeyCipherByLmk   目的密钥密文
*   @pcDstKeyCv            目的密钥校验值
*
* Return:       成功返回0，其他表示失败
* Description:
* Author:       Luo Cangjian
* Date:         2015.06.05
* ModifyRecord:
* *************************************************************************/
#if 0
HSMAPI int
Tass_KeyTypeConversion(
        int     iSrcKeyIdx,
        char    *pcSrcKeyCipherByLmk,
        char    *pcSrcKeyType,
        char    *pcDstKeyType,
        char    *pcDstKeyCipherByLmk/*out*/,
        char    *pcDstKeyCv/*out*/)
{
    int rv = SDR_OK;

    char cDstScheme = 'X';
    char pcKeyType[4] = {0};
    char pcKeyScheme[2] = {0};
    char pcKeyCv[17] = {0};
    char pcKeyLabel[32] = {0};
    char pcTime[32] = {0};

    rv = Tools_CheckKeyValidity_2(iSrcKeyIdx, pcSrcKeyCipherByLmk);
    if(rv)
    {
        LOG_ERROR("Parameter iSrcKeyIdx = [%d] or pcSrcKeyCipherByLmk = [%s] is invalid, reutrn code = [%#010X].",
                iSrcKeyIdx, pcSrcKeyCipherByLmk, rv);
    }

    rv = Toos_CheckKeyType(pcSrcKeyType);
    if(rv)
    {
        LOG_ERROR("Parameter pcSrcKeyType = [%s] is invalid.", pcSrcKeyType);
        return rv;
    }

    rv = Toos_CheckKeyType(pcDstKeyType);
    if(rv)
    {
        LOG_ERROR("Parameter pcDstKeyType = [%s] is invalid.", pcDstKeyType);
        return rv;
    }

    if(pcDstKeyCipherByLmk == NULL)
    {
        LOG_ERROR("Parameter pcDstKeyCipherByLmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(pcDstKeyCv == NULL)
    {
        LOG_ERROR("Parameter pcDstKeyCv = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(iSrcKeyIdx)
    {
        rv = HSM_IC_GetKeyInfo(
            iSrcKeyIdx,
            pcKeyType,
            pcKeyScheme,
            pcKeyCv,
            pcKeyLabel,
            pcTime );
        if(rv)
        {
            LOG_ERROR("Tass hsm api return code1 = [%d], [%#010X].", rv, rv);
            return rv;
        }
        cDstScheme = pcKeyScheme[0];
    }
    else
    {
        cDstScheme = *pcSrcKeyCipherByLmk;
    }

    /*** 导出密钥 ***/
    rv = HSM_RCL_KeyTypeConversion(
           hSessionHandle,
            pcSrcKeyType,
            iSrcKeyIdx,
            pcSrcKeyCipherByLmk,
            pcDstKeyType,
            cDstScheme,
            pcDstKeyCipherByLmk/*out*/,
            pcDstKeyCv/*out*/);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code2 = [%d], [%#010X].", rv, rv);
    }

    return rv;
}
#endif


/**
 * @brief   TODO: 不在本次开发任务
 *
 * @param   pcFormatStr
 *
 * @return  
 */
DLL int Tass_SetPrintFormat(char *pcFormatStr)
{
    int rv = SDR_OK;
    char szFormatData[512 + 1] = {0};

    if(pcFormatStr == NULL)
    {
        strcpy(szFormatData, ">L>010密钥成分>025^P>L>L>010校验值：>025^T>L>L>010备注信息：>025^0>F");
    }
    else
    {
        if(strlen(pcFormatStr) > 512)
        {
            LOG_ERROR("Error, pcFormatStr length = [%d] is invalid, it must be less than 512 characters.", strlen(pcFormatStr));
            return HAR_PARAM_LEN;
        }
        strcpy(szFormatData, pcFormatStr);
    }

    /*** 装载打印的数据格式 ***/
    rv = HSM_RCL_LoadFormatData(szFormatData);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/**
 * @brief   TODO: 不在本次开发任务
 *
 * @param   pcKeyType
 * @param   cKeyScheme
 * @param   pcMarkInfo
 * @param   pcKeyCipherByLmk
 * @param   pcKeyCv
 *
 * @return  
 */
DLL int Tass_GenPrintRandkey(
        char    *pcKeyType,
        char    cKeyScheme,
        char    *pcMarkInfo,
        char    *pcKeyCipherByLmk,
        char    *pcKeyCv)
{
    int rv = SDR_OK;
    char pcPrintDomain[512 + 8] = {0};

    rv = Toos_CheckKeyType(pcKeyType);
    if(rv)
    {
        LOG_ERROR("Parameter pcKeyType = [%s] is invalid.", pcKeyType);
        return rv;
    }

    /*** 判断算法标识是否正确 ***/
    rv = Tools_CheckSchemeValidity(cKeyScheme);
    if(rv)
    {
        LOG_ERROR("Parameter cKeyScheme = [%c] is invalid.", cKeyScheme);
        return rv;
    }

    if(pcMarkInfo != NULL)
    {
        if(strlen(pcMarkInfo) > 512)
        {
            LOG_ERROR("Error, pcMarkInfo length = [%d] is invalid, it must be less than 512 characters.", strlen(pcMarkInfo));
            return HAR_PARAM_LEN;
        }

        strcpy(pcPrintDomain, pcMarkInfo);
        strcat(pcPrintDomain, ";");
    }

    if(pcKeyCipherByLmk == NULL)
    {
        LOG_ERROR("Error, pcKeyCipherByLmk = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(pcKeyCv == NULL)
    {
        LOG_ERROR("Error, pcKeyCv = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    rv = HSM_RCL_GenAndPrintKey(
                0,
                pcKeyType,
                cKeyScheme,
                0,
                30,
                10,
                pcPrintDomain,
                pcKeyCipherByLmk,
                pcKeyCv);
    if(rv)
    {
        LOG_ERROR("Tass hsm api return code = [%d], [%#010X].", rv, rv);
    }

    return rv;
}

/**
 * @brief   TODO: 不在本次开发任务
 *
 * @param   hSessionHandle
 * @param   index
 * @param   RsaTag
 * @param   RsaLen
 * @param   RSA_E
 * @param   pucDerPublicKey
 *
 * @return  
 */
DLL int Tass_GenRSA(
    void *hSessionHandle,int nSock,
    int  index, 
    char *RsaTag,
    int  RsaLen,
    char *RSA_E,
    char *pucDerPublicKey /*out*/)
{
   //定义变量
    int rv = SDR_OK;
          char szDerPubKeyHex[2048] = {0};
          int piDerPublicKeyLen = 0;
          int piDerPrivateKeyLen = 0;       
          int piPrivateKeyLen_Lmk = 0;
    //检查参数
    if(RsaLen < 1024 || RsaLen >4096)
    {
        LOG_ERROR("%s","RsaLen is error,it should between 2048 and 4096");
        return rv;
    }    

   unsigned char Rsa_LMK_m[2048] = {0};
   rv = HSM_RSA_GenerateNewKeyPair(
           hSessionHandle,
           index, /**密钥索引，0表示不存储**/
           RsaTag, /**RSA密钥标签**/
           RsaLen, /**密钥模长**/
           65537, /**公钥指数E ，默认为65537**/
           szDerPubKeyHex/*out*/, 
           &piDerPublicKeyLen/*out*/,
           Rsa_LMK_m/*out*/,/**LMK下加密的RSA私钥密文**/ 
           &piPrivateKeyLen_Lmk/*out*/ );
    if(rv)
        {
              LOG_ERROR("%s","GenerateNewKeyPair is error");
              return rv;
        }
    int len = Tools_ConvertByte2HexStr(szDerPubKeyHex,piDerPublicKeyLen, pucDerPublicKey);
    if(len == -1){
      LOG_ERROR("%s","pucDerPublicKey convert HexStr is failed");
      return HAR_BYTE_TO_HEX;
    }

   return rv;
}

/**
 * @brief   TODO: 不在本次开发任务
 *
 * @param   hSessionHandle
 * @param   ihashFlag
 * @param   pcSignatureData
 * @param   iRsaPrivIndex
 * @param   pcRsaPrivCipher
 * @param   
 *
 * @return  
 */
DLL int Tass_RSA_Signature(
		void *hSessionHandle,int nSock,
    	int   ihashFlag,
    	char *pcSignatureData,
		int   iRsaPrivIndex, 
    	char *pcRsaPrivCipher,
    	char *pcSignature /**out**/ )
{
	int rv = SDR_OK;
	unsigned char pcSignatureData_m[4096] = {0};
	unsigned char pcRsaPrivCipher_m[4096] = {0};
	unsigned char pcSignature_m[4096] = {0};
	int iSignatureDataLen = 0;
	int iRsaPrivCipherLen = 0;
	int len = 0;
	int piSignatureLength = 0;
	
	if(ihashFlag < 0 || ihashFlag > 8){
		LOG_ERROR("the hashFlag is error,code=[%#010X]",HAR_PARAM_VALUE);
		return HAR_PARAM_VALUE;
	}
	
	if(strlen(pcSignatureData) < 0 || strlen(pcSignatureData) > 3968){
		LOG_ERROR("the pcSignatureData length is error, it should in [0-3968],code=[%#010X]",HAR_PARAM_LEN);
		return HAR_PARAM_LEN;
	}
	iSignatureDataLen = Tools_ConvertHexStr2Byte(pcSignatureData,strlen(pcSignatureData),pcSignatureData_m);
	//Tools_PrintBuf("pcSignatureData_m",pcSignatureData_m,iSignatureDataLen);
	if(iSignatureDataLen == -1){
		LOG_ERROR("pcSignatureData Convert hex to byte failed ,code = [%#010X]",HAR_HEX_TO_BYTE);
		return HAR_HEX_TO_BYTE;
	}
	
	if(iRsaPrivIndex <1 || iRsaPrivIndex >64){
		if(!strlen(pcRsaPrivCipher) || strlen(pcRsaPrivCipher) % 2 != 0){
			LOG_ERROR("RsaPrivCipher length is error,code = [%#010X]",HAR_PARAM_LEN);
			return HAR_PARAM_LEN;
		}
		iRsaPrivCipherLen = Tools_ConvertHexStr2Byte(pcRsaPrivCipher,strlen(pcRsaPrivCipher),pcRsaPrivCipher_m);
		if(iRsaPrivCipherLen == -1){
			LOG_ERROR("pcRsaPrivCipher Convert hex to byte failed,code = [%#010X]",HAR_HEX_TO_BYTE);
			return HAR_HEX_TO_BYTE;
	       }
		//Tools_PrintBuf("pcRsaPrivCipher",pcRsaPrivCipher_m,iRsaPrivCipherLen);
	}
	
	
	rv = HSM_RSA_GenerateSignature(
	    hSessionHandle,
               ihashFlag, /**hash算法模式**/ 
    	    1, /**填充模式,PKCS#1.5**/
    	    iRsaPrivIndex, /**RSA密钥索引**/
    	    pcRsaPrivCipher_m, /**LMK加密的RSA私钥**/
	    iRsaPrivCipherLen,  /**LMK加密的RSA私钥长度**/
    	    pcSignatureData_m, /**待签名的数据**/
	    iSignatureDataLen, /**代签名的输入数据长度**/
    	    pcSignature_m/*out*/, 
    	    &piSignatureLength/*out*/ );
		
         if(rv){
	    LOG_ERROR("HSM_RSA_GenerateSignature  failed,code = [%d],[%#010X]",rv,rv);
	    return rv;
	}
	len = Tools_ConvertByte2HexStr(pcSignature_m,piSignatureLength,pcSignature);
	return rv;
}

/**
 * @brief   TODO: 不在本次开发任务
 *
 * @param   hSessionHandle
 * @param   ihashFlag
 * @param   pcSignature
 * @param   pcSignatureData
 * @param   iRsaPubIndex
 * @param   pcRsaPubKey
 *
 * @return  
 */
DLL int Tass_RSA_VerifySignature(
    void  *hSessionHandle,
    int    ihashFlag,
    char  *pcSignature,
    char  *pcSignatureData,
    int    iRsaPubIndex, 
    char  *pcRsaPubKey )
{
    int rv = SDR_OK;
	unsigned char pcSignatureData_m[2048] = {0};
	unsigned char pcRsaPubKey_m[4096] = {0};
	unsigned char pcSignature_m[4096] = {0};
	int iSignatureLength = 0;
	int iSignatureDataLen = 0;
	int iRsaPubKeyLen = 0;
	int len = 0;
	int piSignatureLength = 0;

	if(ihashFlag < 0 || ihashFlag > 8){
		LOG_ERROR("the hashFlag is error,code=[%#010X]",HAR_PARAM_VALUE);
		return HAR_PARAM_VALUE;
	}
	
	if(strlen(pcSignature)% 2 != 0 || strlen(pcSignature) <= 0){
		LOG_ERROR("the pcSignature is error, code = [%#010X]",HAR_PARAM_LEN);
		return HAR_PARAM_LEN;
	}

	//待验证签名转为byte
	iSignatureLength = Tools_ConvertHexStr2Byte(pcSignature,strlen(pcSignature),pcSignature_m);
	if(iSignatureLength == -1){
		LOG_ERROR("pcSignature convert hex to byte failed,code = [%#010X]", HAR_HEX_TO_BYTE);
		return HAR_HEX_TO_BYTE;
	}
	
	if(strlen(pcSignatureData)<0 || strlen(pcSignatureData)>3968){
		LOG_ERROR("the pcSignatureData length is error, it should in [0-3968],code=[%#010X]",HAR_PARAM_LEN);
		return HAR_PARAM_LEN;
	}
	iSignatureDataLen = Tools_ConvertHexStr2Byte(pcSignatureData,strlen(pcSignatureData),pcSignatureData_m);
	//Tools_PrintBuf("pcSignatureData_m",pcSignatureData_m,iSignatureDataLen);
	if(iSignatureDataLen == -1){
		LOG_ERROR("pcSignatureData Convert hex to byte failed ,code = [%#010X]",HAR_HEX_TO_BYTE);
		return HAR_HEX_TO_BYTE;
	}
	
	if(iRsaPubIndex < 1 || iRsaPubIndex >64){
		if(!strlen(pcRsaPubKey) || (strlen(pcRsaPubKey)%2)!= 0){
			LOG_ERROR("pcRsaPubKey length is error,code = [%#010X]",HAR_PARAM_LEN);
			return HAR_PARAM_LEN;
		}
		
		iRsaPubKeyLen = Tools_ConvertHexStr2Byte(pcRsaPubKey,strlen(pcRsaPubKey),pcRsaPubKey_m);
		if(iRsaPubKeyLen == -1){
			LOG_ERROR("pcRsaPubKey Convert hex to byte failed,code = [%#010X]",HAR_HEX_TO_BYTE);
			return HAR_HEX_TO_BYTE;
		}
		
	}
		
    rv = HSM_RSA_VerifySignature(
        hSessionHandle,
        ihashFlag, /**HASH算法标识**/
	    1, /**填充模式：00–不填充（解密后的数据直接输出）；01–PKCS**/
        iRsaPubIndex, /**RSA密钥索引，**/
	    pcRsaPubKey_m, /**DER编码的RSA公钥**/
	    iRsaPubKeyLen, /**DER编码的RSA公钥长度**/
        pcSignatureData_m, /**待验证签名的输入数据**/
	    iSignatureDataLen, /**待验证签名的输入数据长度**/
        pcSignature_m, /**待验证的数据签名**/
	    iSignatureLength /**待验证的数据签名长度**/ ); 
	
	if(rv){
		LOG_ERROR("HSM_RSA_VerifySignature failed,return code = [%d],[%#010X]", rv,rv);
	}

	return rv;
}

/**
 * @brief   TODO: 不在本次开发任务
 *
 * @param   hSessionHandle
 * @param   iSummaryMode
 * @param   pcuserid
 * @param   pcSignatureData
 * @param   iSm2PubIndex
 * @param   pcSm2PubKey
 * @param   pcSm2PrivCipher
 * @param   iSignatureFormat
 * @param   
 *
 * @return  
 */
DLL int Tass_SM2_Signature(
          void	*hSessionHandle,
	int  	iSummaryMode,
	char 	*pcuserid,
	char 	*pcSignatureData,
	int 	 iSm2PubIndex,
	char 	*pcSm2PubKey,
	char 	*pcSm2PrivCipher,
	int 	 iSignatureFormat,
	char 	*pcSignature  /**out**/ )
{
	int rv = SDR_OK;
	unsigned char pcSignatureData_m[4096] = {0};
	unsigned char pcSm2PrivCipher_m[4096] = {0};
	unsigned char pcSm2PubKey_m[4096] = {0};
	unsigned char pcSignature_m[4096] = {0};
	unsigned char pcuserid_m[65] = {0};
	unsigned char pucHash[2048] = {0};
	unsigned char pucSignature[4096] = {0}; /*输出的数据签名*/
	int piSignatureLength = 0; 
	int piHashLength = 0;
	int iSm2PubKeyLen = 0;		
	int iSignatureDataLen = 0;
	int iSm2PrivCipherLen = 0;
	int iSignatureLength = 0;
	int iuseridLen = 0;
	int len = 0;
	
	if(iSummaryMode < 1 || iSummaryMode > 20){
		iSummaryMode = 0;
	}
	
	if(strlen(pcuserid) > 32){
		LOG_ERROR("the userid length should in [0-32],code=[%#010X]",HAR_PARAM_LEN);
		return HAR_PARAM_LEN;
	}
	iuseridLen = Tools_ConvertHexStr2Byte(pcuserid, strlen(pcuserid), pcuserid_m);
	if(iuseridLen == -1){
		LOG_ERROR("pcuserid convert hex to byte failed,code=[%#010X]",HAR_HEX_TO_BYTE);
		return HAR_HEX_TO_BYTE;
	}
	
	if(strlen(pcSignatureData) > 3968){
		LOG_ERROR("the pcSignatureData length should in [0-3968]H,code=[%#010X]",HAR_PARAM_LEN);
		return HAR_PARAM_LEN;
	}
	iSignatureDataLen = Tools_ConvertHexStr2Byte(pcSignatureData, strlen(pcSignatureData), pcSignatureData_m);
	if(iSignatureDataLen == -1){
		LOG_ERROR("pcSignatureData convert hex to byte failed,code=[%#010X]",HAR_HEX_TO_BYTE);
		return HAR_HEX_TO_BYTE;
	}
	if(iSm2PubIndex < 1 || iSm2PubIndex >64){
		if(!strlen(pcSm2PubKey) || (strlen(pcSm2PubKey)%2)!= 0){
			LOG_ERROR("pcSm2PubKey length is error,code = [%#010X]",HAR_PARAM_LEN);
			return HAR_PARAM_LEN;
		}
		if(strlen(pcSm2PrivCipher) % 2 != 0){
		    LOG_ERROR("pcSm2PrivCipher length is error,code = [%#010X]",HAR_PARAM_LEN);
		    return HAR_PARAM_LEN;
        }
		
		iSm2PubKeyLen = Tools_ConvertHexStr2Byte(pcSm2PubKey,strlen(pcSm2PubKey),pcSm2PubKey_m);
		
		if(iSm2PubKeyLen == -1){
			LOG_ERROR("pcSm2PubKey Convert hex to byte failed,code = [%#010X]",HAR_HEX_TO_BYTE);
			return HAR_HEX_TO_BYTE;
		}
		iSm2PrivCipherLen = Tools_ConvertHexStr2Byte(pcSm2PrivCipher,strlen(pcSm2PrivCipher),pcSm2PrivCipher_m);
		if(iSm2PrivCipherLen == -1){
			LOG_ERROR("pcSm2PrivCipher convert hex to byte failed,code=[%#010X]",HAR_HEX_TO_BYTE);
			return HAR_HEX_TO_BYTE;
		}		
	}
	//对数据做摘要运算
	if(iSummaryMode != 0){
		//摘要
	    rv = HSM_CalculateHash(
		    hSessionHandle,
            iSummaryMode, /**hash算法模式**/
			pcSignatureData_m, /**数据块**/
            iSignatureDataLen, /**数据块长度，0-4096字节**/
            pcuserid_m, /**用户ID**/
			iuseridLen, /**用户ID长度**/
            pcSm2PubKey_m, /**SM2公钥**/
			iSm2PubKeyLen, /**SM2公钥长度**/
			pucHash/*out,HASH*/,
			&piHashLength/*out,HASH结果长度*/ );
			
	    if(rv){
			LOG_ERROR("HSM_CalculateHash failed,return code = [%d],[%#010X]",rv,rv);
			return rv;
		}
		
        rv = HSM_SM2_GenSignatureSummary(
            hSessionHandle, 
		    iSm2PubIndex, /**SM2公钥索引**/
		    pcSm2PrivCipher_m, /**LMK加密的SM2私钥**/ 
		    iSm2PrivCipherLen, /**LMK加密的SM2私钥长度**/
            pucHash, /**数据块摘要值**/
		    piHashLength, /**数据块摘要值长度**/
	        iSignatureFormat, /**签名编码格式**/
            pucSignature/*out,输出的数据签名*/, 
		    &piSignatureLength/*out*/ );
			
		if(rv){
			LOG_ERROR("HSM_SM2_GenSignatureSummary failed,return code = [%d],[%#010X]",rv,rv);
			return rv;
		}
		
	    len = Tools_ConvertByte2HexStr(pucSignature, piSignatureLength, pcSignature);
		if(len == -1){
			LOG_ERROR("pucSignature Convert byte to hex failed,code = [%#010X]",HAR_BYTE_TO_HEX);
			return HAR_BYTE_TO_HEX;
		}
	
		return rv;
	}else{//对数据做摘要运算

        rv = HSM_SM2_GenerateSignature(
		    hSessionHandle,
		    iSm2PubIndex, /**SM2密钥索引**/
            pcSm2PubKey_m, /**DER编码的SM2公钥**/
			iSm2PubKeyLen, /**DER编码的SM2公钥长度**/
            pcSm2PrivCipher_m, /**LMK加密的SM2私钥**/
			iSm2PrivCipherLen, /**LMK加密的SM2私钥长度**/
            pcuserid_m, /**用户标识**/
			iuseridLen, /**用户标识长度**/
            pcSignatureData_m, /**待签名的输入数据**/
			iSignatureDataLen, /**待签名的输入数据长度**/
            pucSignature/*out,输出的数据签名*/, 
            &piSignatureLength/*out*/ );
		if(rv){
			LOG_ERROR("HSM_SM2_GenerateSignature failed,return code = [%d],[%#010X]",rv,rv);
			return rv;
		}
		len = Tools_ConvertByte2HexStr(pucSignature, piSignatureLength, pcSignature);
		if(len == -1){
			LOG_ERROR("pucSignature Convert byte to hex failed,code = [%#010X]",HAR_BYTE_TO_HEX);
			return HAR_BYTE_TO_HEX;
		}
		return rv;
	}
	
	return rv;
}

/**
 * @brief   TODO: 不在本次开发任务
 *
 * @param   hSessionHandle
 * @param   iSummaryMode
 * @param   pcuserid
 * @param   pcSignature
 * @param   pcSignatureData
 * @param   iSm2PubIndex
 * @param   pcSm2PubKey
 * @param   iSignatureFormat
 *
 * @return  
 */
DLL int Tass_SM2_VerifySignature (
	void	*hSessionHandle,
	int 	iSummaryMode,
	char 	*pcuserid,
	char 	*pcSignature,
	char 	*pcSignatureData,
	int 	 iSm2PubIndex,
	char 	*pcSm2PubKey,
	int 	 iSignatureFormat)
{
    int rv = SDR_OK;
	unsigned char pcSignatureData_m[4096] = {0};
	unsigned char pcSm2PubKey_m[4096] = {0};
	unsigned char pcuserid_m[65] = {0};
	unsigned char pucHash[2048] = {0};
	unsigned char pcSignature_m[256] = {0};
	unsigned char pucSignature[4096] = {0}; /*输出的数据签名*/
	int piSignatureLength = 0;
	int piHashLength = 0;
	int iSm2PubKeyLen = 0;		
	int iSignatureDataLen = 0;
	int iSignatureLength = 0;//字节数
	int iuseridLen = 0;
	int len = 0;
	
	if(iSummaryMode < 1 || iSummaryMode > 20){
		iSummaryMode = 0;
	}
	if(strlen(pcSignature) < 128 || strlen(pcSignature) > 160){
		LOG_ERROR("Parameter:pcSignature length is error,it should in [128-160]H,code=[%#010X]",HAR_PARAM_LEN);
		return HAR_PARAM_LEN;
	}
	iSignatureLength = Tools_ConvertHexStr2Byte(pcSignature, strlen(pcSignature), pcSignature_m);
	if(iSignatureLength == -1){
		LOG_ERROR("pcSignature Convert hex to byte failed,code = [%#010X]",HAR_HEX_TO_BYTE);
		return HAR_HEX_TO_BYTE;
	}
	if(strlen(pcuserid) > 32){
		LOG_ERROR("the userid length should in [0-32],code=[%#010X]",HAR_PARAM_LEN);
		return HAR_PARAM_LEN;
	}
	iuseridLen = Tools_ConvertHexStr2Byte(pcuserid, strlen(pcuserid), pcuserid_m);
	if(iuseridLen == -1){
		LOG_ERROR("pcuserid convert hex to byte failed,code=[%#010X]",HAR_HEX_TO_BYTE);
		return HAR_HEX_TO_BYTE;
	}
	
	if(strlen(pcSignatureData) > 3968){
		LOG_ERROR("the pcSignatureData length should in [0-3968]H,code=[%#010X]",HAR_PARAM_LEN);
		return HAR_PARAM_LEN;
	}
	iSignatureDataLen = Tools_ConvertHexStr2Byte(pcSignatureData, strlen(pcSignatureData), pcSignatureData_m);
	if(iSignatureDataLen == -1){
		LOG_ERROR("pcSignatureData convert hex to byte failed,code=[%#010X]",HAR_HEX_TO_BYTE);
		return HAR_HEX_TO_BYTE;
	}
	if(iSm2PubIndex < 1 || iSm2PubIndex >64){
		if(!strlen(pcSm2PubKey) || (strlen(pcSm2PubKey)%2)!= 0){
			LOG_ERROR("pcSm2PubKey length is error,code = [%#010X]",HAR_PARAM_LEN);
			return HAR_PARAM_LEN;
		}
		
		iSm2PubKeyLen = Tools_ConvertHexStr2Byte(pcSm2PubKey,strlen(pcSm2PubKey),pcSm2PubKey_m);
		
		if(iSm2PubKeyLen == -1){
			LOG_ERROR("pcSm2PubKey Convert hex to byte failed,code = [%#010X]",HAR_HEX_TO_BYTE);
			return HAR_HEX_TO_BYTE;
		}		
	}
	//对数据做摘要运算
	if(iSummaryMode != 0){
		//摘要
	    rv = HSM_CalculateHash(
		    hSessionHandle,
            iSummaryMode, /**hash算法模式**/
			pcSignatureData_m, /**数据块**/
            iSignatureDataLen, /**数据块长度，0-4096字节**/
            pcuserid_m, /**用户ID**/
			iuseridLen, /**用户ID长度**/
            pcSm2PubKey_m, /**SM2公钥**/
			iSm2PubKeyLen, /**SM2公钥长度**/
			pucHash/*out,HASH*/,
			&piHashLength/*out,HASH结果长度*/ );
		//Tools_PrintBuf("pucHash",pucHash,piHashLength);	
	    if(rv){
			LOG_ERROR("HSM_CalculateHash failed,return code = [%d],[%#010X]",rv,rv);
			return rv;
		}
		
	    rv = HSM_SM2_VerifySummarySignature(
	        hSessionHandle, 
	        pcSignature_m,  /**待验证的签名**/
	        iSignatureLength, /**待验证签名的长度**/
	        iSm2PubIndex,  /**SM2公钥索引**/
	        pcSm2PubKey_m, /**SM2公钥**/
	        iSm2PubKeyLen, /**SM2公钥长度**/
	        pucHash, /**数据块摘要值**/
	        piHashLength, /**数据块摘要值长度**/
	        iSignatureFormat /**签名编码格式**/ );
		//printf("%d\n",rv);
	    if(rv){
		     LOG_ERROR("HSM_SM2_VerifySummarySignature failed,return code = [%d],[%#010X]",rv,rv);
	    }
	    return rv;
		
	}else{//对数据不做摘要运算
	
        rv = HSM_SM2_VerifySignature(
            hSessionHandle,
            iSm2PubIndex, /**SM2公钥索引**/
			pcSm2PubKey_m, /**SM2公钥DER编码**/
			iSm2PubKeyLen, /**公钥DER编码长度**/
            pcuserid_m, /**用户id**/
			iuseridLen, /**userid长度**/
            pcSignatureData_m, /**签名数据**/
            iSignatureDataLen, /**签名数据长度**/
            pcSignature_m, /**待验证的签名**/
            iSignatureLength /**待验证的签名长度**/ );
		//printf("%d",rv);
	    if(rv){
		     LOG_ERROR("HSM_SM2_VerifySignature failed,return code = [%d],[%#010X]",rv,rv);
	    }
	    return rv;
	}
}

#endif
