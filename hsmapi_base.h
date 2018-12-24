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
#ifndef __HSM_API_BASE_H__
#define __HSM_API_BASE_H__

/*产生SM2密钥对*/
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
    unsigned char *pucPriKeyCipherByKEK/*KEK加密的私钥密文 out*/);

/*转加密SM2私钥*/
int HSM_BASE_UY_ConvertSM2PriKeyCipherByHMKToKEK(
    void *hSessionHandle,int nSock,
    char cSymmAlg/*算法类型*/,
    unsigned char *pucPriKeyCipherByHMK/*HMK加密的私钥密文*/,
    int iKEKIdx/*保护密钥索引*/,
    char *pcKEKCipherByHMK/*保护密钥密文*/,
    char cMode/*模式*/,
    char *pcIV/*初始向量*/,
    unsigned char *pucPriKeyCipherByKEK/*KEK加密的私钥密文 out*/);

/*SM2公钥加密*/
int HSM_BASE_UU_SM2PubKeyEncrypt(
    void *hSessionHandle,int nSock,
    int iKeyIdx/*密钥索引*/,
    unsigned char *pucPubKeyX/*公钥X明文*/,
    unsigned char *pucPubKeyY/*公钥Y明文*/,
    int iDataLength/*数据长度*/,
    unsigned char *pucData/*数据*/,
    int *piCipherLength/*密文长度 out*/,
    unsigned char *pucCipher/*密文 out*/);

/*SM2私钥解密*/
int HSM_BASE_UW_SM2PriKeyDecrypt(
    void *hSessionHandle,int nSock,
    int iKeyIdx/*密钥索引*/,
    char *pcKeyPassword/*密钥口令*/,
    unsigned char *pucPriKeyCipherByHMK/*私钥密文*/,
    int iCipherLength/*密文长度*/,
    unsigned char *pucCipher/*密文*/,
    int *piDataLength/*数据长度 out*/,
    unsigned char *pucData/*数据 out*/);

/*SM2签名*/
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
    unsigned char *pucSignatureS/*签名S部分 out*/);

/*SM2验签*/
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
    unsigned char *pucData/*数据*/);

/*产生消息摘要*/
int HSM_BASE_GM_CalculateDigest(
    void *hSessionHandle,int nSock,
    int iAlgType/*算法类型*/,
    char cSeperator/*分隔符*/,
    int iDataLength/*数据长度*/,
    unsigned char *pucData/*数据*/,
    int *piDigestLength/*摘要长度*/,
    unsigned char *pucDigest/*摘要*/);

#endif /*__HSM_API_BASE_H__*/

