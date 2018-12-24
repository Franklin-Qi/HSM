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
#ifndef __HSM_API_RSA_H__
#define __HSM_API_RSA_H__

/*产生RSA密钥对*/
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
    unsigned char *pucPriKeyCipherByKEK/*KEK加密的私钥密文 out*/);

/*RSA签名*/
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
    int iRSAIdx/*RSA索引*/,
    char *pcKeyPassword/*密钥口令*/,
    int iPriKeyCipherByHMKLength/*私钥密文长度*/,
    unsigned char *pucPriKeyCipherByHMK/*私钥密文*/,
    int *piSignatureLength/*签名长度 out*/,
    unsigned char *pucSignature/*签名 out*/);

/*RSA验签*/
int HSM_RSA_EY_Verify(
    void *hSessionHandle, int nSock,
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
    unsigned char *pucPubKey/*私钥密文*/);

/*RSA公钥运算*/
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
    unsigned char *pucDataOut/*输出数据 out*/);

/*RSA私钥运算*/
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
    unsigned char *pucDataOut/*输出数据 out*/);

/*分解RSA私钥分量*/
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
    unsigned char *pucCoef/*coef out*/);

#endif /*__HSM_API_RSA_H__*/

