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
#ifndef __HSM_API_MAGNET_H__
#define __HSM_API_MAGNET_H__

/*产生密钥(对称)*/
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
    char *pcKCV/*密钥校验值 out*/);

/*导入密钥(对称)*/
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
    char *pcKeyCipherByHMK/*HMK加密密钥密文 out*/,
    char *pcKCVOut/*密钥校验值 out*/);

/*导出密钥(对称)*/
int HSM_MGT_A8_ExportKey(
    void *hSessionHandle,int nSock,
    char cSymmAlg/*算法类型*/,
    int iKEKIdx/*保护密钥索引*/,
    char *pcKEKCipherByHMK/*保护密钥密文*/,
    int iKeyIdx/*被导出密钥索引*/,
    char *pcKeyCipherByHMK/*被导出密钥密文*/,
    char cKEKScheme/*KEK密钥方案*/,
    char *pcKeyCipherByKEK/*KEK加密密钥密文 out*/,
    char *pcKCV/*密钥校验值 out*/);

/*合成KEK*/
int HSM_MGT_GG_CompoundKEK(
    void *hSessionHandle,int nSock,
    char cSymmAlg/*算法类型*/,
    char *pcKEKComponent1CipherByHMK/*KEK分量1密文*/,
    char *pcKEKComponent2CipherByHMK/*KEK分量2密文*/,
    char *pcKEKComponent3CipherByHMK/*KEK分量3密文*/,
    char *pcKEKCipherByHMK/*HMK加密KEK密文 out*/,
    char *pcKCV/*密钥校验值 out*/);

/*HMK加密密钥*/
int HSM_MGT_X2_HMKEncryptKey(
    void *hSessionHandle,int nSock,
    char cSymmAlg/*算法类型*/,
    int iKeyIdx/*待加密密钥索引*/,
    char *pcKeyCipherByHMK/*HMK加密密钥密文 out*/,
    char *pcKCV/*密钥校验值 out*/);

/*生成密钥校验值*/
int HSM_MGT_KA_GenerateKCV(
    void *hSessionHandle,int nSock,
    char cSymmAlg/*算法类型*/,
    int iKeyIdx/*待加密密钥索引*/,
    char cSeparator/*分隔符*/,
    char cKCVType/*KCV类型*/,
    char *pcKCV/*密钥校验值 out*/);

/*产生随机PIN*/
int HSM_MGT_JA_GenerateRandomPIN(
    void *hSessionHandle,int nSock,
    char *pcPAN/*PAN*/,
    int iPINLength/*PIN长度*/,
    char *pcPINCipherByHMK/*HMK加密PIN密文 out*/);

/*HMK加密PIN*/
int HSM_MGT_BA_EncryptPIN(
    void *hSessionHandle,int nSock,
    char *pcPIN/*PIN*/,
    char *pcPAN/*PAN*/,
    char *pcPINCipherByHMK/*HMK加密PIN密文 out*/);

/*PIN验证*/
int HSM_MGT_BE_VerifyPIN(
    void *hSessionHandle,int nSock,
    char cSymmAlg/*算法类型*/,
    int iPIKIdx/*PIK索引*/,
    char *pcPIKCipherByHMK/*PIK密文*/,
    char *pcPINBlockByPIK/*PIK加密PIN密文*/,
    int iPINFormat/*PIN格式*/,
    char *pcPAN/*PAN*/,
    char *pcPINCipherByHMK/*HMK加密PIN密文*/);

/*PIN块从PIK到HMK*/
int HSM_MGT_JC_ConvertPINBlockByPIKToHMK(
    void *hSessionHandle,int nSock,
    char cSymmAlg/*算法类型*/,
    int iPIKIdx/*PIK索引*/,
    char *pcPIKCipherByHMK/*PIK密文*/,
    char *pcPINBlockByPIK/*PIK加密PIN密文*/,
    int iPINFormat/*PIN格式*/,
    char *pcPAN/*PAN*/,
    char *pcPINCipherByHMK/*HMK加密PIN密文 out*/);

/*PIN块从HMK到PIK*/
int HSM_MGT_JG_ConvertPINCipherByHMKToPIK(
    void *hSessionHandle,int nSock,
    char cSymmAlg/*算法类型*/,
    int iPIKIdx/*PIK索引*/,
    char *pcPIKCipherByHMK/*PIK密文*/,
    int iPINFormat/*PIN格式*/,
    char *pcPAN/*PAN*/,
    char *pcPINCipherByHMK/*HMK加密PIN密文*/,
    char *pcPINBlockByPIK/*PIK加密PIN密文 out*/);

/*PIN块从PIK1到PIK2*/
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
    char *pcPINBlockByPIK2/*PIK2加密PIN密文 out*/);

/*产生MAC*/
int HSM_MGT_MS_GenerateMAC(
    void *hSessionHandle,int nSock,
    char cDataBlockFlag/*数据块标识*/,
    char cMACAlog/*MAC算法标识*/,
    char cSymmAlg/*算法类型*/,
    int iMAKIdx/*MAK索引*/,
    char *pcMAKCipherByHMK/*MAK密文*/,
    char *pcIV/*IV*/,
    int iDataLength/*MAC数据长度*/,
    unsigned char *pucData/*MAC数据*/,
    char *pcMAC/*MAC out*/);

/*验证MAC*/
int HSM_MGT_MC_VerifyMAC(
    void *hSessionHandle,int nSock,
    char cMACAlog/*MAC算法标识*/,
    char cSymmAlg/*算法类型*/,
    int iMAKIdx/*MAK索引*/,
    char *pcMAKCipherByHMK/*MAK密文*/,
    char *pcMAC/*MAC*/,
    char *pcIV/*IV*/,
    int iDataLength/*MAC数据长度*/,
    unsigned char *pucData/*MAC数据*/);

/*产生CVV*/
int HSM_MGT_CW_GenerateCVV(
    void *hSessionHandle,int nSock,
    char cSymmAlg/*算法类型*/,
    int iCVK_A_BIdx/*CVK_A/B索引*/,
    char *pcCVK_A_BCipherByHMK/*CVK_A/B密文*/,
    char *pcAccountNo/*主账号*/,
    char cSeparator/*分隔符*/,
    char *pcCardValidityDate/*卡有效期*/,
    char *pcCardServiceCode/*卡服务代码*/,
    char *pcCVV/*CVV out*/);

/*验证CVV*/
int HSM_MGT_CY_VerifyCVV(
    void *hSessionHandle,int nSock,
    char cSymmAlg/*算法类型*/,
    int iCVK_A_BIdx/*CVK_A/B索引*/,
    char *pcCVK_A_BCipherByHMK/*CVK_A/B密文*/,
    char *pcCVV/*CVV*/,
    char *pcAccountNo/*主账号*/,
    char cSeparator/*分隔符*/,
    char *pcCardValidityDate/*卡有效期*/,
    char *pcCardServiceCode/*卡服务代码*/);

/*定义打印格式*/
int HSM_MGT_PA_DefinePrintFormat(
    void *hSessionHandle,int nSock,
    char *pcFormatData/*打印格式数据*/);

#endif /*__HSM_API_MAGNET_H__*/

