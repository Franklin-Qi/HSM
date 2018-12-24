/*----------------------------------------------------------------------|
|    hsmapi_ic.h                                                        |
|    Version :     1.0                                                  |
|    Author:       Luo Cangjian                                         |
|    Description:  SJJ1310密码机接口金融IC卡应用主机命令函数            |
|                                                                       |
|    Copyright :   Beijing JN TASS Technology Co., Ltd.                 |
|    data:         2015-06-03. Create                                   |
|-----------------------------------------------------------------------|
|    Modify History:                                                    |
|----------------------------------------------------------------------*/
#ifndef __HSM_API_IC_H__
#define __HSM_API_IC_H__

/*分散子密钥*/
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
    char *pcKCV/*密钥校验值 out*/);

/*ARQC/ARPC产生或验证*/
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
    char *pcARPC/*密钥校验值 out*/);

/*脚本加解密*/
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
    unsigned char *pucDataOut/*输出数据 out*/);

/*计算脚本MAC*/
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
    char *pcMAC/*MAC out*/);

/*数据转加密*/
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
    unsigned char *pucDataOut/*输出数据 out*/);

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
    unsigned char *pucDataOut/*输出数据 out*/);

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
    char *pcMAC/*MAC out*/);

#endif /*__HSM_API_IC_H__*/

