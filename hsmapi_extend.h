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
#ifndef __HSM_API_EXTEND_H__
#define __HSM_API_EXTEND_H__

/*加密PIN*/
int HSM_EXT_BG_EncryptPIN(
    void *hSessionHandle,int nSock,
    char cSymmAlg/*密钥类型*/,
    int iPIKIdx/*密钥索引*/,
    char *pcPIKCipherByHMK/*密钥密文*/,
    char *pcPIN/*PIN明文*/,
    char *pcPAN/*PAN*/,
    char *pcPINCipher/*PIN密文 out */);

/*解密PIN*/
int HSM_EXT_BC_DecryptPIN(
    void *hSessionHandle,int nSock,
    char cSymmAlg/*密钥类型*/,
    int iPIKIdx/*密钥索引*/,
    char *pcPIKCipherByHMK/*密钥密文*/,
    char *pcPINCipher/*PIN密文*/,
    char *pcPAN/*PAN*/,
    char *pcPIN/*PIN明文 out */);

/*转加密PIN-双主账号*/
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
    char *pcPINCipherByPIKDst/*目的PIK加密PIN密文 out*/);

/*IBM3624算法计算pinoffset*/
int HSM_EXT_DE_CalculatePINOffsetWithIBM3642Alg(
    void *hSessionHandle,int nSock,
    int iPVKIdx/*PVK索引*/,
    char *pcPVKCipherByHMK/*PVK密文*/,
    char cFlag/*标识位*/,
    int iPINLength/*PIN明文长度*/,
    char *pcPIN/*PIN明文*/,
    int iCheckLength/*检查长度*/,
    char *pcAccountNo/*账号*/,
    char *pcDecConvertTable/*十进制转换表*/,
    char *pcPINVerifyData/*PIN校验数据*/,
    char cTerminationMsgSeparator/*终止信息分隔符*/,
    char *pcPINOffset/*PINOffset out*/);

/*计算PVV*/
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
    char *pcPVV/*PVV out*/);

/*数据掩盖恢复*/
int HSM_EXT_KE_Cover_RecoverData(
    void *hSessionHandle,int nSock,
    int iMode/*模式*/,
    int iStrInLength/*输入字符串长度*/,
    char *pcStrIn/*输入字符串*/,
    int *piStrOutLength/*输出字符串长度 out*/,
    char *pcStrOut/*输出字符串 out*/);

/*大数指数模运算*/
int HSM_EXT_ED_BigNumExponentModuleOperation(
    void *hSessionHandle,int nSock,
    int iBaseLength/*底数长度*/,
    unsigned char *pucBase/*底数*/,
    int iExpLength/*指数长度*/,
    unsigned char *pucExp/*指数*/,
    int iModLength/*模数长度*/,
    unsigned char *pucMod/*模数*/,
    int *piResultLength/*结果长度 out*/,
    unsigned char *pucResult/*结果 out*/);

/*产生大素数*/
int HSM_EXT_EF_GenerateBigPrimeNum(
    void *hSessionHandle,int nSock,
    int iPrimeNumLengthIn/*输入大素数长度*/,
    int *piPrimeNumLengthOut/*输出大素数长度 out*/,
    unsigned char *pucPrimeNum/*结果 out*/);

/*产生随机数*/
int HSM_EXT_TE_GenerateRandom(
    void *hSessionHandle,int nSock,
    int iRandomLength/*随机数长度*/,
    unsigned char *pucRandom/*随机数 out*/);

/*密机检查*/
int HSM_EXT_NC_CheckHSM(
    void *hSessionHandle,int nSock,
    char *pcHMKCV/*HMK校验值 out*/,
    char *pcVersion/*版本号 out*/);

/*密钥转加密增强型*/
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
    unsigned char *pucKeyCipherByKEK/*KEK加密的密钥密文 out*/);

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
    unsigned char *pucKeyCipherByKEK/*KEK加密的密钥密文 out*/);

/*HMK加密密钥扩展型*/
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
    unsigned char *pucKeyCipherByHMK/*HMK加密密钥密文 out*/);

/*分散卡密钥*/
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
    char *pcKCV/*密钥校验值 out*/);

/*分散密钥并加密导出*/
int HSM_EXT_EO_DiversifyAndExportKey(
    void *hSessionHandle, int nSock,
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
    char *pcKCV/*密钥校验值 out*/);

/*RSA公私钥转加密*/
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
    char *pcRSAPassword/*RSA密钥口令*/,
    int iPubKeyCodeFormat/*公钥编码格式*/,
    int iPubKeyLength/*公钥长度*/,
    unsigned char *pucPubKey/*公钥*/,
    int iPriKeyCipherLength/*私钥密文长度*/,
    unsigned char *pucPriKeyCipher/*私钥密文*/,
    int *piKeycCipherOutLength/*密文长度 out*/,
    unsigned char *pucKeyCipherOut/*密文 out*/);

/*SM2公私钥转加密*/
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
    unsigned char *pucDstKeyCipher/*密文 out*/);

/*根据私钥生成公钥*/
int HSM_EXT_EB_GenerateSM2PubKeyByPriKey(
    void *hSessionHandle,int nSock,
    unsigned char *pucPriKeyCipher/*私钥密文*/,
    int *piPubKeyLength/*公钥长度 out*/,
    unsigned char *pucPubKey/*公钥 out*/);

/*私钥解密对称密钥密文并打印*/
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
    char *pcSymmKCV/*对称密钥校验值 out*/);

/*导出RSA公钥*/
int HSM_EXT_EJ_ExportRSAPubKey(
    void *hSessionHandle,int nSock,
    int iKeyType/*密钥类型*/,
    int iPubKeyCode/*公钥编码*/,
    int iKeyIdx/*密钥索引*/,
    char *pcKeyPassword/*密钥口令*/,
    unsigned char *pucPubKey/*公钥 out*/);

/*导出SM2公钥*/
int HSM_EXT_SJ_ExportSM2PubKey(
    void *hSessionHandle,int nSock,
    int iKeyType/*密钥类型*/,
    int iPubKeyCode/*公钥编码*/,
    int iKeyIdx/*密钥索引*/,
    char *pcKeyPassword/*密钥口令*/,
    unsigned char *pucPubKey/*公钥 out*/);

/*分步HASH*/
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
    unsigned char *pucDataOut_Process/*输出(过程)数据 out*/);

/*产生明文SM2密钥对*/
int HSM_EXT_UG_GeneratePlainSM2KeyPair(
    void *hSessionHandle,int nSock,
    int iKeyLength/*密钥长度*/,
    unsigned char *pucPubKeyX/*公钥X明文 out*/,
    unsigned char *pucPubKeyY/*公钥Y明文 out*/,
    unsigned char *pucPriKey/*私钥 out*/);

/*明文SM2私钥转密文SM2私钥*/
int HSM_EXT_UM_ConverSM2PriKeyPlainToCipher(
    void *hSessionHandle,int nSock,
    int iKeyLength/*密钥长度*/,
    unsigned char *pucPriKeyPlain/*私钥明文*/,
    unsigned char *pucPriKeyCipher/*私钥密文*/);

/*产生明文RSA密钥对*/
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
    unsigned char *pucPubAndPriKey/*公私钥 out*/);

#endif /*__HSM_API_EXTEND_H__*/

