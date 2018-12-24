/*----------------------------------------------------------------------|
|    hsmapi_asym.h                                                      |
|    Version :     1.0                                                  |
|    Author:       Luo Cangjian                                         |
|    Description:  SJJ1310密码机接口非对称算法主机命令函数              |
|                                                                       |
|    Copyright :   Beijing JN TASS Technology Co., Ltd.                 |
|    data:         2015-06-04. Create                                   |
|-----------------------------------------------------------------------|
|    Modify History:                                                    |
|----------------------------------------------------------------------*/
#ifndef __HSMAPI_ASYM_H__
#define __HSMAPI_ASYM_H__

/*** ------------------------ Asymmetric Function API ----------------------- ***/

/*
 * HSM_SM2_GenerateNewKeyPair, 产生一对新的SM2密钥对
 * iKeyIndex                IN          要产生的SM2密钥索引，<=0或=9999时标识不存储
 * pcKeyLabel               IN          SM2密钥标签，仅当iKeyIndex>0且!=9999时有效;
 * pucDerPublicKey          OUT         新生成的SM2公钥，DER编码
 * piDerPublicKeyLen        OUT         新生成的SM2公钥长度
 * pucPrivateKey_Lmk        OUT         LMK下加密的SM2私钥密文
 * piPrivateKeyLen_Lmk      OUT         LMK下加密的SM2私钥密文长度
 */
 int HSM_SM2_GenerateNewKeyPair(
    void *hSessionHandle, int nSock,  int iKeyIndex, char *pcKeyLabel,
    unsigned char *pucDerPublicKey/*out*/, int *piDerPublicKeyLen/*out*/,
    unsigned char *pucPrivateKey_Lmk/*out*/, int *piPrivateKeyLen_Lmk/*out*/ );

/*
 * HSM_SM2_LoadKeyPair, 装载一对SM2密钥对到密码机内存储
 * iKeyIndex                IN        要导入的SM2密钥索引
 * pcKeyLabel               IN        要导入的SM2密钥标签
 * pucDerPublicKey          IN        要导入的SM2公钥，DER编码
 * piDerPublicKeyLen        IN        要导入的SM2公钥长度
 * pucPrivateKey_Lmk        IN        LMK下加密的SM2私钥密文
 * piPrivateKeyLen_Lmk      IN        LMK下加密的SM2私钥密文长度
 */
int HSM_SM2_LoadKeyPair(
    int iKeyIndex, char *pcKeyLabel,
    unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucPrivateKey_Lmk, int iPrivateKeyLen_Lmk );

/*
 * HSM_SM2_GetPublicKey, 获取一对SM2密钥的公钥
 * iKeyIndex                IN          要导出公钥的SM2密钥索引
 * pucDerPublicKey          OUT         导出的SM2公钥，DER编码
 * piDerPublicKeyLen        OUT         导出的SM2公钥长度
 */
int HSM_SM2_GetPublicKey( int iKeyIndex,
    unsigned char *pucDerPublicKey/*out*/, int *piDerPublicKeyLen/*out*/ );

/*
 * HSM_SM2_EncryptData, SM2公钥加密数据
 * iKeyIndex                IN          SM2密钥索引，<=0或=9999时下述2个参数有效
 * pucDerPublicKey          IN          DER编码的SM2公钥，当iKeyIndex=9999时有效
 * iDerPublicKeyLen         IN          DER编码的SM2公钥长度，当iKeyIndex=9999时有效
 * pucInput                 IN          要加密的输入数据，最多支持136字节的加密运算
 * iInputLength             IN          要加密的输入数据长度，最大136
 * pucOutput                OUT         加密后的输出数据
 * piOutputLength           OUT         加密后的输出数据长度
 */
int HSM_SM2_EncryptData(
	void *hSessionHandle,int nSock,
    int iKeyIndex, unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucInput, int iInputLength,
    unsigned char *pucOutput/*out*/, int *piOutputLength/*out*/ );

/*
 * HSM_SM2_DecryptData, SM2私钥解密数据
 * iKeyIndex                IN          SM2密钥索引，<=0或=9999时下述2个参数有效
 * pucPrivateKey_Lmk        IN          LMK加密的SM2私钥，当iSm2KeyIndex=9999时有效
 * iPrivateKeyLen_Lmk       IN          LMK加密的SM2私钥长度，当iSm2KeyIndex=9999时有效
 * pucInput                 IN          要解密的输入数据
 * iInputLength             IN          要解密的输入数据长度
 * pucOutput                OUT         解密后的输出数据
 * piOutputLength           OUT         解密后的输出数据长度
 */
int HSM_SM2_DecryptData(void *hSessionHandle,int nSock,
    int iKeyIndex, unsigned char *pucPrivateKey_Lmk, int iPrivateKeyLen_Lmk,
    unsigned char *pucInput, int iInputLength,
    unsigned char *pucOutput/*out*/, int *piOutputLength/*out*/ );

/*
 * HSM_SM2_GenerateSignature, SM2私钥对数据进行数字签名
 * iKeyIndex                IN          SM2密钥索引，<=0或=9999时下述4个参数有效
 * pucDerPublicKey          IN          DER编码的SM2公钥，当iKeyIndex=9999时有效
 * iDerPublicKeyLen         IN          DER编码的SM2公钥长度，当iKeyIndex=9999时有效
 * pucPrivateKey_Lmk        IN          LMK加密的SM2私钥，当iSm2KeyIndex=9999时有效
 * iPrivateKeyLen_Lmk       IN          LMK加密的SM2私钥长度，当iSm2KeyIndex=9999时有效
 * pucUserId                IN          用户标识
 * iUserIdLength            IN          用户标识长度
 * pucInput                 IN          待签名的输入数据
 * iInputLength             IN          待签名的输入数据长度
 * pucSignature             OUT         输出的数据签名
 * piSignatureLength        OUT         输出的数据签名长度
 */
int HSM_SM2_GenerateSignature(
	void *hSessionHandle,int nSock,
    int iKeyIndex,
    unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucPrivateKey_Lmk, int iPrivateKeyLen_Lmk,
    unsigned char *pucUserId, int iUserIdLength,
    unsigned char *pucInput, int iInputLength,
    unsigned char *pucSignature/*out*/, int *piSignatureLength/*out*/ );
	
/*
 * HSM_SM2_GenSignatureSummary, SM2私钥对数据摘要值进行数字签名
  * hSessionHandle      IN        会话句柄
 * iKeyIndex            IN        SM2公钥索引，<=0或=9999时下述4个参数有效
 * pucPrivateKey_Lmk    IN        LMK加密的SM2私钥，当iSm2KeyIndex=9999时有效
 * iPrivateKeyLen_Lmk   IN        LMK加密的SM2私钥长度，当iSm2KeyIndex=9999时有效
 * pucSummary           IN        数据块摘要
 * iSummaryLen          IN        数据块摘要长度
 * iSignatureFormat     IN        签名编码格式
 * pucSignature         OUT       输出的数据签名
 * piSignatureLength    OUT       输出的数据签名长度
 */
int HSM_SM2_GenSignatureSummary(
    void *hSessionHandle,int nSock,
    int iKeyIndex,
    unsigned char *pucPrivateKey_Lmk, int iPrivateKeyLen_Lmk,
    unsigned char *pucSummary, int iSummaryLen,
	int iSignatureFormat,
    unsigned char *pucSignature/*out*/, int *piSignatureLength/*out*/ );

/*
 * HSM_SM2_VerifySignature, SM2公钥验证数据的签名
 * iKeyIndex                IN        SM2密钥索引，<=0或=9999时下述2个参数有效
 * pucDerPublicKey          IN        DER编码的SM2公钥，当iKeyIndex=9999时有效
 * iDerPublicKeyLen         IN        DER编码的SM2公钥长度，当iKeyIndex=9999时有效
 * pucUserId                IN        用户标识
 * iUserIdLength            IN        用户标识长度
 * pucInput                 IN        待验证签名的输入数据
 * iInputLength             IN        待验证签名的输入数据长度
 * pucSignature             IN        待验证的数据签名
 * iSignatureLength         IN        待验证的数据签名长度
 */
int HSM_SM2_VerifySignature(
	void *hSessionHandle,int nSock,
    int iKeyIndex, unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucUserId, int iUserIdLength,
    unsigned char *pucInput, int iInputLength,
    unsigned char *pucSignature, int iSignatureLength );
	
/*
 * HSM_SM2_VerifySummarySignature, SM2私钥对数据摘要值签名验签
 * hSessionHandle      IN        会话句柄
 * pucSignature        IN        待验证的签名
 * iSignatureLength    IN        待验证签名的长度
 * iKeyIndex           IN        SM2公钥索引，<=0或=9999时下述4个参数有效
 * pucPublicKey        IN        SM2公钥，当iSm2KeyIndex=9999时有效
 * iPublicKeyLen       IN        SM2公钥长度，当iSm2KeyIndex=9999时有效
 * pucSummary          IN        数据块摘要值
 * iSummaryLen         IN        数据块摘要值长度
 * iSignatureFormat    IN        签名编码格式
 */
int HSM_SM2_VerifySummarySignature(
	void *hSessionHandle, int nSock,
	unsigned char *pucSignature, int iSignatureLength,
	int iKeyIndex,  unsigned char *pucPublicKey, 
	int iPublicKeyLen, unsigned char *pucSummary, 
	int iSummaryLen, int iSignatureFormat);
	

/*
 * HSM_SM2_ExportByTK, 传输密钥（KEK/MDK，可分散可不分散）保护导出一对SM2密钥对
 * iMode                    IN        0–ECB, 1–CBC
 * pcTkType                 IN        保护密钥类型："000"–KEK;  "109"–MDK;
 * iTkIndex                 IN        保护密钥索引。<=0, 使用pcTk_Lmk参数；否则使用索引指定的密钥
 * pcTk_Lmk                 IN        LMK加密的保护密钥密文。当iTkIndex<=0时有效
 * iTkDeriveNumber          IN        保护密钥的分散级数
 * pcTkDeriveData           IN        保护密钥的分散因子，每级32H
 * iSm2KeyIndex             IN        要被导出的SM2密钥索引，<=0或=9999时下述4个参数有效
 * pucDerPublicKey          IN        DER编码的SM2公钥，当iSm2KeyIndex=9999时有效
 * iDerPublicKeyLen         IN        DER编码的SM2公钥长度，当iSm2KeyIndex=9999时有效
 * pucPrivateKey_Lmk        IN        LMK加密的SM2私钥，当iSm2KeyIndex=9999时有效
 * iPrivateKeyLen_Lmk       IN        LMK加密的SM2私钥长度，当iSm2KeyIndex=9999时有效
 * pucPrivateKey_Tk         OUT       保护密钥加密的SM2私钥密文
 * piPrivateKeyLen_Tk       OUT       保护密钥加密的SM2私钥密文长度
 */
int HSM_SM2_ExportByTK(
    void *hSessionHandle, int nSock, int iMode, char *pcTkType,
    int iTkIndex, char *pcTk_Lmk,
    int iTkDeriveNumber, char *pcTkDeriveData,
    int iSm2KeyIndex, 
    unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucPrivateKey_Lmk, int iPrivateKeyLen_Lmk,
    unsigned char *pucPrivateKey_Tk/*out*/, int *piPrivateKeyLen_Tk/*out*/ );

/*
 * HSM_SM2_ImportByTK, 传输密钥（KEK/MDK，可分散可不分散）保护导入一对SM2密钥对
 * iMode                   IN        0–ECB, 1–CBC
 * pcTkType                IN        保护密钥类型："000"–KEK;  "109"–MDK;
 * iTkIndex                IN        保护密钥索引。<=0, 使用pcTk_Lmk参数；否则使用索引指定的密钥
 * pcTk_Lmk                IN        LMK加密的保护密钥密文。当iTkIndex<=0时有效
 * iTkDeriveNumber         IN        保护密钥的分散级数
 * pcTkDeriveData          IN        保护密钥的分散因子，每级32H
 * iSm2KeyIndex            IN        要被导入的SM2密钥索引，<=0或=9999时标识不存储
 * pucDerPublicKey         IN        要被导入的DER编码的SM2公钥
 * iDerPublicKeyLen        IN        要被导入的DER编码的SM2公钥长度
 * pucPrivateKey_Tk        IN        保护密钥加密的SM2私钥
 * iPrivateKeyLen_Tk       IN        保护密钥加密的SM2私钥长度
 * pucPrivateKey_Lmk       OUT       LMK加密的SM2私钥密文
 * piPrivateKeyLen_Lmk     OUT       LMK加密的SM2私钥密文长度
 */
int HSM_SM2_ImportByTK(
    int iMode, char *pcTkType,
    int iTkIndex, char *pcTk_Lmk,
    int iTkDeriveNumber, char *pcTkDeriveData,
    int iSm2KeyIndex, char *pcSm2KeyLabel,
    unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucPrivateKey_Tk, int iPrivateKeyLen_Tk,
    unsigned char *pucPrivateKey_Lmk/*out*/, int *piPrivateKeyLen_Lmk/*out*/ );

/*
 * HSM_SM2_GeneratePublicKeyMac, 在授权控制下为SM2公钥产生公钥MAC
 * pucDerPublicKey         IN        要计算MAC的SM2公钥，DER编码
 * iDerPublicKeyLen        IN        要计算MAC的SM2公钥长度
 * pucAuthData             IN        公钥鉴别数据，不能带';'字符
 * iAuthDataLen            IN        公钥鉴别数据长度
 * pucMac                  OUT       SM2公钥的MAC值
 * piMacLen                OUT       SM2公钥的MAC值长度
 */
int HSM_SM2_GeneratePublicKeyMac(
    unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucAuthData, int iAuthDataLen,
    unsigned char *pucMac/*out*/, int *piMacLen/*out*/ );

/*
 * HSM_SM2_ExportSymmetricKey, 由SM2公钥加密保护导出一条对称密钥
 * pcKeyType               IN        被导出密钥的密钥类型："000"–KEK; 00A–DEK; "109"–MDK;
 * iKeyIndex               IN        被导出密钥的索引。<=0, 使用pcKey_Lmk参数；否则使用索引指定的密钥
 * pcKey_Lmk               IN        LMK加密的被导出密钥的密文。当iKeyIndex<=0时有效
 * iKeyDeriveNumber        IN        被导出密钥的分散级数
 * pcKeyDeriveData         IN        被导出密钥的分散因子，每级32H
 * iSm2KeyIndex            IN        作为保护密钥的SM2密钥索引，<=0或=9999时标识使用pucDerPublicKey参数
 * pucDerPublicKey         IN        作为保护密钥的DER编码的SM2公钥，仅当iSm2KeyIndex<=0或=9999时有效
 * iDerPublicKeyLen        IN        作为保护密钥的DER编码的SM2公钥长度，仅当iSm2KeyIndex<=0或=9999时有效
 * pucAuthData             IN        作为保护密钥的公钥鉴别数据，不能带';'字符
 * iAuthDataLen            IN        作为保护密钥的公钥鉴别数据长度
 * pucMac                  IN        作为保护密钥的SM2公钥的MAC值
 * pucCipherKey            OUT       SM2密钥加密的被导出密钥密文
 * piCipherKeyLen          OUT       SM2密钥加密的被导出密钥密文长度
 * pcKeyCv                 OUT       被导出密钥的校验值
 */
int HSM_SM2_ExportSymmetricKey(
    char *pcKeyType, int iKeyIndex, char *pcKey_Lmk,
    int iKeyDeriveNumber, char *pcKeyDeriveData,
    int iSm2KeyIndex,
    unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucAuthData, int iAuthDataLen,
    unsigned char *pucMac,
    unsigned char *pucCipherKey/*out*/, int *piCipherKeyLen/*out*/,
    char *pcKeyCv/*out*/ );

/*
 * HSM_SM2_ImportSymmetricKey, 由SM2公钥加密保护导入一条对称密钥
 * pcKeyType               IN        被导入密钥的密钥类型："000"–KEK; 00A–DEK; "109"–MDK;
 * cKeyScheme              IN        被导入密钥的算法标识：Z/X/Y/U/T/P/L/R
 * iKeyIndex               IN        被导入密钥的索引。<=0, 标识密钥不存储到内部
 * pcKeyLabel              IN        被导入密钥的标签。当iKeyIndex>0时有效
 * iSm2KeyIndex            IN        作为保护密钥的SM2密钥索引，<=0或=9999时标识使用pucPrivateKey_Lmk参数
 * pucPrivateKey_Lmk       IN        作为保护密钥的SM2私钥密文，仅当iSm2KeyIndex<=0或=9999时有效
 * iPrivateKeyLen_Lmk      IN        作为保护密钥的SM2私钥密文长度，仅当iSm2KeyIndex<=0或=9999时有效
 * pucCipherKey            IN        SM2公钥加密的被导入密钥密文
 * iCipherKeyLen           IN        SM2公钥加密的被导入密钥密文长度
 * pcKey_Lmk               OUT        LMK下加密的被导入密钥密文
 * pcKeyCv                 OUT        被导入密钥的校验值
 */
int HSM_SM2_ImportSymmetricKey(
    char *pcKeyType, char cKeyScheme,
    int iKeyIndex, char *pcKeyLabel,
    int iSm2KeyIndex,
    unsigned char *pucPrivateKey_Lmk, int iPrivateKeyLen_Lmk,
    unsigned char *pucCipherKey, int iCipherKeyLen, 
    char *pcKey_Lmk/*out*/, char *pcKeyCv/*out*/ );

/*
 * HSM_RSA_GenerateNewKeyPair, 产生一对新的RSA密钥对
 * iKeyIndex               IN        要产生的RSA密钥索引，<=0或=9999时标识不存储
 * pcKeyLabel              IN        RSA密钥标签，仅当iKeyIndex>0且!=9999时有效;
 * iModulusBits            IN        RSA密钥模长，位数
 * iPubE                   IN        RSA公钥指数E，3或65537
 * pucDerPublicKey         OUT       新生成的RSA公钥，DER编码
 * piDerPublicKeyLen       OUT       新生成的RSA公钥长度
 * pucPrivateKey_Lmk       OUT       LMK下加密的RSA私钥密文
 * piPrivateKeyLen_Lmk     OUT       LMK下加密的RSA私钥密文长度
 */
int HSM_RSA_GenerateNewKeyPair(void *hSessionHandle,int nSock,
    int iKeyIndex, char *pcKeyLabel,
    int iModulusBits, int iPubE,
    unsigned char *pucDerPublicKey/*out*/, int *piDerPublicKeyLen/*out*/,
    unsigned char *pucPrivateKey_Lmk/*out*/, int *piPrivateKeyLen_Lmk/*out*/ );

/*
 * HSM_RSA_GetPublicKey, 获取一对RSA密钥的公钥
 * iKeyIndex               IN        要导出公钥的RSA密钥索引
 * pucDerPublicKey         OUT       导出的RSA公钥，DER编码
 * piDerPublicKeyLen       OUT       导出的RSA公钥长度
 */
int HSM_RSA_GetPublicKey( int iKeyIndex,
    unsigned char *pucDerPublicKey/*out*/, int *piDerPublicKeyLen/*out*/ );

/*
 * HSM_RSA_EncryptData, RSA公钥加密数据
 * iPaddingMode            IN        填充模式：00–不填充（数据块长度必须和模长等长）；01–PKCS#1 v1.5
 * iKeyIndex               IN        RSA密钥索引，<=0或=9999时下述2个参数有效
 * pucDerPublicKey         IN        DER编码的RSA公钥，当iKeyIndex=9999时有效
 * iDerPublicKeyLen        IN        DER编码的RSA公钥长度，当iKeyIndex=9999时有效
 * pucInput                IN        要加密的输入数据，最多支持136字节的加密运算
 * iInputLength            IN        要加密的输入数据长度，最大136
 * pucOutput               OUT       加密后的输出数据
 * piOutputLength          OUT       加密后的输出数据长度
 */
int HSM_RSA_EncryptData(
void *hSessionHandle,int nSock,	int iPaddingMode,
    int iKeyIndex, unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucInput, int iInputLength,
    unsigned char *pucOutput/*out*/, int *piOutputLength/*out*/ );

/*
 * HSM_RSA_DecryptData, RSA私钥解密数据
 * iPaddingMode            IN        填充模式：00–不填充（解密后的数据直接输出）；01–PKCS#1 v1.5
 * iKeyIndex               IN        RSA密钥索引，<=0或=9999时下述2个参数有效
 * pucPrivateKey_Lmk       IN        LMK加密的RSA私钥，当iKeyIndex=9999时有效
 * iPrivateKeyLen_Lmk      IN        LMK加密的RSA私钥长度，当iKeyIndex=9999时有效
 * pucInput                IN        要解密的输入数据
 * iInputLength            IN        要解密的输入数据长度
 * pucOutput               OUT       解密后的输出数据
 * piOutputLength          OUT       解密后的输出数据长度
 */
int HSM_RSA_DecryptData(void *hSessionHandle, int nSock, int iPaddingMode,
    int iKeyIndex, unsigned char *pucPrivateKey_Lmk, int iPrivateKeyLen_Lmk,
    unsigned char *pucInput, int iInputLength,
    unsigned char *pucOutput/*out*/, int *piOutputLength/*out*/ );

/*
 * HSM_RSA_GenerateSignature, RSA私钥对数据进行数字签名
 * iHashMode               IN        HASH算法标识
 * iPaddingMode            IN        填充模式：00–不填充（解密后的数据直接输出）；01–PKCS#1 v1.5
 * iKeyIndex               IN        RSA密钥索引，<=0或=9999时下述4个参数有效
 * pucPrivateKey_Lmk       IN        LMK加密的RSA私钥，当iSm2KeyIndex=9999时有效
 * iPrivateKeyLen_Lmk      IN        LMK加密的RSA私钥长度，当iSm2KeyIndex=9999时有效
 * pucInput                IN        待签名的输入数据
 * iInputLength            IN        待签名的输入数据长度
 * pucSignature            OUT       输出的数据签名
 * piSignatureLength       OUT       输出的数据签名长度
 */
int HSM_RSA_GenerateSignature(
    void *hSessionHandle,int nSock,
    int iHashMode, int iPaddingMode,
    int iKeyIndex, unsigned char *pucPrivateKey_Lmk, int iPrivateKeyLen_Lmk,
    unsigned char *pucInput, int iInputLength,
    unsigned char *pucSignature/*out*/, int *piSignatureLength/*out*/ );

/*
 * HSM_RSA_VerifySignature, RSA公钥验证数据的签名
 * hSession                IN        NULL or OpenSession的输出参数
 * iHashMode               IN        HASH算法标识
 * iPaddingMode            IN        填充模式：00–不填充（解密后的数据直接输出）；01–PKCS#1 v1.5
 * iKeyIndex               IN        RSA密钥索引，<=0或=9999时下述2个参数有效
 * pucDerPublicKey         IN        DER编码的RSA公钥，当iKeyIndex=9999时有效
 * iDerPublicKeyLen        IN        DER编码的RSA公钥长度，当iKeyIndex=9999时有效
 * pucInput                IN        待验证签名的输入数据
 * iInputLength            IN        待验证签名的输入数据长度
 * pucSignature            IN        待验证的数据签名
 * iSignatureLength        IN        待验证的数据签名长度
 */
int HSM_RSA_VerifySignature(
    void *hSessionHandle, int nSock,int iHashMode, int iPaddingMode,
    int iKeyIndex, unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucInput, int iInputLength,
    unsigned char *pucSignature, int iSignatureLength );

/*
 * HSM_RSA_GeneratePublicKeyMac, 在授权控制下为RSA公钥产生公钥MAC
 * pucDerPublicKey         IN        要计算MAC的RSA公钥，DER编码
 * iDerPublicKeyLen        IN        要计算MAC的RSA公钥长度
 * pucAuthData             IN        公钥鉴别数据，不能带';'字符
 * iAuthDataLen            IN        公钥鉴别数据长度
 * pucMac                  OUT       RSA公钥的MAC值
 * piMacLen                OUT       RSA公钥的MAC值长度
 */
int HSM_RSA_GeneratePublicKeyMac(
    void *hSessionHandle,int nSock,
    unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucAuthData, int iAuthDataLen,
    unsigned char *pucMac/*out*/, int *piMacLen/*out*/,
    unsigned char *pucPublicKey,int *piDerPublicKeyLen );

/*
 * HSM_RSA_ExportSymmetricKey, 由RSA公钥加密保护导出一条对称密钥
 * pcKeyType               IN        被导出密钥的密钥类型
 * iKeyIndex               IN        被导出密钥的索引。<=0, 使用pcKey_Lmk参数；否则使用索引指定的密钥
 * pcKey_Lmk               IN        LMK加密的被导出密钥的密文。当iKeyIndex<=0时有效
 * iKeyDeriveNumber        IN        被导出密钥的分散级数
 * pcKeyDeriveData         IN        被导出密钥的分散因子，每级32H
 * iRsaKeyIndex            IN        作为保护密钥的RSA密钥索引，<=0或=9999时标识使用pucDerPublicKey参数
 * pucDerPublicKey         IN        作为保护密钥的DER编码的RSA公钥，仅当iRsaKeyIndex<=0或=9999时有效
 * iDerPublicKeyLen        IN        作为保护密钥的DER编码的RSA公钥长度，仅当iRsaKeyIndex<=0或=9999时有效
 * pucAuthData             IN        作为保护密钥的公钥鉴别数据，不能带';'字符
 * iAuthDataLen            IN        作为保护密钥的公钥鉴别数据长度
 * pucMac                  IN        作为保护密钥的RSA公钥的MAC值
 * pucCipherKey            OUT       RSA密钥加密的被导出密钥密文
 * piCipherKeyLen          OUT       RSA密钥加密的被导出密钥密文长度
 * pcKeyCv                 OUT       被导出密钥的校验值
 */
int HSM_RSA_ExportSymmetricKey(
    void *hSessionHandle,int nSock,
    char *pcKeyType, int iKeyIndex, char *pcKey_Lmk,
    int iKeyDeriveNumber, char *pcKeyDeriveData,
    int iRsaKeyIndex,
    unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucAuthData, int iAuthDataLen,
    unsigned char *pucMac, 
    unsigned char *pucCipherKey/*out*/, int *piCipherKeyLen/*out*/,
    char *pcKeyCv/*out*/ );

/*
 * HSM_RSA_ExportSymmetricKey2, 由RSA公钥加密保护导出一条对称密钥
 * hSessionHandle              IN        会话句柄
 * pcKeyType                   IN        被导出密钥的密钥类型
 * iKeyFlag                    IN        对称密钥标记：0：单倍长度，8字节，1：双倍长度,16字节，2：三倍长度，24字节
 * pcKey_Lmk                   IN        LMK加密的被导出密钥的密文。当iKeyIndex<=0时有效
 * iKeyLen_Lmk                 IN        LMK加密的密钥的长度
 * pcKeyCv                     IN        对称密钥的校验值
 * pucMac                      IN        作为保护密钥的RSA公钥的MAC值
 * iMacLen                     IN        作为保护密钥的RSA公钥的MAC值长度            IN        被导出密钥的分散因子，每级32H
 * pucDerPublicKey             IN        作为保护密钥的DER编码的RSA公钥，仅当iRsaKeyIndex<=0或=9999时有效
 * iDerPublicKeyLen            IN        作为保护密钥的DER编码的RSA公钥长度，仅当iRsaKeyIndex<=0或=9999时有效
 * pucAuthData                 IN        作为保护密钥的公钥鉴别数据，不能带';'字符
 * iAuthDataLen                IN        作为保护密钥的公钥鉴别数据长度
 * pucInitIV                   OUT       对称密钥的初始化值IV
 * pucCipherKey                OUT       RSA密钥加密的被导出密钥密文
 * piCipherKeyLen              OUT       RSA密钥加密的被导出密钥密文长度
 * pcKeyCv                     OUT       被导出密钥的校验值
 */
int HSM_RSA_ExportSymmetricKey2(
    void *hSessionHandle,int nSock,
    int pcKeyType, int iKeyFlag, 
    char *pcKey_Lmk, int iKeyLen_Lmk,
    char *pcKeyCv,  int iKeyCvLen,
    unsigned char *pucMac,int iMacLen,
    unsigned char *pucDerPublicKey, int iDerPublicKeyLen,
    unsigned char *pucAuthData, int iAuthDataLen,
    unsigned char *pucInitIV /**out*/,
    unsigned char *pucCipherKey/*out*/,
    int *piCipherKeyLen/*out*/);

/*
 * HSM_RSA_ImportSymmetricKey, 由RSA公钥加密保护导入一条对称密钥
 * pcKeyType               IN        被导入密钥的密钥类型
 * cKeyScheme              IN        被导入密钥的算法标识：Z/X/Y/U/T/P/L/R
 * iKeyIndex               IN        被导入密钥的索引。<=0, 标识密钥不存储到内部
 * pcKeyLabel              IN        被导入密钥的标签。当iKeyIndex>0时有效
 * iRsaKeyIndex            IN        作为保护密钥的RSA密钥索引，<=0或=9999时标识使用pucPrivateKey_Lmk参数
 * pucPrivateKey_Lmk       IN        作为保护密钥的RSA私钥密文，仅当iRsaKeyIndex<=0或=9999时有效
 * iPrivateKeyLen_Lmk      IN        作为保护密钥的RSA私钥密文长度，仅当iRsaKeyIndex<=0或=9999时有效
 * pucCipherKey            IN        RSA公钥加密的被导入密钥密文
 * iCipherKeyLen           IN        RSA公钥加密的被导入密钥密文长度
 * pcKey_Lmk               OUT       LMK下加密的被导入密钥密文
 * pcKeyCv                 OUT       被导入密钥的校验值
 */
int HSM_RSA_ImportSymmetricKey(
    char *pcKeyType, char cKeyScheme,
    int iKeyIndex, char *pcKeyLabel,
    int iRsaKeyIndex,
    unsigned char *pucPrivateKey_Lmk, int iPrivateKeyLen_Lmk,
    unsigned char *pucCipherKey, int iCipherKeyLen, 
    char *pcKey_Lmk/*out*/, char *pcKeyCv/*out*/ );


/*
 * HSM_RSA_ExportRSAKey     保护密钥（对称）加密导入一对RSA密钥
 * iMode                    加密算法模式  2 H  00 – ECB 01 – CBC
 * pcTkType                 用于加密保护RSA密钥的保护密钥类型 000 – KEK;   109 – MDK;
 * iTkIndex                 用于加密保护RSA的保护密钥索引
 * pcTk_Lmk                 用于加密保护RSA的保护密钥密文
 * iTkDeriveNumber          保护密钥分散级数
 * pcTkDeriveData           保护密钥分散因子
 * iRsaKeyIndex             被导出密钥索引号
 * pucPrivateKey            被导出密钥私钥数据
 * iPrivateKeyLen           被导出密钥私钥长度
 * pcExpandFlg              扩展标识
 * pcPADFlg                 标识被导出的各私钥分量的填充规则
 * iOutPublicKeyFlg         公钥输出格式,0 - 明文DER格式输出， ASN.1 格式DER 编码（模，指数序列） 1 - m及e采用分量密文形式输出
 * pcIV                     初始化向量
 * pucDerPrivateKey
 * piDerPrivateKeyLen
 */

int HSM_RSA_ExportRSAKey(
    void *hSessionHandle,int nSock,
    int iMode,  char *pcTkType,
    int iTkIndex, char *pcTk_Lmk,
    int iTkDeriveNumber, char *pcTkDeriveData,
    int iRsaKeyIndex,
    unsigned char *pucPrivateKey, int iPrivateKeyLen,
    char *pcExpandFlg, char *pcPADFlg,
    int iOutPublicKeyFlg, char *pcIV,
    unsigned char *pucDerPublicKey/*OUT*/, int *piDerPublicKeyLen/*OUT*/,
    unsigned char *pucPublicKey_m/*OUT*/, int *piPublicKey_mLen/*OUT*/,
    unsigned char *pucPublicKey_e/*OUT*/, int *piPublicKey_eLen/*OUT*/,
    unsigned char *pucPrivateKey_d/*OUT*/, int *piPrivateKey_dLen/*OUT*/,
    unsigned char *pucPrivateKey_p/*OUT*/, int *piPrivateKey_pLen/*OUT*/,
    unsigned char *pucPrivateKey_q/*OUT*/, int *piPrivateKey_qLen/*OUT*/,
    unsigned char *pucPrivateKey_dp/*OUT*/, int *piPrivateKey_dpLen/*OUT*/,
    unsigned char *pucPrivateKey_dq/*OUT*/, int *piPrivateKey_dqLen/*OUT*/,
    unsigned char *pucPrivateKey_qInv/*OUT*/, int *piPrivateKey_qInvLen/*OUT*/,
    unsigned char *pucDerPrivateKey/*OUT*/, int *piDerPrivateKeyLen/*OUT*/);


/*
 * HSM_RSA_ExportRSAKey     保护密钥（对称）加密导入一对RSA密钥
 * iMode                    加密算法模式  2 H  00 – ECB 01 – CBC
 * pcTkType                 用于加密保护RSA密钥的保护密钥类型 000 – KEK;   109 – MDK;
 * iTkIndex                 用于加密保护RSA的保护密钥索引
 * pcTk_Lmk                 用于加密保护RSA的保护密钥密文
 * iTkDeriveNumber          保护密钥分散级数
 * pcTkDeriveData           保护密钥分散因子
 * iRsaKeyIndex             被导出密钥索引号
 * pucRsaKeyTag             RSA密钥标签
 * iRsaKeyTagLen            RSA密钥标签长度
 * pucPublicKey             公钥， ASN.1 格式DER 编码（模，指数序列)
 * iPublicKeyLen            公钥数据长度
 * pucPrivateKey_d          私钥指数d  n B  私钥指数d密文
 * iPrivateKey_dLen         私钥指数d长度  4 N  私钥指数d密文长度，字节数
 * pucPrivateKey_p          私钥分量P  n B  私钥分量p密文
 * iPrivateKey_pLen         私钥分量P长度  4 N  私钥分量p密文长度，字节数
 * pucPrivateKey_q          私钥分量Q  n B  私钥分量q密文
 * iPrivateKey_qLen         私钥分量Q长度  4 N  私钥分量q密文长度，字节数
 * pucPrivateKey_dp         私钥分量dP  n B  私钥分量dP密文
 * iPrivateKey_dpLen        私钥分量dP长度  4 N  私钥分量dP密文长度，字节数
 * pucPrivateKey_dq         私钥分量dQ  n B  私钥分量dQ密文
 * iPrivateKey_dqLen        私钥分量dQ长度  4 N  私钥分量dQ密文长度，字节数
 * pucPrivateKey_qInv       私钥分量qInv  n B  私钥分量qInv密文
 * iPrivateKey_qInvLen      私钥分量qInv长度  4 N  私钥分量qInv密文长度，字节数
 */

int HSM_RSA_ImportByTk(
    int iMode,  char *pcTkType,
    int iTkIndex, char *pcTk_Lmk,
    int iTkDeriveNumber, char *pcTkDeriveData,
    int iRsaKeyIndex,
    unsigned char *pucRsaKeyTag, int iRsaKeyTagLen,
    unsigned char *pucPublicKey, int iPublicKeyLen,
    unsigned char *pucPrivateKey_d, int iPrivateKey_dLen,
    unsigned char *pucPrivateKey_p, int iPrivateKey_pLen,
    unsigned char *pucPrivateKey_q, int iPrivateKey_qLen,
    unsigned char *pucPrivateKey_dp, int iPrivateKey_dpLen,
    unsigned char *pucPrivateKey_dq, int iPrivateKey_dqLen,
    unsigned char *pucPrivateKey_qInv, int iPrivateKey_qInvLen,
    unsigned char *pucPrivateKey_Lmk/*out*/, int *piPrivateKeyLen_Lmk/*out*/ );
#endif    // __HSMAPI_ASYM_H__



