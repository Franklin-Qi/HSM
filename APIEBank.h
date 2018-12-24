#ifndef _APIEBANK_H_
#define _APIEBANK_H_

#ifdef __cplusplus
extern "C"{
#endif //__cplusplus

#ifndef NULL 
#define NULL 0
#endif

#ifdef _MSC_VER
#define DLL _declspec(dllexport)
#else
#define DLL
#endif

#define HSMAPI DLL

#define RSAref_MAX_BITS     4096
#define RSAref_MAX_LEN      ((RSAref_MAX_BITS + 7) / 8)
#define RSAref_MAX_PBITS    ((RSAref_MAX_BITS + 1) / 2)
#define RSAref_MAX_PLEN     ((RSAref_MAX_PBITS + 7)/ 8)

typedef struct RSArefPublicKey_st
{
    unsigned int  bits;
    unsigned char m[RSAref_MAX_LEN];
    unsigned char e[RSAref_MAX_LEN];
} RSArefPublicKey;

/*
名称： RSA私钥结构体
成员：
名称			数据长度（字节）			含义
bits				4						模长
M				RSAref_MAX_LEN				模N
E				RSAref_MAX_LEN				指数
D				RSAref_MAX_LEN				模D
prime[2]		RSAref_MAX_PLEN * 2			素数p和q
pexp[2]			RSAref_MAX_PLEN * 2			Dp 和Dq
coef			RSAref_MAX_PLEN				系数i
*/
typedef struct RSArefPrivateKey_st
{
    unsigned int  bits;
    unsigned char m[RSAref_MAX_LEN];
    unsigned char e[RSAref_MAX_LEN];
    unsigned char d[RSAref_MAX_LEN];
    unsigned char prime[2][RSAref_MAX_PLEN];
    unsigned char pexp[2][RSAref_MAX_PLEN];
    unsigned char coef[RSAref_MAX_PLEN];
} RSArefPrivateKey;

#define ECCref_MAX_BITS             512
#define ECCref_MAX_LEN              ((ECCref_MAX_BITS+7) / 8)

typedef struct EccKeyChain {
    int               id;
    unsigned char     signpubkey[ECCref_MAX_LEN*2];
    unsigned char     signprikey[ECCref_MAX_LEN];
    unsigned char     encpubkey[ECCref_MAX_LEN*2];
    unsigned char     encprikey[ECCref_MAX_LEN];
}ECCKEY;

typedef struct ECCrefPublicKey_st
{
    unsigned int  bits;
    unsigned char x[ECCref_MAX_LEN]; 
    unsigned char y[ECCref_MAX_LEN]; 
}ECCrefPublicKey;

typedef struct ECCrefPrivateKey_st
{
    unsigned int  bits;
    unsigned char K[ECCref_MAX_LEN];
} ECCrefPrivateKey;

typedef struct ECCCipher_st
{
    unsigned char x[ECCref_MAX_LEN]; 
    unsigned char y[ECCref_MAX_LEN]; 
    unsigned char M[32];
    unsigned int L;
    unsigned char C[2048];
} ECCCipher;

typedef struct ECCSignature_st
{
    unsigned char r[ECCref_MAX_LEN];
    unsigned char s[ECCref_MAX_LEN];
} ECCSignature;

/* ECC曲线类型 */
//国密局标准
#define OSCCA_FP_256          6

/*分组对称密码算法标识*/
#define SGD_SM1_ECB	     0x00000101	// SM1算法ECB加密模式
#define SGD_SM1_CBC	     0x00000102	// SM1算法CBC加密模式
#define SGD_SM4_ECB	     0x00000401	// SM4算法ECB加密模式
#define SGD_SM4_CBC	     0x00000402	// SM4算法CBC加密模式
#define SGD_AES_ECB	     0x90000401	// AES算法ECB加密模式
#define SGD_AES_CBC	     0x90000402	// AES算法CBC加密模式
#define SGD_DES_ECB	     0x90000101	// DES算法ECB加密模式
#define SGD_DES_CBC	     0x90000102	// DES算法CBC加密模式

/*非对称算法标识*/
#define SGD_RSA                         0x00010000  /* RSA算法机制 */
#define SGD_SM2                         0x00020100  /* SM2椭圆曲线密码算法 */
#define SGD_SM2_1                       0x00020200  /* SM2椭圆曲线签名算法 */
#define SGD_SM2_2                       0x00020400  /* SM2椭圆曲线密钥交换协议 */
#define SGD_SM2_3                       0x00020800  /* SM2椭圆曲线加密算法 */

// 摘要算法
#define SGD_SM3	         0x00000001	// SM3杂凑算法 SM3-256
#define SGD_SHA1         0x00000002	// SHA_1杂凑算法
#define SGD_SHA256       0x00000004	// SHA_256杂凑算法
#define SGD_MD5	         0x00000008	// MD5杂凑算法
#define SGD_SHA224	     0x00000010	// SHA_224杂凑算法
#define SGD_SHA384	     0x00000020	// SHA_384杂凑算法
#define SGD_SHA512	     0x00000040	// SHA_512杂凑算法

/*签名算法标识*/
#define SGD_SM3_RSA                     SGD_SM3 | SGD_RSA       /*基于SM3算法和RSA算法的签名*/
#define SGD_SHA1_RSA                    SGD_SHA1 | SGD_RSA      /*基于SHA_1算法和RSA算法的签名*/
#define SGD_SHA256_RSA                  SGD_SHA256 | SGD_RSA    /*基于SHA_256算法和RSA算法的签名*/
#define SGD_SM3_SM2                     SGD_SM3 | SGD_SM2       /*基于SM3算法和SM2算法的签名*/

/**
 * @brief   打开设备句柄，phDeviceHandle 由函数初始化并填写内容 
 *
 * @param   phDeviceHandle      [out]   返回设备句柄
 * @param   ipaddr              [in]    密码设备IP
 * @param   port 密码设备端口
 *
 * @return  0,成功
 */
DLL int SDF_OpenDevice(
        void **phDeviceHandle,
        char *ipaddr,
        int port );


/**
 * @brief   关闭密码设备，并释放相关资源
 *
 * @param   hDeviceHandle       [in]    已打开的设备句柄
 *
 * @return  
 */
DLL int SDF_CloseDevice(
        void *hDeviceHandle);

/**
 * @brief   创建与密码设备的会话
 *
 * @param   hDeviceHandle       [in]    已打开的设备句柄
 * @param   phSessionHandle     [out]   与密码设备建立的新会话句柄
 *
 * @return  
 */
DLL int SDF_OpenSession(
        void *hDeviceHandle,
        void **phSessionHandle);

/**
 * @brief   关闭与密码设备已建立的会话，并释放相关资源
 *
 * @param   hSessionHandle      [in]    与密码设备已建立的会话句柄
 *
 * @return  
 */
DLL int SDF_CloseSession(
        void *hSessionHandle);

/**
 * @brief   使用指定的密钥句柄和IV对数据进行对称解密运算
 * @brief   此函数不对数据进行填充处理，输入的数据必须是指定算法分组长度的整数倍
 *
 * @param   hSessionHandle      [in]    与设备建立的会话句柄
 * @param   hKeyHandle          [in]    指定的密钥句柄
 * @param   uiAlgID             [in]    算法标识，指定对称加密算法
 * @param   pucIV               [i/o]   缓冲区指针，用于存放输入和返回的IV数据
 * @param   pucEncData          [in]    缓冲区指针，用于存放输入的数据密文
 * @param   uiEncDataLength     [in]    输入的数据密文长度
 * @param   pucData             [out]   缓冲区指针，用于存放输出的数据明文
 * @param   puiDataLength       [i/o]   输出的数据明文长度
 *
 * @return  
 */
DLL int SDF_Decrypt (
        void *hSessionHandle,
        void *hKeyHandle,
        unsigned int uiAlgID,
        unsigned char *pucIV,
        unsigned char *pucEncData,
        unsigned int uiEncDataLength,
        unsigned char *pucData,
        unsigned int *puiDataLength);

/**
 * @brief   使用指定的密钥句柄和IV对数据进行对称加密运算
 * @brief   此函数不对数据进行填充处理，输入的数据必须是指定算法分组长度的整数倍
 *
 * @param   hSessionHandle      [in]    与设备建立的会话句柄
 * @param   hKeyHandle          [in]    指定的密钥句柄
 * @param   uiAlgID             [in]    算法标识，指定对称加密算法
 * @param   pucIV               [i/o]   缓冲区指针，用于存放输入和返回的IV数据
 * @param   pucData             [in]    缓冲区指针，用于存放输入的数据明文
 * @param   uiDataLength        [in]    输入的数据明文长度
 * @param   pucEncData          [out]   缓冲区指针，用于存放输出的数据密文
 * @param   puiEncDataLength    [out]   输出的数据密文长度
 *
 * @return  
 */
DLL int SDF_Encrypt(
        void *hSessionHandle,
        void *hKeyHandle,unsigned int uiAlgID,
        unsigned char *pucIV,
        unsigned char *pucData,
        unsigned int uiDataLength,
        unsigned char *pucEncData,
        unsigned int *puiEncDataLength);

/**
 * @brief   销毁会话密钥，并释放为密钥句柄分配的内存等资源
 * @brief   在对称算法运算完成后，应调用本函数销毁会话密钥
 *
 * @param   hSessionHandle      [in]    与设备建立的会话句柄
 * @param   hKeyHandle          [in]    输入的密钥句柄
 *
 * @return  
 */
DLL int SDF_DestoryKey(
        void *hSessionHandle,
        void *hKeyHandle);

/**
 * @brief   导出密码设备内部存储的指定索引位置的ECC算法加密公钥
 *
 * @param   hSessionHandle      [in]    与设备建立的会话句柄
 * @param   uiKeyId             [in]    密码设备存储的ECC密钥对索引值
 * @param   pucPublicKey        [out]   ECC公钥结构
 *
 * @return  
 */
DLL int SDF_ExportEncPublicKey_ECC(
        void *hSessionHandle,int nSock,
        unsigned int uiKeyId,
        ECCrefPublicKey *pucPublicKey);

/**
 * @brief  导出密码设备内部存储的指定索引位置的ECC算法签名公钥 
 *
 * @param   hSessionHandle      [in]    与设备建立的会话句柄
 * @param   uiKeyIndex          [in]    密码设备存储的ECC密钥对索引值
 * @param   pucPublicKey        [out]   ECC公钥结构
 *
 * @return  
 */
DLL int SDF_ExportSignPublicKey_ECC(
        void *hSessionHandle,int nSock,
        unsigned int uiKeyIndex,
        ECCrefPublicKey *pucPublicKey);

/**
 * @brief   导出密码设备内部存储的指定索引位置的RSA算法签名公钥
 *
 * @param   hSessionHandle      [in]    与设备建立的会话句柄
 * @param   uiKeyIndex          [in]    密码设备存储的RSA密钥对索引值
 * @param   pucPublicKey        [out]   RSA公钥结构
 *
 * @return  
 */
DLL int SDF_ExportSignPublicKey_RSA(
        void *hSessionHandle,int nSock,
        unsigned int uiKeyIndex,
        RSArefPublicKey *pucPublicKey);

/**
 * @brief   使用外部ECC私钥进行解密运算
 *
 * @param   hSessionHandle      [in]    与设备建立的会话句柄
 * @param   uiAlgID             [in]    算法标识，指定使用的ECC算法
 * @param   pucPrivateKey       [in]    外部ECC私钥结构
 * @param   pucEncData          [in]    缓冲区指针，用于存放输入的数据密文
 * @param   pucData             [out]   缓冲区指针，用于存放输出的数据明文
 * @param   puiDataLength       [i/o]   输出的数据明文长度
 *
 * @return  
 */
DLL int SDF_ExternalDecrypt_ECC(
        void *hSessionHandle,int nSock,
        unsigned int uiAlgID,
        ECCrefPrivateKey *pucPrivateKey,
        ECCCipher *pucEncData,
        unsigned char *pucData,
        unsigned int *puiDataLength);

/**
 * @brief   使用外部ECC公钥对数据进行加密运算
 *
 * @param   hSessionHandle      [in]    与设备建立的会话句柄
 * @param   uiAlgID             [in]    算法标识，指定使用的ECC算法
 * @param   pucPublicKey        [in]    外部ECC公钥结构
 * @param   pucData             [in]    缓冲区指针，用于存放外部输入的数据
 * @param   uiDataLength        [in]    输入的数据长度
 * @param   pucEncData          [out]   缓冲区指针，用于存放输出的数据密文
 *
 * @return  
 */
DLL int SDF_ExternalEncrypt_ECC(
        void *hSessionHandle,int nSock,
        unsigned int uiAlgID,
        ECCrefPublicKey *pucPublicKey,
        unsigned char *pucData,
        unsigned int uiDataLength,
        ECCCipher *pucEncData);

/**
 * @brief   使用外部ECC私钥对数据进行签名运算
 *
 * @param   hSessionHandle      [in]    与设备建立的会话句柄
 * @param   uiAlgID             [in]    算法标识，指定使用的ECC算法
 * @param   pucPrivateKey       [in]    外部ECC私钥结构
 * @param   pucData             [in]    缓冲区指针，用于存放外部输入的数据
 * @param   uiDataLength        [in]    输入的数据长度
 * @param   pucSignature        [out]   缓冲区指针，用于存放输出的签名值数据
 *
 * @return  
 */
DLL int SDF_ExternalSign_ECC(
        void *hSessionHandle,int nSock,
        unsigned int uiAlgID,
        ECCrefPrivateKey *pucPrivateKey,
        unsigned char *pucData,
        unsigned int uiDataLength,
        ECCSignature *pucSignature);

/**
 * @brief   使用外部ECC公钥对ECC签名值进行验证运算
 *
 * @param   hSessionHandle      [in]    与设备建立的会话句柄
 * @param   uiAlgID             [in]    算法标识，指定使用的ECC算法
 * @param   pucPublicKey        [in]    外部ECC公钥结构
 * @param   pucDataInput        [in]    缓冲区指针，用于存放外部输入的数据
 * @param   uiInputLength       [in]    输入的数据长度
 * @param   pucSignature        [in]    缓冲区指针，用于存放输入的签名值数据
 *
 * @return  成功时返回0
 */
DLL int SDF_ExternalVerify_ECC(
        void *hSessionHandle,int nSock,
        unsigned int uiAlgID,
        ECCrefPublicKey *pucPublicKey,
        unsigned char *pucDataInput,
        unsigned int uiInputLength,
        ECCSignature *pucSignature);

/**
 * @brief   请求密码设备产生指定类型和模长的ECC密钥对
 *
 * @param   hSessionHandle      [in]    与设备建立的会话句柄
 * @param   uiAlgID             [in]    指定算法标识
 * @param   uiKeyBits           [in]    指定密钥长度
 * @param   pucPublicKey        [out]   ECC公钥结构
 * @param   pucPrivateKey       [out]   ECC私钥结构
 *
 * @return  
 */
DLL int SDF_GenerateKeyPair_ECC(
        void *hSessionHandle,int nSock,
        unsigned int uiAlgID,
        unsigned int uiKeyBits,
        ECCrefPublicKey *pucPublicKey,
        ECCrefPrivateKey *pucPrivateKey);

/**
 * @brief   请求密码设备产生指定模长的RSA密钥对
 *
 * @param   hSessionHandle      [in]    与设备建立的会话句柄
 * @param   uiKeyBits           [in]    指定密钥模长
 * @param   pucPublicKey        [out]   RSA公钥结构
 * @param   pucPrivateKey       [out]   RSA私钥结构
 *
 * @return  
 */
DLL int SDF_GenerateKeyPair_RSA(
        void *hSessionHandle,int nSock,
        unsigned int uiKeyBits,
        RSArefPublicKey *pucPublicKey,
        RSArefPrivateKey *pucPrivateKey);

/**
 * @brief   生成会话密钥并用外部ECC公钥加密输出
 *
 * @param   hSessionHandle      [in]    与设备建立的会话句柄
 * @param   uiKeyBits           [in]    指定产生的会话密钥长度
 * @param   uiAlgID             [in]    外部ECC公钥的算法标识
 * @param   pucPublicKey        [in]    输入的外部ECC公钥结构
 * @param   pucKey              [out]   缓冲区指针，用于存放返回的密钥密文
 * @param   phKeyHandle         [out]   返回的密钥句柄
 *
 * @return  
 */
DLL int SDF_GenerateKeyWithEPK_ECC(
        void *hSessionHandle,int nSock,
        unsigned int uiKeyBits,
        unsigned int uiAlgID,
        ECCrefPublicKey *pucPublicKey,
        ECCCipher *pucKey,
        void **phKeyHandle);

/**
 * @brief   生成会话密钥并用密钥加密密钥加密输出，同时返回密钥句柄
 *
 * @param   hSessionHandle      [in]    与设备建立的会话句柄
 * @param   uiKeyBits           [in]    指定产生的会话密钥长度
 * @param   uiAlgID             [in]    算法标识，指定对称加密算法
 * @param   uiKEKIndex          [in]    密码设备内部存储密钥加密密钥的索引值
 * @param   pucKey              [out]   缓冲区指针，用于存放返回的密钥密文
 * @param   puiKeyLength        [out]   返回的密钥密文长度
 * @param   phKeyHandle         [out]   返回的密钥句柄
 *
 * @return  
 */
DLL int SDF_GenerateKeyWithKEK(
        void *hSessionHandle,int nSock,
        unsigned int uiKeyBits,
        unsigned int uiAlgID,
        unsigned int uiKEKIndex,
        unsigned char *pucKey,
        unsigned int *puiKeyLength,
        void **phKeyHandle);

/**
 * @brief   产生随机数
 *
 * @param   hSessionHandle      [in]    与设备建立的会话句柄
 * @param   iRandomLen          [in]    随机数长度
 * @param   pcRandom            [out]   生成的随机数（十进制字符串）
 *
 * @return  
 */
DLL int SDF_GenerateRandom(
        void *hSessionHandle,int nSock,
        int iRandomLen,
        char *pcRandom);

/**
 * @brief   获取密码设备内部存储的指定索引私钥的使用权
 *
 * @param   hSessionHandle      [in]    与设备建立的会话句柄
 * @param   uiKeyIndex          [in]    密码设备存储私钥的索引值
 * @param   pucPassword         [in]    使用私钥权限的标识码
 * @param   uiPwdLength         [in]    私钥权限标识码长度，不少于8字节
 *
 * @return  
 */
DLL int SDF_GetPrivateKeyAccessRight(
        void *hSessionHandle,int nSock,
        unsigned int uiKeyIndex,
        unsigned char *pucPassword,
        unsigned int uiPwdLength);

/**
 * @brief   释放密码设备存储的指定索引私钥的使用权
 *
 * @param   hSessionHandle      [in]    与设备建立的会话句柄
 * @param   uiKeyIndex          [in]    密码设备存储私钥索引值
 *
 * @return  
 */
DLL int SDF_ReleasePrivateKeyAccessRight(
        void *hSessionHandle,int nSock,
        unsigned int uiKeyIndex);

/**
 * @brief   三步式数据杂凑运算第一步
 *
 * @param   hSessionHandle      [in]    与设备建立的会话句柄
 * @param   uiAlgID             [in]    指定杂凑算法标识
 * @param   pucPublicKey        [in]    签名者的ECC公钥，产生用于ECC签名的杂凑值时有效
 * @param   pucID               [in]    签名者的ID值，产生用于ECC签名的杂凑值时有效
 * @param   uiIDLength          [in]    签名者的ID长度
 *
 * @return  
 */
DLL int SDF_HashInit(
        void *hSessionHandle,int nSock,
        unsigned int uiAlgID,
        ECCrefPublicKey *pucPublicKey,
        unsigned char *pucID,
        unsigned int uiIDLength);

/**
 * @brief   三步式数据杂凑运算第二步，对输入的明文进行杂凑运算
 *
 * @param   hSessionHandle      [in]    与设备建立的会话句柄
 * @param   pucData             [in]    缓冲区指针，用于存放输入的数据明文
 * @param   uiDataLength        [in]    输入的数据明文长度
 *
 * @return  
 */
DLL int SDF_HashUpdate(
        void *hSessionHandle,int nSock,
        unsigned char *pucData,
        unsigned int uiDataLength);

/**
 * @brief   三步式数据杂凑算法第三步，杂凑运算结束返回杂凑值并清除中间数据
 *
 * @param   hSessionHandle      [in]    与设备建立的会话句柄
 * @param   pucHash             [out]   缓冲区指针，用于存放输出的杂凑数据
 * @param   puiHashLength       [i/o]   返回的杂凑数据长度
 *
 * @return  
 */
DLL int SDF_HashFinal(
        void *hSessionHandle,int nSock,
        unsigned char *pucHash,
        unsigned int *puiHashLength);

/**
 * @brief   导入明文会话密钥，同时返回密钥句柄
 *
 * @param   hSessionHandle      [in]    与设备建立的会话句柄
 * @param   pucKey              [in]    缓冲区指针，用于存放输入的密钥明文
 * @param   uiKeyLength         [in]    输入的密钥明文长度
 * @param   phKeyHandle         [out]   返回的密钥句柄
 *
 * @return  
 */
DLL int SDF_ImportKey(
        void *hSessionHandle,
        unsigned char *pucKey,
        unsigned int uiKeyLength,
        void **phKeyHandle);

/**
 * @brief   导入会话密钥并用内部ECC加密私钥解密，同时返回密钥句柄
 *
 * @param   hSessionHandle      [in]    与设备建立的会话句柄
 * @param   uiISKIndex          [in]    密码设备内部存储加密私钥的索引值，对应于加密时的公钥
 * @param   pucKey              [in]    缓冲区指针，用于存放输入的密钥密文
 * @param   phKeyHandle         [out]   返回的密钥句柄
 *
 * @return  
 */
DLL int SDF_ImportKeyWithISK_ECC(
        void *hSessionHandle,int nSock,
        unsigned int uiISKIndex,
        ECCCipher *pucKey,
        void **phKeyHandle);

/**
 * @brief   使用内部指定索引的私钥对数据进行运算
 * @brief   索引范围仅限于内部签名密钥对，数据格式由应用层封装
 *
 * @param   hSessionHandle      [in]    与设备建立的会话句柄
 * @param   uiKeyIndex          [in]    密码设备内部存储私钥的索引值
 * @param   pucDataInput        [in]    缓冲区指针，用于存放外部输入的数据
 * @param   uiInputLength       [in]    输入的数据长度
 * @param   pucDataOutput       [out]   缓冲区指针，用于存放输出的数据
 * @param   puiOutputLength     [i/o]   输出的数据长度
 *
 * @return  
 */
DLL int SDF_InternalPrivateKeyOperation_RSA(
        void *hSessionHandle,int nSock,
        unsigned int uiKeyIndex,
        unsigned char *pucDataInput,
        unsigned int uiInputLength,
        unsigned char *pucDataOutput,
        unsigned int *puiOutputLength);

/**
 * @brief   使用内部指定索引的公钥对数据进行运算
 * @brief   索引范围仅限于内部签名密钥对，数据格式由应用层封装
 *
 * @param   hSessionHandle      [in]    与设备建立的会话句柄
 * @param   uiKeyIndex          [in]    密码设备内部存储公钥的索引值
 * @param   pucDataInput        [in]    缓冲区指针，用于存放外部输入的数据
 * @param   uiInputLength       [in]    输入数据的长度
 * @param   pucDataOutput       [out]   缓冲区指针，用于存放输出的数据
 * @param   puiOutputLength     [i/o]   输出的数据长度
 *
 * @return  
 */
DLL int SDF_InternalPublicKeyOperation_RSA(
        void *hSessionHandle,int nSock,
        unsigned int uiKeyIndex,
        unsigned char *pucDataInput,
        unsigned int uiInputLength,
        unsigned char *pucDataOutput,
        unsigned int *puiOutputLength);

/**
 * @brief   使用内部ECC私钥对数据进行签名运算
 *
 * @param   hSessionHandle      [in]    与设备建立的会话句柄
 * @param   uiISKIndex          [in]    密码设备内部存储的ECC签名私钥的索引值
 * @param   pucData             [in]    缓冲区指针，用于存放外部输入的数据
 * @param   uiDataLength        [in]    输入数据的长度
 * @param   pucSignature        [out]   缓冲区指针，用于存放输出的签名值数据
 *
 * @return  
 */
DLL int SDF_InternalSign_ECC(
        void *hSessionHandle,int nSock,unsigned int uiISKIndex,
        unsigned char *pucData,
        unsigned int uiDataLength,
        ECCSignature *pucSignature);

/**
 * @brief   使用内部ECC公钥对ECC签名值进行验证运算
 *
 * @param   hSessionHandle      [in]    与设备建立的会话句柄
 * @param   uiISKIndex          [in]    密码设备内部存储的ECC签名公钥的索引值
 * @param   pucData             [in]    缓冲区指针，用于存放外部输入的数据
 * @param   uiDataLength        [in]    输入的数据长度
 * @param   pucSignature        [in]    缓冲区指针，用于存放输入的签名值数据
 *
 * @return  
 */
DLL int SDF_InternalVerify_ECC(
        void *hSessionHandle,int nSock,
        unsigned int uiISKIndex,
        unsigned char *pucData,
        unsigned int uiDataLength,
        ECCSignature *pucSignature);

/**
 * @brief   使用ZEK解密磁道数据密文
 *
 * @param   hSessionHandle      [in]    与设备建立的会话句柄
 * @param   iKeyIdx             [in]    ZEK密钥索引，该参数固定为0
 * @param   pcKey_LMK           [in]    LMK加密的ZEK密文，长度为16H/1A+32H/1A+48H
 * @param   pcTrackCipher       [in]    磁道数据密文，长度为n*2H
 * @param   iTrackTextLen       [in]    磁道密文数据长度
 * @param   iAlgIdx             [in]    解密模式：0-ECB；1-CBC
 * @param   iPadFlg             [in]    数据填充标识：0- ANSIx9.19；1-ANSIx9.23；2-PBOC MAC
 * @param   pcIV                [in]    初始化向量，当算法标识为2时存在
 * @param   pcTrackText         [out]   磁道数据明文，长度为n*2H
 *
 * @return  
 */
DLL int Tass_DecryptTrackData(
        void *hSessionHandle,int nSock,
        int iKeyIdx,
        char *pcKey_LMK,
        char *pcTrackCipher,
        int iTrackTextLen,
        int iAlgId,
        int iPadFlg,
        char *pcIV,
        char *pcTrackText);

/**
 * @brief   使用ZEK加密磁道数据
 *
 * @param   hSessionHandle      [in]    与设备建立的会话句柄
 * @param   iKeyIdx             [in]    ZEK密钥索引，该参数固定为0
 * @param   pcKey_LMK           [in]    LMK加密的ZEK密文，长度为16H/1A+32H/1A+48H
 * @param   pcTrackText         [in]    磁道数据明文，长度为n*2H
 * @param   iTrackTextLen       [in]    磁道数据明文长度
 * @param   iAlgId              [in]    加密模式：0-ECB；1-CBC
 * @param   iPadFlg             [in]    数据填充标识：0- ANSIx9.19；1-ANSIx9.23；2-PBOC MAC
 * @param   pcIV                [in]    初始化向量，当算法标识为2时存在
 * @param   pcTrackCipher       [out]   磁道数据密文，长度为n*2H
 *
 * @return  
 */
DLL int Tass_EncryptTrackData(
        void *hSessionHandle,int nSock,
        int iKeyIdx,
        char *pcKey_LMK,
        char *pcTrackText,
        int iTrackTextLen,
        int iAlgId,
        int iPadFlg,
        char *pcIV,
        char *pcTrackCipher);

/**
 * @brief   解密PIN，把ANSIx9.8格式组织的PIN明文用指定的PIK进行解密
 *
 * @param   hSessionHandle      [in]    与设备建立的会话句柄
 * @param   iKeyIdx             [in]    ZPK密钥索引，0-2048（当此参数为0的时候，采用pcKeyCipherByLMK）
 * @param   pcKeyCipherByLmk    [in]    LMK加密的ZPK密钥密文，长度为16H/1A+32H/1A+48H
 * @param   pcPinBlkCipher      [in]    PIN密文，长度为n*2H
 * @param   iPinBlkFmt          [in]    PINBLOCK格式标识，此参数固定为1，即ANSIx9.8
 * @param   pcPan               [in]    用户账号，长度为12N
 * @param   pcPinText           [out]   PIN明文，长度为nN
 *
 * @return  
 */
DLL int Tass_Decrypt_PIN(
        void *hSessionHandle,int nSock,
        int iKeyIdx,
        char *pcKeyCipherByLmk,
        char *pcPinBlkCipher,
        int iPinBlkFmt,
        char *pcPan,
        char *pcPinText);

/**
 * @brief   将ZMK分散产生子密钥，然后用保护密钥将子密钥保护导出
 *
 * @param   hSessionHandle      [in]    与设备建立的会话句柄
 * @param   pcZmkCipher_Lmk     [in]    待分散的ZMK，长度为1A+32H
 * @param   pcPublicKey         [in]    DER编码格式的RSA算法的保护公钥，长度为n*2H
 * @param   pcDisData           [in]    16字节分散因子，长度为32H
 * @param   pcKeyType           [in]    要导出的对称密钥类型：000-KEK/ZMK; 109-MKAC/MKD; ...
 * @param   pcSubKeyCipher_TK   [out]   保护公钥加密的子密钥密文，长度为n*2H
 * @param   pcSubKeyCipher_Lmk  [out]   LMK加密的子密钥密文，长度为1A+32H
 * @param   pcSubKeyCv          [out]   子密钥的4字节校验值，长度为8H
 *
 * @return  
 */
DLL int Tass_DiversifyKeyExportedByRsa(
        void *hSessionHandle,int nSock,
        char *pcZmkCipher_Lmk,
        char *pcPublicKey,
        char *pcDisData,
        char *pcKeyType,
        char *pcSubKeyCipher_TK,
        char *pcSubKeyCipher_Lmk,
        char *pcSubKeyCv);

/**
* @brief   分散产生子密钥，然后用ZMK保护导出
*
* @param   hSessionHandle       [in]    与设备建立的会话句柄
* @param   pcKeyCipher_Lmk      [in]    源密钥密文
* @param   pcZmkCipher_Lmk      [in]    ZMK密文
* @param   pcDisData            [in]    导出密钥分散因子，长度为 32H，备注： 16 个字节的分散因子
* @param   pcKeyType            [in]    密钥类型
* @param   pcSubKeyCipher_ZMK   [out]   ZMK保护的子密钥密文
* @param   pcSubKeyCipher_Lmk   [out]   ZMK保护的子密钥密文
* @param   pcSubKeyCv           [out]   校验值
*
* @return
*/
DLL int  Tass_DiversifyKeyExportedByZMK(
    void *hSessionHandle,int nSock,
    char *pcKeyCipher_Lmk,
    char *pcZmkCipher_Lmk,
    char *pcDisData,
    char *pcKeyType,
    char *pcSubKeyCipher_ZMK,
    char *pcSubKeyCipher_Lmk,
    char *pcSubKeyCv);

/**
 * @brief   由一个ZMK分散生成另外一个ZMK子密钥，并通过保护ZMK密钥加密保护导出
 *
 * @param   hSessionHandle      [in]    与设备建立的会话句柄
 * @param   iKeyIdx             [in]    保护ZMK密钥索引，此参数固定为0
 * @param   pcKey_LMK           [in]    LMK加密的保护ZMK密钥密文，长度为1A+32H
 * @param   pcDisData           [in]    16字节导出ZMK密钥分散因子，长度为32H
 * @param   iZmkIdx             [in]    导出ZMK密钥索引
 * @param   pcZmkKey_LMK        [in]    需要导出的由LMK加密的ZMK密钥密文
 * @param   pcZmk_ZMK           [out]   保护ZMK加密的子密钥密文
 * @param   pcZmk_LMK           [out]   LMK加密的子密钥密文
 * @param   pcZmkCv             [out]   子密钥校验值
 *
 * @return  
 */
DLL int Tass_Disper_Zmk(
        void *hSessionHandle,int nSock,
        int iKeyIdx,
        char *pcKey_LMK,
        char *pcDisData,
        int iZmkIdx,
        char *pcZmkKey_LMK,
        char *pcZmk_ZMK,
        char *pcZmk_LMK,
        char *pcZmkCv);

/**
 * @brief   随机生成RSA密钥对，并使用ZMK加密保护导出
 *
 * @param   hSessionHandle      [in]    与设备建立的会话句柄
 * @param   RsaIndex            [in]    存储到密码机内的密钥索引，0表示不存储
 * @param   RsaTag              [in]    RAS密钥标签，仅当RsaIndex>0且!=9999时有效
 * @param   RsaLen              [in]    公钥模长
 * @param   pub_E               [in]    公钥指数，65537或3
 * @param   zmkIndex            [in]    保护密钥索引
 * @param   zmk_Lmk             [in]    保护RSA密钥分量的保护密钥，为NULL时不保护导出，只输出RSA本地密文
 * @param   zmk_disData         [in]    保护密钥的分散因子，NULL时不分散
 * @param   mode                [in]    加密算法模式： 0-ECB；1-CBC
 * @param   pucDerPublicKey     [out]   公钥DER编码
 * @param   pucDerPrivateKey    [out]   ZMK保护密钥时存在使用ZMK加密导出的RSA密钥分量
 *
 * @return  
 */
DLL int Tass_GenRSAKey(
        void *hSessionHandle,int nSock,
        int RsaIndex,
        char *RsaTag,
        int RsaLen,int pub_E,
        int zmkIndex,
        char *zmk_Lmk,
        char *zmk_disData,
        int mode,
        char *pucDerPublicKey,
        char *pucDerPrivateKey);

/**
 * @brief   随机生成SM2密钥对，并使用ZMK加密保护导出
 *
 * @param   hSessionHandle      [in]    与设备建立的会话句柄
 * @param   zmkIndex            [in]    保护密钥索引
 * @param   zmk_Lmk             [in]    保护密钥在LMK下加密的密文
 * @param   zmk_disData         [in]    保护密钥的分散因子
 * @param   mode                [in]    保护密钥加密SM2私钥的算法模式：0-ECB；1-CBC
 * @param   SM2_D_ZMK           [out]   私钥分量D在保护密钥下加密的密文数据
 * @param   SM2_PUBKEY          [out]   SM2公钥的DER编码数据
 * @param   SM2_LMK             [out]   私钥分量D在LMK下加密的密文数据
 *
 * @return  
 */
DLL int Tass_GenSm2Key(
        void *hSessionHandle,int nSock,
        int zmkIndex,
        char *zmk_Lmk,
        char *zmk_disData,
        int mode,
        char *SM2_D_ZMK,
        char * SM2_PUBKEY,
        char * SM2_LMK );

/**
 * @brief   根据输入的MAC数据采用标准的 ANSI x9.19 算法产生MAC
 *
 * @param   hSessionHandle      [in]    与设备建立的会话句柄
 * @param   iKeyIdx             [in]    计算MAC的密钥索引
 * @param   pcKeyCipherByLmk    [in]    计算MAC的密钥在LMK下加密的密文
 * @param   iInDataLen          [in]    MAC数据长度，待计算MAC的数据字符个数
 * @param   pcInData            [in]    待计算MAC的数据
 * @param   pcMac               [out]   计算出来的MAC值，长度为16H
 *
 * @return  
 */
DLL int Tass_Gen_ANSI_Mac(
        void *hSessionHandle,int nSock,
        int iKeyIdx,
        char *pcKeyCipherByLmk,
        int iInDataLen,
        unsigned char *pcInData,
        char *pcMac);

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
        char *pcMakCv);

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
        char *pcPikCv);

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
        char cZekScheme,char *pcZekCipherByZmk,
        char *pcZekCipherByLmk,
        char *pcZekCv);

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
        char *pcZmkCv);

/**
 * @brief   私钥解密
 *
 * @param   hSessionHandle      [in]    与设备建立的会话句柄
 * @param   keytype             [in]    识别SM2或RSA：0-RSA；1-SM2
 * @param   Rsa_LMK             [in]    LMK加密的RSA本地私钥密文
 * @param   SM2_LMK             [in]    LMK加密的SM2本地私钥密文
 * @param   indata              [in]    外部送入密文数据
 * @param   outdata             [out]   私钥解密后数据
 *
 * @return  
 */
DLL int Tass_PRIVATE_Oper(
        void *hSessionHandle,int nSock,
        int keytype,
        char *Rsa_LMK,
        char *SM2_LMK,
        char *indata,
        char *outdata);

/**
 * @brief   公钥加密
 *
 * @param   hSessionHandle      [in]    与设备建立的会话句柄
 * @param   keytype             [in]    识别SM2或RSA：0-RSA；1-SM2
 * @param   indata              [in]    输入数据，需符合公钥运算长度要求，接口内不进行数据填充处理
 * @param   RSAPubKeyE          [in]    RSA公钥指数
 * @param   RSAPubKeyN          [in]    RAS公钥模数据
 * @param   SM2_PUBKEY          [in]    SM2公钥，RSA算法时此项为空
 * @param   outdata             [out]   加密后的数据
 *
 * @return  
 */
DLL int Tass_PubKey_Oper(
        void *hSessionHandle,int nSock,
        int keytype,
        char *indata,
        char *RSAPubKeyE,
        char *RSAPubKeyN,
        char *SM2PubKey,
        char *outdata);

#define SDR_OK                                         0x00000000	// 操作成功
#define SDR_BASE                                       0x01000000   // 错误码基础值
#define SDR_UNKNOWERR                       SDR_BASE | 0x00000001	// 未知错误
#define SDR_DECRYPT_ALGID                   SDR_BASE | 0x00000002   // 算法标识错误
#define SDR_DECRYPT_IV                      SDR_BASE | 0x00000002   // 算法标识错误
#define SDR_DECRYPT_ENCDATALENGTH           SDR_BASE | 0x00000002   // 密文长度错误
#define SDR_DECRYPT_MALLOC                  SDR_BASE | 0x00000002   // 动态分配空间失败
#define SDR_DECRYPT_DATA                    SDR_BASE | 0x00000002   // 输出明文指针不得为空
#define SDR_DECRYPT_DATALENGTH              SDR_BASE | 0x00000002   // 输出明文长度指针不得为空

#define SDR_EXPENCPUBKEYECC_PUBLICKEY       SDR_BASE | 0x00000001   // 公钥结构体指针不得为空
#define SDR_EXPSIGNPUBKEYECC_PUBLICKEY      SDR_BASE | 0x00000002   // 公钥结构体指针不得为空

#define SDR_EXPSIGNPUBKEYRSA_PUBLICKEY      SDR_BASE | 0x00000003   // 公钥结构体指针不得为空

#define SDR_EXTDECRYPTECC_ALGID             SDR_BASE | 0x00000004   // 算法标识错误
#define SDR_EXTDECRYPTECC_PRIVATEKEY        SDR_BASE | 0x00000005   // 私钥结构体指针不得为空
#define SDR_EXTDECRYPTECC_ENCDATA           SDR_BASE | 0x00000006   // 密文结构体指针不得为空
#define SDR_EXTDERYPTECC_DATA               SDR_BASE | 0x00000007   // 输出明文指针不得为空
#define SDR_EXTDECRYPTECC_DATALENGTH        SDR_BASE | 0x00000008   // 输出明文长度指针不得为空


#define SDR_EXTENCRYPTECC_ALGID             SDR_BASE | 0x00000009   // 算法标识错误
#define SDR_EXTENCRYPTECC_PUBLICKEY         SDR_BASE | 0x0000000A   // 公钥结构体指针不得为空
#define SDR_EXTENCRYPTECC_ENCDATA           SDR_BASE | 0x0000000B   // 密文结构体指针不得为空

#define SDR_EXTSIGNECC_ALGID                SDR_BASE | 0x0000000C   // 算法标识错误
#define SDR_EXTSIGNECC_PRIVATEKEY           SDR_BASE | 0x0000000D   // 私钥结构体指针不得为空
#define SDR_EXTSIGNECC_SIGNATURE            SDR_BASE | 0x0000000E   // 签名结构体指针不得为空

#define SDR_EXTVERIFYECC_ALGID              SDR_BASE | 0x0000000F   // 算法标识错误
#define SDR_EXTVERIFYECC_PUBLICKEY          SDR_BASE | 0x00000010   // 公钥结构体指针不得为空
#define SDR_EXTVERIFYECC_SIGNATURE          SDR_BASE | 0x00000011   // 签名结构体指针不得为空

#define SDR_GENKEYPAIRECC_ALGID             SDR_BASE | 0x00000012   // 算法标识错误
#define SDR_GENKEYPAIRECC_KEYBITS           SDR_BASE | 0x00000013   // 密钥长度错误
#define SDR_GENKEYPAIRECC_PUBLICKEY         SDR_BASE | 0x00000014   // 公钥结构体指针不得为空
#define SDR_GENKEYPAIRECC_PRIVATEKEY        SDR_BASE | 0x00000015   // 私钥结构体指针不得为空

#define SDR_GENKEYPAIRRSA_PUBLICKEY         SDR_BASE | 0x00000016   // 公钥结构体指针不得为空
#define SDR_GENKEYPAIRRSA_PRIVATEKEY        SDR_BASE | 0x00000017   // 私钥结构体指针不得为空

#define SDR_GENKEYWITHEPKECC_ALGID          SDR_BASE | 0x00000018   // 算法标识错误
#define SDR_GENKEYWITHEPKECC_PUBLICKEY      SDR_BASE | 0x00000019   // 公钥结构体指针不得为空
#define SDR_GENKEYWITHEPKECC_KEY            SDR_BASE | 0x0000001A   // 公钥加密密钥密文结构体指针不得为空
#define SDR_GENKEYWITHEPKECC_MALLOC         SDR_BASE | 0x0000001B   // 分配句柄空间失败

#define SDR_GENKEYWITHKEK_ALGID             SDR_BASE | 0x0000001C   // 算法标识错误
#define SDR_GENKEYWITHKEK_KEY               SDR_BASE | 0x0000001D   // 输出密钥密文指针不得为空
#define SDR_GENKEYWITHKEK_KEYLENGTH         SDR_BASE | 0x0000001F   // 输出密钥密文长度指针不得为空
#define SDR_GENKEYWITHKEK_MALLOC            SDR_BASE | 0x00000020   // 分配句柄空间失败

#define SDR_GENRANDOM_RANDOM                SDR_BASE | 0x00000021   // 随机数指针不得为NULL

#define SDR_GETPRIKEYACCRIGHT_KEYINDEX      SDR_BASE | 0x00000022   // 密钥索引范围错误
#define SDR_GETPRIKEYACCRIGHT_PWDORLENGTH   SDR_BASE | 0x00000023   // 口令指针为空或长度错误

#define SDR_RELPRIKEYACCRIGHT_KEYINDEX      SDR_BASE | 0x00000024   // 密钥索引范围错误

#define SDR_HASHINIT_ALGID                  SDR_BASE | 0x00000025   // 算法标识错误
#define SDR_HASHINIT_PUBLICKEY              SDR_BASE | 0x00000026   // 公钥结构体指针不得为空
#define SDR_HASHINIT_ID                     SDR_BASE | 0x00000027   // ID指针不得为空

#define SDR_HASHFINAL_HASH                  SDR_BASE | 0x00000028   // HASH指针不得为空
#define SDR_HASHFINAL_HASHLENGTH            SDR_BASE | 0x00000029   // HASH长度指针不得为空

#define SDR_IMPORTKEY_MALLOC                SDR_BASE | 0x0000002A   // 分配句柄空间失败

#define SDR_IMPORTKEYWITHEPKECC_MALLOC      SDR_BASE | 0x0000002B   // 分配句柄空间失败
#define SDR_IMPORTKEYWITHEPKECC_KEY         SDR_BASE | 0x0000002C   // 密文指针不得为空

#define SDR_INPRIOPT_KEYINDEX               SDR_BASE | 0x0000002D   // 密钥索引范围错误
#define SDR_INPRIOPT_DATAOUTPUT             SDR_BASE | 0x0000002E   // 输出数据指针不得为空
#define SDR_INPRIOPT_DATAOUTPUTLENGTH       SDR_BASE | 0x0000002F   // 输出数据长度指针不得为空

#define SDR_INPUBOPT_KEYINDEX               SDR_BASE | 0x00000030   // 密钥索引范围错误
#define SDR_INPUBOPT_DATAOUTPUT             SDR_BASE | 0x00000031   // 输出数据指针不得为空
#define SDR_INPUBOPT_DATAOUTPUTLENGTH       SDR_BASE | 0x00000032   // 输出数据长度指针不得为空

#define SDR_INSIGNECC_ISKINDEX              SDR_BASE | 0x00000033   // 密钥索引范围错误
#define SDR_INSIGNECC_SIGNATURE             SDR_BASE | 0x00000034   // 签名结构体指针不得为空

#define SDR_INVERIFYECC_ISKINDEX            SDR_BASE | 0x00000035   // 密钥索引范围错误
#define SDR_INVERIFYECC_SIGNATURE           SDR_BASE | 0x00000036   // 签名结构体指针不得为空


#ifdef __cplusplus
}
#endif //__cplusplus

#endif  //_EBANKAPI_H_
