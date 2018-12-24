/*********************************************************************/
/* 文 件 名：  smapi.h                                               */
/* 版 本 号：  v1.1                                                  */
/* 所 有 者：                                                        */
/* 版    权：  Union Beijing                                         */
/* 功    能：  农行ICCM_密钥安全系统_第05号_加密机接口（国密）api      */
/* 维护记录： 1. 2008-6-11 by  Liwb                                  */
/*           2. 2008-12-11 by xusj                                   */
/*           3. 2012-07-11 by zhangx                                 */
/*           4. 2017-03-07 by zhaomx                                 */
/*********************************************************************/

#ifndef _SMAPI_H_
#define _SMAPI_H_

#ifdef __cplusplus
extern "C"{
#endif

#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "unionsck.h"
#include "unionlog.h"
#include "DerCode.h"
#include "type.h"
#include "net.h"

typedef struct  InitParam
{
    char ipaddress[15+1];
    char port[8+1];
    int timeout;
} InitParm;

typedef int Boolean;
typedef unsigned char byte;
int sockid;
int Timeout;

#define FALSE 0
#define	TRUE 1
/****FLAG:1-for 2 print response*******/
/****     0-for 1 print response*******/
#define FLAG 0		

#define _KEY 1

#define STEP 600

/*Added by chendy 2009.4.16*/
/*Added by chenf 2013.4.20*/
#define	CKR_SOCKET_ERR 	    -1
#define CKR_SMAPI_ERR       -1
#define CKR_SMAPI_OK         0
#define	CKR_PARAMETER_ERR    1
#define CKR_INVALIDKEY_ERR   2
#define	CKR_SENDFAIL_ERR     3
#define	CKR_RCVTMOUT_ERR     4
#define	CKR_RCVFORMAT_ERR    5
#define CKR_PLAINTEXT_ERR    6
#define CRK_ENCTEXT_ERR      7
#define CKR_PRINTKEY_ERR     8
#define CKR_OTHER_ERR        9
#define CKR_VERIFY_ERR       10
#define CKR_PRINTFORMAT_ERR  11
#define CRK_MIXKEY_ERR       12
#define CRK_GENRSA_ERR       13
#define CRK_IMPORTRSA_ERR    14
#define CRK_HASH_ERR         15


#define	CKR_MEMORY_ERR     -200
#define	CKR_INNER_CALL_ERR -400
#define	CKR_PUBLIC_FMT_ERR -500

int SMAPIConnectSM(char *pszAddr, UINT nPort, UINT nTimeout, UINT *pnSock, char *szDeviceInfo);
int SMAPIDisconnectSM(UINT nSock);
int SMAPICmdNC(UINT nSock);
int CheckACN(char * accon,int len);
int CheckPW(char * psw,int len);
int HexToInt(char source[],int len);
int CheckCmdReturn(int ret,char *funName,char *retstr);

/******************************************************  三未信安   **********************************************/
/******************************************************************************************************************
1: 分行数据加解密（7.3.6 数据加解密）
2. 函数功能： 调用加密机中指定索引位上存储的密钥对传入数据进行加解密
              注： 专供分行加解密数据使用，总行系统加解密使用数据库中存储的密钥
3. 输入参数： .
	UINT nSock：连接的socket 句柄
	int nEncrypt：加密、解密标志，1-加密；0-解密
	int nMode：加密模式，0-ECB；1-CBC
	注： CBC 模式的初始向量为8 字节全零二进制数"0000 0000 0000 0000"
	int nIndex：密钥索引位置，取值范围[257, 486]，其中257 为传输主密钥索引
	byte *bIndata：需要进行加密/解密的数据，二进制数，长度由nDataLen 指定
	int nDatalen：bIndata 的长度，取值范围[8，4096]且为8 的倍数
4. 输出参数：
	byte *bOutData：经过加密/解密之后的密文/明文数据，二进制数
5. 返回值：
        0： 执行成功
	1： 输入参数验证失败
	2： 无效的索引值
	3： 向加密机发送数据失败
	4： 接收加密机数据超时
	5： 接收到的数据格式错
	6： 指定索引位对应的密钥不存在
	9： 其他错误  
*******************************************************************************************************************/
int SMAPIEncryptData(UINT nSock, int nEncrypt, int nMode, int nIndex, byte *bIndata, 
                      int nDatalen, byte *bOutdata);

/*******************************************************************************************************************
1. 数据加密（7.3.6 数据加解密）
2. 函数功能：用mech 指定算法对明文数据进行加密。
3. 输入参数：
	UINT nSock：连接的socket 句柄
	char *encryptKey：经LMK 加密的加密密钥的密文值，16 进制ASCII 字符串。（例
	如：8 字节密钥，则该输入为16 个ASCII 字符串）
	UINT mech：算法类型：
	decryptMech = 20 表示DES_ECB 算法
	decryptMech = 17 表示DES_CBC 算法
	decryptMech = 3 表示SM4_ECB 算法
	decryptMech = 4 表示SM4_CBC 算法
	decryptMech = 5 表示AES_ECB 算法（暂不支持）
	decryptMech = 6 表示AES_CBC 算法（暂不支持）
	char *data：待处理数据，16 进制ASCII 字符串，数据长度为16 / 32 的整数倍
	char *IV,：CBC 解密时的初始向量
4. 输出参数：
	char *outData： 输出数据，16 进制ASCII 字符串
5. 返回值： 
    	0：成功
        其他：失败错误代码
*******************************************************************************************************************/
int SMAPIEncrypt(UINT nSock ,char * encryptKey, UINT mech, char *data, char *IV , char *outData);

/******************************************************************************************************************
1. 数据加密(索引版) （7.3.6 数据加解密）
2. 函数功能：用mech 指定算法对明文数据进行加密。
3. 输入参数：
	UINT nSock：连接的socket 句柄
	int encryptKeyIndex：在加密机中的密钥索引。[257 486]
	UINT mech：算法类型：：
	decryptMech = 20 表示DES_ECB 算法
	decryptMech = 17 表示DES_CBC 算法
	decryptMech = 3 表示SM4_ECB 算法
	decryptMech = 4 表示SM4_CBC 算法
	decryptMech = 5 表示AES_ECB 算法（暂不支持）
	decryptMech = 6 表示AES_CBC 算法（暂不支持）
	char *data：待处理数据，十六进制ASCII 字符串
	char *IV,：CBC 解密时的初始向量
4. 输出参数：
	char *outData： 输出数据，十六进制ASCII 字符串
5. 返回值： 
	0：成功
	其他：失败错误代码
*********************************************************************************************************************/
int SMAPIEncrypt_index(UINT  nSock ,int encryptKeyIndex, UINT mech, char *data, char *IV, char *outData);

/******************************************************************************************************************
1. 数据解密（7.3.6 数据加解密）
2. 函数功能：
        用mech 指定算法对数据进行解密。
3. 输入参数：
	UINT nSock：连接的socket 句柄
	char * DecryptKey：经LMK 加密的解密密钥的密文值，16 进制ASCII 字符串。（例
	如：8 字节密钥，则该输入为16 个ASCII 字符串）
	UINT mech：算法类型：
	decryptMech = 20 表示DES_ECB 算法
	decryptMech = 17 表示DES_CBC 算法
	decryptMech = 3 表示SM4_ECB 算法
	decryptMech = 4 表示SM4_CBC 算法
	decryptMech = 5 表示AES_ECB 算法（暂不支持）
	decryptMech = 6 表示AES_CBC 算法（暂不支持）
	char *data：待处理数据，16 进制ASCII 字符串
	char *IV,：CBC 解密时的初始向量
4. 输出参数：
	char *outData： 输出数据，16 进制ASCII 字符串
5. 返回值： 
	0：成功
	其他：失败错误代码
*********************************************************************************************************************/
int SMAPIDecrypt(UINT  nSock ,char * DecryptKey, UINT mech, char *data, char *IV,char *outData);

/********************************************************************************************************************
1. 数据解密(索引版) （7.3.6 数据加解密） 
2. 函数功能：
	用mech 指定算法对数据进行解密。
3. 输入参数：
	UINT nSock：连接的socket 句柄
	int DecryptKeyIndex：在加密机中的密钥索引。16 进制ASCII 字符串。（例如：8
	字节密钥，则该输入为16 个ASCII 字符串）
	UINT mech：算法类型：
	decryptMech = 20 表示DES_ECB 算法
	decryptMech = 17 表示DES_CBC 算法
	decryptMech = 3 表示SM4_ECB 算法
	decryptMech = 4 表示SM4_CBC 算法
	decryptMech = 5 表示AES_ECB 算法（暂不支持）
	decryptMech = 6 表示AES_CBC 算法（暂不支持）
	char *data：待处理数据，16 进制ASCII 字符串
	char *IV：CBC 解密时的初始向量
4. 输出参数：
	char *outData： 输出数据，16 进制ASCII 字符串
5. 返回值：
	0：成功
	其他：失败错误代码
*********************************************************************************************************************/
int SMAPIDecrypt_index(UINT  nSock ,int DecryptKeyIndex, UINT mech, char *data, char *IV , char *outData);

/********************************************************************************************************************
1. 产生随机数（7.6.9 产生随机数）
2. 函数功能：
	产生输入长度的随机数。
3. 输入参数：
	UINT nSock：连接的socket 句柄
	int rdmLength：需要产生随机数的长度。
4. 输出参数：
	char *outData： 随机数，ASCII 字符串。（例如需要产生8 字节随机数，则该返
	回值为16 个ASCII 字符串）
5. 返回值：
	0：成功
	其他：失败错误代码
*********************************************************************************************************************/
int SMAPIGenerateRandom(UINT  nSock, int rdmLength,char * outData);

/********************************************************************************************************************
1.MAC 计算（7.2.13 产生MAC）
2. 函数功能：
        当mech = 1 时用PBOC2.0 双倍长模式计算输入数据的MAC 值。算法
        当mech = 2 时用PBOC2.0 单倍长模式计算输入数据的MAC 值。其算法;
	当mech = 3 时用SM4 计算输入数据的MAC 值。算法详见下图B；
	数据data 的填充算法如下：将输入输入按照8 / 16 字节为单位分为若干数据块，若最
	后的数据块的长度为8 / 16 字节，填充“0x800000000000…”;若最后数据块长度小于
	8 / 16 字节，首先填充0x80，再填充若干个0x00，使得最后的数据块长度为8 / 16 字
	节。

3. 输入参数：
	UINT nSock：连接的socket 句柄
	char *MACKey：经LMK 加密的MAC 密钥的密文值，16 进制ASCII 字符串。
	UINT mech：算法类型：1、2、3
	char *data：需要计算MAC 的数据，类型为十六进制ASCII 字符串
	char *IV：初始向量
4. 输出参数：
	char * Mac：Mac 的计算结果，16 位十六进制ASCII 字符串
5. 返回值： 
	0：成功
	其他：失败错误代码
*****************************************************************************************************************/
int SMAPIPBOCMAC(UINT  nSock , char *MACKey, UINT mech,char *data,char *IV, char * Mac);

/****************************************************************************************************************
1. MAC 计算(索引版) （7.2.13 产生MAC）
2. 函数功能：
	当mech = 1 时用PBOC2.0 双倍长模式计算输入数据的MAC 值。算法
	当mech = 2 时用PBOC2.0 单倍长模式计算输入数据的MAC 值。其算法
	当mech = 3 时用SM4 计算输入数据的MAC 值。算法详见下图B；
	数据data 的填充算法如下：将输入输入按照8 / 16 字节为单位分为若干数据块，若最
	后的数据块的长度为8 / 16 字节，填充“0x80000000000000…”;若最后数据块长度小
	于8 / 16 字节，首先填充0x80，再填充若干个0x00，使得最后的数据块长度为8 / 16字节。
3. 输入参数：
	UINT nSock：连接的socket 句柄
	int MACKeyIndex：MAK 密钥在加密机中的密钥索引，范围为[257，486]，并且该密钥为双倍长(16 字节)
	UINT mech：算法类型：1 、2、3
	char *data：需要计算MAC 的数据，类型为十六进制ASCII 字符串
	char *IV：初始向量
4. 输出参数：
	char * Mac：Mac 的计算结果，16 位十六进制ASCII 字符串
5. 返回值：
	0：成功
	其他：失败错误代码
*****************************************************************************************************************/
int SMAPIPBOCMAC_index(UINT  nSock , int MACKeyIndex, UINT mech,char *data, char *IV,  char * Mac);

/****************************************************************************************************************
1. 密钥分散（7.6.15 分散密钥并加密导出）
2. 函数功能：
	对输入主密钥（masterKey 由LMK 保护的密钥）进行分散。
3. 输入参数：
	UINT nSock：连接的socket 句柄
	char *masterKey：经LMK 加密的主密钥的密文值。
	UINT mech：分散算法类型：
	decryptMech = 20 表示DES_ECB 算法
	decryptMech = 17 表示DES_CBC 算法
	decryptMech = 3 表示SM4_ECB 算法
	decryptMech = 4 表示SM4_CBC 算法
	decryptMech = 5 表示AES_ECB 算法（暂不支持）
	decryptMech = 6 表示AES_CBC 算法（暂不支持）
	char * divdata：分散数据，16 进制ASCII 字符串
	char *IV：CBC 解密时的初始向量
4. 输出参数：
	char * derivedKey：密钥分散后经LMK 加密的密钥，16 进制ASCII 字符串
5. 返回值： 
	0：成功
	其他：失败错误代码
*****************************************************************************************************************/
int SMAPIderiveKey(UINT  nSock, char *masterKey, UINT mech, char *divdata, char *IV , char *derivedKey);

/****************************************************************************************************************
1. 密钥分散(索引版) （7.6.15 分散密钥并加密导出）
2. 函数功能：
	对输入密钥索引指定的主密钥进行分散。
3. 输入参数：
	UINT nSock：连接的socket 句柄
	int masterKeyIndex：待分散密钥在加密机中的索引。
	UINT mech：分散算法类型：
	decryptMech = 20 表示DES_ECB 算法
	decryptMech = 17 表示DES_CBC 算法
	decryptMech = 3 表示SM4_ECB 算法
	decryptMech = 4 表示SM4_CBC 算法
	decryptMech = 5 表示AES_ECB 算法（暂不支持）
	decryptMech = 6 表示AES_CBC 算法（暂不支持）
	char *data：分散数据，16 进制ASCII 字符串
	char *IV：CBC 解密时的初始向量
4. 输出参数：
	char * derivedKey：密钥分散后经LMK 加密的密文输出数据，16 进制ASCII 字符串
5. 返回值： 
	0：成功
	其他：失败错误代码
*****************************************************************************************************************/
int SMAPIderiveKey_index(UINT  nSock,int masterKeyIndex, UINT mech, char *data, char *IV ,char *derivedKey);

/****************************************************************************************************************
1. 密钥转加密（7.6.11 密钥转加密增强型）
2. 函数功能：
	用mech 指定算法对密钥进行转加密，即将key 由LMK 加密转为由
	wrapKey 对应的密钥加密。
3. 输入参数：
	UINT nSock：连接的socket 句柄
	char * wrapKey：经LMK 加密的加密密钥的密文值，16 进制ASCII 字符串。（例
	如：8 字节密钥，则该输入为16 个ASCII 字符串）
	UINT mech：算法类型：decryptMech = 20 表示DES_ECB 算法。
	decryptMech = 17 表示DES_CBC 算法。
	char * key：待处理的密钥数据，16 进制ASCII 字符串，数据长度为16 的整数倍。
	（该密钥数据同样经LMK 加密）
	char *IV：CBC 解密时的初始向量
4. 输出参数：
	char *outData： 输出密钥，16 进制ASCII 字符串，即由wrapKey 加密的Key 的密文
5. 返回值： 
	0：成功
	其他：失败错误代码
*****************************************************************************************************************/
int SMAPIwrap(UINT  nSock ,char * wrapKey, UINT mech, char *key, char *IV , char *outData);

/****************************************************************************************************************
1. 函数声明：密钥转加密(索引版) （7.6.11 密钥转加密增强型）
2. 函数功能：
	用mech 指定算法对密钥进行转加密，即将key 由LMK 加密转为由
	wrapKeyIndex 索引对应的密钥加密。
3. 输入参数：
	UINT nSock：连接的socket 句柄
	int wrapKeyIndex：密钥索引
	UINT mech：算法类型：decryptMech = 20 表示DES_ECB 算法。
	decryptMech = 17 表示DES_CBC 算法。
	char * key：待处理的密钥数据，16 进制ASCII 字符串，数据长度为16 的整数倍。
	（该密钥数据同样经LMK 加密）
	char *IV：CBC 解密时的初始向量
4. 输出参数：
	char *outData： 输出密钥，16 进制ASCII 字符串，即由wrapKeyIndex 索引对应
	密钥加密Key 的密文
5. 返回值： 
	0：成功
	其他：失败错误代码
*****************************************************************************************************************/
int SMAPIwrap_index(UINT  nSock , int wrapKeyIndex, UINT mech, char *key, char *IV , char *outData);

/****************************************************************************************************************
1. 密钥转加密扩展型（7.6.12 密钥转加密扩展型）
2. 函数功能：
	用以下算法对主控密钥进行转加密。其中，主控密钥= KeyMac^ KeyEnc^
	KeyDek。算法描述如下：
	步骤1：用LMK 解密KeyMac、KeyEnc、KeyDek 得到PlainKeyMac、
	Plain KeyEnc、PlainKeyDek。
	步骤2： Data1= PlainKeyMac^ PlainKeyEnc ^ PlainKeyDek
	步骤3： Data2= 长度(KeyHeader + Data1)+ KeyHeader + Data1 +填充
	数据，其中，长度为1 字节，填充数据方式同1.11 小节MAC 计算的
	填充方式。
	步骤4、用LMK 解密出wrapKey 明文，即PlainwrapKey
	步骤5、用PlainwrapKey 密钥和mech 制定算法加密Data2，将结果通
	过outData 数据返回。
3. 输入参数：
	UINT nSock：连接的socket 句柄
	char * KeyMac：经LMK 加密的加密密钥的密文值，16 进制ASCII 字符串。
	char * KeyEnc：经LMK 加密的加密密钥的密文值，16 进制ASCII 字符串。
	char * KeyDek：经LMK 加密的加密密钥的密文值，16 进制ASCII 字符串。
	char* KeyHeader：密钥头数据，16 进制ASCII 字符串。
	char *wrapKey,：经LMK 加密的转加密密钥密文值，16 进制ASCII 字符串。
	UINT mech：分散算法类型： mech = 20 表示DES_ECB 算法。
	mech = 17 表示DES_CBC 算法。
	char *IV：当mech =CBC 时的初始向量，16 进制ASCII 字符串。
4. 输出参数：
	char *outData： 输出的转加密之后的密钥，16 进制ASCII 字符串
5. 返回值： 
	0：成功
	其他：失败错误代码
*****************************************************************************************************************/
int SMAPIwrap_ext(UINT  nSock , char  *KeyMac, char  * KeyEnc, char  *KeyDek , char  *KeyHeader,
                   char  *wrapKey, UINT mech,  char *IV , char *outData);

/****************************************************************************************************************
1. 密钥转加密扩展型（索引版）（7.6.12 密钥转加密扩展型）
2. 函数功能：
	用以下算法对主控密钥进行转加密。其中，主控密钥= KeyMac^ KeyEnc^
	KeyDek。算法描述如下：
	步骤1：用LMK 解密KeyMac、KeyEnc、KeyDek 得到PlainKeyMac、
	Plain KeyEnc、PlainKeyDek。
	步骤2： Data1= PlainKeyMac^ PlainKeyEnc ^ PlainKeyDek
	步骤3： Data2= 长度(KeyHeader + Data1)+ KeyHeader + Data1 +填充
	数据，其中，长度为1 字节，填充数据方式同1.11 小节MAC 计算的
	填充方式。
	步骤4、用wrapKeyIndex 指定密钥和mech 制定算法加密Data2，将
	结果通过outData 数据返回。
3. 输入参数：
	UINT nSock：连接的socket 句柄
	char * KeyMac：经LMK 加密的加密密钥的密文值，16 进制ASCII 字符串。
	char * KeyEnc：经LMK 加密的加密密钥的密文值，16 进制ASCII 字符串。
	char * KeyDek：经LMK 加密的加密密钥的密文值，16 进制ASCII 字符串。
	char* KeyHeader：密钥头数据，16 进制ASCII 字符串。
	UINT wrapKeyIndex：转加密密钥索引
	UINT mech：分散算法类型： mech = 20 表示DES_ECB 算法。
	mech = 17 表示DES_CBC 算法。
	char *IV：当mech =CBC 时的初始向量，16 进制ASCII 字符串。
4. 输出参数：
	char *outData： 输出的转加密之后的密钥，16 进制ASCII 字符串
5. 返回值： 
	0：成功
	其他：失败错误代码
*****************************************************************************************************************/
int SMAPIwrap_ext_index(UINT  nSock , char  *KeyMac, char  * KeyEnc, char  *KeyDek , char  *KeyHeader,
                        UINT  wrapKeyIndex, UINT mech,  char *IV , char *outData);

/****************************************************************************************************************
1. 密钥转加密增强型（7.6.11 密钥转加密增强型）
2. 函数功能：
	用mech 指定算法对密钥进行转加密，即将key 由LMK 加密转为由
	wrapKey 对应的密钥加密。
	加密机操作步骤：
	步骤1：用LMK 解密wrapKey。
	步骤2：用LMK 解密key，得到PlainKey
	步骤3：计算DATALEN = LEN(prePix + PlainKey)
	步骤4：Data= DATALEN + prePix + PlainKey，填充数据方式同1.11 小
	节MAC 计算的填充方式。如果prePix 为空，则无密钥前缀
	步骤5：用步骤1 解密的wrapKey 和mech 制定算法加密Data，将结
	果通过outData 数据返回。
3. 输入参数：
	UINT nSock：连接的socket 句柄
	char * wrapKey：经LMK 加密的加密密钥的密文值，16 进制ASCII 字符串。（例
	如：8 字节密钥，则该输入为16 个ASCII 字符串）
	UINT mech：算法类型：decryptMech = 20 表示DES_ECB 算法。
	decryptMech = 17 表示DES_CBC 算法。
	char * key：待处理的密钥数据，16 进制ASCII 字符串，数据长度为16 的整数倍。
	（该密钥数据同样经LMK 加密）
	char *IV：CBC 解密时的初始向量
	char *prePix 待处理的密钥前缀。
4. 输出参数：
	char *outData： 输出密钥，16 进制ASCII 字符串，即由wrapKey 加密的Key 的密文
5. 返回值： 
	0：成功
	其他：失败错误代码
*****************************************************************************************************************/

int SMAPIwrapEnhance(UINT  nSock ,char * wrapKey, UINT mech, char *key, char *IV, char *prePix , char *outData);


/****************************************************************************************************************
1. 密钥转加密增强型(索引版) （7.6.11 密钥转加密增强型）
2. 函数功能：
	用mech 指定算法对密钥进行转加密，即将key 由LMK 加密转为由
	wrapKey 对应的密钥加密。
	加密机操作步骤：
	步骤1：用LMK 解密key，得到PlainKey
	步骤2：计算DATALEN = LEN(prePix + PlainKey)
	步骤3：Data= DATALEN +prePix + PlainKey，填充数据方式同1.11 小节MAC
	计算的填充方式。如果prePix 为空，则无密钥前缀
	步骤4：用wrapKeyIndex 指定的密钥索引和mech 制定算法加密Data，将结
	果通过outData 数据返回。
3. 输入参数：
	UINT nSock：连接的socket 句柄
	int wrapKeyIndex：指定的转加密密钥索引
	UINT mech：算法类型：decryptMech = 20 表示DES_ECB 算法。
	decryptMech = 17 表示DES_CBC 算法。
	char * key：待处理的密钥数据，16 进制ASCII 字符串，数据长度为16 的整数倍。
	（该密钥数据经LMK 加密）
	char *IV：CBC 解密时的初始向量
	char *prePix 待处理的密钥前缀。
4. 输出参数：
	char *outData： 输出密钥，16 进制ASCII 字符串，即由wrapKey 加密的Key 的密文
5. 返回值： 
	0：成功
	其他：失败错误代码
*****************************************************************************************************************/
int SMAPIwrapEnhance_index (UINT  nSock ,int wrapKeyIndex, UINT mech, char *key, char *IV, char *prePix ,  char *outData);

/****************************************************************************************************************
1. 用LMK 加密密钥扩展型（7.6.13 用HMK 加密密钥扩展型）
2. 函数功能：
	将三个子密钥进行异或，之后用LMK 加密，输出密文。算法描述如下：
	步骤1：用LMK 解密pszKeyMac、pszKeyEnc、pszKeyDek 得到PlainKeyMac、
	Plain KeyEnc、PlainKeyDek。
	步骤2： Data= PlainKeyMac^ PlainKeyEnc ^ PlainKeyDek
	步骤3：使用LMK 加密Data 得到其子密钥并输出。
3. 输入参数：
	UINT nSock：连接的socket 句柄
	char * pszKeyMac：经LMK 加密的加密密钥的密文值，16 进制ASCII 字符串。
	char * pszKeyEnc：经LMK 加密的加密密钥的密文值，16 进制ASCII 字符串。
	char * pszKeyDek：经LMK 加密的加密密钥的密文值，16 进制ASCII 字符串。
4. 输出参数：
	char * pszKeyUnderLMK： 密钥异或之后经LMK 加密的密钥，16 进制ASCII 字符串
5. 返回值： 
	0：成功
	其他：失败错误代码
*****************************************************************************************************************/
int SMAPIEncryptKeyExt (UINT  nSock,char  *pszKeyMac, char  * pszKeyEnc, char  *pszKeyDek , char  *pszKeyUnderLMK);


/****************************************************************************************************************
1. 制卡密钥的导入（7.2.2 导入密钥）
2. 函数功能：
	将制卡密钥(以KEK 加密)导入到加密机指定索引上
3. 输入参数：
	UINT nSock：连接的socket 句柄
	Int nKekIndex：传输主密钥的索引值(默认索引为257)
	byte *bKeyByKek：需要导入的制卡密钥(经过KEK 加密)
	int nKeyLen：制卡密钥的长度, 取值范围{8, 16, 24}
	char szCheckValue：制卡密钥的效验值， 8 个十六进制字符
	int nDestIndex：需要将密钥导入的索引位置，取值范围[258, 486]，该密钥默认的
	Tag 为3
4. 输出参数：无
5. 返回值：
	0： 执行成功
	1： 输入参数验证失败
	2： 无效的校验值
	3： 向加密机发送数据失败
	4： 接收加密机数据超时
	5： 接收到的数据格式错
	9:  其他错误
*****************************************************************************************************************/
int SMAPIImportKey(UINT nSock, int nKekIndex, byte *bKeyByKek, int nKeyLen, char szCheckValue[8 + 1],  int nDestIndex);


/****************************************************************************************************************
1. 制卡密钥的导出（7.2.5 LMK 加密密钥）
2. 函数功能：
	从加密机指定索引上将制卡密钥(以HMK 加密)导出(存入数据库)
3. 输入参数：
	UINT nSock：连接的socket 句柄
	int nIndex：需要将密钥导出的索引位置，取值范围[256, 486]，该密钥默认的Tag
	为3
4. 输出参数：
	byte *bKeyByKek：需要导出的制卡密钥(经过HMK 加密)
	int *pnKeyLen：制卡密钥的长度
	char szCheckValue：制卡密钥的效验值， 8 个十六进制字符
5. 返回值：
	0： 执行成功
	1： 输入参数验证失败
	2： 无效的索引值
	3： 向加密机发送数据失败
	4： 接收加密机数据超时
	5： 接收到的数据格式错
	9:  其他错误
*****************************************************************************************************************/
int SMAPIExportKey(UINT nSock, int nIndex, byte *bKeyByHMK, int *pnKeyLen, char szCheckValue[8 + 1]);

/****************************************************************************************************************
1. 数据转加密（7.3.5 数据转加密）
2. 函数功能：
	将被decryptKeyIndex 索引指示的密钥加密的密文，转换为被密钥（encryptKey）加密的密文
3. 输入参数：
	UINT nSock：连接的socket 句柄
	Int decryptKeyIndex：解密密钥索引[257 486]。
	UINT decryptMech：解密密钥算法类型:
	decryptMech = 20 表示DES_ECB 算法
	decryptMech = 17 表示DES_CBC 算法
	decryptMech = 3 表示SM4_ECB 算法
	decryptMech = 4 表示SM4_CBC 算法
	decryptMech = 5 表示AES_ECB 算法（暂不支持）
	decryptMech = 6 表示AES_CBC 算法（暂不支持）
	char *encryptKey：经LMK 加密的加密密钥的密文值，16 进制ASCII 字符串。（例如：8 字节密钥，则该输入为16 个ASCII 字符串）
	UINT encryptMech：加密密钥算法类型：
	decryptMech = 20 表示DES_ECB 算法
	decryptMech = 17 表示DES_CBC 算法
	decryptMech = 3 表示SM4_ECB 算法
	decryptMech = 4 表示SM4_CBC 算法
	decryptMech = 5 表示AES_ECB 算法（暂不支持）
	decryptMech = 6 表示AES_CBC 算法（暂不支持）
	char *data：待处理数据，16 进制ASCII 字符串。
	char *decryptIV,：CBC 解密时的初始向量
	char *encryptIV,：CBC 加密时的初始向量
4. 输出参数：
	char *outData： 输出数据，16 进制ASCII 字符串。
5. 返回值： 
	0：成功
	其他：失败错误代码
*****************************************************************************************************************/

int SMAPIDecryptEncrypt(UINT nSock , int decryptKeyIndex, UINT decryptMech, char  *encryptKey, UINT encryptMech, 
                        char *data, char *decryptIV, char *encryptIV, char *outData);

/****************************************************************************************************************
1. 导出内部SM4 密钥_国密版（7.2.5LMK 加密密钥）
2. 函数功能：
	从加密机指定索引上将制卡密钥(以HMK 加密)导出(存入数据库)
3. 输入参数：
	UINT nSock：连接的socket 句柄
	int nIndex：被导出密钥的索引位置，取值范围[256, 486]，该密钥默认的Tag 为3
4. 输出参数：
	byte *bKeyByHMK：需要导出的制卡密钥(经过HMK 加密)
	int *pnKeyLen：制卡密钥的长度
	char szCheckValue：制卡密钥的效验值， 8 个十六进制字符
5. 返回值：
	0： 执行成功
	1： 输入参数验证失败
	2： 无效的索引值
	3： 向加密机发送数据失败
	4： 接收加密机数据超时
	5： 接收到的数据格式错
	9:  其他错误
*****************************************************************************************************************/

int SMAPIExportKey_GM(UINT nSock, int nIndex,byte *bKeyByHMK, int *pnKeyLen, char szCheckValue[8 + 1]);

/****************************************************************************************************************
1. 子密钥离散扩展1（主密钥加密子密钥）（7.6.15分散密钥并加密导出）
2. 函数功能：
	将应用主密钥离散为子密钥使用传入的MasterKey 加密（DES）分散因子得到子密钥，再计算（DES）
	子密钥的校验值。返回被HMK 加密（DES）的密钥密文。
3. 输入参数：
	UINT nSock：连接的socket 句柄
	byte *pbMasterKey：被离散的应用主密钥(被HMK-3DES 加密)，二进制数，16 字节长。
	byte *pbFactor：分散因子，长度同主密钥
4. 输出参数：
	byte *pbSubKey：离散的子密钥的密文(被HMK-3DES 加密)，二进制数，16 字节长，
	char pszCheckValue[8]: 产生子密钥的效验值（DES 加密得到），是将CheckValue
	的前四个字节进行扩展，得到的8 个十六进制字符
5. 返回值：
	0： 执行成功
	1： 输入参数验证失败
	2： 无效的密钥(MasterKey)
	3： 向加密机发送数据失败
	4： 接收加密机数据超时
	5： 接收到的数据格式错
	9:  其他错误
*****************************************************************************************************************/

int SMAPIDisreteSubKeyExt1(UINT nSock, byte *pbMasterKey, byte *pbFactor, byte *pbSubKey, char pszCheckValue[8 + 1]);

/****************************************************************************************************************
1. 子密钥离散扩展2（国密转加密子密钥）（7.6.15分散密钥并加密导出）
2. 函数功能：
	将应用主密钥离散为卡子密钥或者会话子密钥，用传入的KEK-SM4 加密输出
	使用传入的MasterKey 加密（DES）分散因子得到子密钥，再计算（DES）
	子密钥的校验值。返回被KEK 加密（SM4）的密钥密文。
3. 输入参数：
	UINT nSock：连接的socket 句柄
	byte *pbKek：加密子密钥的KEK(被HMK 加密)，加密算法为SM4，二进制数，16 字节长。
	byte *pbMasterKey：被离散的应用主密钥(被HMK-3DES 加密)，二进制数，16 字节长。
	byte *pbFactor：分散因子，长度同主密钥
4. 输出参数：
	byte *pbSubKey：离散的子密钥的密文(被KEK-SM4 加密)，二进制数，16 字节长，
	char pszCheckValue[8]: 产生子密钥的效验值（DES 加密得到），是将CheckValue
	的前四个字节进行扩展，得到的8 个十六进制字符
5. 返回值：
	0： 执行成功
	1： 输入参数验证失败
	2： 无效的密钥(MasterKey、KEK)
	3： 向加密机发送数据失败
	4： 接收加密机数据超时
	5： 接收到的数据格式错
	9:  其他错误
*****************************************************************************************************************/

int SMAPIDisreteSubKeyExt2(UINT nSock, byte *pbKek, byte *pbMasterKey, byte *pbFactor, byte *pbSubKey, char pszCheckValue[8 + 1]);

/****************************************************************************************************************

1. PIN 转加密-双主账号_国密版（7.6.3 转加密PIN-双主账号）
2. 函数功能：
	转加密PIN 密文，双主帐号参与计算(X9.8B)
3. 输入参数：
	UINT nSock：连接的socket 句柄
	Int nMode:转换类型. 1: 2DES-->2DES 2: 2DES-->SM4 3: SM4-->2DES 4:
	SM4-->SM4
	char*pszSrcPan: 主帐号，ASCII 字符串，上层应用调用时传入全部的PAN 号，计算
	时使用去掉校验位的最右12 个字符
	int nSrcPanLen：主帐号长度（字符数），13-19 位
	char *pszDstPan: 主帐号，ASCII 字符串，上层应用调用时传入全部的PAN 号，计
	算时使用去掉校验位的最右16 个字符
	int nDstPanLen：主帐号长度（字符数），13-19 位
	byte *pbSrcPinKey：经HMK 加密的源Pik 的密文值，二进制数
	int nSrcPinKeyLen：pbSrcPinKey 的长度，字节数
	byte *pbDestPinKey：经HMK 加密的目的Pik 的密文值，二进制数
	int nDestPinKeyLen：pbDestPinKey 的长度，字节数
	byte *pszSrcPinCipher：源Pinblock 密文，长度与源算法分组长度相等
4. 输出参数：
	char *pbDestPinCipher：目的Pinblock 密文,目的算法为DES 时长度为8 字节，目
	的算法为SM4 时长度为16 字节
5. 返回值：
	0： 执行成功
	1： 输入参数验证失败
	2： 无效的索引值
	3： 向加密机发送数据失败
	4： 接收加密机数据超时
	5： 接收到的数据格式错
	9:  其他错误
*****************************************************************************************************************/

int SMAPIConvertPinX98B_DoublePan(UINT nSock, int nMode, char *pszSrcPan, int nSrcPanLen, char *pszDstPan, int nDstPanLen, 
                                  byte *pbSrcPinKey, int nSrcPinKeyLen, byte *pbDestPinKey, int nDestPinKeyLen, 
                                  byte *pszSrcPinCipher, byte pbDes1tPinCipher[16]);

/****************************************************************************************************************
1. PIN 转加密_X98 到IBM3624（7.6.3 转加密PIN-双主账号）
2. 函数功能：
	转加密PIN 密文，从X98 格式转换成IBM3624 格式
3. 输入参数：
	UINT nSock：连接的socket 句柄
	Int nMode:转换类型. 1: DES->IBM3624 2: 2DES->IBM3624
	3: 3DES->IBM3624 4: SM4->IBM3624
	int nX98Algo：X98 算法类型。1: X98A 2: X98B
	char *pszSrcPan: 当nX98Algo=1 时，pszPan = NULL
	当nX98Algo=2 时，源主帐号，ASCII 字符串，上层调用时传入全
	部的PAN 号，计算时使用PAN 号最右边的16 位;
	int nSrcPanLen：源主帐号长度（字符数），13-19 位
	char *pszDstPan: 目的主账号，ASCII 字符串，上层调用时传入全部的PAN 号，计算
	时使用PAN 号最右边的16 位;
	int nDstPanLen: 目的主帐号长度（字符数），13-19 位
	byte *pbSrcPinKey：经HMK 加密的源Pik 的密文值，二进制数
	int nSrcPinKeyLen：pbSrcPinKey 的长度，字节数
	byte *pbDstPinKey: 经HMK 加密的目的Pik 的密文值，二进制数
	int nDstPinKeyLen: pbDstPinKey 的长度，字节数
	byte *pszSrcPinCipher：源Pin 密文，长度与nMode 定义的算法分组长度相等
4. 输出参数：
	char *pbDestPinCipher：IBM3624 格式的Pin Offset，长度范围[1~12]
5. 返回值：
	0： 执行成功
	1： 输入参数验证失败
	2： 无效的索引值
	3： 向加密机发送数据失败
	4： 接收加密机数据超时
	5： 接收到的数据格式错
	9:  其他错误
*****************************************************************************************************************/
int SMAPIConvertPinX98ToIBM3624(UINT nSock, int nMode, int nX98Algo, char *pszSrcPan, int nSrcPanLen, char *pszDstPan, 
                                int nDstPanLen, byte *pbPinKey, int nPinKeyLen, byte *pbIBM3624Key, int nIBM3624KeyLen, 
                                byte *pszSrcPinCipher, char pbDestPinCipher[13]);

/****************************************************************************************************************
1. 用LMK 加密密钥（7.6.13 用HMK 加密密钥扩展型）
2. 函数功能：
	将密钥的明文，以LMK 加密，输出密文
3. 输入参数：
	UINT nSock：连接的socket 句柄
	char *pszPlainKey：密钥的明文，16 进制ASCII 字符串, 长度由nKeyLen 指定
	int nKeyLen：pszPlainKey 的长度，取值范围：{8,16,24}
4. 输出参数：
	char * pszKeyUnderLMK：被LMK 加密的密钥的密文
5. 返回值：
	0： 成功
	1： 输入参数验证失败
	3： 向加密机发送数据失败
	4： 接收加密机数据超时
	5： 接收到的数据格式错
	9:  其他错误
*****************************************************************************************************************/
int SMAPIEncryptKey_LMK (UINT nSock, char *pszPlainKey,char *pszKeyUnderLMK);


/******************************************************  卫士通   ********************************************/
/************************************************************************************************************
 *
 * 功能描述: 用ANSI X9.8标准对PIN明文加密,主帐号不参与计算(指令D022)
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          nAlgo:  算法类型: Single_Des = 1; Double_Des = 2; Triple_Des = 3
 *          pbPinKey: 经HMK(LMK)加密的Pik的密文值,二进制数
 *                    buffer长度: nAlgo = 1时,8字节长
 *                                nAlgo = 2时,16字节长
 *                                nAlgo = 3时,24字节长
 *          pszPlainPin: Pin的明文. buffer长度: 13字节长, 数字字符型
 *           
 * 输出参数:
 *          pbCryptPin: Pin的密文,8字节长的二进制数
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          2: 无效的密钥(PIK);
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          6: 明文数据格式错(Pin);
 *          9 -- 其它错误
 *
 ***********************************************************************************************************/
int SMAPIEncryptPinX98A(int nSock,int nAlgo,u8 *pbPinKey,char *pszPlainPin,u8 bCryptPin[8]);


/**************************************************************************************
 *
 * 功能描述: 用ANSI X9.8标准对PIN明文加密,主帐号参与计算(指令D022)
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          nAlgo:  算法类型: Single_Des = 1; Double_Des = 2; Triple_Des = 3
 *          pszPan: 用户主帐号,ASCII字符串
 *          nPanLen: 主帐号长度(字节数)
 *          pbPinKey: 经HMK(LMK)加密的Pik的密文值,二进制数
 *                    buffer长度: nAlgo = 1时,8字节长
 *                                nAlgo = 2时,16字节长
 *                                nAlgo = 3时,24字节长
 *          pszPlainPin: Pin的明文. buffer长度: 13字节长, 数字字符型
 *           
 * 输出参数:
 *          pbCryptPin: Pin的密文,8字节长的二进制数
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          2: 无效的密钥(PIK);
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          6: 明文数据格式错(Pin);
 *          9 -- 其它错误
 *
 ***************************************************************************************/
int SMAPIEncryptPinX98B(int nSock,int nAlgo,char *pszPan, int nPanLen, u8 *pbPinKey, char *pszPlainPin, 
                        u8 bCryptPin[8]);

/**************************************************************************************
 *
 * 功能描述: 用ANSI X9.8标准对PIN明文解密,主帐号不参与计算(指令D024)
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          nAlgo:  算法类型: Single_Des = 1; Double_Des = 2; Triple_Des = 3
 *          pbPinKey: 经HMK(LMK)加密的Pik的密文值,二进制数
 *                    buffer长度: nAlgo = 1时,8字节长
 *                                nAlgo = 2时,16字节长
 *                                nAlgo = 3时,24字节长
 *          pbCryptPin: Pin的密文,8字节长的二进制数据
 *           
 * 输出参数:
 *          szPlainPin: Pin的明文, buffer长度: 13字节长, 数字字符型
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          2: 无效的密钥(PIK);
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          6: PIN密文数据格式错;
 *          9 -- 其它错误
 *
 ***************************************************************************************/
int SMAPIDecryptPinX98A(int nSock,int nAlgo,u8 *pbPinKey, u8 *pbCryptPin, 
                        char szPlainPin[13]);


/**************************************************************************************
 *
 * 功能描述: 用ANSI X9.8标准对PIN明文解密,主帐号参与计算(指令D024)
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          nAlgo:  算法类型: Single_Des = 1; Double_Des = 2; Triple_Des = 3
 *          pszPan: 主帐号,ASCII字符
 *          nPanLen: 主帐号长度(字节数, 值为13~19)
 *          pbPinKey: 经HMK(LMK)加密的Pik的密文值,二进制数
 *                    buffer长度: nAlgo = 1时,8字节长
 *                                nAlgo = 2时,16字节长
 *                                nAlgo = 3时,24字节长
 *          pbCryptPin: Pin的密文,8字节长的二进制数据
 *           
 * 输出参数:
 *          szPlainPin: Pin的明文, buffer长度: 13字节长, 数字字符型
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          2: 无效的密钥(PIK);
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          6: PIN密文数据格式错;
 *          9 -- 其它错误
 *
 ***************************************************************************************/
int SMAPIDecryptPinX98B(int nSock,
                                int nAlgo, 
                                char *pszPan, 
                                int nPanLen, 
                                u8 *pbPinKey, 
                                u8 *pbCryptPin, 
                                char szPlainPin[13]);


/**************************************************************************************
 *
 * 功能描述: 用指定的MacKey计算一段报文数据的MAC值(指令D032)
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          nAlgo:  算法类型: ECB = 1; X9.9 = 2; x9.19 = 3
 *          pbMacKey: 经HMK(LMK)加密的Mak的密文值,二进制数
 *          nMakLen: Mak长度, 即pbMacKey的buffer长度
 *                   nAlgo = 1和nAlgo = 2时, nMakLen应为8
 *                   nAlgo = 3时, nMakLen应为16
 *          pbMsgBuf: 需要计算MAC的数据buffer,二进制数
 *          nMsgLen:  数据buffer的长度, 范围: 8--2048
 *           
 * 输出参数:
 *          bMAC: 计算所得的数据报文的MAC
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          2: 无效的密钥(MAK);
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9 -- 其它错误
 *
 ***************************************************************************************/
int SMAPICalcMac(int nSock,
                       int nAlgo, 
                       u8 *pbMacKey, 
                       int nMakLen, 
                       u8 *pbMsgBuf, 
                       int nMsgLen, 
                       u8 bMAC[8]);

/**************************************************************************************
 *
 * 功能描述: 用指定的MacKey计算一段报文数据的MAC值(指令D342)
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          nMode:  加密模式: ECB = 1; X9.9 = 2; x9.19 = 3;
 *							  ECB_SM4 = 4; X9.9_SM4 = 5;
 *							  ECB_SM4_PBOC = 6; X9.9_SM4_PBOC = 7;
 *
 *          pbKey: 经HMK(LMK)加密的Mak的密文值,二进制数
 *				   nMode=1/2时，MAK长度为8字节，
 *                 nMode=3/4/5/6/7时，MAK长度为16字节
 *          pbInData: 需要计算MAC的数据data,二进制数
 *          nDataLen:  数据data的长度, 范围: 1--2048
 *			pbIV: 初始化向量，二进制数，16字节长，全0x00
 *           
 * 输出参数:
 *          pbMAC: 计算所得的数据报文的MAC，16字节长
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          2: 无效的密钥(MAK);
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9 -- 其它错误
 *
 ***************************************************************************************/
int SMAPICalcMac_GM(int nSock,int nMode,u8 *pbKey,u8 *pbInData,	int nDataLen, u8 *pbIV, 
		    u8 *pbMAC);



/**************************************************************************************
 *
 * 功能描述: 将被密钥1加密的密文,转换为被密钥2加密的密文,其中密钥1和密钥2
 *           已分别提交到加密模块的两个密钥寄存器中(指令D016).
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          nAlgo1:  使用密钥1加密时采用的加密算法的标识
 *                   (Single_Des = 1; Double_Des = 2; Triple_Des = 3)
 *          pbKey1: 经HMK加密的密钥1的密文值,二进制数
 *                  当nAlgo1 = 1时, 8字节长;
 *                  当nAlgo1 = 2时, 16字节长;
 *                  当nAlgo1 = 3时, 24字节长
 *          nAlgo2:  使用密钥2加密时采用的加密算法的标识
 *                   (Single_Des = 1; Double_Des = 2; Triple_Des = 3)
 *          pbKey2: 经HMK加密的密钥2的密文值,二进制数
 *                  当nAlgo2 = 1时, 8字节长;
 *                  当nAlgo2 = 2时, 16字节长;
 *                  当nAlgo2 = 3时, 24字节长 
 *          pbSrcBlock: 被密钥1加密的密文数据,二进制数,8字节长
 *           
 * 输出参数:
 *          bDestBlock: 被密钥2加密的密文数据,二进制数,8字节长
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          2: 无效的密钥(密钥1或密钥2);
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9 -- 其它错误
 *
 ***************************************************************************************/
int SMAPITranslateBlock(int nSock,
                               int nAlgo1, 
                               u8 *pbKey1, 
                               int nAlgo2, 
                               u8 *pbKey2, 
                               u8 *pbSrcBlock, 
                               u8 bDestBlock[8]);




/**************************************************************************************
 *
 * 功能描述: 将被HMK加密的密钥的密文, 转换为以KEK加密的密文(导出密钥:指令D004)
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          nAlgo:  KEK加密算法类型
 *                   (Single_Des = 1; Double_Des = 2; Triple_Des = 3)
 *          pbKEK: 经HMK加密的KEK的密文值, 二进制数
 *                  当nAlgo1 = 1时, 8字节长;
 *                  当nAlgo1 = 2时, 16字节长;
 *                  当nAlgo1 = 3时, 24字节长
 *          pbKeyUnderLMK:  被HMK(LMK)加密的密钥的密文, 二进制数, 长度由nKeyLen指定
 *          nKeyLen: 被加密密钥的长度, 取值范围: {8, 16, 24}
 *           
 * 输出参数:
 *          pbKeyUnderKEK: 被KEK加密的密钥的密文, 二进制数, 长度由nKeyLen指定
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          2: 无效的密钥(KEK);
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9 -- 其它错误
 *
 ***************************************************************************************/
int SMAPITranslateKeyOutOf(int nSock,
                                    int nAlgo, 
                                    u8 *pbKEK, 
                                    u8 *pbKeyUnderHMK, 
                                    int nKeyLen, 
                                    u8 *pbKeyUnderKEK);


/**************************************************************************************
 *
 * 功能描述: 将被KEK加密的密钥的密文, 转换为以HMK加密的密文(导入密钥: 指令D002)
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          nAlgo:  KEK加密算法类型
 *                   (Single_Des = 1; Double_Des = 2; Triple_Des = 3)
 *          pbKEK: 经HMK加密的KEK的密文值, 二进制数
 *                  当nAlgo1 = 1时, 8字节长;
 *                  当nAlgo1 = 2时, 16字节长;
 *                  当nAlgo1 = 3时, 24字节长
 *          pbKeyUnderKEK:  被KEK加密的密钥的密文, 二进制数, 长度由nKeyLen指定
 *          nKeyLen: 被加密密钥的长度, 取值范围: {8, 16, 24}
 *           
 * 输出参数:
 *          pbKeyUnderHMK: 被HMK加密的密钥的密文, 二进制数, 长度由nKeyLen指定
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          2: 无效的密钥(KEK);
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9 -- 其它错误
 *
 ***************************************************************************************/
int SMAPITranslateKeyInTo(int nSock,
                                  int nAlgo, 
                                  u8 *pbKEK, 
                                  u8 *pbKeyUnderKEK, 
                                  int nKeyLen, 
                                  u8 *pbKeyUnderHMK);

/**************************************************************************************
 *
 * 功能描述: 根据指定长度随机生成一个密钥, 并返回密钥的效验值; 并根据nIndex选择是否将
 *           产生的密钥保存到加密机的某个索引位上(指令D006、D052、D054、D00C).
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          nKeyLen:  要生成的随机密钥的长度, 取值范围: {8, 16, 24}
 *          pszServId: 打印在密码信封上的终端编号, ASCII字符, 长度由nServIdLen指定
 *          nServIdLen: pszServId的长度
 *          nMode: 密钥被保存的方式
 *                 	0: 不保存;
 *                 	1: 打印密码信封;
 *                 	2: 保存到IC卡上.
 *          nIndex: 索引号, 值为 0: 不保存到加密机上
 *                               1 -- 255: 密钥存储到加密机上相应的索引值
 *           
 * 输出参数:
 *          pbKey: 随机产生的密钥(被HMK加密), 二进制数, 调用函数应分配24字节
 *                 的存储空间, 返回数据实际长度由nKeyLen指定
 *          szCheckValue: 产生密钥的效验值, 是将CheckValue的前四个字节进行扩展而
 *                        得到的8个十六进制字符
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          8: 打印密钥信封
 *          9 -- 其它错误
 *
 * 密钥信封格式: 由程序执行目录下的XXXX.fmt文件指定, 其中: 格尔为GeEr.fmt;
 *               卫士通为: WeiShiTong.fmt; 歌盟为: GeMeng.fmt
 ***************************************************************************************/
int SMAPIGenerateKey(int nSock,
                            int nKeyLen, 
                            char *pszServId,
                            int nServIdLen,
                            int nMode, 
                            int nIndex,
                            u8 *pbKey, 
                            u8 szCheckValue[8]);



/**************************************************************************************
 *
 * 功能描述: 采用内部算法对一段数据进行"掩盖", 输出密文(指令D018)
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          pszPlainText:  明文数据段, ASCII字符, 长度由nTextLen指定
 *          nTextLen: pszPlainText的字节长度
 *           
 * 输出参数:
 *          pszHiddenText: 掩盖之后的密文数据,ASCII字符, 长度由nTextLen指定
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9 -- 其它错误
 *
 ***************************************************************************************/
int SMAPIHideBlock(int nSock, char *pszPlainText, int nTextLen, char *pszHiddenText);


/**************************************************************************************
 *
 * 功能描述: 采用内部算法对一段经过"掩盖"的数据进行还原, 输出明文(指令D019)
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          pszHiddenText:  被掩盖密文数据, ASCII字符, 长度由nTextLen指定
 *          nTextLen: pszHiddenText的字节长度
 *           
 * 输出参数:
 *          pszPlainText: 被还原的明文数据, ASCII字符, 长度由nTextLen指定
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9 -- 其它错误
 *
 ***************************************************************************************/
int SMAPIRevalBlock(int nSock, char *pszHiddenText, int nTextLen, char *pszPlainText);



/**************************************************************************************
 *
 * 功能描述: 将密钥的明文, 以HMK(LMK)加密, 输出密文(根据HMK的长度,选择加密算法),指令D008
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          pbPlainKey:  密钥的明文, 二进制数, 长度由nKeyLen指定
 *          nKeyLen: pbPlainKey的字节长度, 取值范围: {8, 16, 24}
 *           
 * 输出参数:
 *          pbKeyUnderLMK: 被HMK(LMK)加密的密钥的密文
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9 -- 其它错误
 *
 ***************************************************************************************/
int SMAPIEncryptKey(int nSock, u8 *pbPlainKey, int nKeyLen, u8 *pbKeyUnderLMK);

/**************************************************************************************
 *
 * 功能描述: 将密钥的明文, 以HMK(LMK)加密, 输出密文(根据HMK的长度,选择加密算法),指令D348
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *			nAlg:	加密算法, 1:DES 4:SM4
 *          pbPlainKey:  密钥的明文, 二进制数, 长度由nKeyLen指定
 *          nKeyLen: pbPlainKey的字节长度, 取值范围: {8, 16, 24}
 *           
 * 输出参数:
 *          pbKeyUnderLMK: 被HMK(LMK)加密的密钥的密文
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9 -- 其它错误
 *
 ***************************************************************************************/
int SMAPIEncryptKey_GM(int nSock, int nAlg, u8 *pbPlainKey, int nKeyLen, u8 *pbKeyUnderLMK);


/**************************************************************************************
 *
 * 功能描述: 用DES类算法以ECB模式对明文数据进行加密(指令D012)
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          nAlgo:  算法类型(Single_Des = 1; Double_Des = 2; Triple_Des = 3)
 *          pbKey:  DES密钥的密文(由HMK/LMK加密), 二进制数
 *                  当nAlgo = 1时, 长度为8字节
 *                  当nAlgo = 2时, 长度为16字节
 *                  当nAlgo = 3时, 长度为24字节
 *          pbPlainBlock: 需要加密的明文, 二进制数, 长度由nBlockLen指定
 *          nBlockLen: pbPlainBlock的长度, 取值范围: 8的整数倍, 小于等于1024
 *           
 * 输出参数:
 *          pbCryptBlock: 加密之后的密文, 二进制数, 长度由nBlockLen指定
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          2: 无效的密钥(KEK)
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9 -- 其它错误
 *
 ***************************************************************************************/
int SMAPIEncryptBlock(int nSock, int nAlgo, u8 *pbKey, u8 *pbPlainBlock,int nBlockLen, 
                      u8 *pbCryptBlock);



/**************************************************************************************
 *
 * 功能描述: 用DES类算法以ECB模式对密文数据进行解密(指令D014)
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          nAlgo:  算法类型(Single_Des = 1; Double_Des = 2; Triple_Des = 3)
 *          pbKey:  DES密钥的密文(由HMK/LMK加密), 二进制数
 *                  当nAlgo = 1时, 长度为8字节
 *                  当nAlgo = 2时, 长度为16字节
 *                  当nAlgo = 3时, 长度为24字节
 *          pbCryptBlock: 需要解密的密文, 二进制数, 长度由nBlockLen指定
 *          nBlockLen: pbCryptBlock的长度, 取值范围: 8的整数倍, 小于等于1024
 *           
 * 输出参数:
 *          pbPlainBlock: 解密之后的明文, 二进制数, 长度由nBlockLen指定
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          2: 无效的密钥(KEK)
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9 -- 其它错误
 *
 ***************************************************************************************/
int SMAPIDecryptBlock(int nSock,int nAlgo,u8 *pbKey,u8 *pbCryptBlock,int nBlockLen,
                      u8 *pbPlainBlock);


/**************************************************************************************
 *
 * 功能描述: 用DES类算法以CBC模式对明文数据进行加密
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          nAlgo:  算法类型(Single_Des = 1; Double_Des = 2; Triple_Des = 3)
 *          pbKey:  DES密钥的密文(由HMK/LMK加密), 二进制数
 *                  当nAlgo = 1时, 长度为8字节
 *                  当nAlgo = 2时, 长度为16字节
 *                  当nAlgo = 3时, 长度为24字节
 *          pbPlainBlock: 需要加密的明文, 二进制数, 长度由nBlockLen指定
 *          nBlockLen: pbPlainBlock的长度, 取值范围: 8的整数倍, 小于等于1024
 *          pbIV: 初始化向量, 二进制数, 长度为8字节
 *           
 * 输出参数:
 *          pbCryptBlock: 加密之后的密文, 二进制数, 长度由nBlockLen指定
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          2: 无效的密钥(KEK)
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9 -- 其它错误
 *
 ***************************************************************************************/
int SMAPIEncryptCBC(int nSock, 
                           int nAlgo, 
                           u8 *pbKey, 
                           u8 *pbPlainBlock, 
                           int nBlockLen, 
                           u8 *pbIV,
                           u8 *pbCryptBlock);


/**************************************************************************************
 *
 * 功能描述: 用DES类算法以CBC模式对明文数据进行加密
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          nAlgo:  算法类型(Single_Des = 1; Double_Des = 2; Triple_Des = 3)
 *          pbKey:  DES密钥的密文(由HMK/LMK加密), 二进制数
 *                  当nAlgo = 1时, 长度为8字节
 *                  当nAlgo = 2时, 长度为16字节
 *                  当nAlgo = 3时, 长度为24字节
 *          pbCryptBlock: 需要解密的密文, 二进制数, 长度由nBlockLen指定
 *          nBlockLen: pbPlainBlock的长度, 取值范围: 8的整数倍, 小于等于1024
 *          pbIV: 初始化向量, 二进制数, 长度为8字节
 *           
 * 输出参数:
 *          pbPlainBlock: 解密之后的明文, 二进制数, 长度由nBlockLen指定
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          2: 无效的密钥(KEK)
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9 -- 其它错误
 *
 ***************************************************************************************/
int SMAPIDecryptCBC(int nSock, 
                           int nAlgo, 
                           u8 *pbKey, 
                           u8 *pbCryptBlock, 
                           int nBlockLen, 
                           u8 *pbIV,
                           u8 *pbPlainBlock);


/**************************************************************************************
 *
 * 功能描述: 根据输入参数计算CVV
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          pbCVK:  CVK的密文(LMK加密), 二进制数, 16字节长
 *          pszPan: 主账号, ASCII字符, 长度由nPanLen指定
 *          nPanLen: pszPan的长度, 取值范围: {16, 19}
 *          pszExpireDate: 卡有效期, 格式为YYMM, ASCII字符, 4字节长
 *          pszServiceCode: 服务代码, ASCII字符, 3字节长 
 *           
 * 输出参数:
 *          szCVV: CVV值, ASCII字符, 3字节长
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          2: 无效的密钥(CVK)
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9 -- 其它错误
 *
 ***************************************************************************************/
int SMAPICalCVV(int nSock,
                     u8 *pbCVK, 
                     char *pszPan, 
                     int nPanLen,
                     char *pszExpireDate, 
                     char *pszServiceCode, 
                     char szCVV[3]);



/**************************************************************************************
 *
 * 功能描述: 根据输入参数计算PVV
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          pbPVK:  PVK的密文(LMK加密), 二进制数, 16字节长
 *          pszPan: 主账号, ASCII字符, 长度由nPanLen指定
 *          nPanLen: pszPan的长度, 取值范围: {16, 19}
 *          pszPlainPin: 个人密码的明文, ASCII字符, 12字节长
 *          nPVKIndex: PVK索引代号
 *           
 * 输出参数:
 *          szPVV: PVV值, ASCII字符, 4字节长
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          2: 无效的密钥(PVK)
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9 -- 其它错误
 *
 ***************************************************************************************/
int SMAPICalPVV(int nSock, u8 *pbPVK, char *pszPan,  
                     int nPanLen,
                     char *pszPlainPin, 
                     int nPVKIndex, 
                     char szPVV[4]);



/**************************************************************************************
 *
 * 功能描述: 根据输入参数用IBM3624方法生成PIN OFFSET
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          pbKey:  用HMK(LMK)加密的密文密钥, 二进制数, 8字节长
 *          pszPan: 主账号, ASCII字符, 长度由nPanLen指定
 *          nPanLen: pszPan的长度, 取值范围: {16, 19}
 *          pszPlainPin: 个人密码的明文, ASCII字符, 12字节长
 *           
 * 输出参数:
 *          szOffset: PIN OFFSET, ASCII字符, 12字节长
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          2: 无效的密钥(KEY)
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9 -- 其它错误
 *
 ***************************************************************************************/
int SMAPIIBM3624(int nSock,u8 *pbKey, char *pszPan, int nPanLen, char *pszPlainPin,
                 char szOffset[12]);



/**************************************************************************************
 *
 * 功能描述: 产生指定位数的十进制随机数字串
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          nDigitNum:  数字的位数
 *           
 * 输出参数:
 *          pszDigits: 产生的随机数字串, ASCII字符, 长度为(nDigitNum + 1)
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9 -- 其它错误
 *
 ***************************************************************************************/
int SMAPIGenRandDigits(int nSock, int nDigitNum, char *pszDigits);



/**************************************************************************************
 *
 * 功能描述: 检验指定密钥的CheckValue
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          pbKey:  待校验的密钥(由HMK加密), 可能是KEK, 也可能是WK,二进制数,长度由nKeyLen指定
 *          nKeyLen: 密钥长度
 *          pszCheckValue: 待验证的CheckValue值, 8位十六进制字符
 *           
 * 输出参数:
 *          无
 *
 * 返回值:
 *          0: 验证成功;
 *          1: 输入参数验证失败;
 *          2: 无效的密钥(KEY)
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9 -- 其它错误
 *          10: 验证失败
 *
 ***************************************************************************************/
int SMAPIVerifyCheckValue(int nSock, u8 *pbKey, int nKeyLen, char *pszCheckValue);



/**************************************************************************************
 *
 * 功能描述: 获取加密机状态码及状态信息
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *           
 * 输出参数:
 *          szStatusCode: 加密机状态码 -- "00"表示正常, 其它状态码个厂商可以自己定义
 *          szStatusMsg: 加密机状态信息, 应包括线程数量等加密机状态信息, 供调试用
 *
 * 返回值:
 *          0: 验证成功;
 *          1: 输入参数验证失败;
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9 -- 其它错误
 *          10: 执行失败
 *
 ***************************************************************************************/
//int SMAPIGetHsmStatus(int nSock, char szStatusCode[2], char szStatusMsg[200]);



/**************************************************************************************
 *
 * 功能描述: 计算大数的指数模运算, 即 Out = (Base^Exp) mod Module
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          pbBase:  指数模运算中的底数, 二进制数, 长度由nBaseLen指定
 *          nBaseLen: bpBase的字节长度
 *          pbExp: 指数模运算中的指数, 二进制数, 长度由nExpLen指定
 *          nExpLen: bpExp的字节长度
 *          pbModule: 指数模运算中的模, 二进制数, 长度由nModuleLen指定
 *          nModuleLen: pbModule的字节长度
 *           
 * 输出参数:
 *          pbOut: 指数模运算的结果, 二进制数, 长度由npOutLen指定
 *          pnOutLen: bpOut的长度
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9 -- 其它错误
 *          10: 执行失败
 *
 ***************************************************************************************/
int SMAPIExpMod(int nSock, u8 *pbBase,int nBaseLen,u8 *pbExp,int nExpLen,u8 *pbModule,int nModuleLen,
                u8 *pbOut, int *pnOutLen);



/**************************************************************************************
 *
 * 功能描述: 随机产生大的素数
 * 输入参数:
 *          nSock:  与加密机建立好链接的socket句柄
 *          nPrimeBit:  需要随机产生大素数的bit长度, 取值范围为[1, 2048]
 *           
 * 输出参数:
 *          pbPrime: 产生的大素数, 二进制数, 字节长度为(nPrimeBit/8)
 *
 * 返回值:
 *          0: 成功;
 *          1: 输入参数验证失败;
 *          3: 向加密机发送数据失败;
 *          4: 接收加密机数据超时;
 *          5: 接收到的数据格式错;
 *          9 -- 其它错误
 *          10: 执行失败
 *
 ***************************************************************************************/
int SMAPIGenBigPrime(int nSock, int nPrimeBit, u8 *pbPrime);

/********************************************** 天安   *********************************************************/

















/****************************************** 江南科友  **********************************************************/
/* 函数名称：SMAPIGenRsaKey                                                                                    */
/*          5.1 产生RSA 公私钥对（7.5.1 产生RSA 密钥对）  农行    "EI"                                          */
/* 功能说明：                                                                                                  */
/*	    产生RSA 密钥对。                                                                                   */
/* 输入参数：												      */	
/*	    UINT nSock：   连接的socket 句柄                                                                   */
/*	    int nIndex：   索引位，0：不保存在索引位上；1—50：相应索引位的值                                     */
/*	    int nModLen：  公钥模长，取值范围： 512—2048                                                       */
/*	    char *pszExp： 公钥指数标志，ASCII 码，10 字节长                                                   */
/* 输出参数：                                                                                                 */
/*	    byte *pbPK：   产生的公钥的明文，二进制数，DER 编码格式，调用函数应分配                              */ 
/*		           1.5 * nModLen 的存储空间，实际返回的数据长度由pnPKLen 指定。                         */
/*    	    int *pnPKLen： 返回的公钥数据长度                                                                  */
/*	    byte *pbSK：   私钥密文值，二进制数，DER 编码格式，被HMK 加密，调用函数                             */ 
/*		           应分配3*nModLen 的存储空间，实际返回的数据长度由pnSKLen 指定                         */
/*	    int * pnSKLen：返回的私钥数据长度                                                                  */ 
/* 返回说明：                                                                                                 */
/*          0： 生成成功                                                                                      */
/*	    1： 输入参数验证失败                                                                               */
/*	    3： 向加密机发送数据失败                                                                           */
/*	    4： 接收加密机数据超时                                                                             */
/*	    5： 接收到的数据格式错                                                                             */
/*	    9:  其他错误                                                                                      */
/* 维护记录：                                                                                                 */
/*          2017-03-07 by zhaomx                                                                              */
/**************************************************************************************************************/

int SMAPIGenRsaKey(UINT nSock, int nIndex,	int nModLen,char *pszExp, 
		                             byte * pbPK,int *pnPKLen,byte * pbSK,int *pnSKLen);


/***************************************************************************************************************/
/* 函数名称：  SMAPIGenMasterKey                                                                               */
/*            5.2 产生随机应用主密钥（7.2.1 产生密钥）  农行    "X0"                                            */
/* 功能说明：                                                                                                  */
/*           根据指定长度随机生成一个IC 卡的应用主密钥，并返回密钥的效验值，                                      */
/*           并根据nIndex 和nTag 选择是否将产生的密钥保存到加密机的某个索引位                                    */
/*           上，及保存密钥的类型                                                                              */
/* 输入参数：                                                                                                  */
/*	      UINT nSock：  连接的socket 句柄                                                                  */
/*	      int nKeyLen： 要生成密钥的长度，取值范围：{8,16,24}                                               */
/*	      int nIndex：  索引位，0：不保存在索引位上；	1—255：相应索引位的值                          */ 
/*	      Int nTag：    密钥类型，取值范围{0, 1, 2}，其中 0 ：表示为MDK_AC, 1： 为MDK_ENC，2： 为MDK_MAC     */
/*				                                                                              */
/* 输出参数：                                                                                                  */
/*	      byte *pbKey：          随机产生的密钥(被HMK 加密)，二进制数，调用函数应分配24 字节                 */
/*		                     的存储空间，实际长度返回数据由nKeyLen 指定。                               */
/*	      char pszCheckValue[8]：产生密钥的效验值，是将CheckValue 的前四个字节进行扩                        */
/*		                     展，得到的8 个十六进制字符                                                */ 
/* 返回说明：                                                                                                 */ 
/*            0： 成功                                                                                        */
/*	      1： 输入参数验证失败                                                                             */
/*	      3： 向加密机发送数据失败                                                                         */  
/*	      4： 接收加密机数据超时                                                                           */
/*	      5： 接收到的数据格式错                                                                           */
/*	      9:  其他错误                                                                                     */
/* 维护记录：                                                                                                 */
/*          2017-03-07 by zhaomx                                                                              */
/***************************************************************************************************************/ 

int SMAPIGenMasterKey(UINT nSock, int nKeyLen, int nIndex,int nTag, 
	                                       byte * pbKey, char pszCheckValue[8]);


/***************************************************************************************************************/
/* 函数名称： SMAPIExportMasterKey                                                                             */
/*           5.3  导出应用主密钥（7.2.5 HMK 加密密钥）  农行    "X2"                                            */
/* 功能说明：                                                                                                  */
/*          将制定索引位上特定类型的应用主密钥导出                                                               */
/* 输入参数：										                       */
/*	    UINT nSock：  连接的socket 句柄                                                                    */
/*	    int nIndex：  导出密钥的索引位，固定值为0。                                                         */
/*	    Int nTag：    导出密钥的类型，取值范围{0, 1, 2}，                                                   */
/* 输出参数：												      */	
/*	    byte *pbKey：   导出密钥的密文(被HMK 加密)，二进制数，调用函数应分配24 字节                          */
/*		            的存储空间，实际长度返回数据由pnKeyLen 指定。                                       */
/*	    int *pnKeyLen： 导出密钥的长度，取值范围：{8,16,24}                                                 */
/*	    char pszCheckValue[8]： 导出密钥的效验值，是将CheckValue 的前四个字节进行扩                         */
/*		                    展，得到的8 个十六进制字符                                                 */
/* 返回说明：	                                                                                              */
/*          0： 成功                                                                                          */
/*	    1： 输入参数验证失败                                                                               */
/*	    3： 向加密机发送数据失败                                                                           */ 
/*	    4： 接收加密机数据超时                                                                             */
/*	    5： 接收到的数据格式错                                                                             */
/*	    9:  其他错误                                                                                      */
/* 维护记录：                                                                                                 */
/*          2017-03-07 by zhaomx                                                                              */
/***************************************************************************************************************/ 

int SMAPIExportMasterKey(UINT nSock, int nIndex, int nTag,
	                                          byte * pbKey,int *pnKeyLen, char pszCheckValue[8]);

/***************************************************************************************************************/
/* 函数名称： SMAPIDigest                                                                                      */
/*           5.4 计算信息摘要（7.4.7 产生消息摘要）  农行    "GM"                                               */
/* 功能说明：                                                                                                  */
/*          生成摘要                                                                                           */
/* 输入参数：                                                                                                  */
/*	     UINT nSock：  连接的socket 句柄                                                                   */
/*	     int nAlgo：   算法类型, 0-MD5 算法；1—SHA-1 算法; 2—SHA-224；3—SHA-256；                          */
/*		           4—SHA-384；5—SHA-512；7—SM3                                                        */
/*	     byte *pbData：计算信息摘要的报文数据，二进制数，长度由nDataLen 指定                                 */
/*	     int nDataLen：数据长度, 取值范围[16, 4096]                                                        */ 
/* 输出参数：                                                                                                  */
/*	     byte *pbDigest：信息摘要，二进制数，                                                               */
/*		             当nAlgo = 0 时，16 字节长                                                         */  
/*			     当nAlgo = 1 时，20 字节长                                                         */
/*			     当nAlgo = 2 时，28 字节长                                                         */
/*			     当nAlgo = 3 时，32 字节长                                                         */
/* 			     当nAlgo = 4 时，48 字节长                                                         */
/*			     当nAlgo = 5 时，64 字节长                                                         */
/*			     当nAlgo = 7 时，32 字节长                                                         */
/* 返回说明：                                                                                                  */
/*           0： 生成成功                                                                                      */
/*	     1： 输入参数验证失败                                                                              */
/*	     3： 向加密机发送数据失败                                                                          */   
/*	     4： 接收加密机数据超时                                                                            */   
/*	     5： 接收到的数据格式错                                                                            */ 
/*	     9:  其他错误                                                                                     */ 
/* 维护记录：                                                                                                 */
/*          2017-03-07 by zhaomx                                                                              */
/***************************************************************************************************************/ 

int SMAPIDigest(UINT nSock, 	int nAlgo,	byte *pbData,	int nDataLen,
                         	 byte *pbDigest) ;


/***************************************************************************************************************/
/* 函数名称： SMAPIPublicCalc                                                                                   */
/*           5.5 公钥加解密   （7.5.4 RSA 公钥运算）  农行    "UK"                                               */
/* 功能说明：                                                                                                   */
/*           RSA 公钥加解密                                                                                     */
/* 输入参数：                                                                                                   */ 
/*	     UINT nSock：    连接的socket 句柄                                                                  */
/*	     int nFlag：     加密、解密标志, 1-加密; 0-解密                                                      */
/*	     int nPad:       填充模式， 0：不填充；1：PKCS#1 填充算法；2：OAEP 填充算法。                         */
/*			     注：公钥解密时不支持OAEP 填充                                                       */ 
/* 			     当nFlag = 0 时，nPad = 0 或者nPad = 1                                              */ 
/*	     byte * pbPK：   公钥明文，DER 格式，二进制数，长度由nPKLen 指定                                      */ 
/*	     int nPKLen：    公钥数据长度，取值范围[1, 2048] (有效长度范围参见附录一)                             */
/*	     byte *pbInData：需要进行加密/解密的数据，二进制数，长度由nInLen 指定                                 */
/*	     int nInLen：    pbInData 的长度， 取值范围[1, 256]                                                 */
/*			     注：nFlag、nPad、nInLen、pnOutLen 四个参数之间的关系：                              */
/*			     当nPad = 0 时，nInLen== pnOutLen ==公钥模长                                        */  
/*			     当nPad = 1，nFlag = 0 时，nInLen <= pnOutLen==公钥模长                             */
/*			     当nPad = 1，nFlag = 1 时，pnOutLen<= nInLen ==公钥模长                             */  
/* 输出参数：                                                                                                   */
/*	     byte *pbOutData：经过加密/解密之后的密文/明文数据，二进制数，                                        */
/*	     int *pnOutLen：  返回的pbOutData 的数据长度，                                                       */
/* 返回说明：                                                                                                   */
/*           0： 生成成功                                                                                      */
/*	     1： 输入参数验证失败                                                                               */
/*	     2： 无效的密钥(PK)                                                                                */  
/*	     3： 向加密机发送数据失败                                                                           */
/*	     4： 接收加密机数据超时                                                                             */
/*	     5： 接收到的数据格式错                                                                             */
/*	     9:  其他错误                                                                                      */
/* 维护记录：                                                                                                  */
/*          2017-03-07 by zhaomx                                                                              */
/***************************************************************************************************************/ 

int SMAPIPublicCalc(UINT nSock, int nFlag, int nPad,byte * pbPK, int nPKLen, byte * pbInData, int nInLen, 	
		    byte * pbOutData, 	int *pnOutLen);

/***************************************************************************************************************/
/* 函数名称： SMAPIPrivateCalc                                                                                  */
/*           5.6      私钥加解密（7.5.5 RSA 私钥运算）  农行    "VA"                                             */
/* 功能说明：                                                                                                   */
/*	     RSA 私钥加解密										       */
/* 输入参数：                                                                                                   */
/*	     UINT nSock：       连接的socket 句柄                                                               */
/*	     int nFlag：        加密、解密标志, 1-加密; 0-解密                                                   */
/*	     int nPad:          填充模式，0：不填充；1：PKCS#1 填充算法；2：OAEP 填充算法。                       */
/*	                        注：私钥加密时不支持OAEP 填充                                                    */  
/*				当nFlag = 1 时，nPad = 0 或者nPad = 1                                           */
/*	     byte * pbSK：      私钥密文(由HMK 加密)，二进制数，长度由nSKLen 指定                                 */ 
/*	     int nSKLen：       私钥数据长度，取值范围[1, 2048] (有效长度范围参见附录一)                          */  
/*	     byte *pbInData：   需要进行加密/解密的数据，二进制数，长度由nInLen 指定                              */
/*	     int nInLen：       pbInData 的长度取值范围[1, 256]                                                 */
/*			        注：nFlag、nPad、nInLen、pnOutLen 四个参数之间的关系：                           */
/*				当nPad = 0 时，nInLen== pnOutLen ==私钥模长                                     */ 
/*				当nPad = 1，nFlag = 0 时，nInLen <= pnOutLen==私钥模长                          */ 
/*				当nPad = 1，nFlag = 1 时，pnOutLen<= nInLen ==私钥模长                          */ 
/* 输出参数：                                                                                                   */ 
/*	     byte *pbOutData：经过加密/解密之后的密文/明文数据，二进制数，                                        */
/*	     int *pnOutLen：    返回的pbOutData 的数据长度，                                                     */
/* 返回说明：                                                                                                   */
/*	     0： 生成成功                                                                                       */
/*	     1： 输入参数验证失败                                                                               */
/*	     2： 无效的密钥(SK)                                                                                 */
/*	     3： 向加密机发送数据失败                                                                           */ 
/*	     4： 接收加密机数据超时                                                                             */
/*	     5： 接收到的数据格式错                                                                             */
/*	     9:  其他错误                                                                                      */ 
/* 维护记录：                                                                                                  */
/*          2017-03-07 by zhaomx                                                                              */
/***************************************************************************************************************/ 

int SMAPIPrivateCalc(UINT nSock, int nFlag,int nPad,byte * pbSK,int nSKLen, 
		                             byte * pbInData, int nInLen, byte * pbOutData, int *pnOutLen);

/***************************************************************************************************************/
/* 函数名称： SMAPIPrivateSign                                                                                  */
/*           5.7 私钥签名（7.5.2 RSA 签名）   农行    "EW"                                                      */
/* 功能说明：                                                                                                   */
/*           RSA 私钥签名                                                                                       */
/*           注：对输入数据计算摘要，然后直接对其进行私钥加密，非证书签名用接口。                                  */
/* 输入参数：                                                                                                   */ 
/*	    UINT nSock：    连接的socket 句柄 		                                                       */ 
/*	    int nAlgo：     算法类型, 0-MD5 算法；1—SHA-1 算法; 2—SHA-224；3—SHA-256；4—SHA-384；5—SHA-512      */
/*                                    “00”一 MD5  “01” -SHA1  “02” -SHA224 “03” -SHA256 “04” -SHA384           */
/*                                    “05” -SHA512 “07” –SM3  99 = 不计算hash                                  */
/*	    int nPad:       填充模式， 0：不填充；1：PKCS#1 填充算法；2：OAEP 填充算法。                         */ 
/*	    byte *pbSK：    私钥密文(由HMK 加密)，二进制数，长度由nSKLen 指定                                    */
/*	    int nSKLen：    私钥数据长度，取值范围[1, 2048] (有效长度范围参见附录一)                             */
/*	    byte *pbData：  进行签名数据，二进制数，长度由nDataLen 指定                                         */
/*	    int nDataLen：  pbData 的长度取值范围[1, 2048]                                                     */
/* 输出参数：                                                                                                  */
/*	    byte *pbSign：  签名值，二进制数，长度由pnSignLen 指定                                              */
/*	    int *pnSignLen：返回的pbSign 的数据长度，应等于私钥的模长                                           */   
/* 返回说明：                                                                                                  */
/*	    0： 生成成功                                                                                       */
/*	    1： 输入参数验证失败                                                                                */
/*	    2： 无效的密钥(SK)                                                                                 */ 
/*	    3： 向加密机发送数据失败                                                                            */
/*	    4： 接收加密机数据超时                                                                              */
/*	    5： 接收到的数据格式错                                                                             */
/*	    9:  其他错误                                                                                      */
/* 维护记录：                                                                                                  */
/*          2017-03-07 by zhaomx                                                                              */
/***************************************************************************************************************/ 

int SMAPIPrivateSign(UINT nSock, int nAlgo, int nPad, byte *pbSK, int nSKLen,byte *pbData, int nDataLen, 
	                                 byte *pbSign, int *pnSignLen) ;



/***************************************************************************************************************/
/* 函数名称： SMAPIVerifySign                                                                                  */
/*           5.8   签名验证（7.5.3 RSA 验签）   农行    "EY"                                                    */
/* 功能说明：                                                                                                  */
/*          RSA 验证签名                                                                                       */
/*	    注：对输入数据计算摘要，对输入的签名进行公钥解密，比较计算出的摘要和解密出                             */
/*	        的摘要是否一致，非证书签名验证用接口。                                                           */
/* 输入参数：                                                                                                  */
/*	    UINT nSock：    连接的socket 句柄                                                                  */
/*	    int nAlgo：     算法类型, 0-MD5 算法；1—SHA-1 算法; 2—SHA-224；3—SHA-256；                          */ 
/*		                      4—SHA-384；5—SHA-512                                                     */
/*	    int nPad:       填充模式， 0：不填充；1：PKCS#1 填充算法；2：OAEP 填充算法。                         */
/*	    byte *pbPK：    公钥明文，DER 格式，二进制数，长度由nPKLen 指定                                      */
/*	    int nPKLen：    公钥数据长度，取值范围[1, 2048] (有效长度范围参见附录一)                             */ 
/*	    byte *pbData：  签名对应的数据，二进制数，长度由nDataLen 指定                                       */
/*	    int nDataLen：  pbData 的长度取值范围[1, 2048]                                                     */
/*	    byte *pbSign：  签名值，二进制数，长度由nSignLen 指定                                               */
/*	    int nSignLen：  pbSign 的长度，应等于公钥的模长                                                     */   
/* 输出参数：                                                                                                  */
/*          无                                                                                                */ 
/* 返回说明：                                                                                                  */ 
/*	    0： 验证成功                                                                                       */
/*	    1： 输入参数验证失败                                                                               */
/*	    2： 无效的密钥(PK)                                                                                 */
/*	    3： 向加密机发送数据失败                                                                           */
/*	    4： 接收加密机数据超时                                                                             */
/*	    5： 接收到的数据格式错 		                                                              */ 
/*	    9:  其他错误                                                                                      */
/*         10:  Hash 结果匹配失败                                                                              */ 
/* 维护记录：                                                                                                  */
/*          2017-03-07 by zhaomx                                                                              */
/***************************************************************************************************************/ 

int SMAPIVerifySign(UINT nSock, int nAlgo, int nPad, unsigned char *pbPK, int nPKLen, unsigned char *pbData, 
		                           int nDataLen, unsigned char *pbSign, int nSignLen) ;


/***************************************************************************************************************/
/* 函数名称： SMAPITransKeyOutofPK                                                                              */
/*           5.9 RSA 公钥转加密（7.6.17 RSA 公私钥转加密）   农行    "UE"                                        */
/* 功能说明：                                                                                                   */
/*            将被HMK 加密的密钥转化为被PK 加密                                                                  */
/* 输入参数：                                                                                                   */
/*	      UINT nSock：      连接的socket 句柄                                                               */
/*	      int nPad:         填充模式， 0：不填充；1：PKCS#1 填充算法；2：OAEP 填充算法                        */
/*	      byte *pbPK：      公钥的明文，DER 格式，二进制数，长度由nPKLen 指定                                 */
/*	      int nPKLen：      公钥的长度, 取值范围[1, 2048] (有效长度范围参见附录一)                            */
/*	      byte *pbKeyByHMK：被HMK 加密的密钥，二进制数，长度由nKeyLen 指定，                                  */
/*	      int iKeyByMfkLen：pbKeyByHMK 的长度, 取值范围[8, 2048]并能被8 整除且不超过公钥模长。                 */  
/*				注：把“被HMK 加密的密钥”看做单纯的被HMK 加密的数据进行处理。                       */
/* 输出参数：                                                                                                    */
/*	      byte *pbKeyByPK：  被PK 加密的密钥，二进制数，长度由*pnKeyByPKLen 给出                              */ 
/*	      int *pnKeyByPKLen：pbKeyByPK 的长度，等于公钥模长。                                                */
/* 返回说明：                                                                                                   */
/*	      0： 执行成功                                                                                      */
/*	      1： 输入参数验证失败                                                                               */
/*	      2： 无效的密钥(PK)                                                                                */
/*	      3： 向加密机发送数据失败                                                                           */
/*	      4： 接收加密机数据超时                                                                             */
/*	      5： 接收到的数据格式错                                                                             */
/*	      9:  其他错误	                                                                                */
/* 维护记录：                                                                                                   */
/*          2017-03-07 by zhaomx                                                                               */
/****************************************************************************************************************/ 

int SMAPITransKeyOutofPK(UINT nSock, UINT nPad, unsigned char *pbPK, int nPKLen, unsigned char *pbKeyByMfk, int iKeyByMfkLen, 
	                 unsigned char *pbKeyByPK, int *piKeyByPKLen);



/***************************************************************************************************************/
/* 函数名称： SMAPIDisreteSubKey                                                                               */
/*           5.10 子密钥离散（7.6.15 分散卡密钥）   农行    "EG"                                                */
/* 功能说明：                                                                                                  */
/*           将应用主密钥离散为卡子密钥或者会话子密钥，用传入的KEK 加密输出                                       */
/*           （接口设计参见附录四）                                                                             */
/* 输入参数：                                                                                                  */
/*	    UINT nSock：       连接的socket 句柄                                                               */
/*	    int nDivNum：      离散的次数，取值范围{1, 2}                                                       */
/*			       当nDivNum =1 时，离散为卡密钥                                                    */
/*			       当nDivNum =2 时，离散为会话密钥                                                  */
/*	    int iccType：      IC 卡类型，具体格式参见附录二，对应的算法参见附录三。                              */
/*                              '0'-pboc   '1'-visa   '2'-mastercard                                           */ 
/*	    int nAlgo：        KEK 加密的算法类型，取值范围{1,2,3}                                              */ 
/*			       当nAlgo = 1 时，用KEK 单DES 加密子密钥，此时pbKek 为8 字节长。                    */ 
/*			       当nAlgo = 2 时，用KEK 双DES 加密子密钥，此时pbKek 为16 字节长。                   */ 
/*			       当nAlgo = 3 时，用KEK 三DES 加密子密钥，此时pbKek 为24 字节长。                   */
/*	    byte *pbKek：      加密子密钥的KEK(被HMK 加密)，长度由nAlgo 决定                                    */
/*	    byte *pbMasterKey：被离散的应用主密钥，可以为应用密文主密钥、安全报文加                              */
/*			       密主密钥和安全报文认证主密钥(被HMK 加密)，二进制数，16 字节长。                   */
/*	    byte *pbCardFactor：   卡密钥分散因子，                                                            */
/*		                   iccType=0 时，长度为8 字节，由卡号+卡序号经过PBOC 规则产生的8 字节二进制数。  */ 
/*		                   iccType!=0 时，由上层接口拼接好的卡片密钥离散因子，长度为16 字节              */
/*	    byte *pbSessionFactor：会话密钥分散因子，当nDivNum=1 时，该参数不参与运算，设为null。                */
/*		                   iccType=0 时，为交易序列号(ATC), 二进制数，2 字节长                          */
/*				   iccType!=0 时，由上层接口拼接好的会话密钥离散因子，长度为16 字节。            */ 
/* 输出参数：                                                                                                  */
/*	    byte *pbSubKey：       离散的子密钥的密文(被KEK 加密)，二进制数，16 字节长，                         */
/*		                   当nDivNum =1，为卡子密钥；当nDivNum =2，为会话子密钥                         */
/*  	    char pszCheckValue[8]: 产生子密钥的效验值，是将CheckValue 的前四个字节进行                          */
/*		                   扩展，得到的8 个十六进制字符                                                */   
/* 返回说明：                                                                                                 */
/*	    0： 执行成功                                                                                      */ 
/*	    1： 输入参数验证失败                                                                              */ 
/*	    2： 无效的密钥(MasterKey)                                                                         */
/*	    3： 向加密机发送数据失败                                                                           */
/*	    4： 接收加密机数据超时                                                                             */  
/*	    5： 接收到的数据格式错                                                                             */ 
/*	    9:  其他错误                                                                                      */
/* 维护记录：                                                                                                 */
/*          2017-03-07 by zhaomx                                                                              */
/**************************************************************************************************************/ 

int SMAPIDisreteSubKey(UINT nSock, int nDivNum,int iccType, int nAlgo, byte * pbKek, 
	                                      byte * pbMasterKey, byte * pbCardFactor, byte * pbSessionFactor, 
	                                      byte * pbSubKey, char pszCheckValue[8 + 1]);


/***************************************************************************************************************/
/* 函数名称： SMAPIVerifyARQC                                                                                  */
/*           5.11 ARQC 验证（7.3.2 ARQC/ARPC 产生或验证）  农行    "VM"                                         */
/* 功能说明：                                                                                                  */
/*           验证ARQC （接口设计参见附录四）                                                                    */
/* 输入参数：                                                                                                  */
/*	     UINT nSock：           连接的socket 句柄                                                          */
/*	     int iccType：          IC 卡类型，具体格式参见附录二，对应的算法参见附录三。                        */
/*	     byte *pbKey：          应用密文主密钥，二进制数，16 字节长                                         */
/*	     byte *pbCardFactor：   卡密钥分散因子                                                             */
/*		   		    iccType=0 时，由有卡号+卡序号经过PBOC 规则产生的8字节二进制数。              */  
/*				    iccType!=0 时，长度为16 字节。                                             */
/*	     byte *pbSessionFactor：会话密钥分散因子                                                           */
/*		                    iccType=0 时，为交易序列号(ATC), 二进制数2字节长                            */
/*				    iccType!=0 时，长度为16 字节。如果值为NULL，表示只进行                      */ 
/*				    一次密钥离散（即使用卡片密钥而非会话密钥对数据进行MAC 计算）                 */ 
/*	     byte *pbData：         用于计算ARQC 的数据，二进制数，长度由nDataLen 指定。                        */
/*	     int nDataLen：         pbData 的长度, 取值范围[1, 1024]                                           */
/*	     byte *pbARQC：         待验证的ARQC 值，二进制数，8 字节长                                         */
/* 输出参数：                                                                                                  */
/*	     无                                                                                                */
/* 返回说明：                                                                                                  */
/*	     0： 验证成功                                                                                      */
/*	     1： 输入参数验证失败                                                                              */ 
/*	     2： 无效的密钥(Key)                                                                               */
/*	     3： 向加密机发送数据失败                                                                           */
/*	     4： 接收加密机数据超时                                                                             */
/*	     5： 接收到的数据格式错                                                                             */
/*	     9:  其他错误                                                                                      */
/*	    10:  匹配失败                                                                                      */
/* 维护记录：                                                                                                  */
/*          2017-03-07 by zhaomx                                                                               */
/****************************************************************************************************************/ 

int SMAPIVerifyARQC(UINT nSock, int iccType, byte * pbKey, byte * pbCardFactor, 
	                                  byte * pbSessionFactor, byte * pbData,	int nDataLen, byte * pbARQC);

/***************************************************************************************************************/
/* 函数名称： SMAPICalcARPC                                                                                    */
/*           5.12 ARPC 计算（7.3.2 ARQC/ARPC 产生或验证）  农行    "VM"                                         */
/* 功能说明：                                                                                                  */
/*	     计算ARPC （接口设计参见附录四）                                                                    */
/* 输入参数：                                                                                                  */ 
/*	     UINT nSock：           连接的socket 句柄                                                          */
/*	     int iccType：          IC 卡类型，具体格式参见附录二，对应的算法参见附录三。                        */
/*	     byte *pbKey：          应用密文主密钥，二进制数，16 字节长，                                       */
/*	     byte *pbCardFactor：   卡密钥分散因子                                                             */ 
/*		                    iccType=0 时，由有卡号+卡序号经过PBOC 规则产生的8 字节二进制数。             */
/*		                    iccType!=0 时，长度为16 字节。                                             */ 
/*	     byte *pbSessionFactor：会话密钥分散因子                                                           */
/*		                    iccType=0 时，为交易序列号(ATC), 二进制数，2 字节长                         */
/*				    iccType!=0 时，长度为16 字节。如果值为NULL，表示只进行                      */
/*				    一次密钥离散（即使用卡片密钥而非会话密钥对数据进行MAC 计算）                 */ 
/*	     byte *pbData：         计算ARPC 所需数据                                                          */
/*	                            iccType=0 时，输入的数据为ARQC，8 字节长。                                  */
/*			            iccType!=0 时，输入的数据为计算ARPC 所需的数据块，数据块长度根据卡片类型      */
/*                                   中的算法类型值而定。                                                      */  
/*	     byte *pbARC：          授权响应码，二进制数，2 字节长                                              */
/* 输出参数：                                                                                                  */ 
/*	     byte *pbARPC：         生成的ARPC 值，二进制数，8 字节长                                           */
/* 返回说明：                                                                                                  */
/*	     0： 执行成功                                                                                      */
/*	     1： 输入参数验证失败                                                                              */
/*	     2： 无效的密钥(Key)                                                                               */
/*	     3： 向加密机发送数据失败                                                                          */
/*	     4： 接收加密机数据超时                                                                            */
/*	     5： 接收到的数据格式错                                                                            */
/*	     9:  其他错误                                                                                      */
/* 维护记录：                                                                                                  */
/*          2017-03-07 by zhaomx                                                                               */
/***************************************************************************************************************/ 

int  SMAPICalcARPC(UINT nSock, int iccType, byte * pbKey, byte * pbCardFactor, 
	                                byte * pbSessionFactor, byte * pbARQC,	byte * pbARC, 
	                                byte * pbARPC);




/*********************************************************************************************************************/
/* 函数名称： SMAPIEncryptWithDerivedKey                                                                              */
/*           5.13 脚本加解密（7.3.3 脚本加解密）  农行    "VI"                                                         */
/* 功能说明：                                                                                                         */
/*           加解密发卡行脚本数据及其它密秘数据（接口设计参见附录四）                                                    */  
/* 输入参数：                                                                                                         */
/*	     UINT nSock：           连接的socket 句柄                                                                 */
/*	     int nType：            1—加密； 0—解密                                                                   */
/*	     int iccType：          IC 卡类型，具体格式参见附录二，对应的算法参见附录三。                               */
/*                                  0-pboc   1-visa   2-mastercard                                                   */
/*	     int nMode：            加密模式， nMode = 0，ECB 模式			nMode =1，CBC 模式           */
/*	     byte *pbKey：          安全报文加密主密钥，二进制数，16 字节长                                            */ 
/*	     byte *pbCardFactor：   卡密钥分散因子                                                                    */
/*		 		    iccType=0 时，由有卡号+卡序号经过PBOC 规则产生的8 字节二进制数。                    */
/*				    iccType!=0 时，长度为16 字节。                                                    */
/*	     byte *pbSessionFactor：会话密钥分散因子                                                                  */
/*		 	            iccType=0 时，为交易序列号(ATC), 二进制数，2 字节长                                */
/*				    iccType!=0 时，长度为16 字节。如果值为NULL，表示只进行                             */
/*				    一次密钥离散（即使用卡片密钥而非会话密钥对数据进行MAC 计算）                        */
/*	     byte *pbIV：           当nMode = 0 时，为NULL，当nMode = 1 时， 为CBC 模式的初始化向量，二进制数，8字节长，*/
/*	     byte *pbInData：       需要加密的明文数据，二进制数，长度由nInLen 指定                                    */
/*	     int nInLen：           pbInData 的长度,取值范围[8, 128]                                                  */
/* 输出参数：                                                                                                         */
/*	     byte *pbOutData：      加密之后的密文数据，二进制数，长度由pnOutLen 指定                                  */
/*	     int *pnOutLen：        pbOutData 的长度，应等于pbInData                                                  */ 
/* 返回说明：                                                                                                         */
/*	     0： 执行成功                                                                                            */
/*	     1： 输入参数验证失败                                                                                    */
/*	     2： 无效的密钥(Key)                                                                                     */
/*	     3： 向加密机发送数据失败                                                                                 */
/*	     4： 接收加密机数据超时                                                                                   */
/*	     5： 接收到的数据格式错                                                                                   */ 
/*	     9:  其他错误                                                                                            */
/* 维护记录：                                                                                                        */
/*          2017-03-07 by zhaomx                                                                                    */
/********************************************************************************************************************/ 

int SMAPIEncryptWithDerivedKey(UINT nSock, int nType, int iccType, int nMode, byte * pbKey, byte * pbCardFactor, 
	                                                      byte * pbSessionFactor, byte * pbIV, byte * pbInData, int nInLen, 
														  byte * pbOutData, int *pnOutLen);


/*****************************************************************************************************************/
/* 函数名称： SMAPICalcMacWithDerivedKey                                                                         */
/*           5.14 脚本数据计算MAC（7.3.4 计算脚本MAC）  农行    "VK"                                              */
/* 功能说明：                                                                                                    */
/*	     计算发卡行脚本MAC（接口设计参见附录四）                                                              */
/* 输入参数：                                                                                                    */
/*	     UINT nSock：           连接的socket 句柄                                                            */
/*	     int iccType：          IC 卡类型，具体格式参见附录二，对应的算法参见附录三。                          */
/*                                  0-pboc   1-visa   2-mastercard                                              */ 
/*	     byte *pbKey：          安全报文认证主密钥，二进制数，16 字节长                                       */
/*	     byte *pbCardFactor：   卡密钥分散因子                                                               */
/*		  		    iccType=0 时，由有卡号+卡序号经过PBOC 规则产生的8 字节二进制数。               */
/*			  	    iccType!=0 时，长度为16 字节。                                               */ 
/*	     byte *pbSessionFactor：会话密钥分散因子                                                             */    
/*				    iccType=0 时，为交易序列号(ATC), 二进制数，2 字节长                           */
/*				    iccType!=0 时，长度为16 字节。如果值为NULL，表示只进行                        */
/*				    一次密钥离散（即使用卡片密钥而非会话密钥对数据进行MAC 计算）                   */
/*	     byte *pbData：         需要计算MAC 的脚本数据，二进制数，长度由nDataLen 指定                         */
/*	     int nDataLen：         pbData 的长度, 取值范围[8, 128]                                              */
/* 输出参数：                                                                                                    */
/*	     byte *pbMac：脚本数据的MAC 值，二进制数，8 字节长                                                    */
/* 返回说明：                                                                                                    */
/*	     0： 执行成功                                                                                        */
/*	     1： 输入参数验证失败                                                                                */
/*	     2： 无效的密钥(Key)                                                                                 */
/*	     3： 向加密机发送数据失败                                                                             */
/*	     4： 接收加密机数据超时                                                                               */
/*	     5： 接收到的数据格式错                                                                               */ 
/*	     9:  其他错误                                                                                         */ 
/* 维护记录：                                                                                                     */
/*          2017-03-07 by zhaomx                                                                                 */
/******************************************************************************************************************/ 

int SMAPICalcMacWithDerivedKey(UINT nSock, int iccType, byte *pbKey, byte *pbCardFactor, byte *pbSessionFactor,
                               byte *pbData, int nDataLen,
	                       byte *pbMac);



/******************************************************************************************************/
/* 函数名称： SMAPIPrivateAnalyse                                                                     */
/*           5.15 私钥解析（7.5.6 分解RSA 私钥分量）  农行    "UA"                                     */
/* 功能说明：                                                                                         */
/*              将私钥解析为各个分量(以KEK 加密)，以便个人化制卡时写入私钥分量                           */
/*              注：私钥的6 个分量(pbD, pbP, pbQ, pbDmP1, pbDmQ1, pbCoef)不管长度                      */
/*                  是不是8 的整数倍，都先强制补80，之后填充最少个0x00，使得分量                        */ 
/*                  的长度为8 的整数倍，之后再用pbKEK 加密。                                           */
/*                                                                                                   */
/* 输入参数：                                                                                         */
/*		UINT nSock：  连接的socket 句柄                                                       */
/*		byte *pbSK：  私钥密文值，二进制数，DER 编码格式，被HMK 加密，长度由nSKLen指定          */   
/*		int nSKLen：  私钥的长度, 私钥长度取值范围[1, 2048] (有效长度范围参见附录一)            */
/*		int nAlgo：   KEK 加密算法类型。Single_Des = 1，Double_Des = 2 ,Triple_Des = 3        */ 
/*		byte *pbKEK： 经HMK 加密的KEK 的密文值，二进制数，                                     */
/*		              当nAlgo =1 是，8 字节长                                                 */
/*		              当nAlgo =2 是，16 字节长                                                */
/*		              当nAlgo =3 是，24 字节长                                                */ 
/* 输出参数：                                                                                         */
/*		byte *pbD：      私钥指数，二进制数，被pbKEK 加密，长度由pnDLen 指定                    */  
/*		int *pnDLen：    私钥指数的长度                                                       */
/*		byte *pbP：      RSA 的第一个大素数，二进制数，被pbKEK 加密，长度由pnPLen 指定          */
/*		int *pnPLen：    pbP 的长度                                                           */ 
/*		byte *pbQ：      RSA 的第二个大素数，二进制数，被pbKEK 加密，长度由pnQLen 指定          */
/*		int *pnQLen：    pbQ 的长度                                                           */   
/*		byte *pbDmP1：   D mod (P-1) 的值，二进制数，被pbKEK 加密，长度由pnDmP1Len指定          */
/*		int *pnDmP1Len： pbDmP1 的长度                                                        */ 
/*		byte *pbDmQ1：   D mod (Q-1) 的值，二进制数，被pbKEK 加密，长度由pnDmQ1Len指定          */
/*		int *pnDmQ1Len： pbDmQ1 的长度                                                        */
/*		byte *pbCoef：   Q^-1mod P 的值，二进制数，被pbKEK 加密，长度由pnCoefLen指定            */
/*		int *pnCoefLen： pbCoef 的长度                                                        */
/* 返回值：                                                                                           */
/*		0： 执行成功                                                                          */
/*		1： 输入参数验证失败                                                                   */
/*		2： 无效的密钥(pbSK)                                                                   */
/*		3： 向加密机发送数据失败                                                               */
/*		4： 接收加密机数据超时                                                                 */ 
/*		5： 接收到的数据格式错                                                                 */  
/*		9:  其他错误                                                                          */ 
/* 维护记录：                                                                                         */
/*          2017-03-07 by zhaomx                                                                      */
/******************************************************************************************************/ 

int SMAPIPrivateAnalyse(UINT nSock, byte * pbSK, int nSKLen, int nAlgo,byte * pbKEK,
	                byte * pbD, int *pnDLen, byte * pbP, int *pnPLen, byte * pbQ, 
	                int *pnQLen, byte * pbDmP1, int *pnDmP1Len, 	byte * pbDmQ1, 
	                int *pnDmQ1Len, byte * pbCoef, int *pnCoefLen);



/*****************************************************************************************************/
/* 函数名称： SMAPIGenEccKey                                                                         */
/*           5.16 产生ECC 公私钥对（7.4.1 产生SM2 密钥对）  农行    "U0"                              */
/* 功能说明：                                                                                        */
/*           产生ECC 密钥对。                                                                        */
/* 输入参数：                                                                                        */
/*	     UINT nSock： 连接的socket 句柄                                                          */
/*	     int nIndex： 索引位，0：不保存在索引位上；1—19：相应索引位的值                            */
/*	     int nEcMark：椭圆曲线标识                                                               */
/*	                  0x01：ECC 128 位，NIST P-256，公钥长度64 字节（暂不支持）                   */
/*		 	  0x02：ECC 256 位，NIST P-521，公钥长度132 字节（暂不支持）                  */
/*			  0x11：SM2 128 位，SM2 曲线，公钥长度64 字节                                 */
/* 输出参数：                                                                                        */
/*	     byte *pbPK：    产生的公钥的明文，二进制数，调用函数应分配足够的存储空间，实               */
/*	                     际返回的数据长度由pnPKLen 指定。                                         */
/*	     int *pnPKLen：  返回的公钥数据长度                                                       */
/*	     byte *pbSK：    私钥密文值，二进制数，强制填充”80 00…”至8 的整数倍后被HMK                 */
/*		             加密，调用函数应分配足够的存储空间，实际返回的数据长度由pnSKLen 指定       */ 
/*	     int * pnSKLen： 返回的私钥数据长度                                                       */
/* 返回说明：                                                                                        */ 
/*	     0： 生成成功                                                                            */
/*	     1： 输入参数验证失败                                                                     */ 
/*	     3： 向加密机发送数据失败                                                                 */    
/*	     4： 接收加密机数据超时                                                                   */
/*	     5： 接收到的数据格式错                                                                   */
/*	     9:  其他错误                                                                            */
/*	     补充：如果指定的索引位上已经存有数据，清除原数据后保存新密钥对。密钥存储                    */
/*	  	   索引与RSA 密钥共用。                                                               */
/*                                                                                                   */ 
/* 维护记录：                                                                                         */
/*          2017-03-07 by zhaomx                                                                     */
/*****************************************************************************************************/ 

int SMAPIGenEccKey (UINT nSock, int nIndex, int nEcMark,
	            byte *pbPK, int *pnPKLen, byte *pbSK, int *pnSKLen);



/*****************************************************************************************************/
/* 函数名称： SMAPIGetEccPkBySk                                                                      */
/*           5.17 根据ECC 私钥生成公钥  （7.6.19 根据ECC 私钥生成公钥）  农行    "EB"                  */
/* 功能说明：                                                                                        */
/*          通过指定的EC 及私钥获取对应的公钥。                                                       */
/* 输入参数：                                                                                        */
/*	     UINT nSock：连接的socket 句柄                                                           */ 
/*	     int nEcMark：椭圆曲线标识                                                               */
/*		 	  0x01：ECC 128 位，NIST P-256，公钥长度64 字节（暂不支持）                   */  
/*			  0x02：ECC 256 位，NIST P-521，公钥长度132 字节（暂不支持）                  */
/*			  0x11：SM2 128 位，SM2 曲线，公钥长度64 字节                                 */
/*	     byte *pbSK： 私钥密文值，二进制数，强制填充”80 00…”至8 的整数倍后被HMK                    */
/*			  加密，数据长度由pnSKLen 指定                                               */  
/*	     int  nSKLen：私钥数据长度                                                               */ 
/* 输出参数：                                                                                        */
/*	     byte *pbPK：产生的公钥的明文，二进制数，调用函数应分配足够的存储空间，实                   */
/*		         际返回的数据长度由pnPKLen 指定。                                             */
/*	     int *pnPKLen：返回的公钥数据长度                                                         */    
/* 返回说明：                                                                                        */ 
/*	     0： 生成成功                                                                            */
/*	     1： 输入参数验证失败                                                                    */
/*	     3： 向加密机发送数据失败                                                                */ 
/*	     4： 接收加密机数据超时                                                                  */ 
/*	     5： 接收到的数据格式错                                                                  */ 
/*	     9:  其他错误                                                                           */ 
/* 维护记录：                                                                                       */
/*          2017-03-07 by zhaomx                                                                    */
/*****************************************************************************************************/ 

int SMAPIGetEccPkBySk (UINT nSock, int nEcMark, byte *pbSK, int nSKLen,
                       byte *pbPK, int *pnPKLen);


/*****************************************************************************************************/
/* 函数名称： SMAPIEccPkEncrypt                                                                      */
/*           5.18 ECC 公钥加密（7.4.3 SM2 公钥加密）  农行    "UU"                                    */
/* 功能说明：                                                                                        */
/*           ECC 公钥加密                                                                            */
/* 输入参数：                                                                                        */
/*		UINT nSock：     连接的socket 句柄                                                   */
/*		int nEcMark：    椭圆曲线标识                                                        */  
/*		 	         0x01：ECC 128 位，NIST P-256，公钥长度64 字节（暂不支持）            */
/*				 0x02：ECC 256 位，NIST P-521，公钥长度132 字节（暂不支持）           */ 
/*				 0x11：SM2 128 位，SM2 曲线，公钥长度64 字节                          */
/*		int nPad:        填充模式， 0：不填充(具体填充方式待补充，暂不支持)。                  */ 
/*		byte * pbPK：    公钥明文，二进制数，（字节）长度由nPKLen 指定                         */
/*		int   nPKLen：   公钥长度，取值范围[1, 512]                                           */
/*		byte *pbInData： 需要进行加密的数据，二进制数，（字节）长度由nInLen 指定                */
/*		int nInLen：     pbInData 的长度，取值范围[1, 4000]                                   */ 
/* 输出参数：                                                                                         */
/*		byte *pbOutData：经过加密后的密文数据，二进制数，                                      */
/*		int *pnOutLen：  返回的pbOutData 的数据长度，                                         */
/* 返回说明：                                                                                        */
/*		0： 生成成功                                                                         */
/*		1： 输入参数验证失败                                                                 */
/*		2： 无效的密钥(PK)                                                                   */
/*		3： 向加密机发送数据失败                                                             */
/*		4： 接收加密机数据超时                                                               */
/*		5： 接收到的数据格式错                                                               */
/*		9:  其他错误                                                                        */
/* 维护记录：                                                                                       */
/*          2017-03-07 by zhaomx                                                                    */
/*****************************************************************************************************/ 

int SMAPIEccPkEncrypt(UINT nSock, int nEcMark, int nPad, byte * pbPK,int nPKLen, byte *pbInData, int nInLen, 
	              byte *pbOutData, int *pnOutLen);



/*****************************************************************************************************/
/* 函数名称： SMAPIEccSkDecrypt                                                                      */
/*           5.19 ECC 私钥解密（7.4.4 SM2 私钥解密）  农行    "UW"                                    */
/* 功能说明：                                                                                        */
/*              ECC 私钥解密                                                                         */ 
/* 输入参数：                                                                                        */
/*		UINT nSock：    连接的socket 句柄                                                    */ 
/*		int nEcMark：   椭圆曲线标识                                                         */  
/*				0x01：ECC 128 位，NIST P-256，公钥长度64 字节（暂不支持）             */
/*				0x02：ECC 256 位，NIST P-521，公钥长度132 字节（暂不支持）            */
/*				0x11：SM2 128 位，SM2 曲线，公钥长度64 字节                           */ 
/*		int nPad:       填充模式， 0：不填充(具体填充方式待补充，暂不支持)。                   */
/*		byte *pbSK：    私钥密文(经填充并由HMK 加密)，二进制数，(字节)长度由nSKLen 指定        */
/*		int nSKLen：    私钥长度，取值范围[1, 256]                                           */
/*		byte *pbInData：需要进行解密的数据，二进制数，(字节)长度由nInLen 指定                  */
/*		int nInLen：    pbInData 的长度取值范围[1, 4096]                                     */ 
/* 输出参数：                                                                                        */
/*		byte *pbOutData：经过解密之后的明文数据，二进制数，                                   */  
/*		int *pnOutLen：  返回的pbOutData 的数据长度，                                        */ 
/* 返回值：                                                                                         */  
/*		0： 生成成功                                                                        */   
/*		1： 输入参数验证失败                                                                */ 
/*		2： 无效的密钥(SK)                                                                  */   
/*		3： 向加密机发送数据失败                                                             */
/*		4： 接收加密机数据超时                                                               */
/*		5： 接收到的数据格式错                                                               */
/*		9:  其他错误                                                                        */ 
/* 维护记录：                                                                                       */
/*          2017-03-07 by zhaomx                                                                    */
/*****************************************************************************************************/ 

int SMAPIEccSkDecrypt(UINT nSock, int nEcMark, int nPad, byte * pbSK,int nSKLen, byte *pbInData, int nInLen, 
                      byte *pbOutData, int *pnOutLen);


/*****************************************************************************************************/
/* 函数名称： SMAPIEccSign                                                                            */
/*           5.20 ECC 私钥签名（7.4.5 SM2 签名）  农行    "UQ"                                        */
/* 功能说明：                                                                                         */
/*              ECC 私钥签名                                                                          */ 
/* 输入参数：                                                                                         */   
/*		UINT nSock：    连接的socket 句柄                                                     */ 
/*		int nEcMark：   椭圆曲线标识                                                          */ 
/*				0x01：ECC 128 位，NIST P-256，公钥长度64 字节（暂不支持）              */ 
/*				0x02：ECC 256 位，NIST P-521，公钥长度132 字节（暂不支持）             */
/*				0x11：SM2 128 位，SM2 曲线，公钥长度64 字节                            */
/*                                    （使用PBOC 3.0 规范第17部分5.4.2.2 中定义的签名算法）            */
/*		int nPad:       填充模式， 0：不填充(具体填充方式待补充，暂不支持)。                    */ 
/*		byte * pbPK：   公钥明文，二进制数，（字节）长度由nPKLen 指定                           */ 
/* 		int nPKLen：    公钥长度，取值范围[1, 512]                                             */
/*		byte *pbSK：    私钥密文(经填充并由HMK 加密)，二进制数，(字节)长度由nSKLen 指定          */
/*		int nSKLen：    私钥数据长度，取值范围[1, 256]                                         */
/*		byte *pbData：  进行签名数据，二进制数，(字节)长度由nDataLen 指定                       */
/*		int nDataLen：  pbData 的长度取值范围[1, 4096]                                         */ 
/* 输出参数：                                                                                         */ 
/*		byte *pbSign：  签名值，二进制数，(字节)长度由pnSignLen 指定                           */
/*		int *pnSignLen：返回的pbSign 的数据长度                                               */
/* 返回值：                                                                                           */
/*	        0： 生成成功                                                                          */
/*		1： 输入参数验证失败                                                                  */
/*		2： 无效的密钥(SK)                                                                    */
/*		3： 向加密机发送数据失败                                                              */
/*		4： 接收加密机数据超时                                                                */ 
/*		5： 接收到的数据格式错                                                                */
/*		9:  其他错误                                                                         */
/* 维护记录：                                                                                       */
/*          2017-03-07 by zhaomx                                                                    */
/*****************************************************************************************************/ 

int SMAPIEccSign (UINT nSock, int nEcMark, int nPad, byte *pbPK,int nPKLen, byte *pbSK, int nSKLen, byte *pbData, int nDataLen, 
	          byte *pbSign, int *pnSignLen);

/*****************************************************************************************************/
/* 函数名称： SMAPIEccSign                                                                            */
/*           5.21 ECC 签名验证（7.4.6 SM2 验签）    "US"                                              */
/* 功能说明：                                                                                         */
/*               ECC 验证签名                                                                         */
/*		注：对输入数据计算摘要，对输入的签名进行公钥解密，比较计算出的摘要和解密出               */ 
/*		的摘要是否一致，非证书签名验证用接口。                                                 */
/* 输入参数：                                                                                        */ 
/*		UINT nSock：  连接的socket 句柄                                                      */
/*		int nEcMark： 椭圆曲线标识                                                           */
/*		              0x01：ECC 128 位，NIST P-256，公钥长度64 字节（暂不支持）               */
/*		              0x02：ECC 256 位，NIST P-521，公钥长度132 字节（暂不支持）              */
/*		              0x11：SM2 128 位，SM2 曲线，公钥长度64 字节                            */
/*		int nPad:     填充模式， 0：不填充(具体填充方式待补充，暂不支持)。                    */
/*		byte *pbPK：  公钥明文，二进制数，(字节)长度由nPKLen 指定                             */
/*		int nPKLen：  公钥数据长度，取值范围[1, 512]                                         */
/*		byte *pbData：签名对应的数据，二进制数，(字节)长度由nDataLen 指定                     */ 
/*		int nDataLen：pbData 的长度取值范围[1, 4096]                                         */
/*		byte *pbSign：签名值，二进制数，长度由nSignLen 指定                                   */  
/*		int nSignLen：pbSign 的长度                                                          */
/* 输出参数：                                                                                        */ 
/*               无                                                                                  */
/* 返回说明：                                                                                        */ 
/*		0： 验证成功                                                                         */  
/*		1： 输入参数验证失败                                                                 */
/*		2： 无效的密钥(PK)                                                                  */
/*		3： 向加密机发送数据失败                                                             */
/*		4： 接收加密机数据超时                                                               */
/*		5： 接收到的数据格式错                                                               */
/*		9:  其他错误                                                                        */
/*		10: Hash 结果匹配失败                                                               */
/* 维护记录：                                                                                       */
/*          2017-03-07 by zhaomx                                                                    */
/*****************************************************************************************************/ 

int SMAPIEccVerify (UINT nSock, int nEcMark, int nPad, byte *pbPK,int nPKLen, byte *pbData,
	            int nDataLen, byte *pbSign, int nSignLen);

/*****************************************************************************************************/
/* 函数名称： SMAPISm4Calc                                                                            */
/*           5.22 SM4 加解密（7.3.6 数据加解密）    "V2"                                              */
/* 功能说明：                                                                                         */
/*                用SM4 算法以ECB、CBC 等模式对数据进行加解密。                                        */
/* 输入参数：                                                                                        */
/*		UINT nSock：       连接的socket 句柄                                                 */
/*		int nFlag：        加密、解密标志。1-加密；0-解密                                     */
/*		int nMode：        加密模式。ECB = 0；CBC = 1；（其它待补充）                         */
/*		byte * pbKey：     SM4 密钥的密文(由HMK 经3DES 加密)，二进制数，16 字节长             */
/*		byte *pbInData：   需要加密/解密的数据，二进制数, （字节）长度由nDataLen 指定          */
/*		int nDataLen：     数据长度，取值范围：16 的整数倍，小于等于4096                      */
/*		byte *pbIV：       初始化向量，二进制数，16 字节长  nMode = 1                        */
/* 输出参数：                                                                                       */
/*		byte *pbOutData：  经解密/加密后的输出数据，二进制数，（字节）长度由nDataLen指定      */
/* 返回值：                                                                                        */
/*		0： 成功                                                                           */
/*		1： 输入参数验证失败                                                                */
/*		2： 无效的密钥（KEY）                                                               */
/*		3： 向加密机发送数据失败                                                            */
/*		4： 接收加密机数据超时                                                              */
/*		5： 接收到的数据格式错                                                              */
/*		9:  其他错误                                                                        */
/* 维护记录：                                                                                       */
/*          2017-03-07 by zhaomx                                                                    */
/*****************************************************************************************************/ 

int SMAPISm4Calc (UINT nSock, int nFlag, int nMode, byte *pbKey, byte *pbInData, int nDataLen, byte *pbIV,
	          byte *pbOutData);

/*******************************************************************************************************/
/* 函数名称： SMAPITransKeyIntoSK                                                                       */
/*           5.23 RSA 私钥转加密（7.6.17 RSA 公私钥转加密）    "UE"                                      */
/* 功能说明：                                                                                           */
/*              将被RSA 算法的PK 加密的密钥（先用SK 解密再）转化为被HMK 加密                              */
/* 输入参数：                                                                                           */
/*		UINT nSock：      连接的socket 句柄                                                     */
/*		int nPad:         填充模式， 0：不填充；1：PKCS#1 填充算法；2：OAEP 填充算法              */
/*		byte *pbSK：      私钥的密文（被HMK 加密），DER 格式，二进制数，（字节）长度由nSKLen 指定  */
/*		int nSKLen：      私钥的长度, 取值范围[1, 2048]                                         */   
/*		byte *pbKeyByPK： 被公钥PK 加密的密钥，二进制数，密文数据（字节）长度由nKeyLen指定，      */
/*		int nKeyLen：     pbKeyByPK 的长度, 取值范围[8, 2048]并能被8 整除且不超过公钥模长。       */ 
/*		                  注：把“被HMK 加密的密钥”看做单纯的被HMK 加密的数据进行处理。            */  
/* 输出参数：                                                                                           */
/*		byte *pbKeyByHMK：被HMK 加密的密钥，二进制数，长度由*pnKeyByHMKLen 给出                  */
/*		int *pnKeyByHMKLen：pbKeyByHMK 的长度。                                                 */
/* 返回说明：                                                                                           */
/*		0： 执行成功                                                                            */
/*		1： 输入参数验证失败                                                                    */
/*		2： 无效的密钥(PK)                                                                      */
/*		3： 向加密机发送数据失败                                                                 */
/*		4： 接收加密机数据超时                                                                   */
/*		5： 接收到的数据格式错                                                                   */
/*		9:  其他错误                                                                            */
/* 维护记录：                                                                                           */
/*          2017-03-07 by zhaomx                                                                       */
/*******************************************************************************************************/ 

int SMAPITransKeyIntoSK(UINT nSock, int nPad, byte *pbSK, int nSKLen, byte *pbKeyByPK, int nKeyLen,
	                byte *pbKeyByHMK, int *pnKeyByHMKLen);

/**************************************************************************************************************/
/* 函数名称： SMAPISm2PKTransOutof                                                                             */
/*           5.24 SM2 公钥转加密（7.6.18 SM2 公私钥转加密）   //算法转换类型  01:3DES 加密转 SM2 公钥加密   "UC" */
/* 功能说明：                                                                                                  */
/*              将被HMK 加密的数据转化为被SM2 算法的PK 加密                                                     */
/* 输入参数：                                                                                                 */
/*		UINT nSock：      连接的socket 句柄                                                           */
/*		int nEcMark：     椭圆曲线标识                                                                */
/*				  0x01：ECC 128 位，NIST P-256，公钥长度64 字节（暂不支持）                    */
/*				  0x02：ECC 256 位，NIST P-521，公钥长度132 字节（暂不支持）                   */
/*				  0x11：SM2 128 位，SM2 曲线，公钥长度64 字节                                  */
/*		int nPad:         填充模式， 0：不填充（具体填充方式待补充，暂不支持）                          */
/*		byte *pbPK：      公钥的明文，二进制数，（字节）长度由nPKLen 指定                               */
/*		int nPKLen：      公钥的长度, 取值范围[1, 512]                                                 */
/*		byte *pbKeyByHMK：被HMK 加密的密钥，二进制数，长度由nKeyLen 指定，                              */
/*		int nKeyLen：     pbKeyByHMK 的长度, 取值范围[8, 2048]并能被8 整除且不超过公钥模长。            */
/*				  注：把“被HMK 加密的密钥”看做单纯的被HMK 加密的数据进行处理。                  */
/* 输出参数：                                                                                                 */
/*		byte *pbKeyByPK：被PK 加密的密钥，二进制数，长度由*pnKeyByPKLen 给出                           */
/*		int *pnKeyByPKLen：pbKeyByPK 的长度，等于公钥模长。                                           */
/* 返回值：                                                                                                  */
/*		0： 执行成功                                                                                 */
/*		1： 输入参数验证失败                                                                         */
/*		2： 无效的密钥(PK)                                                                           */
/*		3： 向加密机发送数据失败                                                                      */
/*		4： 接收加密机数据超时                                                                        */
/*		5： 接收到的数据格式错                                                                        */
/*		9:  其他错误                                                                                 */
/* 维护记录：                                                                                                */
/*          2017-03-07 by zhaomx                                                                            */
/************************************************************************************************************/ 

int SMAPISm2PKTransOutof(UINT nSock, int nEcMark, int nPad, byte *pbPK,int nPKLen, byte *pbKeyByHMK, int nKeyLen, 
	                 byte *pbKeyByPK, int  *pnKeyByPKLen);

/**************************************************************************************************************/
/* 函数名称： SMAPISm2SKTransInto                                                                             */
/*           5.25 SM2 私钥转加密（7.6.18 SM2 公私钥转加密）  农行   "UC"                                        */
/* 功能说明：                                                                                                  */
/*		将被SM4 算法PK 加密的密钥（先用SK 解密再）转化为被HMK 加密                                       */
/* 输入参数：                                                                                                  */   
/*		UINT nSock：     连接的socket 句柄                                                             */
/*		int nEcMark：    椭圆曲线标识                                                                  */
/*		                 0x01：ECC 128 位，NIST P-256，公钥长度64 字节（暂不支持）                      */ 
/*				 0x02：ECC 256 位，NIST P-521，公钥长度132 字节（暂不支持）                     */
/*				 0x11：SM2 128 位，SM2 曲线，公钥长度64 字节                                   */
/*		int nPad:        填充模式， 0：不填充（具体填充方式待补充，暂不支持）                            */
/*		byte *pbSK：     私钥的密文（被HMK 加密），二进制数，（字节）长度由nSKLen 指定                   */
/*		int nSKLen：     私钥的长度, 取值范围[1, 256]                                                  */
/*		byte *pbKeyByPK：被公钥PK 加密的密钥，二进制数，密文数据（字节）长度由nKeyLen	指定，        */
/*		int nKeyLen：    pbKeyByPK 的长度, 取值范围[8, 2048]并能被8 整除且不超过公钥模长。              */
/*				 注：把“被HMK 加密的密钥”看做单纯的被HMK 加密的数据进行处理。                   */
/* 输出参数：                                                                                                 */
/*		byte *pbKeyByHMK：被HMK 加密的密钥，二进制数，长度由*pnKeyByHMKLen 给出                        */
/*		int *pnKeyByHMKLen：pbKeyByHMK 的长度。                                                      */
/* 返回值：                                                                                                  */
/*		0： 执行成功                                                                                 */
/*		1： 输入参数验证失败                                                                          */
/*		2： 无效的密钥(PK)                                                                            */
/*		3： 向加密机发送数据失败                                                                      */
/*		4： 接收加密机数据超时                                                                        */
/*		5： 接收到的数据格式错                                                                        */
/*		9:  其他错误                                                                                 */
/* 维护记录：                                                                                                */
/*          2017-03-07 by zhaomx                                                                             */
/*************************************************************************************************************/ 

int SMAPISm2SKTransInto(UINT nSock, int nEcMark, int nPad, byte *pbSK,int nSKLen, byte *pbKeyByPK, int nKeyLen, 
	                byte *pbKeyByHMK, int  *pnKeyByHMKLen);


/**************************************************************************************************************/
/* 函数名称： SMAPITransKeyDesToSm4                                                                           */
/*           5.26 DES到SM4 密钥转加密（7.3.5 数据转加密）  农行   "VS"                                         */
/* 功能说明：                                                                                                 */
/*		将被DES算法加密的密钥密文，转换为以SM4 加密的密文。                                             */
/* 输入参数：                                                                                                 */
/*		UINT nSock：         连接的socket 句柄                                                        */
/*		int nAlgo：          DES 加密算法类型。Single_Des = 1，Double_Des = 2 ,Triple_Des = 3         */ 
/*		byte *pbDesKey：     经HMK 加密的DES-Key 的密文值，二进制数，（字节）长度由算法确定             */
/*		byte *pbSm4Key：     经HMK 加密的SM4-Key 的密文值，二进制数，（字节）长度=16                   */
/*		byte *pbKeyUnderDes：被DES-Key 加密的密钥密文，二进制数，（字节）长度=16                       */
/* 输出参数：                                                                                                */
/*		byte *pbKeyUnderSm4：被SM4-Key 加密的密钥的密文，二进制数，长度=16                            */
/* 返回值：                                                                                                  */
/*		0： 成功                                                                                     */
/*		1： 输入参数验证失败                                                                          */
/*		3： 向加密机发送数据失败                                                                      */
/*		4： 接收加密机数据超时                                                                        */
/*		5： 接收到的数据格式错                                                                        */
/*		9:  其他错误                                                                                 */
/* 维护记录：                                                                                                */
/*          2017-03-07 by zhaomx                                                                             */
/*************************************************************************************************************/ 

int SMAPITransKeyDesToSm4(UINT nSock, int nAlgo, byte *pbDesKey, byte  *pbSm4Key, byte *pbKeyUnderDes, 
	                  byte *pbKeyUnderSm4);

/*************************************************************************************************************/
/* 函数名称： SMAPITransKeySm4ToDes                                                                          */
/*           5.27 SM4 到DES 密钥转加密（7.3.5 数据转加密）  农行   "VS"                                       */
/* 功能说明：                                                                                                */
/*              将被SM4算法加密的密钥密文，转换为以DES加密的密文。                                             */ 
/* 输入参数：                                                                                                */
/*	        UINT nSock：         连接的socket 句柄                                                       */
/*		int  nAlgo：         DES加密算法类型。Single_Des = 1，Double_Des = 2 ,Triple_Des = 3         */
/*		byte *pbSm4Key：     经HMK加密的SM4-Key 的密文值，二进制数，（字节）长度=16                   */
/*		byte *pbDesKey：     经HMK加密的DES-Key 的密文值，二进制数，（字节）长度由算法确定             */
/*		byte *pbKeyUnderSm4：被SM4-Key 加密的密钥密文，二进制数，（字节）长度=16                      */ 
/* 输出参数：                                                                                               */
/*		byte *pbKeyUnderDes：被DES-Key 加密的密钥的密文，二进制数，长度=16                            */
/* 返回值：                                                                                                 */
/*		0： 成功                                                                                    */
/*		1： 输入参数验证失败                                                                         */
/*		3： 向加密机发送数据失败                                                                     */
/*		4： 接收加密机数据超时                                                                       */
/*		5： 接收到的数据格式错                                                                       */
/*		9:  其他错误                                                                                */
/* 维护记录：                                                                                               */
/*          2017-03-07 by zhaomx                                                                            */
/************************************************************************************************************/ 

int SMAPITransKeySm4ToDes(UINT nSock, int nAlgo, byte *pbSm4Key, byte *pbDesKey, byte *pbKeyUnderSm4, 
	                  byte *pbKeyUnderDes);


#ifdef __cplusplus
}
#endif
#endif
