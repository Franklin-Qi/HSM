/*----------------------------------------------------------------------|
|    hsmapi_define.h                                                    |
|    Version :     1.0                                                  |
|    Author:       by lcj.                                              |
|    Description:  SJJ1310密码机接口宏定义文件                          |
|                                                                       |
|    Copyright :   Beijing JN TASS Technology Co., Ltd.                 |
|    data:         2015-05-21. Create                                   |
|-----------------------------------------------------------------------|
|    Modify History:                                                    |
|----------------------------------------------------------------------*/
#ifndef __HSM_API_DEFINE_H__
#define __HSM_API_DEFINE_H__

#define SOCKET_MAXDATALEN       5 * 1024 + 128
#define DEFAULT_INIFILE         "CfgTassHsmApi.ini"

/*** 系统函数宏定义 ***/
#ifdef _MSC_VER
#define TASS_SPRINTF sprintf_s
#define  __func__ __FUNCTION__
#else
#define TASS_SPRINTF snprintf
#endif

//#define DEBUG

/*** 数据长度 ***/
#define PANFMT_PIN_LMK          99
#define PANFMT_PIN4             4
#define PANFMT_DISPER           0
#define PANFMT_CVV              88

/*** 加密算法模式 ***/
#define ENCRYPT_MODE_ECB            0
#define ENCRYPT_MODE_CBC            1
#define ENCRYPT_MODE_CFB            2
#define ENCRYPT_MODE_OFB            3

/*** 定义MAC模式 ***/
#define    MAC_MODE_ISO9797_1_1     1
#define    MAC_MODE_ISO9797_1_3     3

/*** 定义HASH算法标识 ***/
#define    HASH_MODE_SHA1           1
#define    HASH_MODE_MD5            2
#define    HASH_MODE_ISO10118_2     3
#define    HASH_MODE_NOHASH         4
#define    HASH_MODE_SHA224         5
#define    HASH_MODE_SHA256         6
#define    HASH_MODE_SHA384         7
#define    HASH_MODE_SHA512         8
#define    HASH_MODE_SM3            20

/*** 定义数据填充模式 ***/
#define    PADDING_MODE_SYMM_PBOCENC        0
#define    PADDING_MODE_SYMM_PBOCMAC        1
#define    PADDING_MODE_SYMM_ANSIX9_19      2
#define    PADDING_MODE_SYMM_ANSIX9_23      3
#define    PADDING_MODE_SYMM_PKCS5          4
#define    PADDING_MODE_SYMM_NOPAD          5

#define    PADDING_MODE_ASYM_NOPAD          0
#define    PADDING_MODE_ASYM_PKCS1V1_5      1

/*** 对称密钥类型 ***/
#define KEY_TYPE_KEKZMK          "000"
#define KEY_TYPE_ZPK             "001"
#define KEY_TYPE_PVKTPK          "002"
#define KEY_TYPE_CVK             "402"
#define KEY_TYPE_TAK             "003"
#define KEY_TYPE_ZAK             "008"
#define KEY_TYPE_BDK             "009"
#define KEY_TYPE_MDKMKAC         "109"
#define KEY_TYPE_MKSMI           "209"
#define KEY_TYPE_MKSMC           "309"
#define KEY_TYPE_MKDAK           "409"
#define KEY_TYPE_MKDN            "509"
#define KEY_TYPE_DEKZEK          "00A"
#define KEY_TYPE_TEK             "00B"
#define KEY_TYPE_HMAC            "10C"
#define KEY_TYPE_KMC             "011"

/*** 非对称密钥类型 ***/
#define KEY_TYPE_RSA                 1
#define KEY_TYPE_ECC                 2
#define KEY_USAGE_SIGN               0
#define KEY_USAGE_ENC                1
#define KEY_USAGE_KEYEX              2

/*** 定义算法标识 ***/
#define KEY_SCHEME_DES           'Z'
#define KEY_SCHEME_DES2X         'X'
#define KEY_SCHEME_DES2U         'U'
#define KEY_SCHEME_DES3Y         'Y'
#define KEY_SCHEME_DES3T         'T'
#define KEY_SCHEME_SM1           'P'
#define KEY_SCHEME_SM4           'R'
#define KEY_SCHEME_AES           'L'

/*** 错误码定义 ***/
#define HAR_OK                        0x00000000              /*** 操作成功 ***/
#define HAR_BASE                      0x06000000              /*** 错误码基础值 ***/
#define HAR_SOCK_INIT                 HAR_BASE + 0x00000001              /*** socket初始化失败 ***/
#define HAR_SOCK_CONNECT              HAR_BASE + 0x00000002              /*** socket连接失败 ***/
#define HAR_SOCK_SELECT               HAR_BASE + 0x00000003              /*** 设置连接属性失败 ***/
#define HAR_SOCK_SEND                 HAR_BASE + 0x00000004              /*** 发送数据失败 ***/
#define HAR_SOCK_RECV                 HAR_BASE + 0x00000005              /*** 接收数据失败 ***/
#define HAR_SOCK_INVALID              HAR_BASE + 0x00000006              /*** 无效的socket ***/
#define HAR_SOCK_CREATE               HAR_BASE + 0x00000007              /*** 创建socket失败 ***/
#define HAR_SOCK_DATA_LEN             HAR_BASE + 0x00000008              /*** 无效的报文数据长度 ***/

#define HAR_MSG_LENFLG                HAR_BASE + 0x00000009              /*** 消息长度错误 ***/
#define HAR_MSG_RSPCODE               HAR_BASE + 0x0000000A              /*** 响应代码错误 ***/

#define HAR_MEM_LENLESS               HAR_BASE + 0x0000000B              /*** 数据缓存区不足 ***/
#define HAR_MEM_MALLOC                HAR_BASE + 0x0000000C              /*** 内存申请失败 ***/

#define HAR_CFGFILE_NOEXIST           HAR_BASE + 0x0000000D              /*** 找不到配置文件 ***/
#define HAR_CFGFILE_OPEN              HAR_BASE + 0x0000000E              /*** 打开配置文件失败 ***/
#define HAR_CFGFILE_KEY_NOEXIST       HAR_BASE + 0x0000000F              /*** 键名不存在 ***/
#define HAR_CFGFILE_VALUE_NOEXIST     HAR_BASE + 0x00000010              /*** 键值不存在 ***/
#define HAR_CFGFILE_VALUE_INVALID     HAR_BASE + 0x00000011              /*** 键值无效 ***/

#define HAR_HEX_TO_BYTE               HAR_BASE + 0x00000012              /*** 十六进制转二进制失败 ***/
#define HAR_BYTE_TO_HEX               HAR_BASE + 0x00000013              /*** 二进制转十六进制失败 ***/
#define HAR_DER_DECODE                HAR_BASE + 0x00000014              /*** der解码失败 ***/

#define HAR_PARAM_KEY_ID              HAR_BASE + 0x00000015              /*** 无效的密钥索引 ***/
#define HAR_PARAM_KEY_TYPE            HAR_BASE + 0x00000016              /*** 无效的密钥类型 ***/
#define HAR_PARAM_KEY_CIPHER          HAR_BASE + 0x00000017              /*** 无效的密钥密文 ***/
#define HAR_PARAM_KEY_SCHEME          HAR_BASE + 0x00000018              /*** 无效的算法标识 ***/
#define HAR_PARAM_KEY_HEADER          HAR_BASE + 0x00000019              /*** 无效的密钥头 ***/
#define HAR_PARAM_Diversify_NUM          HAR_BASE + 0x0000001A              /*** 无效的分散级数 ***/
#define HAR_PARAM_Diversify_DATA         HAR_BASE + 0x0000001B              /*** 无效的分散因子 ***/
#define HAR_PARAM_SESSION_KEY_MODE    HAR_BASE + 0x0000001C              /*** 无效的会话密钥产生模式 ***/
#define HAR_PARAM_SESSION_KEY_DATA    HAR_BASE + 0x0000001D              /*** 无效的会话密钥因子 ***/
#define HAR_PARAM_ENC_MODE            HAR_BASE + 0x0000001E              /*** 无效的加密算法模式 ***/
#define HAR_PARAM_MAC_MODE            HAR_BASE + 0x0000001F              /*** 无效的MAC算法模式 ***/
#define HAR_PARAM_PRINT               HAR_BASE + 0x00000020              /*** 打印密钥或加载打印格式失败 ***/
#define HAR_PARAM_ELEMENT_NUM         HAR_BASE + 0x00000021              /*** 密钥成份个数无效 ***/
#define HAR_PARAM_IV                  HAR_BASE + 0x00000022              /*** 无效的IV值 ***/
#define HAR_PARAM_PAN                 HAR_BASE + 0x00000023              /*** 无效的PAN号 ***/
#define HAR_PARAM_PADDING_MODE        HAR_BASE + 0x00000024              /*** 数据填充模式错误 ***/

#define HAR_PARAM_CHAR                HAR_BASE + 0x00000025
#define HAR_PARAM_UNKNOWN             HAR_BASE + 0x00000026              /*** 未知的错误 ***/
#define HAR_PARAM_LEN                 HAR_BASE + 0x00000027              /*** 参数值长度无效 ***/
#define HAR_PARAM_VALUE               HAR_BASE + 0x00000028              /*** 参数值内容无效 ***/
#define HAR_PARAM_ISNULL              HAR_BASE + 0x00000029              /*** 参数值为NULL ***/

#define HAR_ALREADY_INITIALIZED       HAR_BASE + 0x0000002A              /*** 初始化已调用 ***/
#define HAR_NOT_INITIALIZED           HAR_BASE + 0x0000002B              /*** 未调用初始化 ***/
#define HAR_OPENDEVICE                HAR_BASE + 0x0000002C              /*** 打开设备失败 ***/
#define HAR_OPENSESSION               HAR_BASE + 0x0000002D              /*** 创建会话失败 ***/
#define HAR_DEVICEHANDLE_INVALID      HAR_BASE + 0x0000002E              /*** 设备句柄无效 ***/
#define HAR_SESSIONHANDLE_INVALID     HAR_BASE + 0x0000002F              /*** 会话句柄无效 ***/
#define HAR_SOCK_TIMEOUT     		  HAR_BASE + 0x00000030              /*** socket通讯超时 ***/

#define HAR_MUTEX_CREATE     		  HAR_BASE + 0x00000031              /*** 创建互斥锁失败 ***/


#endif    /***  __HSM_API_DEFINE_H__ ***/
