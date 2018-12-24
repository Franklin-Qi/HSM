#ifndef  __ERROR_H__
#define  __ERROR_H__

/* error code for HSM */
#define  EDES_NO_MODE			0x10		/* ECB、CBC模式错误 */
#define  SIGN_LEN			0x92		/* 签名长度错误（应该等于模长/8） */
#define  RSA_MODE_LEN			0xb0		/* 模长错误 */
#define  RSA_INDEX_OUTBOUND	        0xb4		/* RSA密钥索引越界 */
#define  RSA_PUB_DECODE		        0xb2		/* 公钥的der格式错误 */
#define  RSA_PRI_DECODE		        0xbf		/* 私钥的der格式错误 */
#define  PRIVATE_KEY_PAD		0x93		/* 私钥的der格式填充错误 */
#define  RSA_PUB_ENC			0xb3		/* 公钥加密错误 */
#define  RSA_PUB_DEC			0xbc		/* 公钥解密错误 */
#define  RSA_PRI_ENC			0xbb		/* 私钥加密错误 */
#define  RSA_PRI_DEC			0xae		/* 私钥解密错误 */
#define  RSA_VER_SIGN			0xbd		/* 验证失败 */
#define  EMAC_AUTH			0x2d		/* 验证失败 */
#define  EPIN_AUTH			0x1d
#define  EKEY_LEN 			0x88		/* 密钥长度错误 {8,16,24} */
#define  EICM_DVSF_NUM			0x55		/* 分散次数错误 */
#define  EICT_KEY_TYPE			0x75 	        /* 密钥类型错误 */
#define  EICT_BANK_INDEX		0x70		/* 次主密钥索引错误 */
#define  EICT_SHSMK			0x72		/* 密钥不存在 */
#define  EASC_DATA_LEN			0x68		/* 数据长度错误 */
#define  EASC_INVALID			0x67		/* 数据不是ascii */
#define  EMAC_INVALID_FLAG		0x2f
#define  EMES_TOO_SHORT		        0x61		/* 指令长度太短 */
#define  RSA_DATA_LEN			0xb1		/* RSA加解密时数据长度错误 */
#define  EIEB_RSA_INDEX			0xc1

/* error code for HSM API */
#define  HSM_API_SUCC			0
#define  EHSM_READY			1		/*hsm connect fail*/
#define  ERR_SNDDATA			2		/* 向加密机发送数据失败 */
#define  ERR_RECVDATA			3		/* 接收加密机数据超时 */
#define  EHSM_RECV			4		/* receiv data fail*/
#define  ERR_INVALID_PARA		5		/* 输入参数验证失败*/
#define  ERR_DIGEST_FLAG		6		/* 摘要算法标志错误 */
#define  ERR_PADDING_MODE		7		/* 填充模式错误 */
#define  ERR_ENC_OR_DEC		        9		/* 加解密标志错误 */

#define  ERR_DES_MODE			10		/* ECB、CBC模式错误 */
#define  ERR_SIGN_LEN			11		/* 签名长度错误（应该等于模长/8） */
#define  ERR_RSA_MODE_LEN		12		/* 模长错误 */
#define  ERR_RSA_INDEX_OUTBOUND	        13		/* RSA密钥索引越界 */
#define  ERR_RSA_PUB_DECODE		14		/* 公钥的der格式错误 */
#define  ERR_RSA_PRI_ENCODE		15		/* 私钥的der格式错误 */
#define  ERR_PRI_KEY_PAD		16		/* 私钥的der格式填充错误 */
#define  ERR_RSA_PUB_ENC		17		/* 公钥加密错误 */
#define  ERR_RSA_PUB_DEC		18		/* 公钥解密错误 */
#define  ERR_RSA_PRI_ENC		19		/* 私钥加密错误 */

#define  ERR_RSA_PRI_DEC		20		/* 私钥解密错误 */
#define  ERR_VERIFY_FAILED		21		/* 验证失败 */
#define  ERR_KEY_LEN			22		/* 密钥长度错误 {8,16,24} */
#define  ERR_DVSF_NUM			23		/* 分散次数错误 */
#define  ERR_KEY_TYPE			24		/* 密钥类型错误 */
#define  ERR_KEY_INDEX			25		/* 密钥索引错误 */
#define  ERR_NO_SHSMK			26		/* 密钥不存在 */

#define  ERR_ASC_INVALID		28		/* 数据不是ascii */
#define  ERR_DEFINE_PRINTFORMAT	        29		/* 定义打印格式失败 */

#define  ERR_GENERATE_PRINT_KEY	        30		/* 产生并打印密钥失败 */
#define  ERR_MAC_FLAG			31		/* MAC算法错误 */
#define  ERR_MSG_TOO_SHORT		32		/* 指令长度太短 */
#define  ERR_RSA_DATA_LEN		33		/* RSA加解密时数据长度错误 */
#define  ERR_READ_FILE			34		/* 读取打印格式文件失败 */
#define  ERR_OTHER			35		/* 其他错误 */
#define  ERR_SOCK_INVALID               36              /* 无效的套接字 */

#define  ERR_RE_DATA			37              /*return data  error */

//new err code
#define  ERR_INPUT		        15
#define  ERR_PINLEN		        24
#define  ERR_DATA_LEN			80		/* 数据长度错误 */
#define  ERR_ALGO_FLAG			4		/* 算法标志错误 Single_Des = 1，Double_Des = 2 ,Triple_Des = 3 */

/*newadd20170523*/
#define ERR_PIN_INVALID     100
#define ERR_PAN_LEN         101
#define ERR_PAN_INVALID     102

#endif




