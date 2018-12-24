#ifndef _UTIL_H_
#define _UTIL_H_ 1

#define ERR_OK				 0
#define ERR_CONNECT_HSM			 1
#define ERR_SEND_DATA			 2
#define ERR_RECIVE_TIMEOUT	         3
#define ERR_RECIVE_FAIL	   	         4
#define ERR_INPUT_DATA		         5
#define ERR_HASH_ID 			 6
#define ERR_PADDING_MODE		 7
#define ERR_ALG_ID			 8
#define ERR_ENCRYPT_ID			 9
#define ERR_ECB_CBC_MODE		 10
#define ERR_SIGNATURE_LEN                11
#define ERR_MODULE			 12
#define ERR_RSA_INDEX		         13
#define ERR_PUBKEY_DER			 14
#define ERR_PRIBKEY_DER			 15
#define ERR_PRIBKEY_PAD			 16
#define ERR_PUBKEY_ENC			 17
#define ERR_PUBKEY_DEC			 18
#define ERR_PRIKEY_ENC			 19
#define ERR_PRIKEY_DEC			 20
#define ERR_VERIFY			 21
#define ERR_KEY_LEN			 22
#define ERR_DIV_TIMES			 23
#define ERR_KEY_TYPE		         24
#define ERR_KEY_INDEX			 25
#define ERR_KEY_NOT_EXIST                26
#define ERR_DATA_LEN	                 27
#define ERR_NOT_ASCII			 28
#define ERR_PRINT_TEMPLATE	         29
#define ERR_GEN_PRINT_KEY		 30
#define ERR_MAC_ALG_ID		         31
#define ERR_INS_TOOSHOUT		 32
#define ERR_RSA_DATA_LEN		 33
#define ERR_READ_PRINT_FILE	         34
#define ERR_OTHER		         35

////临时错误码
#define ERR_KEK_NULL                     36

#ifdef __cplusplus
extern "C"{
#endif

int Hex2Bin(char *string, unsigned char* bytes, unsigned int *length);
int Bin2Hex(unsigned char *bytes, unsigned int length, char *string);
int Hex2Int(char *string, int size);
int Num2Int(char *string, int size);
int Int2Num(unsigned int integer, char *string, int size);
int Int2Hex(unsigned int integer, char *string, int size);
int Int2Bin(unsigned int integer, unsigned char *string, int size);
unsigned int Bin2Int(unsigned char *string, int size);
int CheakNum(char *string,unsigned int length);
int GetNumCnt(char *string,unsigned int *length);

#ifdef __cplusplus
}
#endif
#endif
