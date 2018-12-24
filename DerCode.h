
/*********************************************************************/
/* 文 件 名：  DerCode.h                                             */
/* 版 本 号：  v1.1                                                  */
/* 所 有 者：                                                        */
/* 版    权：  Union Beijing                                         */
/* 功    能：  农行ICCM_密钥安全系统_第05号_加密机接口（国密）api      */
/* 维护记录： 1. 2009-4-16 by  Chendy                                */
/********************************************************************/

#ifndef _DERCODE_H_
#define _DERCODE_H_

#define	DR_OK		1
#define	DR_ERR		-1
#define	DR_ERR_FORMAT	-2
#define	DR_ERR_BUFFER	-3
#define	DR_ERR_MEMORY	-4
#define	DR_ERR_VER	-5

#define MAX_MODULUS_LEN 512
//#define MAX_MODULUS_LEN 2048

int Der_Pubkey_Pkcs1(unsigned char *modulus, int modulusLen, unsigned char *pubExp,
					 int pubExpLen, unsigned char *pubkeyDer, int *pubkeyDerLen);
int DDer_Pubkey_Pkcs1(unsigned char *pubkeyDer, int pubkeyDerLen, unsigned char *ppmodulus, 
					  int *modulusLen, unsigned char *pppubExp, int *pubExpLen);

#endif
