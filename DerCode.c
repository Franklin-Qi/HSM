
/*********************************************************************/
/* 文 件 名：  DerCode.c                                             */
/* 版 本 号：  v1.1                                                  */
/* 所 有 者：                                                        */
/* 版    权：  Union Beijing                                         */
/* 功    能：  农行ICCM_密钥安全系统_第05号_加密机接口（国密）api      */
/* 维护记录： 1. 2009-4-16 by  Chendy                                */
/********************************************************************/

#include <stdlib.h>
#include <string.h>
#include "DerCode.h"

int derlen_to_bytenum(int der_len, unsigned char *A)
{
    int	bytenum=5;

    if( (der_len/65536) >255)
    {
	bytenum=5;
	A[0]=0x84;
	A[1]=(unsigned char)(der_len/(65536*256));
	A[2]=(unsigned char)( (der_len%(65536*256))/65535);
	A[3]=(unsigned char)( (der_len%66536)/256);
	A[4]=(unsigned char)( (der_len%65536)%256);
    }
    else if( (der_len /256) > 255)
    {
	bytenum=4;
	A[0]=0x83;
	A[1]=(unsigned char)(der_len/65536);
	A[2]=(unsigned char)( (der_len%65536)/256);
	A[3]=(unsigned char)( (der_len%65536)%256);
    }
    else if(der_len >255)
    {
	bytenum=3;
	A[0]=0x82;
	A[1]=(unsigned char)(der_len/256);
	A[2]=(unsigned char)(der_len%256);
    }
    else if(der_len>127)
    {
	bytenum=2;
	A[0]=0x81;
	A[1]=(unsigned char)(der_len);
    }
    else
    {
	bytenum=1;
	A[0]=(unsigned char)(der_len);
    }	
    return(bytenum);
}

int bytenum_to_derlen(unsigned char *bytes, int *lenlength, int *len)
{
    if(bytes[0] > 0x84)
	return DR_ERR_FORMAT;
    switch(bytes[0])
    {
	case 0x81:
		*lenlength = 2;
		*len = bytes[1];
		break;
	case 0x82:
		*lenlength = 3;
		*len = bytes[1]*256+bytes[2];
		break;
	case 0x83:
		*lenlength = 4;
		*len = bytes[1]*256*256+bytes[2]*256+bytes[3];
		break;
	case 0x84:
		*lenlength = 5;
		*len = bytes[1]*256*256*256+bytes[2]*256*256+bytes[3]*256+bytes[4];
		break;
				
	default:
		*lenlength = 1;
		*len = bytes[0];
	}
	return DR_OK;
}

int der_integer(unsigned char *integer, int integerlen, unsigned char *der, int derlen)
{

    int bfill = 0;
    int contentlen, lencodelen, offset, i, newintegerlen;
    unsigned char lencode[5], *newinteger = NULL;

    memset(lencode,0x00,sizeof(lencode));

    for(i=0;i<integerlen;i++)
    {
	if(integer[i] != 0)
	    break;
    }
    if(i == integerlen)
	return DR_ERR;

    newinteger = integer+i;
    newintegerlen = integerlen-i;
    contentlen = newintegerlen;
    if( (newinteger[0] & 0x80) != 0x00 )
    {
	bfill = 1;
	contentlen++;
    }
    lencodelen = derlen_to_bytenum(contentlen,lencode);
    if(lencodelen+contentlen+1 > derlen)
	return DR_ERR_BUFFER;
    der[0] = 0x02;
    memcpy(der+1,lencode,lencodelen);
    offset = 1+lencodelen;
    if(bfill)
	der[offset++] = 0;
    memcpy(der+offset,newinteger,newintegerlen);
    offset += newintegerlen;
    return offset;

}

int dder_integer(unsigned char *der, 
	unsigned char *ppinteger, int *contentlen, int *totallen)
{

    int lencodelen, offset, integerlen, dr;

    if(der[0] != 0x02)
	return DR_ERR_FORMAT;
    dr = bytenum_to_derlen(der+1,&lencodelen,&integerlen);
    if(dr != DR_OK)
	return dr;
    offset = 1+lencodelen;
    *totallen = 1+lencodelen+integerlen;
    if(der[offset] == 0x00)
    {
	integerlen--;
	offset++;
    }
    memcpy(ppinteger,der+offset,integerlen);
    *contentlen = integerlen;	
    return DR_OK;	
}

int Der_Pubkey_Pkcs1(unsigned char *modulus, 
	int modulusLen, unsigned char *pubExp,
	int pubExpLen, unsigned char *pubkeyDer, int *pubkeyDerLen)
{

    unsigned char spkmod[MAX_MODULUS_LEN+10], spkexp[MAX_MODULUS_LEN+10];
    int pkmodlen, pkexplen;
    unsigned char lencode[5];
    int contentlen, lencodelen, offset;

    pkmodlen = der_integer(modulus,modulusLen,spkmod,sizeof(spkmod));
    if(pkmodlen < 0)
	return pkmodlen;
    pkexplen = der_integer(pubExp,pubExpLen,spkexp,sizeof(spkexp));
    if(pkexplen < 0)
	return pkexplen;
    contentlen = pkmodlen+pkexplen;
    lencodelen = derlen_to_bytenum(contentlen,lencode);
    if(pubkeyDer)
    {
	/*
	if(1+lencodelen+contentlen > *pubkeyDerLen)
	{
	    *pubkeyDerLen = 1+lencodelen+contentlen;
	    return DR_ERR_BUFFER;
	}
	*/
	pubkeyDer[0] = 0x30;
	memcpy(pubkeyDer+1,lencode,lencodelen);
	offset = lencodelen+1;
	memcpy(pubkeyDer+offset,spkmod,pkmodlen);
	offset += pkmodlen;
	memcpy(pubkeyDer+offset,spkexp,pkexplen);
	offset += pkexplen;
	*pubkeyDerLen = offset;
    }
    *pubkeyDerLen = 1+lencodelen+contentlen;
    return DR_OK;
}


int DDer_Pubkey_Pkcs1(unsigned char *pubkeyDer, int pubkeyDerLen, 
	unsigned char *ppmodulus, int *modulusLen, 
	unsigned char *pppubExp, int *pubExpLen)
{
    int lencodelen, offset;
    int len, dr, unitlen;
    int explen, modlen;
    unsigned char mod[MAX_MODULUS_LEN+1];
    unsigned char exp[MAX_MODULUS_LEN+1];

    memset(mod,0x00,sizeof(mod));
    memset(exp,0x00,sizeof(exp));

    modlen=explen=0;

    if(pubkeyDer[0] != 0x30)
	return DR_ERR_FORMAT;
    dr = bytenum_to_derlen(pubkeyDer+1,&lencodelen,&len);
    if(dr != DR_OK)
	return dr;
    if(1+lencodelen+len > pubkeyDerLen)
	return DR_ERR_FORMAT;
    offset = 1+lencodelen;
	
    dr = dder_integer(pubkeyDer+offset,mod,&modlen,&unitlen);
    if(dr != DR_OK)
	return dr;
    memcpy(ppmodulus,mod,modlen);
    *modulusLen=modlen;

    offset += unitlen;

    dr = dder_integer(pubkeyDer+offset,exp,&explen,&unitlen);
    if(dr != DR_OK)
	return dr;

    memcpy(pppubExp,exp,explen);
    *pubExpLen=explen;

    return dr;

}

