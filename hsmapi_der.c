#include <stdlib.h>
#include <string.h>
#include "hsmapi_der.h"
//////////////////////////////////////////
#define MAX_MODULUS_LEN                512
//////////////////////////////////////////
//        Assistant functions:            //
int derlen_to_bytenum(int der_len, unsigned char A[5])
{
    int    bytenum=5;

    if( (der_len/65536) >255){
        bytenum=5;
        A[0]=0x84;
        A[1]=(unsigned char)(der_len/(65536*256));
        A[2]=(unsigned char)( (der_len%(65536*256))/65535);
        A[3]=(unsigned char)( (der_len%66536)/256);
        A[4]=(unsigned char)( (der_len%65536)%256);
    }
    else if( (der_len /256) > 255){
        bytenum=4;
        A[0]=0x83;
        A[1]=(unsigned char)(der_len/65536);
        A[2]=(unsigned char)( (der_len%65536)/256);
        A[3]=(unsigned char)( (der_len%65536)%256);
    }
    else if(der_len >255){
        bytenum=3;
        A[0]=0x82;
        A[1]=(unsigned char)(der_len/256);
        A[2]=(unsigned char)(der_len%256);
    }
    else if(der_len>127){
        bytenum=2;
        A[0]=0x81;
        A[1]=(unsigned char)(der_len);
    }
    else{
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
    default:
        *lenlength = 1;
        *len = bytes[0];
    }
    return DR_OK;
}

int der_integer(unsigned char *integer, int integerlen, unsigned char *der, int derlen)
{
    int            bfill = 0;
    int                contentlen, lencodelen, offset, i, newintegerlen;
    unsigned char    lencode[5], *newinteger;

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

int dder_integer(unsigned char *der, unsigned char **ppinteger, int *contentlen, int *totallen)
{
    int        lencodelen, offset, integerlen, dr;

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
    *ppinteger = der+offset;
    *contentlen = integerlen;    
    return DR_OK;    
}

int der_bitString(unsigned char *string, int stringlen, unsigned char *der, int derlen)
{
    int                contentlen, lencodelen, offset;
    unsigned char    lencode[5];

    contentlen = stringlen+1;
    lencodelen = derlen_to_bytenum(contentlen,lencode);
    if(1+lencodelen+contentlen > derlen)
        return DR_ERR_BUFFER;
    der[0] = 0x03;
    memcpy(der+1,lencode,lencodelen);
    offset = 1+lencodelen;
    der[offset] = 0x00;
    memcpy(der+offset+1,string,stringlen);
    offset += contentlen;
    return offset;
}

int dder_bitString(unsigned char *der, unsigned char **ppString, int *contentlen, int *totallen)
{
    int        lencodelen, offset, stringlen, dr;

    if(der[0] != 0x03)
        return DR_ERR_FORMAT;
    dr = bytenum_to_derlen(der+1,&lencodelen,&stringlen);
    if(dr != DR_OK)
        return dr;
    offset = 1+lencodelen;
    if(der[offset++] != 0x00)
        return DR_ERR_FORMAT;
    *ppString = der+offset;
    *totallen = 1+lencodelen+stringlen;
    *contentlen = stringlen-1;    
    return DR_OK;    
}

int der_printString(unsigned char *string, int stringlen, unsigned char *der, int derlen)
{
    int                contentlen, lencodelen, offset;
    unsigned char    lencode[5];

    contentlen = stringlen;
    lencodelen = derlen_to_bytenum(contentlen,lencode);
    if(1+lencodelen+contentlen > derlen)
        return DR_ERR_BUFFER;
    der[0] = 0x13;
    memcpy(der+1,lencode,lencodelen);
    offset = 1+lencodelen;
    memcpy(der+offset,string,stringlen);
    offset += contentlen;
    return offset;
}

int dder_printString(unsigned char *der, unsigned char **ppString, int *contentlen, int *totallen)
{
    int        lencodelen, offset, stringlen, dr;

    if(der[0] != 0x13)
        return DR_ERR_FORMAT;
    dr = bytenum_to_derlen(der+1,&lencodelen,&stringlen);
    if(dr != DR_OK)
        return dr;
    offset = 1+lencodelen;
    *ppString = der+offset;
    *totallen = 1+lencodelen+stringlen;
    *contentlen = stringlen;    
    return DR_OK;
}

int der_utctime(unsigned char *time, unsigned char *der, int derlen)
{
    if(derlen < 15)
        return DR_ERR_BUFFER;
    der[0] = 0x17;
    der[1] = 0x0d;
    memcpy(der+2,time+2,12);
    der[14] = 0x5a;
    return 15;
}

int dder_utctime(unsigned char *der, int derlen, unsigned char *time)
{
    unsigned char    year[] = {0x00,0x00,0x00,0x00,0x00};

    if(derlen != 15)
        return DR_ERR_FORMAT;
    memcpy(time+4,der+4,12);
    year[2] = der[2];
    year[3] = der[3];
    if(strcmp((char*)(year+2),"50") < 0)
    {
        year[0] = 0x32;
        year[1] = 0x30;
    }
    else
    {
        year[0] = 0x31;
        year[1] = 0x39;
    }
    memcpy(time,year,4);
    return DR_OK;
}
//////////////////////////////////////////
//        Export functions:                //
//////////////////////////////////////////
//        Coding:                            //
int Der_Pubkey_Pkcs1(unsigned char *modulus, int modulusLen, unsigned char *pubExp,
                     int pubExpLen, unsigned char *pubkeyDer, int *pubkeyDerLen)
{
    unsigned char    spkmod[MAX_MODULUS_LEN+10], spkexp[MAX_MODULUS_LEN+10];
    int                pkmodlen, pkexplen;
    unsigned char    lencode[5];
    int                contentlen, lencodelen, offset;

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
        if(1+lencodelen+contentlen > *pubkeyDerLen)
        {
            *pubkeyDerLen = 1+lencodelen+contentlen;
            return DR_ERR_BUFFER;
        }
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

int Der_Prikey_Pkcs1(unsigned char *modulus, int modulusLen, unsigned char *pubExp,
                     int pubExpLen, unsigned char *priExp, int priExpLen,
                     unsigned char *prime1, int prime1Len, unsigned char *prime2,
                     int prime2Len, unsigned char *exponent1, int exponent1Len,
                     unsigned char *exponent2, int exponent2Len, unsigned char *coefficient,
                     int coefficientLen, unsigned char *prikeyDer, int *prikeyDerLen)
{
    unsigned char    version[3] = {0x02,0x01,0x00};
    unsigned char    lencode[5];
    int                contentlen, lencodelen, offset;
    unsigned char    smod[MAX_MODULUS_LEN+10], spbexp[MAX_MODULUS_LEN+10],
            sprexp[MAX_MODULUS_LEN+10], sprime1[MAX_MODULUS_LEN+10], sprime2[MAX_MODULUS_LEN+10],
            sexp1[MAX_MODULUS_LEN+10], sexp2[MAX_MODULUS_LEN+10], scoeff[MAX_MODULUS_LEN+10];
    int        dmodLen, dpbexpLen, dprexpLen, dprime1Len, dprime2Len, dexp1Len, dexp2Len, dcoeffLen;

    dmodLen = der_integer(modulus,modulusLen,smod,sizeof(smod));
    if(dmodLen < 0)
        return dmodLen;
    dpbexpLen = der_integer(pubExp,pubExpLen,spbexp,sizeof(spbexp));
    if(dpbexpLen < 0)
        return dpbexpLen;
    dprexpLen = der_integer(priExp,priExpLen,sprexp,sizeof(sprexp));
    if(dprexpLen < 0)
        return dprexpLen;
    dprime1Len = der_integer(prime1,prime1Len,sprime1,sizeof(sprime1));
    if(dprime1Len < 0)
        return dprime1Len;
    dprime2Len = der_integer(prime2,prime2Len,sprime2,sizeof(sprime2));
    if(dprime2Len < 0)
        return dprime2Len;
    dexp1Len = der_integer(exponent1,exponent1Len,sexp1,sizeof(sexp1));
    if(dexp1Len < 0)
        return dexp1Len;
    dexp2Len = der_integer(exponent2,exponent2Len,sexp2,sizeof(sexp2));
    if(dexp2Len < 0)
        return dexp2Len;
    dcoeffLen = der_integer(coefficient,coefficientLen,scoeff,sizeof(scoeff));
    if(dcoeffLen < 0)
        return dcoeffLen;
    contentlen = 3+dmodLen+dpbexpLen+dprexpLen+dprime1Len+dprime2Len
            +dexp1Len+dexp2Len+dcoeffLen;
    lencodelen = derlen_to_bytenum(contentlen,lencode);
    if(prikeyDer)
    {
        if(1+lencodelen+contentlen > *prikeyDerLen)
        {
            *prikeyDerLen = 1+lencodelen+contentlen;
            return DR_ERR_BUFFER;
        }
        prikeyDer[0] = 0x30;
        memcpy(prikeyDer+1,lencode,lencodelen);
        offset = 1+lencodelen;
        memcpy(prikeyDer+offset,version,3);
        offset += 3;
        memcpy(prikeyDer+offset,smod,dmodLen);
        offset += dmodLen;
        memcpy(prikeyDer+offset,spbexp,dpbexpLen);
        offset += dpbexpLen;
        memcpy(prikeyDer+offset,sprexp,dprexpLen);
        offset += dprexpLen;
        memcpy(prikeyDer+offset,sprime1,dprime1Len);
        offset += dprime1Len;
        memcpy(prikeyDer+offset,sprime2,dprime2Len);
        offset += dprime2Len;
        memcpy(prikeyDer+offset,sexp1,dexp1Len);
        offset += dexp1Len;
        memcpy(prikeyDer+offset,sexp2,dexp2Len);
        offset += dexp2Len;
        memcpy(prikeyDer+offset,scoeff,dcoeffLen);
    }
    *prikeyDerLen = 1+lencodelen+contentlen;
    return DR_OK;
}

int Der_Name_AttrTypeValue(unsigned char type, unsigned char *value, int valueLen,
                           unsigned char *attrDer, int *attrDerLen)
{
    unsigned char    attrtypeID[5] = {0x06, 0x03, 0x55, 0x04, 0x00};
    unsigned char    lencode[5], strDer[128];
    int                lencodelen, offset, strDerLen;

    attrtypeID[4] = type;
    strDerLen = der_printString(value,valueLen,strDer,128);
    if(strDerLen < 0)
        return strDerLen;
    lencodelen = derlen_to_bytenum(5+strDerLen,lencode);
    if(attrDer)
    {
        if(1+lencodelen+5+strDerLen > *attrDerLen)
        {
            *attrDerLen = 1+lencodelen+5+strDerLen;
            return DR_ERR_BUFFER;
        }
        attrDer[0] = 0x30;
        memcpy(attrDer+1,lencode,lencodelen);
        offset = 1+lencodelen;
        memcpy(attrDer+offset,attrtypeID,5);
        offset += 5;
        memcpy(attrDer+offset,strDer,strDerLen);
    }
    *attrDerLen = 1+lencodelen+5+strDerLen;
    return DR_OK;
}

int Der_Name(unsigned char *countryName, int countryNameLen, unsigned char *unitName, int unitNameLen,
             unsigned char *commonName, int commonNameLen, unsigned char *nameDer, int *nameDerLen)
{
    unsigned char    countryDer[128], unitDer[128], commonDer[128];
    unsigned char    countryHead[8], unitHead[8], commonHead[8], lencode[5];
    int                countryHeadLen, unitHeadLen, commonHeadLen, lencodelen;
    int                countryDerLen, unitDerLen, commonDerLen, len, offset; 
    int                dr;

    countryDerLen = sizeof(countryDer);
    dr = Der_Name_AttrTypeValue(0x06,countryName,countryNameLen,countryDer,&countryDerLen);
    if(dr != DR_OK)
        return dr;
    countryHead[0] = 0x31;
    lencodelen = derlen_to_bytenum(countryDerLen,countryHead+1);
    countryHeadLen = 1+lencodelen;

    unitDerLen = sizeof(unitDer);
    dr = Der_Name_AttrTypeValue(0x0A,unitName,unitNameLen,unitDer,&unitDerLen);
    if(dr != DR_OK)
        return dr;
    unitHead[0] = 0x31;
    lencodelen = derlen_to_bytenum(unitDerLen,unitHead+1);
    unitHeadLen = 1+lencodelen;

    commonDerLen = sizeof(commonDer);
    dr = Der_Name_AttrTypeValue(0x03,commonName,commonNameLen,commonDer,&commonDerLen);
    if(dr != DR_OK)
        return dr;
    commonHead[0] = 0x31;
    lencodelen = derlen_to_bytenum(commonDerLen,commonHead+1);
    commonHeadLen = 1+lencodelen;

    len = countryHeadLen+countryDerLen+unitHeadLen+unitDerLen+commonHeadLen+commonDerLen;
    lencodelen = derlen_to_bytenum(len,lencode);
    if(nameDer)
    {
        if(1+lencodelen+len > *nameDerLen)
        {
            *nameDerLen = 1+lencodelen+len;
            return DR_ERR_BUFFER;
        }
        nameDer[0] = 0x30;
        memcpy(nameDer+1,lencode,lencodelen);
        offset = 1+lencodelen;
        memcpy(nameDer+offset,countryHead,countryHeadLen);
        memcpy(nameDer+offset+countryHeadLen,countryDer,countryDerLen);
        offset += countryHeadLen+countryDerLen;
        memcpy(nameDer+offset,unitHead,unitHeadLen);
        memcpy(nameDer+offset+unitHeadLen,unitDer,unitDerLen);
        offset += unitHeadLen+unitDerLen;
        memcpy(nameDer+offset,commonHead,commonHeadLen);
        memcpy(nameDer+offset+commonHeadLen,commonDer,commonDerLen);
    }
    *nameDerLen = 1+lencodelen+len;
    return DR_OK;
}

int Der_Validity(unsigned char *notBefore, unsigned char *notAfter, unsigned char *validityDer, int *derLen)
{
    int        dr;

    if(*derLen < 32)
    {
        *derLen = 32;
        return DR_ERR_BUFFER;
    }
    if(validityDer)
    {
        validityDer[0] = 0x30;
        validityDer[1] = 0x1e;
        dr = der_utctime(notBefore,validityDer+2,15);
        if(dr < 0)
            return dr;
        dr = der_utctime(notAfter,validityDer+17,15);
        if(dr < 0)
            return dr;
    }
    *derLen = 32;
    return DR_OK;
}

int Der_PubkeyInfo(int signature, unsigned char *modulus, int modulusLen, unsigned char *pubExp,
                   int pubExpLen, unsigned char *pbkeyInfoDer, int *infoDerLen)
{
    unsigned char    algoDer[15] = {0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x0,0x05,0x0};
    unsigned char    *pPubkeyDer, *pPubStrDer, lencode[5];
    int                dr, pubkeyDerLen, pubStrDerLen, contentlen, offset, lencodelen;


    algoDer[12] = signature;
    
    dr = Der_Pubkey_Pkcs1(modulus,modulusLen,pubExp,pubExpLen,NULL,&pubkeyDerLen);
    if(dr != DR_OK)
        return dr;
    pPubkeyDer = (unsigned char *)malloc(pubkeyDerLen);
    if(pPubkeyDer == NULL)
        return DR_ERR_MEMORY;
    dr = Der_Pubkey_Pkcs1(modulus,modulusLen,pubExp,pubExpLen,pPubkeyDer,&pubkeyDerLen);
    if(dr != DR_OK)
    {
        free(pPubkeyDer);
        return dr;
    }
    pubStrDerLen = pubkeyDerLen+16;
    pPubStrDer = (unsigned char *)malloc(pubStrDerLen);
    if(pPubStrDer == NULL)
    {
        free(pPubkeyDer);
        return DR_ERR_MEMORY;
    }
    pubStrDerLen = der_bitString(pPubkeyDer,pubkeyDerLen,pPubStrDer,pubStrDerLen);
    free(pPubkeyDer);
    if(pubStrDerLen < 0)
    {
        free(pPubStrDer);
        return pubStrDerLen;
    }
    
    contentlen = 15+pubStrDerLen;
    lencodelen = derlen_to_bytenum(contentlen,lencode);    
    if(pbkeyInfoDer)
    {
        if(1+lencodelen+contentlen > *infoDerLen)
        {
            *infoDerLen = 1+lencodelen+contentlen;
            free(pPubStrDer);
            return DR_ERR_BUFFER;
        }
        pbkeyInfoDer[0] = 0x30;
        memcpy(pbkeyInfoDer+1,lencode,lencodelen);
        offset = 1+lencodelen;
        memcpy(pbkeyInfoDer+offset,algoDer,15);
        offset += 15;
        memcpy(pbkeyInfoDer+offset,pPubStrDer,pubStrDerLen);
    }
    free(pPubStrDer);
    *infoDerLen = 1+lencodelen+contentlen;
    return DR_OK;
}

int Der_TbsCert(unsigned char    version,
                unsigned char    *serial,
                int                serialLen,
                unsigned char    signID,
                unsigned char    *issuerCountry,
                int                issuerCountryLen,
                unsigned char    *issuerUnit,
                int                issuerUnitLen,
                unsigned char    *issuerCommon,
                int                issuerCommonLen,
                unsigned char    *notBefore,
                unsigned char    *notAfter,
                unsigned char    *holderCountry,
                int                holderCountryLen,
                unsigned char    *holderUnit,
                int                holderUnitLen,
                unsigned char    *holderCommon,
                int                holderCommonLen,
                unsigned char    *modulus,
                int                modulusLen,
                unsigned char    *pubExp,
                int                pubExpLen,
                unsigned char    *pTbsCert,
                int                *tbsCertLen)
{
    unsigned char    versionDer[5] = {0xa0,0x03,0x02,0x01,0x0};
    unsigned char    signIDDer[15] = {0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0, 0x05, 0x00};
    unsigned char    serialDer[16], issuerDer[128], holderDer[128], validityDer[64];
    unsigned char    extensionDer[41] = {0xa3, 0x27, 0x30, 0x25, 0x30, 0x0e, 0x06, 0x03,
                                        0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04,
                                        0x03, 0x02, 0x02, 0xa4, 0x30, 0x13, 0x06, 0x03,
                                        0x55, 0x1d, 0x25, 0x04, 0x0c, 0x30, 0x0a, 0x06,
                                        0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03,
                                        0x02};

    unsigned char    *pbkeyInfoDer, lencode[5];
    int                pbkeyInfoDerLen, lencodelen, len, offset;
    int                serialDerLen, issuerDerLen = 128, holderDerLen = 128, validityDerLen = 64, dr;

    versionDer[4] = version;
    serialDerLen = der_integer(serial,serialLen,serialDer,sizeof(serialDer));
    if(serialDerLen < 0)
        return serialDerLen;
    signIDDer[12] = signID;
    dr = Der_Name(issuerCountry,issuerCountryLen,issuerUnit,issuerUnitLen,
            issuerCommon,issuerCommonLen,issuerDer,&issuerDerLen);
    if(dr != DR_OK)
        return dr;
    dr = Der_Name(holderCountry,holderCountryLen,holderUnit,holderUnitLen,
            holderCommon,holderCommonLen,holderDer,&holderDerLen);
    if(dr != DR_OK)
        return dr;
    dr = Der_Validity(notBefore,notAfter,validityDer,&validityDerLen);
    if(dr != DR_OK)
        return dr;
    dr = Der_PubkeyInfo(0x01,modulus,modulusLen,pubExp,pubExpLen,NULL,&pbkeyInfoDerLen);
    if(dr != DR_OK)
        return dr;
    pbkeyInfoDer = (unsigned char *)malloc(pbkeyInfoDerLen);
    if(pbkeyInfoDer == NULL)
        return DR_ERR_MEMORY;
    dr = Der_PubkeyInfo(0x01,modulus,modulusLen,pubExp,pubExpLen,pbkeyInfoDer,&pbkeyInfoDerLen);
    if(dr != DR_OK)
    {
        free(pbkeyInfoDer);
        return dr;
    }

    len = 5+serialDerLen+15+issuerDerLen+validityDerLen+holderDerLen+pbkeyInfoDerLen+41;
    lencodelen = derlen_to_bytenum(len,lencode);    
    if(pTbsCert)
    {
        if(1+lencodelen+len > *tbsCertLen)
        {
            free(pbkeyInfoDer);
            *tbsCertLen = 1+lencodelen+len;
            return DR_ERR_BUFFER;
        }
        pTbsCert[0] = 0x30;
        memcpy(pTbsCert+1,lencode,lencodelen);
        offset = 1+lencodelen;
        memcpy(pTbsCert+offset,versionDer,5);
        offset += 5;
        memcpy(pTbsCert+offset,serialDer,serialDerLen);
        offset += serialDerLen;
        memcpy(pTbsCert+offset,signIDDer,15);
        offset += 15;
        memcpy(pTbsCert+offset,issuerDer,issuerDerLen);
        offset += issuerDerLen;
        memcpy(pTbsCert+offset,validityDer,validityDerLen);
        offset += validityDerLen;
        memcpy(pTbsCert+offset,holderDer,holderDerLen);
        offset += holderDerLen;
        memcpy(pTbsCert+offset,pbkeyInfoDer,pbkeyInfoDerLen);
        offset += pbkeyInfoDerLen;
        memcpy(pTbsCert+offset,extensionDer,41);
    }
    free(pbkeyInfoDer);
    *tbsCertLen = 1+lencodelen+len;
    return DR_OK;
}

int Der_Cert(unsigned char    *pTbsCert,
             int            tbsCertLen,
             unsigned char    signID,
             unsigned char    *pSignature,
             int            signatureLen,
             unsigned char    *pCert,
             int            *certLen)
{
    unsigned char    algoDer[15] = {0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x0,0x05,0x0};
    unsigned char    *pSignatureDer, lencode[5];
    int                signatureDerLen, lencodelen, len, offset;

    algoDer[12] = signID;

    signatureDerLen = signatureLen+16;
    pSignatureDer = (unsigned char*)malloc(signatureDerLen);
    if(pSignatureDer == NULL)
        return DR_ERR_MEMORY;
    signatureDerLen = der_bitString(pSignature,signatureLen,pSignatureDer,signatureDerLen);
    if(signatureDerLen < 0)
    {
        free(pSignatureDer);
        return signatureDerLen;
    }
    
    len = tbsCertLen+15+signatureDerLen;
    lencodelen = derlen_to_bytenum(len,lencode);
    if(pCert)
    {    
        if(1+lencodelen+len > *certLen)
        {
            *certLen = 1+lencodelen+len;
            free(pSignatureDer);
            return DR_ERR_BUFFER;
        }
        pCert[0] = 0x30;
        memcpy(pCert+1,lencode,lencodelen);
        offset = 1+lencodelen;
        memcpy(pCert+offset,pTbsCert,tbsCertLen);
        offset += tbsCertLen;
        memcpy(pCert+offset,algoDer,15);
        offset += 15;
        memcpy(pCert+offset,pSignatureDer,signatureDerLen);
    }
    free(pSignatureDer);
    *certLen = 1+lencodelen+len;
    return DR_OK;    
}
//////////////////////////////////////////
//        Decoding:                        //
int DDer_Pubkey_Pkcs1(unsigned char *pubkeyDer, int pubkeyDerLen, unsigned char **ppmodulus, 
                      int *modulusLen, unsigned char **pppubExp, int *pubExpLen)
{
    int        lencodelen, offset, len, dr, unitlen;

    if(pubkeyDer[0] != 0x30)
        return DR_ERR_FORMAT;
    dr = bytenum_to_derlen(pubkeyDer+1,&lencodelen,&len);
    if(dr != DR_OK)
        return dr;
    if(1+lencodelen+len > pubkeyDerLen)
        return DR_ERR_FORMAT;
    offset = 1+lencodelen;

    dr = dder_integer(pubkeyDer+offset,ppmodulus,modulusLen,&unitlen);
    if(dr != DR_OK)
        return dr;
    offset += unitlen;

    dr = dder_integer(pubkeyDer+offset,pppubExp,pubExpLen,&unitlen);
    return dr;
}

int DDer_Prikey_Pkcs1(unsigned char *prikeyDer, int prikeyDerLen, unsigned char **ppModulus,
                      int *modulusLen, unsigned char **ppPubExp, int *pubExpLen, 
                      unsigned char **ppPriExp, int *priExpLen, unsigned char **ppPrime1,
                      int *prime1Len, unsigned char **ppPrime2, int *prime2Len,
                      unsigned char **ppExponent1, int *exponent1Len, unsigned char **ppExponent2,
                      int *exponent2Len, unsigned char **ppcoeff, int *coeffLen)
{
    unsigned char    version[5] = {0x02,0x01,0x0};
    int        lencodelen, offset, len, dr, unitlen;
    
    if(prikeyDer[0] != 0x30)
        return DR_ERR_FORMAT;
    dr = bytenum_to_derlen(prikeyDer+1,&lencodelen,&len);
    if(dr != DR_OK)
        return dr;
    if(1+lencodelen+len > prikeyDerLen)
        return DR_ERR_FORMAT;
    offset = 1+lencodelen;

    if(memcmp(version,prikeyDer+offset,1) != 0)
        return DR_ERR_VER;
    offset += 3;

    dr = dder_integer(prikeyDer+offset,ppModulus,modulusLen,&unitlen);
    if(dr != DR_OK)
        return dr;
    offset += unitlen;

    dr = dder_integer(prikeyDer+offset,ppPubExp,pubExpLen,&unitlen);
    if(dr != DR_OK)
        return dr;
    offset += unitlen;

    dr = dder_integer(prikeyDer+offset,ppPriExp,priExpLen,&unitlen);
    if(dr != DR_OK)
        return dr;
    offset += unitlen;

    dr = dder_integer(prikeyDer+offset,ppPrime1,prime1Len,&unitlen);
    if(dr != DR_OK)
        return dr;
    offset += unitlen;

    dr = dder_integer(prikeyDer+offset,ppPrime2,prime2Len,&unitlen);
    if(dr != DR_OK)
        return dr;
    offset += unitlen;

    dr = dder_integer(prikeyDer+offset,ppExponent1,exponent1Len,&unitlen);
    if(dr != DR_OK)
        return dr;
    offset += unitlen;

    dr = dder_integer(prikeyDer+offset,ppExponent2,exponent2Len,&unitlen);
    if(dr != DR_OK)
        return dr;
    offset += unitlen;

    dr = dder_integer(prikeyDer+offset,ppcoeff,coeffLen,&unitlen);
    if(dr != DR_OK)
        return dr;
    offset += unitlen;
    return DR_OK;
}

int DDer_Name_AttrTypeValue(unsigned char *typeValueDer, int derLen, unsigned char *type,
                            unsigned char **ppValue, int *valueLen)
{
    unsigned char    attrtypeID[5] = {0x06, 0x03, 0x55, 0x04, 0x00};
    int                lencodelen, offset, len, strDerLen, dr;

    if(typeValueDer[0] != 0x30)
        return DR_ERR_FORMAT;
    dr = bytenum_to_derlen(typeValueDer+1,&lencodelen,&len);
    if(dr != DR_OK)
        return dr;
    if(1+lencodelen+len > derLen)
        return DR_ERR_FORMAT;
    offset = 1+lencodelen;
    if(memcmp(attrtypeID,typeValueDer+offset,4) != 0)
        return DR_ERR_FORMAT;
    *type = typeValueDer[offset+4];
    offset += 5;
    dr = dder_printString(typeValueDer+offset,ppValue,valueLen,&strDerLen);
    return dr;
}

int DDer_Name(unsigned char *pNameDer, int derLen, unsigned char **ppCountryN, int *countryNLen,
              unsigned char **ppUnitN, int *unitNLen, unsigned char **ppCommonN, int *commonNLen)
{
    unsigned char    type;
    int                lencodelen, len, offset, dr;

    if(pNameDer[0] != 0x30)
        return DR_ERR_FORMAT;
    dr = bytenum_to_derlen(pNameDer+1,&lencodelen,&len);
    if(dr != DR_OK)
        return dr;
    if(1+lencodelen+len > derLen)
        return DR_ERR_FORMAT;
    offset = 1+lencodelen;
    
    if(pNameDer[offset] != 0x31)
        return DR_ERR_FORMAT;
    dr = bytenum_to_derlen(pNameDer+offset+1,&lencodelen,&len);
    if(dr != DR_OK)
        return dr;
    dr = DDer_Name_AttrTypeValue(pNameDer+offset+1+lencodelen,len,&type,ppCountryN,countryNLen);
    if(dr != DR_OK)
        return dr;
    offset += 1+lencodelen+len;

    if(pNameDer[offset] != 0x31)
        return DR_ERR_FORMAT;
    dr = bytenum_to_derlen(pNameDer+offset+1,&lencodelen,&len);
    if(dr != DR_OK)
        return dr;
    dr = DDer_Name_AttrTypeValue(pNameDer+offset+1+lencodelen,len,&type,ppUnitN,unitNLen);
    if(dr != DR_OK)
        return dr;
    offset += 1+lencodelen+len;

    if(pNameDer[offset] != 0x31)
        return DR_ERR_FORMAT;
    dr = bytenum_to_derlen(pNameDer+offset+1,&lencodelen,&len);
    if(dr != DR_OK)
        return dr;
    dr = DDer_Name_AttrTypeValue(pNameDer+offset+1+lencodelen,len,&type,ppCommonN,commonNLen);
    if(dr != DR_OK)
        return dr;
    
    return DR_OK;
}

int DDer_Validity(unsigned char *validityDer, int derLen, unsigned char *notBefore, unsigned char *notAfter)
{
    int        dr;

    if(validityDer[0] != 0x30)
        return DR_ERR_FORMAT;
    if(validityDer[1] != 0x1e)
        return DR_ERR_FORMAT;
    dr = dder_utctime(validityDer+2,15,notBefore);
    if(dr != DR_OK)
        return dr;
    dr = dder_utctime(validityDer+17,15,notAfter);
    return dr;
}

int DDer_PubkeyInfo(unsigned char *pbkeyInfoDer, int infoDerLen, unsigned char **ppmodulus,
                    int *modulusLen, unsigned char **pppubExp, int *pubExpLen)
{
    unsigned char    algoDer[15] = {0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x0,0x05,0x0};
    unsigned char    *pbkeyDer;
    int                lencodelen, offset, len, dr, unitlen, pbkeyDerLen;

    if(pbkeyInfoDer[0] != 0x30)
        return DR_ERR_FORMAT;
    dr = bytenum_to_derlen(pbkeyInfoDer+1,&lencodelen,&len);
    if(dr != DR_OK)
        return dr;
    if(1+lencodelen+len > infoDerLen)
        return DR_ERR_FORMAT;
    offset = 1+lencodelen;
    if(memcmp(algoDer,pbkeyInfoDer+offset,12) != 0)
        return DR_ERR_FORMAT;
    offset += 15;
    
    dr = dder_bitString(pbkeyInfoDer+offset,&pbkeyDer,&pbkeyDerLen,&unitlen);
    if(dr!= DR_OK)
        return dr;
    if(offset+unitlen > infoDerLen)
        return DR_ERR_FORMAT;
    return DDer_Pubkey_Pkcs1(pbkeyDer,pbkeyDerLen,ppmodulus,modulusLen,pppubExp,pubExpLen);    
}

int DDer_TbsCert(unsigned char    *pTbsCert,
                 int            tbsCertLen,
                 unsigned char    *version,
                 unsigned char    **ppSerial,
                 int            *serialLen,
                 unsigned char    *signID,
                 unsigned char    **ppIssuerCountry,
                 int            *issuerCountryLen,
                 unsigned char    **ppIssuerUnit,
                 int            *issuerUnitLen,
                 unsigned char    **ppIssuerCommon,
                 int            *issuerCommonLen,
                 unsigned char    *notBefore,
                 unsigned char    *notAfter,
                 unsigned char    **ppHolderCountry,
                 int            *holderCountryLen,
                 unsigned char    **ppHolderUnit,
                 int            *holderUnitLen,
                 unsigned char    **ppHolderCommon,
                 int            *holderCommonLen,
                 unsigned char    **ppModulus,
                 int            *modulusLen,
                 unsigned char    **ppPubExp,
                 int            *pubExpLen)
{
    unsigned char    versionDer[5] = {0xa0,0x03,0x02,0x01,0x0};
    unsigned char    signIDDer[15] = {0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0, 0x05, 0x00};
    int                lencodelen, len, offset, unitlen, dr;

    if(pTbsCert[0] != 0x30)
        return DR_ERR_FORMAT;
    dr = bytenum_to_derlen(pTbsCert+1,&lencodelen,&len);
    if(dr != DR_OK)
        return dr;
    if(1+lencodelen+len > tbsCertLen)
        return DR_ERR_FORMAT;
    offset = 1+lencodelen;

    if(memcmp(pTbsCert+offset,versionDer,4) != 0)
        return DR_ERR_FORMAT;
    *version = pTbsCert[offset+4];

    offset += 5;
    dr = dder_integer(pTbsCert+offset,ppSerial,serialLen,&unitlen);
    if(dr < 0)
        return dr;
    offset += unitlen;

    if(memcmp(pTbsCert+offset,signIDDer,12) != 0)
        return DR_ERR_FORMAT;
    *signID = pTbsCert[offset+12];
    offset += 15;

    dr = bytenum_to_derlen(pTbsCert+offset+1,&lencodelen,&len);
    if(dr != DR_OK)
        return dr;
    dr = DDer_Name(pTbsCert+offset,tbsCertLen-offset,ppIssuerCountry,issuerCountryLen,
            ppIssuerUnit,issuerUnitLen,ppIssuerCommon,issuerCommonLen);
    if(dr != DR_OK)
        return dr;
    offset += 1+lencodelen+len;

    dr = bytenum_to_derlen(pTbsCert+offset+1,&lencodelen,&len);
    if(dr != DR_OK)
        return dr;
    dr = DDer_Validity(pTbsCert+offset,tbsCertLen-offset,notBefore,notAfter);
    if(dr != DR_OK)
        return dr;
    offset += 1+lencodelen+len;

    dr = bytenum_to_derlen(pTbsCert+offset+1,&lencodelen,&len);
    if(dr != DR_OK)
        return dr;
    dr = DDer_Name(pTbsCert+offset,tbsCertLen-offset,ppHolderCountry,holderCountryLen,
            ppHolderUnit,holderUnitLen,ppHolderCommon,holderCommonLen);
    if(dr != DR_OK)
        return dr;
    offset += 1+lencodelen+len;

    dr = DDer_PubkeyInfo(pTbsCert+offset,tbsCertLen-offset,
                ppModulus,modulusLen,ppPubExp,pubExpLen);
    if(dr != DR_OK)
        return dr;
    return DR_OK;
}

int DDer_Cert(unsigned char    *pCert,
              int            certLen,
              unsigned char **ppTbsCert,
              int            *tbsCertLen,
              unsigned char    *signID,
              unsigned char    **ppSignature,
              int            *signatureLen)
{
    unsigned char    signIDDer[15] = {0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0, 0x05, 0x00};
    int                lencodelen, len, offset, unitlen, dr;

    if(pCert[0] != 0x30)
        return DR_ERR_FORMAT;
    dr = bytenum_to_derlen(pCert+1,&lencodelen,&len);
    if(dr < 0)
        return DR_ERR_FORMAT;
    if(1+lencodelen+len > certLen)
        return DR_ERR_FORMAT;
    offset = 1+lencodelen;

    *ppTbsCert = pCert+offset;
    dr = bytenum_to_derlen(pCert+offset+1,&lencodelen,&len);
    if(dr < 0)
        return DR_ERR_FORMAT;
    *tbsCertLen = 1+lencodelen+len;
    offset += 1+lencodelen+len;

    if(memcmp(pCert+offset,signIDDer,12) != 0)
        return DR_ERR_FORMAT;
    *signID = pCert[offset+12];
    offset += 15;

    dr = dder_bitString(pCert+offset,ppSignature,signatureLen,&unitlen);
    if(dr < 0)
        return dr;
    return DR_OK;
}
