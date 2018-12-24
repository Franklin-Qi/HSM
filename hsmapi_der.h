#ifndef _DERCODING_H_
#define _DERCODING_H_
//////////////////////////////////////////
//		Return value definition:		//
#define		DR_OK			0
#define		DR_ERR			-1
#define		DR_ERR_FORMAT	-2
#define		DR_ERR_BUFFER	-3
#define		DR_ERR_MEMORY	-4
#define		DR_ERR_VER		-5
//////////////////////////////////////////
//		Coding:							//
//PKCS#1 data coding:
int Der_Pubkey_Pkcs1(unsigned char *modulus, int modulusLen, unsigned char *pubExp,
					 int pubExpLen, unsigned char *pubkeyDer, int *pubkeyDerLen);
int Der_Prikey_Pkcs1(unsigned char *modulus, int modulusLen, unsigned char *pubExp,
					 int pubExpLen, unsigned char *priExp, int priExpLen,
					 unsigned char *prime1, int prime1Len, unsigned char *prime2,
					 int prime2Len, unsigned char *exponent1, int exponent1Len,
					 unsigned char *exponent2, int exponent2Len, unsigned char *coefficient,
					 int coefficientLen, unsigned char *prikeyDer, int *prikeyDerLen);

//Certificate coding:
int Der_Name(unsigned char *countryName, int countryNameLen, unsigned char *unitName, int unitNameLen,
			 unsigned char *commonName, int commonNameLen, unsigned char *nameDer, int *nameDerLen);
int Der_Validity(unsigned char *notBefore, unsigned char *notAfter, unsigned char *validityDer, int *derLen);
int Der_PubkeyInfo(int signature, unsigned char *modulus, int modulusLen, unsigned char *pubExp,
				   int pubExpLen, unsigned char *pbkeyInfoDer, int *infoDerLen);

int Der_TbsCert(unsigned char	version,
				unsigned char	*serial,
				int				serialLen,
				unsigned char	signID,
				unsigned char	*issuerCountry,
				int				issuerCountryLen,
				unsigned char	*issuerUnit,
				int				issuerUnitLen,
				unsigned char	*issuerCommon,
				int				issuerCommonLen,
				unsigned char	*notBefore,
				unsigned char	*notAfter,
				unsigned char	*holderCountry,
				int				holderCountryLen,
				unsigned char	*holderUnit,
				int				holderUnitLen,
				unsigned char	*holderCommon,
				int				holderCommonLen,
				unsigned char	*modulus,
				int				modulusLen,
				unsigned char	*pubExp,
				int				pubExpLen,
				unsigned char	*pTbsCert,
				int				*tbsCertLen);

int Der_Cert(unsigned char	*pTbsCert,
			 int			tbsCertLen,
			 unsigned char	signID,
			 unsigned char	*pSignature,
			 int			signatureLen,
			 unsigned char	*pCert,
			 int			*certLen);
//////////////////////////////////////////
//		Decoding:						//
//PKCS#1 data decoding:
int DDer_Pubkey_Pkcs1(unsigned char *pubkeyDer, int pubkeyDerLen, unsigned char **ppmodulus, 
					  int *modulusLen, unsigned char **pppubExp, int *pubExpLen);
int DDer_Prikey_Pkcs1(unsigned char *prikeyDer, int prikeyDerLen, unsigned char **ppModulus,
					  int *modulusLen, unsigned char **ppPubExp, int *pubExpLen, 
					  unsigned char **ppPriExp, int *priExpLen, unsigned char **ppPrime1,
					  int *prime1Len, unsigned char **ppPrime2, int *prime2Len,
					  unsigned char **ppExponent1, int *exponent1Len, unsigned char **ppExponent2,
					  int *exponent2Len, unsigned char **ppcoeff, int *coeffLen);

//Certificate decoding:
int DDer_Name(unsigned char *pNameDer, int derLen, unsigned char **ppCountryN, int *countryNLen,
			  unsigned char **ppUnitN, int *unitNLen, unsigned char **ppCommonN, int *commonNLen);
int DDer_Validity(unsigned char *validityDer, int derLen, unsigned char *notBefore, unsigned char *notAfter);
int DDer_PubkeyInfo(unsigned char *pbkeyInfoDer, int infoDerLen, unsigned char **ppmodulus,
					int *modulusLen, unsigned char **pppubExp, int *pubExpLen);

int DDer_TbsCert(unsigned char	*pTbsCert,
				 int			tbsCertLen,
				 unsigned char	*version,
				 unsigned char	**ppSerial,
				 int			*serialLen,
				 unsigned char	*signID,
				 unsigned char	**ppIssuerCountry,
				 int			*issuerCountryLen,
				 unsigned char	**ppIssuerUnit,
				 int			*issuerUnitLen,
				 unsigned char	**ppIssuerCommon,
				 int			*issuerCommonLen,
				 unsigned char	*notBefore,
				 unsigned char	*notAfter,
				 unsigned char	**ppHolderCountry,
				 int			*holderCountryLen,
				 unsigned char	**ppHolderUnit,
				 int			*holderUnitLen,
				 unsigned char	**ppHolderCommon,
				 int			*holderCommonLen,
				 unsigned char	**ppModulus,
				 int			*modulusLen,
				 unsigned char	**ppPubExp,
				 int			*pubExpLen);
int DDer_Cert(unsigned char	*pCert,
			  int			certLen,
			  unsigned char **ppTbsCert,
			  int			*tbsCertLen,
			  unsigned char	*signID,
			  unsigned char	**ppSignature,
			  int			*signatureLen);
//////////////////////////////////
#endif
