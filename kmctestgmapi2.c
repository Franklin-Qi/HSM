
/*********************************************************/
/* Header File                                           */
/*********************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

typedef unsigned int   UINT;
typedef unsigned char BYTE;
typedef BYTE *PBYTE;
typedef const BYTE CBYTE;
typedef const BYTE *PCBYTE;

typedef int RESULT;
#define NORMAL 0;
#define bufclr(cDest)        memset(cDest, 0, sizeof(cDest))

/*********************************************************/
/* Macro                                                 */
/*********************************************************/

#define TIMEDECLEAR \
          struct timeval tpstart; \
          struct timeval tpend;
#define TIMECOST \
          ((tpend.tv_sec - tpstart.tv_sec)*1000000 + (tpend.tv_usec - tpstart.tv_usec))
#define TIMESTART \
          { \
              int k = 1; \
              for(; k <= 1; k++) \
              { \
                  if(k%10 == 1) \
                  { \
                      gettimeofday(&tpstart, NULL); \
                  }
#define TIMEEND(s) \
                  if(k%10 == 1) \
                  { \
                      gettimeofday(&tpend, NULL); \
                      printf("[%06s][%04d]COST: %09d\n", s, __LINE__, TIMECOST); \
                  } \
              } \
          }


#define SM_SERVER_ADDR "10.233.1.64"
#define SM_SERVER_PORT 6667
#define SM_TIME_OUT    8

/* test lable macro */
#define XXX_TEST_START_XXX \
    {printf(">>>>>>>>>> %s START >>>>>>>>>>\n", __func__);}
#define XXX_TEST_END_XXX \
    {printf("<<<<<<<<<< %s  END  <<<<<<<<<<\n\n", __func__); return;}

static int CASE_NO = 0;
static int iscontinue = 1;
FILE * fp = NULL;

/* log lable */
#define XXX_CASE_XXX(c) \
    {CASE_NO = c; printf("\n=============      Case %-2d     =============\n", c);}

#ifdef LOG_LABLE
static int LF_FLAG = 0;

#define LF_FLAG_CTRL \
    {if((LF_FLAG ^= 1)) printf("\n");}

#define XXX_INPUT_XXX \
    {LF_FLAG_CTRL \
     printf("------------- Input  Parameter -------------\n");}

#define XXX_OUTPUT_XXX \
    {LF_FLAG_CTRL \
     printf("************* Output Parameter *************\n");}

#define XXX_RESULT_XXX \
    {LF_FLAG_CTRL \
     printf("~~~~~~~~~~~~~   Return Value   ~~~~~~~~~~~~~\n");}
#else
#define XXX_INPUT_XXX
#define XXX_OUTPUT_XXX
#define XXX_RESULT_XXX
#endif

#define XXX_INPUT_NONE_XXX  {printf("[IN ] <None>\n");}
#define XXX_OUTPUT_NONE_XXX {printf("[OUT]<None>\n");}

#define ASSERT_RESULT(r, e, m) \
    { \
        if(!((e == 0 && r == e) || (e > 0 && r > 0 && r < 50))) \
        { \
            fprintf(stdout, "\n<%-30s><%02d>\t\t\t ### ASSERT RESULT NG! ###\n", \
                __func__, CASE_NO); \
            fprintf(stdout, "\t[RET]result = %d, expect = %d\n", r, e); \
            fprintf(stdout, "\t[MSG]%s\n\n", m); \
            fflush(stdout); \
        } \
        else if(e > 0 && e != r) \
        { \
            fprintf(stdout, "\n*** e = %d r = %d ***\n\t[MSG]%s\n\n", e, r, m); \
            fflush(stdout); \
        } \
    }

#define ASSERT_OUT(r, e) \
    { \
        if(r != e) \
        { \
            fprintf(stdout, "\n<%-30s><%02d>\t\t\t ### ASSERT OUTPUT NG! ###\n", \
                __func__, CASE_NO); \
            fprintf(stdout, "\t[OUT]result = %d, expect = %d\n", r, e); \
            fflush(stdout); \
        } \
    }

#define ASSERT_OUT2(r, e1, e2) \
    { \
        if(r != e1 && r != e2) \
        { \
            fprintf(stdout, "\n<%-30s><%02d>\t\t\t ### ASSERT OUTPUT NG! ###\n", \
                __func__, CASE_NO); \
            fprintf(stdout, "\t[OUT]result = %d, expect = %d|%d\n", r, e1, e2); \
            fflush(stdout); \
        } \
    }

#define ASSERT_OUT_HEX(r, e, l) \
    { \
        if(memcmp(r, e, l) != 0) \
        { \
            fprintf(stdout, "\n<%-30s><%02d>\t\t\t ### ASSERT OUTPUT NG! ###\n", \
                __func__, CASE_NO); \
            fflush(stdout); \
            DspErrHex("[OUT]result = ", r, l); \
            DspErrHex("[OUT]expect = ", e, l); \
        } \
    }

/* Test Function Type */
typedef void(*TESTFUNC)(void);

/* SM Sock */
static int SM_SOCK = -1;

void DspHex(const char *pszInfo, const PBYTE pbHexStr, const int nStrLen)
{
    int i,j,m,n;
    PBYTE pbHex = pbHexStr;
#if 1
    i = j = 0;
    m = nStrLen / 16;
    n = nStrLen % 16;

    printf("%s\n     0x%08X %d\n", pszInfo, pbHexStr, nStrLen);

    if(nStrLen == 0)
        return;

    if(m)
    {
        for(i = 0; i < m; i++)
        {
            printf("     %08X: ", i*16);
            for(j = 0; j < 16; j++)
            {
                printf("%02X ", pbHex[j]);
            }
            printf("; ");
            for(j = 0; j < 16; j++)
            {
                //printf("%c", (char)pbHex[j]);
            }
            printf("\n");
            pbHex += 16;
        }
    }
    if(n)
    {
        printf("     %08X: ", i*16);
        for(j = 0; j < 16; j++)
        {
            if(j < n)
                printf("%02X ", pbHex[j]);
            else
                printf("   ");
        }
        printf("; ");
        for(j = 0; j < n; j++)
        {
            //printf("%c", (char)pbHex[j]);
        }
        printf("\n");
    }
#endif
    return;
}

void DspHexExt(const char *pszInfo, const PBYTE pbHexStr, const int nStrLen)
{
    int i,j,m,n;
    PBYTE pbHex = pbHexStr;
#if 1
    i = j = 0;
    m = nStrLen / 16;
    n = nStrLen % 16;

    printf("%s\n     0x%08X %d\n", pszInfo, pbHexStr, nStrLen);

    if(nStrLen == 0)
        return;

    if(m)
    {
        for(i = 0; i < m; i++)
        {
            for(j = 0; j < 16; j++)
            {
                printf("%02X", pbHex[j]);
            }
            pbHex += 16;
        }
    }
    if(n)
    {
        for(j = 0; j < 16; j++)
        {
            if(j < n)
                printf("%02X", pbHex[j]);
        }
        for(j = 0; j < n; j++)
        {
            //printf("%c", (char)pbHex[j]);
        }
    }
    printf("\n");
#endif
    return;
}

void DspErrHex(const char *pszInfo, const PBYTE pbHexStr, const int nStrLen)
{
#if 1
    int i,j,m,n;
    PBYTE pbHex = pbHexStr;

    i = j = 0;
    m = nStrLen / 16;
    n = nStrLen % 16;

    fprintf(stdout, "\t%s\n\t     0x%08X %d\n", pszInfo, pbHexStr, nStrLen);

    if(nStrLen == 0)
        return;

    if(m)
    {
        for(i = 0; i < m; i++)
        {
            fprintf(stdout, "\t     %08X: ", i*16);
            for(j = 0; j < 16; j++)
            {
                fprintf(stdout, "%02X ", pbHex[j]);
            }
            fprintf(stdout, "; ");
            for(j = 0; j < 16; j++)
            {
                //fprintf(stdout, "%c", (char)pbHex[j]);
            }
            fprintf(stdout, "\n");
            pbHex += 16;

            if(i > 0 && (i % 64 == 0))
                fflush(stdout);
        }
    }
    if(n)
    {
        fprintf(stdout, "\t     %08X: ", i*16);
        for(j = 0; j < 16; j++)
        {
            if(j < n)
                fprintf(stdout, "%02X ", pbHex[j]);
            else
                fprintf(stdout, "   ");
        }
        fprintf(stdout, "; ");
        for(j = 0; j < n; j++)
        {
            //fprintf(stdout, "%c", (char)pbHex[j]);
        }
        fprintf(stdout, "\n");
    }

    fflush(stdout);
#endif
    return;
}

/*▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼*/
static const char hex_to_char[16] = \
{
    /* '0' - '9' */
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
    /* 'A' - 'F' */
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46
};

void SSMHexToChar(PCBYTE pbHex, char *pcChar, UINT nSize)
{
    int i;

    for (i = 0; i < nSize; i++)
    {
        pcChar[2*i] = hex_to_char[((pbHex[i] & 0xF0) >> 4)];
        pcChar[2*i + 1] = hex_to_char[(pbHex[i] & 0x0F)];
    }

    return;
}

void SSMMakeOddBinStr_Test(PBYTE pbBin, UINT nLen)
{
    int i;
    BYTE x;

    for(i = 0; i < nLen; i++)
    {
        x = pbBin[i];

        x = ((x & 0x55) + ((x >> 1) & 0x55));
        x = ((x & 0x33) + ((x >> 2) & 0x33));
        x = ((x & 0x0f) + ((x >> 4) & 0x0f));
        if((x & 0x01) == 0)
        {
            pbBin[i] ^= 0x01;
        }
    }

    return;
}

void SSMBinStrXOR(PBYTE pbDst, PBYTE pbSrc1, PBYTE pbSrc2, UINT nLen)
{
    UINT i;

    for(i = 0; i < nLen; i++)
        pbDst[i] = pbSrc1[i] ^ pbSrc2[i];

    return;
}
/*▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲*/

/*********************************************************/
/* Test Function                                         */
/*********************************************************/
void ConnectSM_Test_01(void)
{
    XXX_TEST_START_XXX

    char szAddr[20];
    UINT nPort;
    UINT nTimeOut;
    UINT nSock;
    UINT *pnSock;
    char szInfo[100];
    int  nRet;

    bufclr(szAddr);
    bufclr(szInfo);

    strcpy(szAddr, SM_SERVER_ADDR);
    nPort = SM_SERVER_PORT;
    nTimeOut = SM_TIME_OUT;
    pnSock = &nSock;

    XXX_INPUT_XXX
    printf("[IN ]szAddr   = %s\n", szAddr);
    printf("[IN ]nPort    = %d\n", nPort);
    printf("[IN ]nTimeOut = %d\n", nTimeOut);
    printf("[IN ]nSock    = 0x%p\n", pnSock);
    printf("[IN ]szInfo   = 0x%p\n", szInfo);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
#ifdef API30
    nRet = SMAPIConnectSM(szAddr, nPort, nTimeOut, (int *)pnSock, szInfo);
#else
    nRet = SMAPIConnectSM(szAddr, nPort, nTimeOut, pnSock, szInfo);
#endif
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "连接加密机未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[OUT]nSock  = %d\n", nSock);
    printf("[OUT]szInfo = %s\n", szInfo);
    XXX_OUTPUT_XXX

    SM_SOCK = nSock;
    XXX_TEST_END_XXX
}

void DisconnectSM_Test_01(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIDisconnectSM(nSock);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "正常断开连接未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void DisreteSubKey_Test_01(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int nDivNum;
	  int nIccType;
	  int nAlgo;
	  unsigned char  bKek[32];
	  unsigned char  bMasterKey[32];
	  unsigned char  bCardFactor[8];
	  unsigned char  bSessionFactor[4];
	  unsigned char  bSubKey[32];
	  unsigned char  szCheckValue[16];
	  unsigned char  bSubKeyExp[32];
	  unsigned char  szCheckValueExp[16];

    bufclr(bKek);
    bufclr(bMasterKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bSubKey);
    bufclr(szCheckValue);

    nDivNum = 1;
    nIccType = 0x00000000;	
    nAlgo = 2;
    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(bKek,
           "\xA2\xC0\xB0\xF8\xF7\xF5\xEE\x21\xFB\x5C\x6A\xEB\xE7\x14\xE5\x3A"
           , 16);
    /* F431 623E 4997 89C8 C2F1 F725 AD7F 8949 */
    memcpy(bMasterKey,
           "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4"
           , 16);
    memcpy(bCardFactor,
           "\x25\x00\x00\x00\x00\x00\x89\x01"
           , 8);
    memcpy(bSessionFactor,
           "\x00\x02"
           , 2);
    /* 89E9 1FCB 266D 7C51 A437 AE51 2F10 5225 */
    memcpy(bSubKeyExp,
           "\xB9\x80\xE9\x91\xA7\xC6\x6F\x30\x21\x2C\xDE\x6F\xB4\x7A\x59\xD9"
           , 16);
    /* 09F1 C278 E411 C078 */
    memcpy(szCheckValueExp,
           "09F1C278"
           , 8);

    XXX_INPUT_XXX
    printf("[IN ]nSock          = %d\n", nSock);
    printf("[IN ]nDivNum        = %d\n", nDivNum);
    printf("[IN ]nIccType       = %x\n", nIccType);
    printf("[IN ]nAlgo          = %d\n", nAlgo);
    DspHex("[IN ]bKek           =", bKek, 16);
    DspHex("[IN ]bMasterKey     =", bMasterKey, 16);
    DspHex("[IN ]bCardFactor    =", bCardFactor, 8);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 2);
    XXX_INPUT_XXX


    /* Call Test Target Function Start */
    nRet = SMAPIDisreteSubKey(nSock, nDivNum, nIccType, nAlgo, bKek, \
                              bMasterKey, bCardFactor, bSessionFactor, \
                              bSubKey, szCheckValue);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "PBOC卡，二倍KEK，一次离散测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    ASSERT_OUT_HEX(bSubKey, bSubKeyExp, 16);
    ASSERT_OUT_HEX(szCheckValue, szCheckValueExp, 8);
    XXX_OUTPUT_XXX

    DspHex("[RESULT ]expected subkey    =", bSubKeyExp, 16);
    DspHex("[RESULT ]disreted subkey =", bSubKey, 16);
    DspHex("[RESULT ]expected checkvalue    =", szCheckValueExp, 8);
    DspHex("[RESULT]disreted checkvalue =", szCheckValue, 8);

    XXX_TEST_END_XXX
}

void DisreteSubKey_Test_02(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int nDivNum;
	  int nIccType;
	  int nAlgo;
	  unsigned char  bKek[32];
	  unsigned char  bMasterKey[32];
	  unsigned char  bCardFactor[8];
	  unsigned char  bSessionFactor[4];
	  unsigned char  bSubKey[32];
	  unsigned char  szCheckValue[16];
	  unsigned char  bSubKeyExp[32];
	  unsigned char  szCheckValueExp[16];

    bufclr(bKek);
    bufclr(bMasterKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bSubKey);
    bufclr(szCheckValue);

    nDivNum = 2;
    nIccType = 0x00000000;
    nAlgo = 2;
    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(bKek,
           "\xA2\xC0\xB0\xF8\xF7\xF5\xEE\x21\xFB\x5C\x6A\xEB\xE7\x14\xE5\x3A"
           , 16);
    /* F431 623E 4997 89C8 C2F1 F725 AD7F 8949 */
    memcpy(bMasterKey,
           "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4"
           , 16);
    memcpy(bCardFactor,
           "\x25\x00\x00\x00\x00\x00\x89\x01"
           , 8);
    memcpy(bSessionFactor,
           "\x00\x02"
           , 2);
    /* 4FA1 BA64 DC85 58BF EC43 C210 F4FD 4610 */
    memcpy(bSubKeyExp,
           "\xAE\x75\x8D\x48\xCC\x51\x5A\x30\xE9\x5F\x0C\x2F\x62\x34\xD2\xF1"
           , 16);
    /* 04BC 620F 4E58 684D */
    memcpy(szCheckValueExp,
           "04BC620F"
           , 8);

    XXX_INPUT_XXX
    printf("[IN ]nSock          = %d\n", nSock);
    printf("[IN ]nDivNum        = %d\n", nDivNum);
    printf("[IN ]nIccType       = %x\n", nIccType);
    printf("[IN ]nAlgo          = %d\n", nAlgo);
    DspHex("[IN ]bKek           =", bKek, 16);
    DspHex("[IN ]bMasterKey     =", bMasterKey, 16);
    DspHex("[IN ]bCardFactor    =", bCardFactor, 8);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 2);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIDisreteSubKey(nSock, nDivNum, nIccType, nAlgo, bKek, \
                              bMasterKey, bCardFactor, bSessionFactor, \
                              bSubKey, szCheckValue);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "PBOC卡，二倍KEK，二次离散测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    ASSERT_OUT_HEX(bSubKey, bSubKeyExp, 16);
    ASSERT_OUT_HEX(szCheckValue, szCheckValueExp, 8);
    XXX_OUTPUT_XXX
		
    DspHex("[RESULT ]expected subkey	=", bSubKeyExp, 16);
    DspHex("[RESULT ]disreted subkey =", bSubKey, 16);
    DspHex("[RESULT ]expected checkvalue	=", szCheckValueExp, 8);
    DspHex("[RESULT]disreted checkvalue =", szCheckValue, 8);

    XXX_TEST_END_XXX
}

void DisreteSubKey_Test_03(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int nDivNum;
	  int nIccType;
	  int nAlgo;
	  unsigned char  bKek[32];
	  unsigned char  bMasterKey[32];
	  unsigned char  bCardFactor[16];
	  unsigned char  bLeftCardFactor[8];
	  unsigned char bRightCardFactor[8];
	  unsigned char  bSessionFactor[4];
	  unsigned char  bSubKey[32];
	  unsigned char  szCheckValue[16];
	  unsigned char  bSubKeyExp[32];
	  unsigned char  szCheckValueExp[16];

    bufclr(bKek);
    bufclr(bMasterKey);
    bufclr(bCardFactor);
    bufclr(bLeftCardFactor);
    bufclr(bRightCardFactor);
    bufclr(bSessionFactor);
    bufclr(bSubKey);
    bufclr(szCheckValue);

    nDivNum = 1;
    nIccType = 0x0001000A;
    nAlgo = 2;
    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(bKek,
           "\xA2\xC0\xB0\xF8\xF7\xF5\xEE\x21\xFB\x5C\x6A\xEB\xE7\x14\xE5\x3A"
           , 16);
    /* F431 623E 4997 89C8 C2F1 F725 AD7F 8949 */
    memcpy(bMasterKey,
           "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4"
           , 16);
    memcpy(bLeftCardFactor,  "\x25\x00\x00\x00\x00\x00\x89\x01" ,8);
    memcpy(bRightCardFactor,   "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" ,8); 
    SSMBinStrXOR(bRightCardFactor, bLeftCardFactor, bRightCardFactor, 8);
    memcpy(&bCardFactor[0], bLeftCardFactor, 8);
    memcpy(&bCardFactor[8], bRightCardFactor, 8);

     /*89E8 1ECA 276C 7D50 A537 AE51 2E11 5224*/
    memcpy(bSubKeyExp,
           "\xDA\x5E\x25\x93\x43\xEE\x5C\x9D\x79\xB1\xC5\xAD\x1D\xB4\x6A\x23"
           , 16);
	
    /* 09F1 C278 E411 C078 */
    memcpy(szCheckValueExp,
           "09F1C278"
           , 8);

    XXX_INPUT_XXX
    printf("[IN ]nSock          = %d\n", nSock);
    printf("[IN ]nDivNum        = %d\n", nDivNum);
    printf("[IN ]nIccType       = %x\n", nIccType);
    printf("[IN ]nAlgo          = %d\n", nAlgo);
    DspHex("[IN ]bKek           =", bKek, 16);
    DspHex("[IN ]bMasterKey     =", bMasterKey, 16);
    DspHex("[IN ]bCardFactor    =", bCardFactor, 16);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 2);	
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIDisreteSubKey(nSock, nDivNum, nIccType, nAlgo, bKek, \
                              bMasterKey, bCardFactor, bSessionFactor, \
                              bSubKey, szCheckValue);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "VISA卡，二倍KEK，一次离散测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    ASSERT_OUT_HEX(bSubKey, bSubKeyExp, 16);
    ASSERT_OUT_HEX(szCheckValue, szCheckValueExp, 8);
    XXX_OUTPUT_XXX

    DspHex("[RESULT ]expected subkey	=", bSubKeyExp, 16);
    DspHex("[RESULT ]disreted subkey =", bSubKey, 16);
    DspHex("[RESULT ]expected checkvalue	=", szCheckValueExp, 8);
    DspHex("[RESULT]disreted checkvalue =", szCheckValue, 8);

    XXX_TEST_END_XXX
}

void DisreteSubKey_Test_04(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int nDivNum;
	  int nIccType;
	  int nAlgo;
	  unsigned char  bKek[32];
	  unsigned char  bMasterKey[32];
	  unsigned char  bCardFactor[16];
	  unsigned char  bSubCardKey[16];
	  unsigned char  bATC[4];
	  unsigned char bSessionSeed[16];
	  unsigned char  bSubKey[16];
	  unsigned char  szCheckValue[16];
	  unsigned char  bSubKeyExp[32];
	  unsigned char  szCheckValueExp[16];

    bufclr(bKek);
    bufclr(bMasterKey);
    bufclr(bCardFactor);
    bufclr(bSubCardKey);
    bufclr(bATC);
    memset(bSessionSeed,0,16);
    bufclr(bSubKey);
    bufclr(szCheckValue);

    nDivNum = 2;
    nIccType = 0x0001000A;
    nAlgo = 2;
	
    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(bKek,
           "\xA2\xC0\xB0\xF8\xF7\xF5\xEE\x21\xFB\x5C\x6A\xEB\xE7\x14\xE5\x3A"
           , 16);
    /* F431 623E 4997 89C8 C2F1 F725 AD7F 8949 */
    memcpy(bMasterKey,
           "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4"
           , 16);
    memcpy(bCardFactor,
           "\x25\x00\x00\x00\x00\x00\x89\x01"
           , 8);	
   memset(&bCardFactor[8], 0xFF, 8);
   SSMBinStrXOR(&bCardFactor[8], &bCardFactor[8],  bCardFactor,  8);
   
    memcpy(bSubCardKey, 
		"\x89\xE8\x1E\xCA\x27\x6C\x7D\x50\xA5\x37\xAE\x51\x2E\x11\x52\x24"
	  ,16);
	
    memcpy(bATC,  "\x00\x02", 2);
    memcpy(&bSessionSeed[6], bATC, 2);
    memset(&bSessionSeed[14], 0xFF, 2);
    SSMBinStrXOR(&bSessionSeed[14], bATC,  &bSessionSeed[14], 2);

    //SSMBinStrXOR(bSubKeyExp, bSessionSeed, bSubCardKey, 16);
    /* 89 E8 1E CA 27 6C 7D 52 A5 37 AE 51 2E 11 AD D9 */
    memcpy(bSubKeyExp,
           "\x1B\x25\x40\xE5\x2E\x2C\xDA\xE4\x42\x0D\xC8\x5A\x1C\xB7\x5B\x28"
           , 16);
	
    /* D701 16E2 503E 3CC8 */
    memcpy(szCheckValueExp,
           "D70116E2"
           , 8);

    XXX_INPUT_XXX
    printf("[IN ]nSock          = %d\n", nSock);
    printf("[IN ]nDivNum        = %d\n", nDivNum);
    printf("[IN ]nIccType       = %x\n", nIccType);
    printf("[IN ]nAlgo          = %d\n", nAlgo);
    DspHex("[IN ]bKek           =", bKek, 16);
    DspHex("[IN ]bMasterKey     =", bMasterKey, 16);
    DspHex("[IN ]bCardFactor    =", bCardFactor, 16);
    DspHex("[IN ]bSubCardKey    =", bSubCardKey, 16);
    DspHex("[IN ]bATC =", bATC, 2);
    DspHex("[IN ]bSessionSeed =", bSessionSeed, 16);
    DspHex("[OUT] bSubKeyExp=", bSubKeyExp, 16);	
    XXX_INPUT_XXX
	
    /* Call Test Target Function Start */
    nRet = SMAPIDisreteSubKey(nSock, nDivNum, nIccType, nAlgo, bKek, \
                              bMasterKey, bCardFactor, bSessionSeed, \
                              bSubKey, szCheckValue);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "VISA卡，二倍KEK，二次离散脚本会话密钥未成功");
    XXX_RESULT_XXX
		
    XXX_OUTPUT_XXX
    ASSERT_OUT_HEX(bSubKey, bSubKeyExp, 16);
    ASSERT_OUT_HEX(szCheckValue, szCheckValueExp, 8);
    XXX_OUTPUT_XXX

    DspHex("[RESULT ]expected subkey	=", bSubKeyExp, 16);
    DspHex("[RESULT ]disreted subkey =", bSubKey, 16);
    DspHex("[RESULT ]expected checkvalue	=", szCheckValueExp, 8);
    DspHex("[RESULT]disreted checkvalue =", szCheckValue, 8);

    XXX_TEST_END_XXX
}

void DisreteSubKey_Test_05(void)
{
    XXX_TEST_START_XXX
    int nRet;
    int nSock = SM_SOCK;

	  int nDivNum;
	  int nIccType;
	  int nAlgo;
	  unsigned char  bKek[32];
	  unsigned char  bMasterKey[32];
	  unsigned char  bCardFactor[8];
	  unsigned char  bSessionFactor[4];
	  unsigned char  bSubKey[32];
	  unsigned char  szCheckValue[16];
	  unsigned char  bSubKeyExp[32];
	  unsigned char  szCheckValueExp[16];

    bufclr(bKek);
    bufclr(bMasterKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bSubKey);
    bufclr(szCheckValue);

    nDivNum = 1;
    nIccType = 0x00000000;
    nAlgo = 1;
    /* 0123 4567 89AB CDEF */
    memcpy(bKek,
           "\xA2\xC0\xB0\xF8\xF7\xF5\xEE\x21"
           , 8);
    /* F431 623E 4997 89C8 C2F1 F725 AD7F 8949 */
    memcpy(bMasterKey,
           "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4"
           , 16);
    memcpy(bCardFactor,
           "\x25\x00\x00\x00\x00\x00\x89\x01"
           , 8);
    memcpy(bSessionFactor,
           "\x00\x02"
           , 2);
    /* 89E9 1FCB 266D 7C51 A437 AE51 2F10 5225 */
    memcpy(bSubKeyExp,
           "\x4C\xFF\x06\xC4\xDF\xE3\x28\x29\xF7\x12\x38\x90\xE0\x3A\x2E\xDE"
           , 16);
    /* 09F1 C278 E411 C078 */
    memcpy(szCheckValueExp,
           "09F1C278"
           , 8);

    XXX_INPUT_XXX
    printf("[IN ]nSock          = %d\n", nSock);
    printf("[IN ]nDivNum        = %d\n", nDivNum);
    printf("[IN ]nIccType       = %d\n", nIccType);
    printf("[IN ]nAlgo          = %d\n", nAlgo);
    DspHex("[IN ]bKek           =", bKek, 16);
    DspHex("[IN ]bMasterKey     =", bMasterKey, 16);
    DspHex("[IN ]bCardFactor    =", bCardFactor, 8);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 2);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIDisreteSubKey(nSock, nDivNum, nIccType, nAlgo, bKek, \
                              bMasterKey, bCardFactor, bSessionFactor, \
                              bSubKey, szCheckValue);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "PBOC卡，单倍KEK，一次离散测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    ASSERT_OUT_HEX(bSubKey, bSubKeyExp, 16);
    ASSERT_OUT_HEX(szCheckValue, szCheckValueExp, 8);
    XXX_OUTPUT_XXX

    DspHex("[RESULT ]expected subkey	=", bSubKeyExp, 16);
    DspHex("[RESULT ]disreted subkey =", bSubKey, 16);
    DspHex("[RESULT ]expected checkvalue	=", szCheckValueExp, 8);
    DspHex("[RESULT]disreted checkvalue =", szCheckValue, 8);

    XXX_TEST_END_XXX
}

void DisreteSubKey_Test_06(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int nDivNum;
	  int nIccType;
	  int nAlgo;
	  unsigned char  bKek[32];
	  unsigned char  bMasterKey[32];
	  unsigned char  bCardFactor[8];
	  unsigned char  bSessionFactor[4];
	  unsigned char  bSubKey[32];
	  unsigned char  szCheckValue[16];
	  unsigned char  bSubKeyExp[32];
	  unsigned char  szCheckValueExp[16];

    bufclr(bKek);
    bufclr(bMasterKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bSubKey);
    bufclr(szCheckValue);

    nDivNum = 2;
    nIccType = 0x00000000;
    nAlgo = 1;
    /* 0123 4567 89AB CDEF */
    memcpy(bKek,
           "\xA2\xC0\xB0\xF8\xF7\xF5\xEE\x21"
           , 8);
    /* F431 623E 4997 89C8 C2F1 F725 AD7F 8949 */
    memcpy(bMasterKey,
           "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4"
           , 16);
    memcpy(bCardFactor,
           "\x25\x00\x00\x00\x00\x00\x89\x01"
           , 8);
    memcpy(bSessionFactor,
           "\x00\x02"
           , 2);
    /* 4FA1 BA64 DC85 58BF EC43 C210 F4FD 4610 */
    memcpy(bSubKeyExp,
           "\x2C\x52\xE0\x25\xF9\x6B\xF0\x2F\x13\xF2\x52\x1E\xBF\x37\x73\x7F"
           , 16);
    /* 04BC 620F 4E58 684D */
    memcpy(szCheckValueExp,
           "04BC620F"
           , 8);

    XXX_INPUT_XXX
    printf("[IN ]nSock          = %d\n", nSock);
    printf("[IN ]nDivNum        = %d\n", nDivNum);
    printf("[IN ]nIccType       = %d\n", nIccType);
    printf("[IN ]nAlgo          = %d\n", nAlgo);
    DspHex("[IN ]bKek           =", bKek, 16);
    DspHex("[IN ]bMasterKey     =", bMasterKey, 16);
    DspHex("[IN ]bCardFactor    =", bCardFactor, 8);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 2);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIDisreteSubKey(nSock, nDivNum, nIccType, nAlgo, bKek, \
                              bMasterKey, bCardFactor, bSessionFactor, \
                              bSubKey, szCheckValue);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "PBOC卡，单倍KEK，二次离散测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    ASSERT_OUT_HEX(bSubKey, bSubKeyExp, 16);
    ASSERT_OUT_HEX(szCheckValue, szCheckValueExp, 8);
    XXX_OUTPUT_XXX

    DspHex("[RESULT ]expected subkey	=", bSubKeyExp, 16);
    DspHex("[RESULT ]disreted subkey =", bSubKey, 16);
    DspHex("[RESULT ]expected checkvalue	=", szCheckValueExp, 8);
    DspHex("[RESULT]disreted checkvalue =", szCheckValue, 8);

    XXX_TEST_END_XXX
}

void DisreteSubKey_Test_07(void)
{
    XXX_TEST_START_XXX
    int nRet;
    int nSock = SM_SOCK;

	  int nDivNum;
	  int nIccType;
	  int nAlgo;
	  unsigned char  bKek[32];
	  unsigned char  bMasterKey[32];
	  unsigned char  bCardFactor[8];
	  unsigned char  bSessionFactor[4];
	  unsigned char  bSubKey[32];
	  unsigned char  szCheckValue[16];
	  unsigned char  bSubKeyExp[32];
	  unsigned char  szCheckValueExp[16];

    bufclr(bKek);
    bufclr(bMasterKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bSubKey);
    bufclr(szCheckValue);

    nDivNum = 1;
    nIccType = 0x00000000;
    nAlgo = 3;
    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 8796 A5B4 C3D2 E1F0 */
    memcpy(bKek,
           "\xA2\xC0\xB0\xF8\xF7\xF5\xEE\x21\xFB\x5C\x6A\xEB\xE7\x14\xE5\x3A"
           "\x59\x99\xC3\x06\xAB\x84\x01\xB2"
           , 24);
    /* F431 623E 4997 89C8 C2F1 F725 AD7F 8949 */
    memcpy(bMasterKey,
           "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4"
           , 16);
    memcpy(bCardFactor,
           "\x25\x00\x00\x00\x00\x00\x89\x01"
           , 8);
    memcpy(bSessionFactor,
           "\x00\x02"
           , 2);
    /* 89E9 1FCB 266D 7C51 A437 AE51 2F10 5225 */
    memcpy(bSubKeyExp,
           "\x97\xC0\xB3\xE6\x38\x60\x7D\xB7\x89\x95\xC6\x37\xE4\x69\xAC\x74"
           , 16);
    /* 09F1 C278 E411 C078 */
    memcpy(szCheckValueExp,
           "09F1C278"
           , 8);

    XXX_INPUT_XXX
    printf("[IN ]nSock          = %d\n", nSock);
    printf("[IN ]nDivNum        = %d\n", nDivNum);
    printf("[IN ]nIccType       = %d\n", nIccType);
    printf("[IN ]nAlgo          = %d\n", nAlgo);
    DspHex("[IN ]bKek           =", bKek, 16);
    DspHex("[IN ]bMasterKey     =", bMasterKey, 16);
    DspHex("[IN ]bCardFactor    =", bCardFactor, 8);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 2);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIDisreteSubKey(nSock, nDivNum, nIccType, nAlgo, bKek, \
                              bMasterKey, bCardFactor, bSessionFactor, \
                              bSubKey, szCheckValue);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "PBOC卡，三倍长密钥，一次离散测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    ASSERT_OUT_HEX(bSubKey, bSubKeyExp, 16);
    ASSERT_OUT_HEX(szCheckValue, szCheckValueExp, 8);
    XXX_OUTPUT_XXX
		
    DspHex("[RESULT ]expected subkey	=", bSubKeyExp, 16);
    DspHex("[RESULT ]disreted subkey =", bSubKey, 16);
    DspHex("[RESULT ]expected checkvalue	=", szCheckValueExp, 8);
    DspHex("[RESULT]disreted checkvalue =", szCheckValue, 8);

    XXX_TEST_END_XXX
}

void DisreteSubKey_Test_08(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int nDivNum;
	  int nIccType;
	  int nAlgo;
	  unsigned char  bKek[32];
	  unsigned char  bMasterKey[32];
	  unsigned char  bCardFactor[8];
	  unsigned char  bSessionFactor[4];
	  unsigned char  bSubKey[32];
	  unsigned char  szCheckValue[16];
	  unsigned char  bSubKeyExp[32];
	  unsigned char  szCheckValueExp[16];

    bufclr(bKek);
    bufclr(bMasterKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bSubKey);
    bufclr(szCheckValue);

    nDivNum = 2;
    nIccType = 0x00000000;
    nAlgo = 3;
    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 8796 A5B4 C3D2 E1F0 */
    memcpy(bKek,
           "\xA2\xC0\xB0\xF8\xF7\xF5\xEE\x21\xFB\x5C\x6A\xEB\xE7\x14\xE5\x3A"
           "\x59\x99\xC3\x06\xAB\x84\x01\xB2"
           , 24);
    /* F431 623E 4997 89C8 C2F1 F725 AD7F 8949 */
    memcpy(bMasterKey,
           "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4"
           , 16);
    memcpy(bCardFactor,
           "\x25\x00\x00\x00\x00\x00\x89\x01"
           , 8);
    memcpy(bSessionFactor,
           "\x00\x02"
           , 2);
    /* 4FA1 BA64 DC85 58BF EC43 C210 F4FD 4610 */
    memcpy(bSubKeyExp,
           "\x08\xB6\x5B\x2F\x55\x95\x20\xC4\xC4\x64\x84\xA5\x10\xB4\x68\x9B"
           , 16);
    /* 04BC 620F 4E58 684D */
    memcpy(szCheckValueExp,
           "04BC620F"
           , 8);

    XXX_INPUT_XXX
    printf("[IN ]nSock          = %d\n", nSock);
    printf("[IN ]nDivNum        = %d\n", nDivNum);
    printf("[IN ]nIccType       = %d\n", nIccType);
    printf("[IN ]nAlgo          = %d\n", nAlgo);
    DspHex("[IN ]bKek           =", bKek, 16);
    DspHex("[IN ]bMasterKey     =", bMasterKey, 16);
    DspHex("[IN ]bCardFactor    =", bCardFactor, 8);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 2);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIDisreteSubKey(nSock, nDivNum, nIccType, nAlgo, bKek, \
                              bMasterKey, bCardFactor, bSessionFactor, \
                              bSubKey, szCheckValue);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "PBOC卡，三倍长密钥，二次离散测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    ASSERT_OUT_HEX(bSubKey, bSubKeyExp, 16);
    ASSERT_OUT_HEX(szCheckValue, szCheckValueExp, 8);
    XXX_OUTPUT_XXX
		
    DspHex("[RESULT ]expected subkey	=", bSubKeyExp, 16);
    DspHex("[RESULT ]disreted subkey =", bSubKey, 16);
    DspHex("[RESULT ]expected checkvalue	=", szCheckValueExp, 8);
    DspHex("[RESULT]disreted checkvalue =", szCheckValue, 8);

    XXX_TEST_END_XXX
}

void DisreteSubKey_Test_09(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int nDivNum;
	  int nIccType;
	  int nAlgo;
	  unsigned char  bKek[32];
	  unsigned char  bMasterKey[32];
	  unsigned char  bCardFactor[8];
	  unsigned char  bSessionFactor[4];
	  unsigned char  bSubKey[32];
	  unsigned char  szCheckValue[16];
	  unsigned char  bSubKeyExp[32];
	  unsigned char  szCheckValueExp[16];

    bufclr(bKek);
    bufclr(bMasterKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bSubKey);
    bufclr(szCheckValue);

    nSock = -1;
    nDivNum = 1;
    nIccType = 0x00000000;
    nAlgo = 2;
    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(bKek,
           "\xA2\xC0\xB0\xF8\xF7\xF5\xEE\x21\xFB\x5C\x6A\xEB\xE7\x14\xE5\x3A"
           , 16);
    /* F431 623E 4997 89C8 C2F1 F725 AD7F 8949 */
    memcpy(bMasterKey,
           "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4"
           , 16);
    memcpy(bCardFactor,
           "\x25\x00\x00\x00\x00\x00\x89\x01"
           , 8);
    memcpy(bSessionFactor,
           "\x00\x02"
           , 2);
    /* 89E9 1FCB 266D 7C51 A437 AE51 2F10 5225 */
    memcpy(bSubKeyExp,
           "\xB9\x80\xE9\x91\xA7\xC6\x6F\x30\x21\x2C\xDE\x6F\xB4\x7A\x59\xD9"
           , 16);
    /* 09F1 C278 E411 C078 */
    memcpy(szCheckValueExp,
           "09F1C278"
           , 8);

    XXX_INPUT_XXX
    printf("[IN ]nSock          = %d\n", nSock);
    printf("[IN ]nDivNum        = %d\n", nDivNum);
    printf("[IN ]nIccType       = %d\n", nIccType);
    printf("[IN ]nAlgo          = %d\n", nAlgo);
    DspHex("[IN ]bKek           =", bKek, 16);
    DspHex("[IN ]bMasterKey     =", bMasterKey, 16);
    DspHex("[IN ]bCardFactor    =", bCardFactor, 8);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 2);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIDisreteSubKey(nSock, nDivNum, nIccType, nAlgo, bKek, \
                              bMasterKey, bCardFactor, bSessionFactor, \
                              bSubKey, szCheckValue);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 1, "无效Socket ID[-1]测试未失败");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    nSock = SM_SOCK;

    XXX_TEST_END_XXX
}

void DisreteSubKey_Test_10(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int nDivNum;
	  int nIccType;
	  int nAlgo;
	  unsigned char  bKek[32];
	  unsigned char  bMasterKey[32];
	  unsigned char  bCardFactor[8];
	  unsigned char  bSessionFactor[4];
	  unsigned char  bSubKey[32];
	  unsigned char  szCheckValue[16];
	  unsigned char  bSubKeyExp[32];
	  unsigned char  szCheckValueExp[16];

    bufclr(bKek);
    bufclr(bMasterKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bSubKey);
    bufclr(szCheckValue);

    nSock = 8;
    nDivNum = 1;
    nIccType = 0x00000000;
    nAlgo = 2;
    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(bKek,
           "\xA2\xC0\xB0\xF8\xF7\xF5\xEE\x21\xFB\x5C\x6A\xEB\xE7\x14\xE5\x3A"
           , 16);
    /* F431 623E 4997 89C8 C2F1 F725 AD7F 8949 */
    memcpy(bMasterKey,
           "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4"
           , 16);
    memcpy(bCardFactor,
           "\x25\x00\x00\x00\x00\x00\x89\x01"
           , 8);
    memcpy(bSessionFactor,
           "\x00\x02"
           , 2);
    /* 89E9 1FCB 266D 7C51 A437 AE51 2F10 5225 */
    memcpy(bSubKeyExp,
           "\xB9\x80\xE9\x91\xA7\xC6\x6F\x30\x21\x2C\xDE\x6F\xB4\x7A\x59\xD9"
           , 16);
    /* 09F1 C278 E411 C078 */
    memcpy(szCheckValueExp,
           "09F1C278"
           , 8);

    XXX_INPUT_XXX
    printf("[IN ]nSock          = %d\n", nSock);
    printf("[IN ]nDivNum        = %d\n", nDivNum);
    printf("[IN ]nIccType       = %d\n", nIccType);
    printf("[IN ]nAlgo          = %d\n", nAlgo);
    DspHex("[IN ]bKek           =", bKek, 16);
    DspHex("[IN ]bMasterKey     =", bMasterKey, 16);
    DspHex("[IN ]bCardFactor    =", bCardFactor, 8);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 2);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIDisreteSubKey(nSock, nDivNum, nIccType, nAlgo, bKek, \
                              bMasterKey, bCardFactor, bSessionFactor, \
                              bSubKey, szCheckValue);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 1, "无效Socket ID[8]测试未失败");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    nSock = SM_SOCK;

    XXX_TEST_END_XXX
}

void DisreteSubKey_Test_11(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int nDivNum;
	  int nIccType;
	  int nAlgo;
	  unsigned char  bKek[32];
	  unsigned char  bMasterKey[32];
	  unsigned char  bCardFactor[8];
	  unsigned char  bSessionFactor[4];
	  unsigned char  bSubKey[32];
	  unsigned char  szCheckValue[16];
	  unsigned char  bSubKeyExp[32];
	  unsigned char  szCheckValueExp[16];

    bufclr(bKek);
    bufclr(bMasterKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bSubKey);
    bufclr(szCheckValue);

    nDivNum = 0;
    nIccType = 0x00000000;
    nAlgo = 2;
    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(bKek,
           "\xA2\xC0\xB0\xF8\xF7\xF5\xEE\x21\xFB\x5C\x6A\xEB\xE7\x14\xE5\x3A"
           , 16);
    /* F431 623E 4997 89C8 C2F1 F725 AD7F 8949 */
    memcpy(bMasterKey,
           "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4"
           , 16);
    memcpy(bCardFactor,
           "\x25\x00\x00\x00\x00\x00\x89\x01"
           , 8);
    memcpy(bSessionFactor,
           "\x00\x02"
           , 2);
    /* 89E9 1FCB 266D 7C51 A437 AE51 2F10 5225 */
    memcpy(bSubKeyExp,
           "\xB9\x80\xE9\x91\xA7\xC6\x6F\x30\x21\x2C\xDE\x6F\xB4\x7A\x59\xD9"
           , 16);
    /* 09F1 C278 E411 C078 */
    memcpy(szCheckValueExp,
           "09F1C278"
           , 8);

    XXX_INPUT_XXX
    printf("[IN ]nSock          = %d\n", nSock);
    printf("[IN ]nDivNum        = %d\n", nDivNum);
    printf("[IN ]nIccType       = %d\n", nIccType);
    printf("[IN ]nAlgo          = %d\n", nAlgo);
    DspHex("[IN ]bKek           =", bKek, 16);
    DspHex("[IN ]bMasterKey     =", bMasterKey, 16);
    DspHex("[IN ]bCardFactor    =", bCardFactor, 8);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 2);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIDisreteSubKey(nSock, nDivNum, nIccType, nAlgo, bKek, \
                              bMasterKey, bCardFactor, bSessionFactor, \
                              bSubKey, szCheckValue);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 1, "无效离散次数[0]测试未失败");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void DisreteSubKey_Test_12(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int nDivNum;
	  int nIccType;
	  int nAlgo;
	  unsigned char  bKek[32];
	  unsigned char  bMasterKey[32];
	  unsigned char  bCardFactor[8];
	  unsigned char  bSessionFactor[4];
	  unsigned char  bSubKey[32];
	  unsigned char  szCheckValue[16];
	  unsigned char  bSubKeyExp[32];
	  unsigned char  szCheckValueExp[16];

    bufclr(bKek);
    bufclr(bMasterKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bSubKey);
    bufclr(szCheckValue);

    nDivNum = 3;
    nIccType = 0x00000000;
    nAlgo = 2;
    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(bKek,
           "\xA2\xC0\xB0\xF8\xF7\xF5\xEE\x21\xFB\x5C\x6A\xEB\xE7\x14\xE5\x3A"
           , 16);
    /* F431 623E 4997 89C8 C2F1 F725 AD7F 8949 */
    memcpy(bMasterKey,
           "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4"
           , 16);
    memcpy(bCardFactor,
           "\x25\x00\x00\x00\x00\x00\x89\x01"
           , 8);
    memcpy(bSessionFactor,
           "\x00\x02"
           , 2);
    /* 89E9 1FCB 266D 7C51 A437 AE51 2F10 5225 */
    memcpy(bSubKeyExp,
           "\xB9\x80\xE9\x91\xA7\xC6\x6F\x30\x21\x2C\xDE\x6F\xB4\x7A\x59\xD9"
           , 16);
    /* 09F1 C278 E411 C078 */
    memcpy(szCheckValueExp,
           "09F1C278"
           , 8);

    XXX_INPUT_XXX
    printf("[IN ]nSock          = %d\n", nSock);
    printf("[IN ]nDivNum        = %d\n", nDivNum);
    printf("[IN ]nIccType       = %d\n", nIccType);
    printf("[IN ]nAlgo          = %d\n", nAlgo);
    DspHex("[IN ]bKek           =", bKek, 16);
    DspHex("[IN ]bMasterKey     =", bMasterKey, 16);
    DspHex("[IN ]bCardFactor    =", bCardFactor, 8);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 2);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIDisreteSubKey(nSock, nDivNum, nIccType, nAlgo, bKek, \
                              bMasterKey, bCardFactor, bSessionFactor, \
                              bSubKey, szCheckValue);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 1, "无效离散次数[3]测试未失败");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void DisreteSubKey_Test_13(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int nDivNum;
	  int nIccType;
	  int nAlgo;
	  unsigned char  bKek[32];
	  unsigned char  bMasterKey[32];
	  unsigned char  bCardFactor[8];
	  unsigned char  bSessionFactor[4];
	  unsigned char  bSubKey[32];
	  unsigned char  szCheckValue[16];
	  unsigned char  bSubKeyExp[32];
	  unsigned char  szCheckValueExp[16];

    bufclr(bKek);
    bufclr(bMasterKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bSubKey);
    bufclr(szCheckValue);

    nDivNum = 1;
    nIccType = -1;
    nAlgo = 2;
    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(bKek,
           "\xA2\xC0\xB0\xF8\xF7\xF5\xEE\x21\xFB\x5C\x6A\xEB\xE7\x14\xE5\x3A"
           , 16);
    /* F431 623E 4997 89C8 C2F1 F725 AD7F 8949 */
    memcpy(bMasterKey,
           "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4"
           , 16);
    memcpy(bCardFactor,
           "\x25\x00\x00\x00\x00\x00\x89\x01"
           , 8);
    memcpy(bSessionFactor,
           "\x00\x02"
           , 2);
    /* 89E9 1FCB 266D 7C51 A437 AE51 2F10 5225 */
    memcpy(bSubKeyExp,
           "\xB9\x80\xE9\x91\xA7\xC6\x6F\x30\x21\x2C\xDE\x6F\xB4\x7A\x59\xD9"
           , 16);
    /* 09F1 C278 E411 C078 */
    memcpy(szCheckValueExp,
           "09F1C278"
           , 8);

    XXX_INPUT_XXX
    printf("[IN ]nSock          = %d\n", nSock);
    printf("[IN ]nDivNum        = %d\n", nDivNum);
    printf("[IN ]nIccType       = %d\n", nIccType);
    printf("[IN ]nAlgo          = %d\n", nAlgo);
    DspHex("[IN ]bKek           =", bKek, 16);
    DspHex("[IN ]bMasterKey     =", bMasterKey, 16);
    DspHex("[IN ]bCardFactor    =", bCardFactor, 8);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 2);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIDisreteSubKey(nSock, nDivNum, nIccType, nAlgo, bKek, \
                              bMasterKey, bCardFactor, bSessionFactor, \
                              bSubKey, szCheckValue);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 1, "无效IC卡类型[-1]测试未失败");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void DisreteSubKey_Test_14(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int nDivNum;
	  int nIccType;
	  int nAlgo;
	  unsigned char  bKek[32];
	  unsigned char  bMasterKey[32];
	  unsigned char  bCardFactor[8];
	  unsigned char  bSessionFactor[4];
	  unsigned char  bSubKey[32];
	  unsigned char  szCheckValue[16];
	  unsigned char  bSubKeyExp[32];
	  unsigned char  szCheckValueExp[16];

    bufclr(bKek);
    bufclr(bMasterKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bSubKey);
    bufclr(szCheckValue);

    nDivNum = 1;
    nIccType = 2;
    nAlgo = 2;
    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(bKek,
           "\xA2\xC0\xB0\xF8\xF7\xF5\xEE\x21\xFB\x5C\x6A\xEB\xE7\x14\xE5\x3A"
           , 16);
    /* F431 623E 4997 89C8 C2F1 F725 AD7F 8949 */
    memcpy(bMasterKey,
           "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4"
           , 16);
    memcpy(bCardFactor,
           "\x25\x00\x00\x00\x00\x00\x89\x01"
           , 8);
    memcpy(bSessionFactor,
           "\x00\x02"
           , 2);
    /* 89E9 1FCB 266D 7C51 A437 AE51 2F10 5225 */
    memcpy(bSubKeyExp,
           "\xB9\x80\xE9\x91\xA7\xC6\x6F\x30\x21\x2C\xDE\x6F\xB4\x7A\x59\xD9"
           , 16);
    /* 09F1 C278 E411 C078 */
    memcpy(szCheckValueExp,
           "09F1C278"
           , 8);

    XXX_INPUT_XXX
    printf("[IN ]nSock          = %d\n", nSock);
    printf("[IN ]nDivNum        = %d\n", nDivNum);
    printf("[IN ]nIccType       = %x\n", nIccType);
    printf("[IN ]nAlgo          = %d\n", nAlgo);
    DspHex("[IN ]bKek           =", bKek, 16);
    DspHex("[IN ]bMasterKey     =", bMasterKey, 16);
    DspHex("[IN ]bCardFactor    =", bCardFactor, 8);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 2);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIDisreteSubKey(nSock, nDivNum, nIccType, nAlgo, bKek, \
                              bMasterKey, bCardFactor, bSessionFactor, \
                              bSubKey, szCheckValue);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 1, "无效IC卡类型[2]测试未失败");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void DisreteSubKey_Test_15(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int nDivNum;
	  int nIccType;
	  int nAlgo;
	  unsigned char  bKek[32];
	  unsigned char  bMasterKey[32];
	  unsigned char  bCardFactor[8];
	  unsigned char  bSessionFactor[4];
	  unsigned char  bSubKey[32];
	  unsigned char  szCheckValue[16];
	  unsigned char  bSubKeyExp[32];
	  unsigned char  szCheckValueExp[16];

    bufclr(bKek);
    bufclr(bMasterKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bSubKey);
    bufclr(szCheckValue);

    nDivNum = 1;
    nIccType = 0x00000000;
    nAlgo = 0;
    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(bKek,
           "\xA2\xC0\xB0\xF8\xF7\xF5\xEE\x21\xFB\x5C\x6A\xEB\xE7\x14\xE5\x3A"
           , 16);
    /* F431 623E 4997 89C8 C2F1 F725 AD7F 8949 */
    memcpy(bMasterKey,
           "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4"
           , 16);
    memcpy(bCardFactor,
           "\x25\x00\x00\x00\x00\x00\x89\x01"
           , 8);
    memcpy(bSessionFactor,
           "\x00\x02"
           , 2);
    /* 89E9 1FCB 266D 7C51 A437 AE51 2F10 5225 */
    memcpy(bSubKeyExp,
           "\xB9\x80\xE9\x91\xA7\xC6\x6F\x30\x21\x2C\xDE\x6F\xB4\x7A\x59\xD9"
           , 16);
    /* 09F1 C278 E411 C078 */
    memcpy(szCheckValueExp,
           "09F1C278"
           , 8);

    XXX_INPUT_XXX
    printf("[IN ]nSock          = %d\n", nSock);
    printf("[IN ]nDivNum        = %d\n", nDivNum);
    printf("[IN ]nIccType       = %d\n", nIccType);
    printf("[IN ]nAlgo          = %d\n", nAlgo);
    DspHex("[IN ]bKek           =", bKek, 16);
    DspHex("[IN ]bMasterKey     =", bMasterKey, 16);
    DspHex("[IN ]bCardFactor    =", bCardFactor, 8);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 2);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIDisreteSubKey(nSock, nDivNum, nIccType, nAlgo, bKek, \
                              bMasterKey, bCardFactor, bSessionFactor, \
                              bSubKey, szCheckValue);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 1, "无效算法类型[0]测试未失败");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void DisreteSubKey_Test_16(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int nDivNum;
	  int nIccType;
	  int nAlgo;
	  unsigned char  bKek[32];
	  unsigned char  bMasterKey[32];
	  unsigned char  bCardFactor[8];
	  unsigned char  bSessionFactor[4];
	  unsigned char  bSubKey[32];
	  unsigned char  szCheckValue[16];
	  unsigned char  bSubKeyExp[32];
	  unsigned char  szCheckValueExp[16];

    bufclr(bKek);
    bufclr(bMasterKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bSubKey);
    bufclr(szCheckValue);

    nDivNum = 1;
    nIccType = 0x00000000;
    nAlgo = 4;
    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(bKek,
           "\xA2\xC0\xB0\xF8\xF7\xF5\xEE\x21\xFB\x5C\x6A\xEB\xE7\x14\xE5\x3A"
           , 16);
    /* F431 623E 4997 89C8 C2F1 F725 AD7F 8949 */
    memcpy(bMasterKey,
           "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4"
           , 16);
    memcpy(bCardFactor,
           "\x25\x00\x00\x00\x00\x00\x89\x01"
           , 8);
    memcpy(bSessionFactor,
           "\x00\x02"
           , 2);
    /* 89E9 1FCB 266D 7C51 A437 AE51 2F10 5225 */
    memcpy(bSubKeyExp,
           "\xB9\x80\xE9\x91\xA7\xC6\x6F\x30\x21\x2C\xDE\x6F\xB4\x7A\x59\xD9"
           , 16);
    /* 09F1 C278 E411 C078 */
    memcpy(szCheckValueExp,
           "09F1C278"
           , 8);

    XXX_INPUT_XXX
    printf("[IN ]nSock          = %d\n", nSock);
    printf("[IN ]nDivNum        = %d\n", nDivNum);
    printf("[IN ]nIccType       = %d\n", nIccType);
    printf("[IN ]nAlgo          = %d\n", nAlgo);
    DspHex("[IN ]bKek           =", bKek, 16);
    DspHex("[IN ]bMasterKey     =", bMasterKey, 16);
    DspHex("[IN ]bCardFactor    =", bCardFactor, 8);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 2);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIDisreteSubKey(nSock, nDivNum, nIccType, nAlgo, bKek, \
                              bMasterKey, bCardFactor, bSessionFactor, \
                              bSubKey, szCheckValue);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 1, "无效算法类型[4]测试未失败");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void DisreteSubKey_Test_17(void)
{
    	XXX_TEST_START_XXX
    	int nRet;
    	int nSock = SM_SOCK;

	  int nDivNum;
	  int nIccType;
	  int nAlgo;
	  unsigned char  bKek[32];
	  unsigned char  bMasterKey[32];
	  unsigned char  bCardFactor[16];
	  unsigned char  bSessionFactor[4];
	  unsigned char  bLeftCardFactor[8];
	  unsigned char bRightCardFactor[8];
	  unsigned char  bSubKey[32];
	  unsigned char  szCheckValue[16];
	  unsigned char  bSubKeyExp[32];
	  unsigned char  szCheckValueExp[16];

    bufclr(bKek);
    bufclr(bMasterKey);
    bufclr(bCardFactor);
    bufclr(bLeftCardFactor);
    bufclr(bRightCardFactor);
    bufclr(bSessionFactor);
    bufclr(bSubKey);
    bufclr(szCheckValue);

    nDivNum = 1;
    nIccType = 0x0001000A;
    nAlgo = 1;
    /* 0123 4567 89AB CDEF */
    memcpy(bKek,
           "\xA2\xC0\xB0\xF8\xF7\xF5\xEE\x21"
           , 8);
    /* F431 623E 4997 89C8 C2F1 F725 AD7F 8949 */
    memcpy(bMasterKey,
           "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4"
           , 16);
	
    memcpy(bLeftCardFactor,  "\x25\x00\x00\x00\x00\x00\x89\x01" ,8);
    memcpy(bRightCardFactor,   "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" ,8); 
    SSMBinStrXOR(bRightCardFactor, bLeftCardFactor, bRightCardFactor, 8);
    memcpy(&bCardFactor[0], bLeftCardFactor, 8);
    memcpy(&bCardFactor[8], bRightCardFactor, 8);
	
//memcpy(bSessionFactor,  "\x00\x02" , 2);

    /* 89E8 1ECA 276C 7D50 A537 AE51 2E11 5224 */
    memcpy(bSubKeyExp,
           "\x67\x64\x66\x3B\x80\xD2\xBA\x20\x05\xB6\x36\xEE\xFB\xB6\x1F\x36"
           , 16);

    /* 09F1 C278 E411 C078 */
    memcpy(szCheckValueExp,
           "09F1C278"
           , 8);

    XXX_INPUT_XXX
    printf("[IN ]nSock          = %d\n", nSock);
    printf("[IN ]nDivNum        = %d\n", nDivNum);
    printf("[IN ]nIccType       = %x\n", nIccType);
    printf("[IN ]nAlgo          = %d\n", nAlgo);
    DspHex("[IN ]bKek           =", bKek, 16);
    DspHex("[IN ]bMasterKey     =", bMasterKey, 16);
    DspHex("[IN ]bCardFactor    =", bCardFactor, 16);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 2);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIDisreteSubKey(nSock, nDivNum, nIccType, nAlgo, bKek, \
                              bMasterKey, bCardFactor, bSessionFactor, \
                              bSubKey, szCheckValue);

	/* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "VISA卡，单倍长KEK密钥，一次离散测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    ASSERT_OUT_HEX(bSubKey, bSubKeyExp, 16);
    ASSERT_OUT_HEX(szCheckValue, szCheckValueExp, 8);
    XXX_OUTPUT_XXX

    DspHex("[RESULT ]expected subkey	=", bSubKeyExp, 16);
    DspHex("[RESULT ]disreted subkey =", bSubKey, 16);
    DspHex("[RESULT ]expected checkvalue	=", szCheckValueExp, 8);
    DspHex("[RESULT]disreted checkvalue =", szCheckValue, 8);

    XXX_TEST_END_XXX
}

void DisreteSubKey_Test_18(void)
{
		XXX_TEST_START_XXX
		int  nRet;
		int  nSock = SM_SOCK;
	
		  int nDivNum;
		  int nIccType;
		  int nAlgo;
		  unsigned char  bKek[32];
		  unsigned char  bMasterKey[32];
		  unsigned char  bCardFactor[16];
		  unsigned char  bLeftCardFactor[8];
		  unsigned char bRightCardFactor[8];
		  unsigned char  bSessionFactor[4];
		  unsigned char  bSubKey[32];
		  unsigned char  szCheckValue[16];
		  unsigned char  bSubKeyExp[32];
		  unsigned char  szCheckValueExp[16];
	
		bufclr(bKek);
		bufclr(bMasterKey);
		bufclr(bCardFactor);
		bufclr(bLeftCardFactor);
		bufclr(bRightCardFactor);
		bufclr(bSessionFactor);
		bufclr(bSubKey);
		bufclr(szCheckValue);
	
		nDivNum = 1;
		nIccType = 0x0001000A;
		nAlgo = 3;
		
		/* 0123 4567 89AB CDEF FEDC BA98 7654 3210 8796 A5B4 C3D2 E1F0 */
		memcpy(bKek,
			   "\xA2\xC0\xB0\xF8\xF7\xF5\xEE\x21\xFB\x5C\x6A\xEB\xE7\x14\xE5\x3A"
			   "\x59\x99\xC3\x06\xAB\x84\x01\xB2"
			   , 24);

		/* F431 623E 4997 89C8 C2F1 F725 AD7F 8949 */
		memcpy(bMasterKey,
			   "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4"
			   , 16);
		
		memcpy(bLeftCardFactor,  "\x25\x00\x00\x00\x00\x00\x89\x01" ,8);
		memcpy(bRightCardFactor,   "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" ,8); 
		SSMBinStrXOR(bRightCardFactor, bLeftCardFactor, bRightCardFactor, 8);
		memcpy(&bCardFactor[0], bLeftCardFactor, 8);
		memcpy(&bCardFactor[8], bRightCardFactor, 8);
	
		 /*89E8 1ECA 276C 7D50 A537 AE51 2E11 5224*/
		memcpy(bSubKeyExp,
			   "\xBC\x50\x09\xE5\xD1\xA3\x24\x70\xCD\xBA\x80\x7B\xDE\xB5\x38\xCB"
			   , 16);
		
		/* 09F1 C278 E411 C078 */
		memcpy(szCheckValueExp,
			   "09F1C278"
			   , 8);
	
		XXX_INPUT_XXX
		printf("[IN ]nSock			= %d\n", nSock);
		printf("[IN ]nDivNum		= %d\n", nDivNum);
		printf("[IN ]nIccType		= %x\n", nIccType);
		printf("[IN ]nAlgo			= %d\n", nAlgo);
		DspHex("[IN ]bKek			=", bKek, 16);
		DspHex("[IN ]bMasterKey 	=", bMasterKey, 16);
		DspHex("[IN ]bCardFactor	=", bCardFactor, 16);
		DspHex("[IN ]bSessionFactor =", bSessionFactor, 2); 
		XXX_INPUT_XXX
	
		/* Call Test Target Function Start */
		nRet = SMAPIDisreteSubKey(nSock, nDivNum, nIccType, nAlgo, bKek, \
								  bMasterKey, bCardFactor, bSessionFactor, \
								  bSubKey, szCheckValue);
		/* Call Test Target Function End */
	
		XXX_RESULT_XXX
		ASSERT_RESULT(nRet, 0, "VISA卡，三倍KEK，一次离散测试未成功（失败可）");
		XXX_RESULT_XXX
	
		XXX_OUTPUT_XXX
		ASSERT_OUT_HEX(bSubKey, bSubKeyExp, 16);
		ASSERT_OUT_HEX(szCheckValue, szCheckValueExp, 8);
		XXX_OUTPUT_XXX
	
		DspHex("[RESULT ]expected subkey	=", bSubKeyExp, 16);
		DspHex("[RESULT ]disreted subkey =", bSubKey, 16);
		DspHex("[RESULT ]expected checkvalue	=", szCheckValueExp, 8);
		DspHex("[RESULT]disreted checkvalue =", szCheckValue, 8);
	
		XXX_TEST_END_XXX

}

void DisreteSubKey_Test_19(void)
{
	XXX_TEST_START_XXX
	int  nRet;
	int  nSock = SM_SOCK;
	
	int nDivNum;
	int nIccType;
	int nAlgo;
	unsigned char  bKek[8];
	unsigned char  bMasterKey[32];
	unsigned char  bCardFactor[16];
	unsigned char  bSubCardKey[16];
	unsigned char  bATC[4];
	unsigned char  bSessionSeed[16];
	unsigned char  bSubKey[16];
	unsigned char  szCheckValue[16];
	unsigned char  bSubKeyExp[32];
	unsigned char  szCheckValueExp[16];
	
	bufclr(bKek);
	bufclr(bMasterKey);
	bufclr(bCardFactor);
	bufclr(bSubCardKey);
	bufclr(bATC);
	memset(bSessionSeed,0,16);
	bufclr(bSubKey);
	bufclr(szCheckValue);

	nDivNum = 2;
	nIccType = 0x0001000A;
	nAlgo = 1;
	
	/* 0123 4567 89AB CDEF */
	memcpy(bKek,
		   "\xA2\xC0\xB0\xF8\xF7\xF5\xEE\x21"
		   , 8);
	/* F431 623E 4997 89C8 C2F1 F725 AD7F 8949 */
	memcpy(bMasterKey,
		   "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4"
		   , 16);
	memcpy(bCardFactor,
		   "\x25\x00\x00\x00\x00\x00\x89\x01"
		   , 8);	
	memset(&bCardFactor[8], 0xFF, 8);
	SSMBinStrXOR(&bCardFactor[8], &bCardFactor[8], bCardFactor, 8);
	
	memcpy(bSubCardKey, 
		"\x89\xE8\x1E\xCA\x27\x6C\x7D\x50\xA5\x37\xAE\x51\x2E\x11\x52\x24"
		  ,16);
		
	memcpy(bATC,  "\x00\x02", 2);
	memcpy(&bSessionSeed[6], bATC, 2);
	memset(&bSessionSeed[14], 0xFF, 2);
	SSMBinStrXOR(&bSessionSeed[14], bATC,  &bSessionSeed[14], 2);
	
	//SSMBinStrXOR(bSubKeyExp, bSessionSeed, bSubCardKey, 16);
	/* 89 E8 1E CA 27 6C 7D 52 A5 37 AE 51 2E 11 AD D9 */
	memcpy(bSubKeyExp,
		   "\x11\x3F\x55\xB4\x5D\xCE\xE7\xE2\xA8\xD5\xCE\x7F\xA5\xF3\xF7\xCE"
		   , 16);
	
	/* D701 16E2 503E 3CC8 */
	memcpy(szCheckValueExp,
		   "D70116E2"
		   , 8);
	
	XXX_INPUT_XXX
	printf("[IN ]nSock			= %d\n", nSock);
	printf("[IN ]nDivNum		= %d\n", nDivNum);
	printf("[IN ]nIccType		= %x\n", nIccType);
	printf("[IN ]nAlgo			= %d\n", nAlgo);
	DspHex("[IN ]bKek			=", bKek, 8);
	DspHex("[IN ]bMasterKey 	=", bMasterKey, 16);
	DspHex("[IN ]bCardFactor	=", bCardFactor, 16);
	DspHex("[IN ]bSubCardKey	=", bSubCardKey, 16);
	DspHex("[IN ]bATC =", bATC, 2);
	DspHex("[IN ]bSessionSeed =", bSessionSeed, 16);
	DspHex("[OUT] bSubKeyExp=", bSubKeyExp, 16);	
	XXX_INPUT_XXX
		
	/* Call Test Target Function Start */
	nRet = SMAPIDisreteSubKey(nSock, nDivNum, nIccType, nAlgo, bKek, \
							  bMasterKey, bCardFactor, bSessionSeed, \
							  bSubKey, szCheckValue);
	/* Call Test Target Function End */
	XXX_RESULT_XXX
	ASSERT_RESULT(nRet, 0, "VISA卡，单倍KEK，二次离散脚本会话密钥未成功（失败可）");
	XXX_RESULT_XXX
			
	XXX_OUTPUT_XXX
	ASSERT_OUT_HEX(bSubKey, bSubKeyExp, 16);
	ASSERT_OUT_HEX(szCheckValue, szCheckValueExp, 8);
	XXX_OUTPUT_XXX
	
	DspHex("[RESULT ]expected subkey	=", bSubKeyExp, 16);
	DspHex("[RESULT ]disreted subkey =", bSubKey, 16);
	DspHex("[RESULT ]expected checkvalue	=", szCheckValueExp, 8);
	DspHex("[RESULT]disreted checkvalue =", szCheckValue, 8);
	
	XXX_TEST_END_XXX

}

void DisreteSubKey_Test_20(void)
{
		XXX_TEST_START_XXX
		int  nRet;
		int  nSock = SM_SOCK;
		
		int nDivNum;
		int nIccType;
		int nAlgo;
		unsigned char  bKek[24];
		unsigned char  bMasterKey[32];
		unsigned char  bCardFactor[16];
		unsigned char  bSubCardKey[16];
		unsigned char  bATC[4];
		unsigned char bSessionSeed[16];
		unsigned char  bSubKey[16];
		unsigned char  szCheckValue[16];
		unsigned char  bSubKeyExp[32];
		unsigned char  szCheckValueExp[16];
		
		bufclr(bKek);
		bufclr(bMasterKey);
		bufclr(bCardFactor);
		bufclr(bSubCardKey);
		bufclr(bATC);
		memset(bSessionSeed,0,16);
		bufclr(bSubKey);
		bufclr(szCheckValue);
	
		nDivNum = 2;
		nIccType = 0x0001000A;
		nAlgo = 3;
		
		/* 0123 4567 89AB CDEF FEDC BA98 7654 3210 8796 A5B4 C3D2 E1F0 */
		memcpy(bKek,
			   "\xA2\xC0\xB0\xF8\xF7\xF5\xEE\x21\xFB\x5C\x6A\xEB\xE7\x14\xE5\x3A"
			   "\x59\x99\xC3\x06\xAB\x84\x01\xB2"
			   , 24);

		/* F431 623E 4997 89C8 C2F1 F725 AD7F 8949 */
		memcpy(bMasterKey,
			   "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4"
			   , 16);
		memcpy(bCardFactor,
			   "\x25\x00\x00\x00\x00\x00\x89\x01"
			   , 8);	
		memset(&bCardFactor[8], 0xFF, 8);
		SSMBinStrXOR(&bCardFactor[8], &bCardFactor[8], bCardFactor, 8);
		
		memcpy(bSubCardKey, 
			"\x89\xE8\x1E\xCA\x27\x6C\x7D\x50\xA5\x37\xAE\x51\x2E\x11\x52\x24"
			  ,16);
			
		memcpy(bATC,  "\x00\x02", 2);
		memcpy(&bSessionSeed[6], bATC, 2);
		memset(&bSessionSeed[14], 0xFF, 2);
		SSMBinStrXOR(&bSessionSeed[14], bATC,  &bSessionSeed[14], 2);
		
		//SSMBinStrXOR(bSubKeyExp, bSessionSeed, bSubCardKey, 16);
		/* 89 E8 1E CA 27 6C 7D 52 A5 37 AE 51 2E 11 AD D9 */
		memcpy(bSubKeyExp,
			   "\x3A\x7E\x41\x2E\x68\x3A\xCA\xC8\x65\x96\x43\xFB\x17\x32\xFA\x5D"
			   , 16);
		       
		/* D701 16E2 503E 3CC8 */
		memcpy(szCheckValueExp,
			   "D70116E2"
			   , 8);
		
		XXX_INPUT_XXX
		printf("[IN ]nSock			= %d\n", nSock);
		printf("[IN ]nDivNum		= %d\n", nDivNum);
		printf("[IN ]nIccType		= %x\n", nIccType);
		printf("[IN ]nAlgo			= %d\n", nAlgo);
		DspHex("[IN ]bKek			=", bKek, 24);
		DspHex("[IN ]bMasterKey 	=", bMasterKey, 16);
		DspHex("[IN ]bCardFactor	=", bCardFactor, 16);
		DspHex("[IN ]bSubCardKey	=", bSubCardKey, 16);
		DspHex("[IN ]bATC =", bATC, 2);
		DspHex("[IN ]bSessionSeed =", bSessionSeed, 16);
		DspHex("[OUT] bSubKeyExp=", bSubKeyExp, 16);	
		XXX_INPUT_XXX
			
		/* Call Test Target Function Start */
		nRet = SMAPIDisreteSubKey(nSock, nDivNum, nIccType, nAlgo, bKek, \
								  bMasterKey, bCardFactor, bSessionSeed, \
								  bSubKey, szCheckValue);
		/* Call Test Target Function End */
		XXX_RESULT_XXX
		ASSERT_RESULT(nRet, 0, "VISA卡，三倍KEK，二次离散脚本会话密钥未成功（失败可）");
		XXX_RESULT_XXX
				
		XXX_OUTPUT_XXX
		ASSERT_OUT_HEX(bSubKey, bSubKeyExp, 16);
		ASSERT_OUT_HEX(szCheckValue, szCheckValueExp, 8);
		XXX_OUTPUT_XXX
		
		DspHex("[RESULT ]expected subkey	=", bSubKeyExp, 16);
		DspHex("[RESULT ]disreted subkey =", bSubKey, 16);
		DspHex("[RESULT ]expected checkvalue	=", szCheckValueExp, 8);
		DspHex("[RESULT]disreted checkvalue =", szCheckValue, 8);
		
		XXX_TEST_END_XXX

}

void DisreteSubKey_Test_21(void)
{
		XXX_TEST_START_XXX
		int nRet;
		int nSock = SM_SOCK;
	
		  int nDivNum;
		  int nIccType;
		  int nAlgo;
		  unsigned char  bKek[8];
		  unsigned char  bMasterKey[32];
		  unsigned char  bCardFactor[16];
		  unsigned char  bSessionFactor[4];
		  unsigned char  bLeftCardFactor[8];
		  unsigned char bRightCardFactor[8];
		  unsigned char  bSubKey[32];
		  unsigned char  szCheckValue[16];
		  unsigned char  bSubKeyExp[32];
		  unsigned char  szCheckValueExp[16];
	
		bufclr(bKek);
		bufclr(bMasterKey);
		bufclr(bCardFactor);
		bufclr(bLeftCardFactor);
		bufclr(bRightCardFactor);
		bufclr(bSessionFactor);
		bufclr(bSubKey);
		bufclr(szCheckValue);
	
		nDivNum = 1;
		nIccType = 0x0002000E;
		nAlgo = 1;
		/* 0123 4567 89AB CDEF */
		memcpy(bKek,
			   "\xA2\xC0\xB0\xF8\xF7\xF5\xEE\x21"
			   , 8);
		/* F431 623E 4997 89C8 C2F1 F725 AD7F 8949 */
		memcpy(bMasterKey,
			   "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4"
			   , 16);
		
		memcpy(bLeftCardFactor,  "\x25\x00\x00\x00\x00\x00\x89\x01" ,8);
		memcpy(bRightCardFactor,   "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" ,8); 
		SSMBinStrXOR(bRightCardFactor, bLeftCardFactor, bRightCardFactor, 8);
		memcpy(&bCardFactor[0], bLeftCardFactor, 8);
		memcpy(&bCardFactor[8], bRightCardFactor, 8);
	
		/* 89E9 1FCB 266D 7C51 A437 AE51 2F10 5225 */
		memcpy(bSubKeyExp,
			   "\x4C\xFF\x06\xC4\xDF\xE3\x28\x29\xF7\x12\x38\x90\xE0\x3A\x2E\xDE"
			   , 16);

		/* 09F1 C278 E411 C078 */
		memcpy(szCheckValueExp,
			   "09F1C278"
			   , 8);
	
		XXX_INPUT_XXX
		printf("[IN ]nSock			= %d\n", nSock);
		printf("[IN ]nDivNum		= %d\n", nDivNum);
		printf("[IN ]nIccType		= %x\n", nIccType);
		printf("[IN ]nAlgo			= %d\n", nAlgo);
		DspHex("[IN ]bKek			=", bKek, 8);
		DspHex("[IN ]bMasterKey 	=", bMasterKey, 16);
		DspHex("[IN ]bCardFactor	=", bCardFactor, 16);
		DspHex("[IN ]bSessionFactor =", bSessionFactor, 2);
		XXX_INPUT_XXX
	
		/* Call Test Target Function Start */
		nRet = SMAPIDisreteSubKey(nSock, nDivNum, nIccType, nAlgo, bKek, \
								  bMasterKey, bCardFactor, bSessionFactor, \
								  bSubKey, szCheckValue);
	
		/* Call Test Target Function End */
	
		XXX_RESULT_XXX
		ASSERT_RESULT(nRet, 0, "MASTER卡，单倍长KEK密钥，一次离散测试未成功");
		XXX_RESULT_XXX
	
		XXX_OUTPUT_XXX
		ASSERT_OUT_HEX(bSubKey, bSubKeyExp, 16);
		ASSERT_OUT_HEX(szCheckValue, szCheckValueExp, 8);
		XXX_OUTPUT_XXX
	
		DspHex("[RESULT ]expected subkey	=", bSubKeyExp, 16);
		DspHex("[RESULT ]disreted subkey =", bSubKey, 16);
		DspHex("[RESULT ]expected checkvalue	=", szCheckValueExp, 8);
		DspHex("[RESULT]disreted checkvalue =", szCheckValue, 8);
	
		XXX_TEST_END_XXX

}

void DisreteSubKey_Test_22(void)
{
    XXX_TEST_START_XXX
    int nRet;
    int nSock = SM_SOCK;

    int nDivNum;
    int nIccType;
    int nAlgo;
    unsigned char  bKek[16];
    unsigned char  bMasterKey[32];
    unsigned char  bCardFactor[16];
    unsigned char  bSessionFactor[4];
    unsigned char  bLeftCardFactor[8];
    unsigned char bRightCardFactor[8];
    unsigned char  bSubKey[32];
    unsigned char  szCheckValue[16];
    unsigned char  bSubKeyExp[32];
    unsigned char  szCheckValueExp[16];

    bufclr(bKek);
    bufclr(bMasterKey);
    bufclr(bCardFactor);
    bufclr(bLeftCardFactor);
    bufclr(bRightCardFactor);
    bufclr(bSessionFactor);
    bufclr(bSubKey);
    bufclr(szCheckValue);

    nDivNum = 1;
    nIccType = 0x00020014;
    nAlgo = 2;
        
    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(bKek,
           "\xA2\xC0\xB0\xF8\xF7\xF5\xEE\x21\xFB\x5C\x6A\xEB\xE7\x14\xE5\x3A"
           , 16);

    /* F431 623E 4997 89C8 C2F1 F725 AD7F 8949 */
    memcpy(bMasterKey,
           "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4"
           , 16);
        
    memcpy(bLeftCardFactor,  "\x25\x00\x00\x00\x00\x00\x89\x01" ,8);
    memcpy(bRightCardFactor,   "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" ,8); 
    SSMBinStrXOR(bRightCardFactor, bLeftCardFactor, bRightCardFactor, 8);
    memcpy(&bCardFactor[0], bLeftCardFactor, 8);
    memcpy(&bCardFactor[8], bRightCardFactor, 8);

    /* 89E9 1FCB 266D 7C51 A437 AE51 2F10 5225 */
    memcpy(bSubKeyExp,
           "\xB9\x80\xE9\x91\xA7\xC6\x6F\x30\x21\x2C\xDE\x6F\xB4\x7A\x59\xD9"
           , 16);        

    /* 09F1 C278 E411 C078 */
    memcpy(szCheckValueExp,
           "09F1C278"
               , 8);

    XXX_INPUT_XXX
    printf("[IN ]nSock            = %d\n", nSock);
    printf("[IN ]nDivNum        = %d\n", nDivNum);
    printf("[IN ]nIccType        = %x\n", nIccType);
    printf("[IN ]nAlgo            = %d\n", nAlgo);
    DspHex("[IN ]bKek            =", bKek, 16);
    DspHex("[IN ]bMasterKey     =", bMasterKey, 16);
    DspHex("[IN ]bCardFactor    =", bCardFactor, 16);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 16);
    XXX_INPUT_XXX
    
    /* Call Test Target Function Start */
    nRet = SMAPIDisreteSubKey(nSock, nDivNum, nIccType, nAlgo, bKek, \
                              bMasterKey, bCardFactor, bSessionFactor, \
                              bSubKey, szCheckValue);
    
    /* Call Test Target Function End */
    
    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "MASTER卡，二倍长KEK密钥，一次离散测试未成功");
    XXX_RESULT_XXX
    
    XXX_OUTPUT_XXX
    ASSERT_OUT_HEX(bSubKey, bSubKeyExp, 16);
    ASSERT_OUT_HEX(szCheckValue, szCheckValueExp, 8);
    XXX_OUTPUT_XXX
    
    DspHex("[RESULT ]expected subkey    =", bSubKeyExp, 16);
    DspHex("[RESULT ]disreted subkey =", bSubKey, 16);
    DspHex("[RESULT ]expected checkvalue    =", szCheckValueExp, 8);
    DspHex("[RESULT]disreted checkvalue =", szCheckValue, 8);
    
    XXX_TEST_END_XXX
}

void DisreteSubKey_Test_23(void)
{
	XXX_TEST_START_XXX
		int nRet;
		int nSock = SM_SOCK;
		
		int nDivNum;
		int nIccType;
		int nAlgo;
		unsigned char  bKek[24];
		unsigned char  bMasterKey[32];
		unsigned char  bCardFactor[16];
		unsigned char  bSessionFactor[4];
		unsigned char  bLeftCardFactor[8];
		unsigned char bRightCardFactor[8];
		unsigned char  bSubKey[32];
		unsigned char  szCheckValue[16];
		unsigned char  bSubKeyExp[32];
		unsigned char  szCheckValueExp[16];

		bufclr(bKek);
		bufclr(bMasterKey);
		bufclr(bCardFactor);
		bufclr(bLeftCardFactor);
		bufclr(bRightCardFactor);
		bufclr(bSessionFactor);
		bufclr(bSubKey);
		bufclr(szCheckValue);
		
		nDivNum = 1;
		nIccType = 0x0002000E;
		nAlgo = 3;
			
		/* 0123 4567 89AB CDEF FEDC BA98 7654 3210 8796 A5B4 C3D2 E1F0 */
		memcpy(bKek,
			"\xA2\xC0\xB0\xF8\xF7\xF5\xEE\x21\xFB\x5C\x6A\xEB\xE7\x14\xE5\x3A"
			 "\x59\x99\xC3\x06\xAB\x84\x01\xB2"
			, 24);

		/* F431 623E 4997 89C8 C2F1 F725 AD7F 8949 */
		memcpy(bMasterKey,
			   "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4"
			   , 16);
			
		memcpy(bLeftCardFactor,  "\x25\x00\x00\x00\x00\x00\x89\x01" ,8);
		memcpy(bRightCardFactor,   "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" ,8); 
		SSMBinStrXOR(bRightCardFactor, bLeftCardFactor, bRightCardFactor, 8);
		memcpy(&bCardFactor[0], bLeftCardFactor, 8);
		memcpy(&bCardFactor[8], bRightCardFactor, 8);
		
		/* 89E9 1FCB 266D 7C51 A437 AE51 2F10 5225 */
		memcpy(bSubKeyExp,
			   "\x97\xC0\xB3\xE6\x38\x60\x7D\xB7\x89\x95\xC6\x37\xE4\x69\xAC\x74"
			   , 16);		
	
		/* 09F1 C278 E411 C078 */
		memcpy(szCheckValueExp,
			   "09F1C278"
			   , 8);
		
		XXX_INPUT_XXX
		printf("[IN ]nSock			= %d\n", nSock);
		printf("[IN ]nDivNum		= %d\n", nDivNum);
		printf("[IN ]nIccType		= %x\n", nIccType);
		printf("[IN ]nAlgo			= %d\n", nAlgo);
		DspHex("[IN ]bKek			=", bKek, 24);
		DspHex("[IN ]bMasterKey 	=", bMasterKey, 16);
		DspHex("[IN ]bCardFactor	=", bCardFactor, 16);
		DspHex("[IN ]bSessionFactor =", bSessionFactor, 2);
		XXX_INPUT_XXX
		
		/* Call Test Target Function Start */
		nRet = SMAPIDisreteSubKey(nSock, nDivNum, nIccType, nAlgo, bKek, \
								  bMasterKey, bCardFactor, bSessionFactor, \
								  bSubKey, szCheckValue);
		
		/* Call Test Target Function End */
		
		XXX_RESULT_XXX
		ASSERT_RESULT(nRet, 0, "MASTER卡，三倍长KEK密钥，一次离散测试未成功");
		XXX_RESULT_XXX
		
		XXX_OUTPUT_XXX
		ASSERT_OUT_HEX(bSubKey, bSubKeyExp, 16);
		ASSERT_OUT_HEX(szCheckValue, szCheckValueExp, 8);
		XXX_OUTPUT_XXX
		
		DspHex("[RESULT ]expected subkey	=", bSubKeyExp, 16);
		DspHex("[RESULT ]disreted subkey =", bSubKey, 16);
		DspHex("[RESULT ]expected checkvalue	=", szCheckValueExp, 8);
		DspHex("[RESULT]disreted checkvalue =", szCheckValue, 8);
		
		XXX_TEST_END_XXX

}

void DisreteSubKey_Test_24(void)
{
    	XXX_TEST_START_XXX
    	int  nRet;
    	int  nSock = SM_SOCK;

	 int nDivNum;
	 int nIccType;
	 int nAlgo;
	 unsigned char  bKek[8];
	 unsigned char  bMasterKey[32];
	 unsigned char  bCardFactor[16];
	 unsigned char  bSubCardKey[16];
	 unsigned char  bATC[4];
	 unsigned char  bLeftCardFactor[8];
	 unsigned char bRightCardFactor[8];
	 unsigned char bSessionSeed[16];
	 unsigned char  bSubKey[32];
	 unsigned char  szCheckValue[16];
	 unsigned char  bSubKeyExp[32];
	 unsigned char  szCheckValueExp[16];

    	bufclr(bKek);
    	bufclr(bMasterKey);
    	bufclr(bCardFactor);
    	bufclr(bLeftCardFactor);
    	bufclr(bRightCardFactor);
    	bufclr(bSubCardKey);
    	bufclr(bATC);
    	memset(bSessionSeed,0,16);
    	bufclr(bSubKey);
    	bufclr(szCheckValue);

    	nDivNum = 2;
    	nIccType = 0x0002000E;
    	nAlgo = 1;
	
   	 /* 0123 4567 89AB CDEF */
    	memcpy(bKek,
        	  "\xA2\xC0\xB0\xF8\xF7\xF5\xEE\x21"
           	, 8);
	 
    	/* F431 623E 4997 89C8 C2F1 F725 AD7F 8949 */
    	memcpy(bMasterKey,
           	"\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4"
           	, 16);

	memcpy(bLeftCardFactor,  "\x25\x00\x00\x00\x00\x00\x89\x01" ,8);
	memcpy(bRightCardFactor,   "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" ,8); 
	SSMBinStrXOR(bRightCardFactor, bLeftCardFactor, bRightCardFactor, 8);
	memcpy(&bCardFactor[0], bLeftCardFactor, 8);
	memcpy(&bCardFactor[8], bRightCardFactor, 8);

	memcpy(bSubCardKey, 
		"\x89\xE9\x1F\xCB\x26\x6D\x7C\x51\xA4\x37\xAE\x51\x2F\x10\x52\x25"
		  ,16);	
	
	memcpy(bATC,  "\x00\x02", 2);
	memcpy(&bSessionSeed[6], bATC, 2);
	memset(&bSessionSeed[14], 0xFF, 2);
	SSMBinStrXOR(&bSessionSeed[14], bATC,  &bSessionSeed[14], 2);

    	/* 4FA1 BA64 DC85 58BF EC43 C210 F4FD 4610 */
	memcpy(bSubKeyExp,
           	"\x2C\x52\xE0\x25\xF9\x6B\xF0\x2F\x13\xF2\x52\x1E\xBF\x37\x73\x7F"
           	, 16);
	
    /* 04BC 620F 4E58 684D */
    memcpy(szCheckValueExp,
           "04BC620F"
           , 8);

    	XXX_INPUT_XXX
    	printf("[IN ]nSock          = %d\n", nSock);
    	printf("[IN ]nDivNum        = %d\n", nDivNum);
    	printf("[IN ]nIccType       = %d\n", nIccType);
    	printf("[IN ]nAlgo          = %d\n", nAlgo);
    	DspHex("[IN ]bKek           =", bKek, 8);
    	DspHex("[IN ]bMasterKey     =", bMasterKey, 16);
    	DspHex("[IN ]bCardFactor    =", bCardFactor, 8);
    	DspHex("[IN ]bSubCardKey	=", bSubCardKey, 16);
    	DspHex("[IN ]bATC =", bATC, 2);
    	DspHex("[IN ]bSessionSeed =", bSessionSeed, 16);
    	XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIDisreteSubKey(nSock, nDivNum, nIccType, nAlgo, bKek, \
                              bMasterKey, bCardFactor, bSessionSeed, \
                              bSubKey, szCheckValue);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "MASTER卡，单倍长KEK密钥，二次离散测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    ASSERT_OUT_HEX(bSubKey, bSubKeyExp, 16);
    ASSERT_OUT_HEX(szCheckValue, szCheckValueExp, 8);
    XXX_OUTPUT_XXX

	DspHex("[RESULT ]expected subkey	=", bSubKeyExp, 16);
	DspHex("[RESULT ]disreted subkey =", bSubKey, 16);
	DspHex("[RESULT ]expected checkvalue	=", szCheckValueExp, 8);
	DspHex("[RESULT]disreted checkvalue =", szCheckValue, 8);

    XXX_TEST_END_XXX
}

void DisreteSubKey_Test_25(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int nDivNum;
    int nIccType;
    int nAlgo;
    unsigned char  bKek[16];
    unsigned char  bMasterKey[32];
    unsigned char  bCardFactor[16];
    unsigned char  bSubCardKey[16];
    unsigned char  bATC[4];
    unsigned char  bLeftCardFactor[8];
    unsigned char bRightCardFactor[8];
    unsigned char bSessionSeed[16];
    unsigned char  bSubKey[32];
    unsigned char  szCheckValue[16];
    unsigned char  bSubKeyExp[32];
    unsigned char  szCheckValueExp[16];

    bufclr(bKek);
    bufclr(bMasterKey);
    bufclr(bCardFactor);
    bufclr(bLeftCardFactor);
    bufclr(bRightCardFactor);
    bufclr(bSubCardKey);
    bufclr(bATC);
    memset(bSessionSeed,0,16);
    bufclr(bSubKey);
    bufclr(szCheckValue);

    nDivNum = 2;
    nIccType = 0x00020014;
    nAlgo = 2;

    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(bKek,
        "\xA2\xC0\xB0\xF8\xF7\xF5\xEE\x21\xFB\x5C\x6A\xEB\xE7\x14\xE5\x3A"
         , 16);

    /* F431 623E 4997 89C8 C2F1 F725 AD7F 8949 */
    memcpy(bMasterKey,
           "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4"
           , 16);
               
//for test
/*
        memcpy(bMasterKey,
               "\x89\x23\x17\x1C\x70\xE5\x72\x92\x9B\xB6\x31\xE9\xC8\x05\xA3\xA0"
               , 16);
*/

    memcpy(bLeftCardFactor,  "\x25\x00\x00\x00\x00\x00\x89\x01" ,8);
    memcpy(bRightCardFactor,   "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" ,8); 
    SSMBinStrXOR(bRightCardFactor, bLeftCardFactor, bRightCardFactor, 8);
    memcpy(&bCardFactor[0], bLeftCardFactor, 8);
    memcpy(&bCardFactor[8], bRightCardFactor, 8);

    memcpy(bSubCardKey, 
        "\x89\xE9\x1F\xCB\x26\x6D\x7C\x51\xA4\x37\xAE\x51\x2F\x10\x52\x25"
          ,16);    
    
    memcpy(bATC,  "\x00\x02", 2);
    memcpy(&bSessionSeed[6], bATC, 2);
    memset(&bSessionSeed[14], 0xFF, 2);
    SSMBinStrXOR(&bSessionSeed[14], bATC,  &bSessionSeed[14], 2);

    /* 4FA1 BA64 DC85 58BF EC43 C210 F4FD 4610 */
    memcpy(bSubKeyExp,
               "\xAE\x75\x8D\x48\xCC\x51\x5A\x30\xE9\x5F\x0C\x2F\x62\x34\xD2\xF1"
               , 16);
    
    /* 04BC 620F 4E58 684D */
    memcpy(szCheckValueExp,
           "04BC620F"
           , 8);

    XXX_INPUT_XXX
    printf("[IN ]nSock          = %d\n", nSock);
    printf("[IN ]nDivNum        = %d\n", nDivNum);
    printf("[IN ]nIccType       = %d\n", nIccType);
    printf("[IN ]nAlgo          = %d\n", nAlgo);
    DspHex("[IN ]bKek           =", bKek, 16);
    DspHex("[IN ]bMasterKey     =", bMasterKey, 16);
    DspHex("[IN ]bCardFactor    =", bCardFactor, 16);
    DspHex("[IN ]bSubCardKey    =", bSubCardKey, 16);
    DspHex("[IN ]bATC =", bATC, 2);
    DspHex("[IN ]bSessionSeed =", bSessionSeed, 16);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIDisreteSubKey(nSock, nDivNum, nIccType, nAlgo, bKek, \
                              bMasterKey, bCardFactor, bSessionSeed, \
                              bSubKey, szCheckValue);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "MASTER卡，二倍长KEK密钥，二次离散测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    ASSERT_OUT_HEX(bSubKey, bSubKeyExp, 16);
    ASSERT_OUT_HEX(szCheckValue, szCheckValueExp, 8);
    XXX_OUTPUT_XXX

    DspHex("[RESULT ]expected subkey    =", bSubKeyExp, 16);
    DspHex("[RESULT ]disreted subkey =", bSubKey, 16);
    DspHex("[RESULT ]expected checkvalue    =", szCheckValueExp, 8);
    DspHex("[RESULT]disreted checkvalue =", szCheckValue, 8);

    XXX_TEST_END_XXX
}

void DisreteSubKey_Test_26(void)
{
   	XXX_TEST_START_XXX
    	int  nRet;
    	int  nSock = SM_SOCK;

	 int nDivNum;
	 int nIccType;
	 int nAlgo;
	 unsigned char  bKek[24];
	 unsigned char  bMasterKey[32];
	 unsigned char  bCardFactor[16];
	 unsigned char  bSubCardKey[16];
	 unsigned char  bATC[4];
	 unsigned char  bLeftCardFactor[8];
	 unsigned char bRightCardFactor[8];
	 unsigned char bSessionSeed[16];
	 unsigned char  bSubKey[32];
	 unsigned char  szCheckValue[16];
	 unsigned char  bSubKeyExp[32];
	 unsigned char  szCheckValueExp[16];

    	bufclr(bKek);
    	bufclr(bMasterKey);
    	bufclr(bCardFactor);
    	bufclr(bLeftCardFactor);
    	bufclr(bRightCardFactor);
    	bufclr(bSubCardKey);
    	bufclr(bATC);
    	memset(bSessionSeed,0,16);
    	bufclr(bSubKey);
    	bufclr(szCheckValue);

    	nDivNum = 2;
    	nIccType = 0x0002000E;
    	nAlgo = 2;

	/* 0123 4567 89AB CDEF FEDC BA98 7654 3210 8796 A5B4 C3D2 E1F0 */
	memcpy(bKek,
		"\xA2\xC0\xB0\xF8\xF7\xF5\xEE\x21\xFB\x5C\x6A\xEB\xE7\x14\xE5\x3A"
		 "\x59\x99\xC3\x06\xAB\x84\x01\xB2"
		, 24);
	 
    	/* F431 623E 4997 89C8 C2F1 F725 AD7F 8949 */
    	memcpy(bMasterKey,
           	"\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4"
           	, 16);

	memcpy(bLeftCardFactor,  "\x25\x00\x00\x00\x00\x00\x89\x01" ,8);
	memcpy(bRightCardFactor,   "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" ,8); 
	SSMBinStrXOR(bRightCardFactor, bLeftCardFactor, bRightCardFactor, 8);
	memcpy(&bCardFactor[0], bLeftCardFactor, 8);
	memcpy(&bCardFactor[8], bRightCardFactor, 8);

	memcpy(bSubCardKey, 
		"\x89\xE9\x1F\xCB\x26\x6D\x7C\x51\xA4\x37\xAE\x51\x2F\x10\x52\x25"
		  ,16);	
	
	memcpy(bATC,  "\x00\x02", 2);
	memcpy(&bSessionSeed[6], bATC, 2);
	memset(&bSessionSeed[14], 0xFF, 2);
	SSMBinStrXOR(&bSessionSeed[14], bATC,  &bSessionSeed[14], 2);

    	/* 4FA1 BA64 DC85 58BF EC43 C210 F4FD 4610 */
	memcpy(bSubKeyExp,
           	"\xAE\x75\x8D\x48\xCC\x51\x5A\x30\xE9\x5F\x0C\x2F\x62\x34\xD2\xF1"
           	, 16);
	
    /* 04BC 620F 4E58 684D */
    memcpy(szCheckValueExp,
           "04BC620F"
           , 8);

    	XXX_INPUT_XXX
    	printf("[IN ]nSock          = %d\n", nSock);
    	printf("[IN ]nDivNum        = %d\n", nDivNum);
    	printf("[IN ]nIccType       = %d\n", nIccType);
    	printf("[IN ]nAlgo          = %d\n", nAlgo);
    	DspHex("[IN ]bKek           =", bKek, 24);
    	DspHex("[IN ]bMasterKey     =", bMasterKey, 16);
    	DspHex("[IN ]bCardFactor    =", bCardFactor, 8);
    	DspHex("[IN ]bSubCardKey	=", bSubCardKey, 16);
    	DspHex("[IN ]bATC =", bATC, 2);
    	DspHex("[IN ]bSessionSeed =", bSessionSeed, 16);
    	XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIDisreteSubKey(nSock, nDivNum, nIccType, nAlgo, bKek, \
                              bMasterKey, bCardFactor, bSessionSeed, \
                              bSubKey, szCheckValue);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "MASTER卡，三倍长KEK密钥，二次离散测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    ASSERT_OUT_HEX(bSubKey, bSubKeyExp, 16);
    ASSERT_OUT_HEX(szCheckValue, szCheckValueExp, 8);
    XXX_OUTPUT_XXX

	DspHex("[RESULT ]expected subkey	=", bSubKeyExp, 16);
	DspHex("[RESULT ]disreted subkey =", bSubKey, 16);
	DspHex("[RESULT ]expected checkvalue	=", szCheckValueExp, 8);
	DspHex("[RESULT]disreted checkvalue =", szCheckValue, 8);

    XXX_TEST_END_XXX

}

void DisreteSubKey_Test_27(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int nDivNum;
	  int nIccType;
	  int nAlgo;
	  unsigned char  bKek[32];
	  unsigned char  bMasterKey[32];
	  unsigned char  bCardFactor[16];
	  unsigned char  bLeftCardFactor[8];
	  unsigned char bRightCardFactor[8];
	  unsigned char  bSessionFactor[4];
	  unsigned char  bSubKey[32];
	  unsigned char  szCheckValue[16];
	  unsigned char  bSubKeyExp[32];
	  unsigned char  szCheckValueExp[16];

    bufclr(bKek);
    bufclr(bMasterKey);
    bufclr(bCardFactor);
    bufclr(bLeftCardFactor);
    bufclr(bRightCardFactor);
    bufclr(bSessionFactor);
    bufclr(bSubKey);
    bufclr(szCheckValue);

    nDivNum = 1;
    nIccType = 0x00000401;
    nAlgo = 2;
    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(bKek,
           "\xA2\xC0\xB0\xF8\xF7\xF5\xEE\x21\xFB\x5C\x6A\xEB\xE7\x14\xE5\x3A"
           , 16);
    /* F431 623E 4997 89C8 C2F1 F725 AD7F 8949 */
    memcpy(bMasterKey,
           "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4"
           , 16);
    /* 2500 0000 0000 8901 DAFF FFFF FFFF 76FE */
    memcpy(bLeftCardFactor,  "\x25\x00\x00\x00\x00\x00\x89\x01" ,8);
    memcpy(bRightCardFactor,   "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF" ,8); 
    SSMBinStrXOR(bRightCardFactor, bLeftCardFactor, bRightCardFactor, 8);
    memcpy(&bCardFactor[0], bLeftCardFactor, 8);
    memcpy(&bCardFactor[8], bRightCardFactor, 8);

    /* EB53C9ADD78EAE205EDD9C3389D3D73D */
    /* F63C 212F 8CD8 E6CD 5F13 B30D 7D29 DB17 */
    memcpy(bSubKeyExp,
           "\xF6\x3C\x21\x2F\x8C\xD8\xE6\xCD" \
           "\x5F\x13\xB3\x0D\x7D\x29\xDB\x17" \
           , 16);
	
    /* A767 DEA1 9589 6AB9 */
    memcpy(szCheckValueExp,
           "A767DEA1"
           , 8);

    XXX_INPUT_XXX
    printf("[IN ]nSock          = %d\n", nSock);
    printf("[IN ]nDivNum        = %d\n", nDivNum);
    printf("[IN ]nIccType       = %x\n", nIccType);
    printf("[IN ]nAlgo          = %d\n", nAlgo);
    DspHex("[IN ]bKek           =", bKek, 16);
    DspHex("[IN ]bMasterKey     =", bMasterKey, 16);
    DspHex("[IN ]bCardFactor    =", bCardFactor, 16);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 2);	
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIDisreteSubKey(nSock, nDivNum, nIccType, nAlgo, bKek, \
                              bMasterKey, bCardFactor, bSessionFactor, \
                              bSubKey, szCheckValue);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "PBOC卡，二倍KEK，SM4, 一次离散测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    ASSERT_OUT_HEX(bSubKey, bSubKeyExp, 16);
    ASSERT_OUT_HEX(szCheckValue, szCheckValueExp, 8);
    XXX_OUTPUT_XXX

//    DspHex("[RESULT ]expected subkey	=", bSubKeyExp, 16);
//    DspHex("[RESULT ]disreted subkey =", bSubKey, 16);
//    DspHex("[RESULT ]expected checkvalue	=", szCheckValueExp, 8);
//    DspHex("[RESULT]disreted checkvalue =", szCheckValue, 8);

    XXX_TEST_END_XXX
}

void DisreteSubKey_Test_28(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int nDivNum;
	  int nIccType;
	  int nAlgo;
	  unsigned char  bKek[32];
	  unsigned char  bMasterKey[32];
	  unsigned char  bCardFactor[16];
	  unsigned char  bATC[4];
	  unsigned char  bSessionSeed[16];
	  unsigned char  bSubKey[16];
	  unsigned char  szCheckValue[16];
	  unsigned char  bSubKeyExp[32];
	  unsigned char  szCheckValueExp[16];

    bufclr(bKek);
    bufclr(bMasterKey);
    bufclr(bCardFactor);
    bufclr(bATC);
    memset(bSessionSeed,0,16);
    bufclr(bSubKey);
    bufclr(szCheckValue);

    nDivNum = 2;
    nIccType = 0x00000417;
    nAlgo = 2;
	
    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(bKek,
           "\xA2\xC0\xB0\xF8\xF7\xF5\xEE\x21\xFB\x5C\x6A\xEB\xE7\x14\xE5\x3A"
           , 16);
    /* F431 623E 4997 89C8 C2F1 F725 AD7F 8949 */
    memcpy(bMasterKey,
           "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4"
           , 16);
    memcpy(bCardFactor,
           "\x25\x00\x00\x00\x00\x00\x89\x01"
           , 8);	
    memset(&bCardFactor[8], 0xFF, 8);
    SSMBinStrXOR(&bCardFactor[8], &bCardFactor[8],  bCardFactor,  8);
   
    memcpy(bATC, "\x00\x02", 2);
    memcpy(&bSessionSeed[6], bATC, 2);
    memset(&bSessionSeed[14], 0xFF, 2);
    SSMBinStrXOR(&bSessionSeed[14], bATC, &bSessionSeed[14], 2);

    /* 669D80C23AED1147ACD33BB3E532B2B8 */
    /* 5EC5 A790 BCA9 451C 48B9 8254 C937 5DE4 */
    memcpy(bSubKeyExp,
           "\x5E\xC5\xA7\x90\xBC\xA9\x45\x1C" \
           "\x48\xB9\x82\x54\xC9\x37\x5D\xE4" \
           , 16);
	
    /* 142C C7AB 7F5B 20D2 */
    memcpy(szCheckValueExp,
           "142CC7AB"
           , 8);

    XXX_INPUT_XXX
    printf("[IN ]nSock          = %d\n", nSock);
    printf("[IN ]nDivNum        = %d\n", nDivNum);
    printf("[IN ]nIccType       = %x\n", nIccType);
    printf("[IN ]nAlgo          = %d\n", nAlgo);
    DspHex("[IN ]bKek           =", bKek, 16);
    DspHex("[IN ]bMasterKey     =", bMasterKey, 16);
    DspHex("[IN ]bCardFactor    =", bCardFactor, 16);
    DspHex("[IN ]bATC =", bATC, 2);
    DspHex("[IN ]bSessionSeed =", bSessionSeed, 16);
//    DspHex("[OUT] bSubKeyExp=", bSubKeyExp, 16);	
    XXX_INPUT_XXX
	
    /* Call Test Target Function Start */
    nRet = SMAPIDisreteSubKey(nSock, nDivNum, nIccType, nAlgo, bKek, \
                              bMasterKey, bCardFactor, bSessionSeed, \
                              bSubKey, szCheckValue);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "PBOC卡，二倍KEK，SM4, 二次离散脚本会话密钥未成功");
    XXX_RESULT_XXX
		
    XXX_OUTPUT_XXX
    ASSERT_OUT_HEX(bSubKey, bSubKeyExp, 16);
    ASSERT_OUT_HEX(szCheckValue, szCheckValueExp, 8);
    XXX_OUTPUT_XXX

//    DspHex("[RESULT ]expected subkey	=", bSubKeyExp, 16);
//    DspHex("[RESULT ]disreted subkey =", bSubKey, 16);
//    DspHex("[RESULT ]expected checkvalue	=", szCheckValueExp, 8);
//    DspHex("[RESULT]disreted checkvalue =", szCheckValue, 8);

    XXX_TEST_END_XXX
}

void GenBigPrime_Test_01(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nPrimeBit;
    BYTE bPrime[1024];

    bufclr(bPrime);

    nPrimeBit = 512;

    XXX_INPUT_XXX
    printf("[IN ]nSock     = %d\n", nSock);
    printf("[IN ]nPrimeBit = %d\n", nPrimeBit);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIGenBigPrime(nSock, nPrimeBit, bPrime);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "512位素数测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    DspHex("[OUT]bPrime    =", bPrime, 64);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void GenBigPrime_Test_02(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nPrimeBit;
    BYTE bPrime[1024];

    bufclr(bPrime);

    nPrimeBit = 1024;

    XXX_INPUT_XXX
    printf("[IN ]nSock     = %d\n", nSock);
    printf("[IN ]nPrimeBit = %d\n", nPrimeBit);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIGenBigPrime(nSock, nPrimeBit, bPrime);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "1024位素数测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    DspHex("[OUT]bPrime    =", bPrime, 128);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void GenBigPrime_Test_03(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nPrimeBit;
    BYTE bPrime[1024];

    bufclr(bPrime);

    nPrimeBit = 2048;

    XXX_INPUT_XXX
    printf("[IN ]nSock     = %d\n", nSock);
    printf("[IN ]nPrimeBit = %d\n", nPrimeBit);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIGenBigPrime(nSock, nPrimeBit, bPrime);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "2048位素数测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    DspHex("[OUT]bPrime    =", bPrime, 256);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void VerifyARQC_Test_01(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int  nIccType;
	  BYTE bKey[32];
	  BYTE bCardFactor[8];
	  BYTE bSessionFactor[2];
	  BYTE bData[64];
	  int  nDataLen;
	  BYTE bARQC[8];

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bData);
    bufclr(bARQC);

    nIccType = 0x00000000;
    memcpy(bKey,
           "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4"
           , 16);
    memcpy(bCardFactor,
           "\x25\x00\x00\x00\x00\x00\x89\x01"
           , 8);
    memcpy(bSessionFactor,
           "\x00\x02"
           , 2);
    memcpy(bData,
           "\x00\x00\x00\x01\x68\x00\x00\x00\x00\x00\x00\x00\x01\x56\x00\x00"
           "\x00\x80\x00\x01\x56\x07\x11\x09\x01\xDC\xCD\x7C\x16\x7D\x00\x00"
           "\x02\x03\xA0\x00\x02"
           , 37);
    nDataLen = 37;
    memcpy(bARQC, "\x8B\x6F\x6D\x8F\x49\x64\xA6\x09", 8);

    printf("[IN ]nSock     = %d\n", nSock);
    printf("[IN ]nIccType  = %d\n", nIccType);
    DspHex("[IN ]bKey      =", bKey, 16);
    DspHex("[IN ]bCardFactor =", bCardFactor, 8);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 2);
    DspHex("[IN ]bData     =", bData, 37);
    printf("[IN ]nDataLen  = %d\n", nDataLen);

    /* Call Test Target Function Start */
    nRet = SMAPIVerifyARQC(nSock, nIccType, bKey, bCardFactor, bSessionFactor, \
                    bData, nDataLen, bARQC);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "PBOC卡，Verify_ARQC测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void VerifyARQC_Test_02(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int  nIccType;
	  BYTE bKey[32];
	  BYTE bCardFactor[16];
	  BYTE bSessionFactor[16];
	  BYTE bData[64];
	  int  nDataLen;
	  BYTE bARQC[8];

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bData);
    bufclr(bARQC);

    nIccType = 0x0001000A;
	
    memcpy(bKey,
           "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4"
           , 16);
	
    memcpy(bCardFactor,
           "\x25\x00\x00\x00\x00\x00\x89\x01\xDA\xFF\xFF\xFF\xFF\xFF\x76\xFE"
           , 16);

    bufclr(bSessionFactor);
	
    memcpy(bData,
           "\x00\x00\x00\x01\x68\x00\x00\x00\x00\x00\x00\x00\x01\x56\x00\x00"
           "\x00\x80\x00\x01\x56\x07\x11\x09\x01\xDC\xCD\x7C\x16\x7D\x00\x00"
           "\x02\x03\xA0\x00\x02"
           , 37);
    nDataLen = 37;

    memcpy(bARQC, "\xAA\x51\xA6\x05\x74\xFF\x83\x02", 8);

    printf("[IN ]nSock     = %d\n", nSock);
    printf("[IN ]nIccType  = %x\n", nIccType);
    DspHex("[IN ]bKey      =", bKey, 16);
    DspHex("[IN ]bCardFactor =", bCardFactor, 16);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 16);
    DspHex("[IN ]bData     =", bData, 37);
    printf("[IN ]nDataLen  = %d\n", nDataLen);

    /* Call Test Target Function Start */
    nRet = SMAPIVerifyARQC(nSock, nIccType, bKey, bCardFactor, bSessionFactor, \
                    bData, nDataLen, bARQC);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "VISA卡，Verify_ARQC测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void VerifyARQC_Test_03(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nIccType;
    BYTE bKey[32];
    BYTE bCardFactor[16];
    BYTE bSessionFactor[16];
    BYTE bData[64];
    int  nDataLen;
    BYTE bARQC[8];

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bData);
    bufclr(bARQC);

    nIccType = 0X00020014;
    memcpy(bKey,
           "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4" 
           , 16);
        
    memcpy(bCardFactor,
           "\x25\x00\x00\x00\x00\x00\x89\x01\xDA\xFF\xFF\xFF\xFF\xFF\x76\xFE"
           , 16);
        
    memcpy(bSessionFactor,
           "\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\xFF\xFD"
           , 16);
        
    memcpy(bData,
           "\x00\x00\x00\x01\x20\x00\x00\x00" \
           "\x00\x00\x00\x00\x01\x56\x00\x08" \
           "\x04\xE8\x00\x01\x56\x30\x11\x25" \
           "\x00\xAC\xCE\x7A\xA4\x7C\x00\x00" \
           "\x0E\x03\xA0\xB8\x02"
               , 37);
    nDataLen = 37;
    memcpy(bARQC, "\x02\x87\x61\x1F\xA1\x13\xE6\xF7", 8);    

    printf("[IN ]nSock     = %d\n", nSock);
    printf("[IN ]nIccType  = %x\n", nIccType);
    DspHex("[IN ]bKey      =", bKey, 16);
    DspHex("[IN ]bCardFactor =", bCardFactor, 16);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 16);
    DspHex("[IN ]bData     =", bData, 37);
    printf("[IN ]nDataLen  = %d\n", nDataLen);

    /* Call Test Target Function Start */
    nRet = SMAPIVerifyARQC(nSock, nIccType, bKey, bCardFactor, bSessionFactor, \
                    bData, nDataLen, bARQC);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "MASTER卡，Verify_ARQC测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void VerifyARQC_Test_04(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int  nIccType;
	  BYTE bKey[32];
	  BYTE bCardFactor[16];
	  BYTE bSessionFactor[16];
	  BYTE bData[64];
	  int  nDataLen;
	  BYTE bARQC[8];

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bData);
    bufclr(bARQC);

    nIccType = 0x00000401;
    memcpy(bKey,
           "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4"
           , 16);
    memcpy(bCardFactor,
           "\x25\x00\x00\x00\x00\x00\x89\x01" \
           "\xDA\xFF\xFF\xFF\xFF\xFF\x76\xFE" \
           , 16);
    memcpy(bSessionFactor,
           "\x00\x00\x00\x00\x00\x00\x00\x02" \
           "\x00\x00\x00\x00\x00\x00\xFF\xFD" \
           , 16);
    /* 669D80C23AED1147ACD33BB3E532B2B8 */
    /* 00000001680000000000000001560000008000015607110901DCCD7C167D00000203A000028000000000000000000000 */
    memcpy(bData,
           "\x00\x00\x00\x01\x68\x00\x00\x00\x00\x00\x00\x00\x01\x56\x00\x00"
           "\x00\x80\x00\x01\x56\x07\x11\x09\x01\xDC\xCD\x7C\x16\x7D\x00\x00"
           "\x02\x03\xA0\x00\x02"
           , 37);
    nDataLen = 37;
    /* 378804CC872FCDAD3AAB71EA2BC9E71FAA1180963C126B78F2972305FC8AA919 205BD2A2A1E8E9C4 C9F0B06E8B3DCDDE */
    memcpy(bARQC, "\x20\x5B\xD2\xA2\xA1\xE8\xE9\xC4", 8);

    printf("[IN ]nSock     = %d\n", nSock);
    printf("[IN ]nIccType  = %d\n", nIccType);
    DspHex("[IN ]bKey      =", bKey, 16);
    DspHex("[IN ]bCardFactor =", bCardFactor, 8);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 2);
    DspHex("[IN ]bData     =", bData, 37);
    printf("[IN ]nDataLen  = %d\n", nDataLen);

    /* Call Test Target Function Start */
    nRet = SMAPIVerifyARQC(nSock, nIccType, bKey, bCardFactor, bSessionFactor, \
                    bData, nDataLen, bARQC);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "PBOC卡，SM4, Verify_ARQC测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void VerifyARQC_Test_05(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int  nIccType;
	  BYTE bKey[32];
	  BYTE bCardFactor[16];
	  BYTE bSessionFactor[16];
	  BYTE bData[64];
	  int  nDataLen;
	  BYTE bARQC[8];

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bData);
    bufclr(bARQC);

    nIccType = 0x00000417;
    memcpy(bKey,
           "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4"
           , 16);
    memcpy(bCardFactor,
           "\x25\x00\x00\x00\x00\x00\x89\x01" \
           "\xDA\xFF\xFF\xFF\xFF\xFF\x76\xFE" \
           , 16);
    memcpy(bSessionFactor,
           "\x00\x00\x00\x00\x00\x00\x00\x02" \
           "\x00\x00\x00\x00\x00\x00\xFF\xFD" \
           , 16);
    /* 669D80C23AED1147ACD33BB3E532B2B8 */
    /* 000000016800DCCD7C160002A0800000 */
    memcpy(bData,
           "\x00\x00\x00\x01\x68\x00\xDC\xCD" \
           "\x7C\x16\x00\x02\xA0" \
           , 13);
    nDataLen = 13;
    /* 69250B222FA12A75D25E1477BB48F1D8 */
    memcpy(bARQC, "\x69\x25\x0B\x22\x2F\xA1\x2A\x75", 8);

    printf("[IN ]nSock     = %d\n", nSock);
    printf("[IN ]nIccType  = %d\n", nIccType);
    DspHex("[IN ]bKey      =", bKey, 16);
    DspHex("[IN ]bCardFactor =", bCardFactor, 8);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 2);
    DspHex("[IN ]bData     =", bData, 37);
    printf("[IN ]nDataLen  = %d\n", nDataLen);

    /* Call Test Target Function Start */
    nRet = SMAPIVerifyARQC(nSock, nIccType, bKey, bCardFactor, bSessionFactor, \
                    bData, nDataLen, bARQC);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "PBOC卡，SM4, Verify_ARQC测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void VerifyARQC_Test_06(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int  nIccType;
	  BYTE bKey[32];
	  BYTE bCardFactor[8];
	  BYTE bSessionFactor[2];
	  BYTE bData[64];
	  int  nDataLen;
	  BYTE bARQC[8];

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bData);
    bufclr(bARQC);

    nIccType = 0x00000000;
    memcpy(bKey,
           "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4"
           , 16);
    memcpy(bCardFactor,
           "\x25\x00\x00\x00\x00\x00\x89\x01"
           , 8);
    memcpy(bSessionFactor,
           "\x00\x02"
           , 2);
    memcpy(bData,
           "\x00\x00\x00\x01\x68\x00\x00\x00\x00\x00\x00\x00\x01\x56\x00\x00"
           "\x00\x80\x00\x01\x56\x07\x11\x09\x01\xDC\xCD\x7C\x16\x7D\x00\x00"
           "\x02\x03\xA0\x00\x02"
           , 37);
    nDataLen = 37;
    memcpy(bARQC, "\x8B\x6F\x6D\x8F\x49\x64\xA6\x0A", 8);

    printf("[IN ]nSock     = %d\n", nSock);
    printf("[IN ]nIccType  = %d\n", nIccType);
    DspHex("[IN ]bKey      =", bKey, 16);
    DspHex("[IN ]bCardFactor =", bCardFactor, 8);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 2);
    DspHex("[IN ]bData     =", bData, 37);
    printf("[IN ]nDataLen  = %d\n", nDataLen);

    /* Call Test Target Function Start */
    nRet = SMAPIVerifyARQC(nSock, nIccType, bKey, bCardFactor, bSessionFactor, \
                    bData, nDataLen, bARQC);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 21, "PBOC卡，Verify_ARQC测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void VerifyARQC_Test_07(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int  nIccType;
	  BYTE bKey[32];
	  BYTE bCardFactor[16];
	  BYTE bSessionFactor[16];
	  BYTE bData[64];
	  int  nDataLen;
	  BYTE bARQC[8];

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bData);
    bufclr(bARQC);

    nIccType = 0x0001000A;
	
    memcpy(bKey,
           "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4"
           , 16);
	
    memcpy(bCardFactor,
           "\x25\x00\x00\x00\x00\x00\x89\x01\xDA\xFF\xFF\xFF\xFF\xFF\x76\xFE"
           , 16);
    //memcpy(bSessionFactor,
    //       "\x00\x02"
     //      , 2);

    bufclr(bSessionFactor);
	
    memcpy(bData,
           "\x00\x00\x00\x01\x68\x00\x00\x00\x00\x00\x00\x00\x01\x56\x00\x00"
           "\x00\x80\x00\x01\x56\x07\x11\x09\x01\xDC\xCD\x7C\x16\x7D\x00\x00"
           "\x02\x03\xA0\x00\x02"
           , 37);
    nDataLen = 37;
	
    memcpy(bARQC, "\xAA\x51\xA6\x05\x74\xFF\x83\x03", 8);

    printf("[IN ]nSock     = %d\n", nSock);
    printf("[IN ]nIccType  = %x\n", nIccType);
    DspHex("[IN ]bKey      =", bKey, 16);
    DspHex("[IN ]bCardFactor =", bCardFactor, 16);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 16);
    DspHex("[IN ]bData     =", bData, 37);
    printf("[IN ]nDataLen  = %d\n", nDataLen);

    /* Call Test Target Function Start */
    nRet = SMAPIVerifyARQC(nSock, nIccType, bKey, bCardFactor, bSessionFactor, \
                    bData, nDataLen, bARQC);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 21, "VISA卡，Verify_ARQC测试未成功（失败可）");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void VerifyARQC_Test_08(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nIccType;
    BYTE bKey[32];
    BYTE bCardFactor[16];
    BYTE bSessionFactor[16];
    BYTE bData[64];
    int  nDataLen;
    BYTE bARQC[8];

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bData);
    bufclr(bARQC);

    nIccType = 0X00020014;
    memcpy(bKey,
           "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4" 
           , 16);
        
    memcpy(bCardFactor,
           "\x25\x00\x00\x00\x00\x00\x89\x01\xDA\xFF\xFF\xFF\xFF\xFF\x76\xFE"
           , 16);
        
    memcpy(bSessionFactor,
           "\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\xFF\xFD"
           , 16);
        
    memcpy(bData,
           "\x00\x00\x00\x01\x20\x00\x00\x00" \
           "\x00\x00\x00\x00\x01\x56\x00\x08" \
           "\x04\xE8\x00\x01\x56\x30\x11\x25" \
           "\x00\xAC\xCE\x7A\xA4\x7C\x00\x00" \
           "\x0E\x03\xA0\xB8\x02"
               , 37);
    nDataLen = 37;
    memcpy(bARQC, "\x02\x87\x61\x1F\xA1\x13\xE6\xF8", 8);    

    printf("[IN ]nSock     = %d\n", nSock);
    printf("[IN ]nIccType  = %x\n", nIccType);
    DspHex("[IN ]bKey      =", bKey, 16);
    DspHex("[IN ]bCardFactor =", bCardFactor, 16);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 16);
    DspHex("[IN ]bData     =", bData, 37);
    printf("[IN ]nDataLen  = %d\n", nDataLen);

    /* Call Test Target Function Start */
    nRet = SMAPIVerifyARQC(nSock, nIccType, bKey, bCardFactor, bSessionFactor, \
                    bData, nDataLen, bARQC);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 21, "MASTER卡，Verify_ARQC测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void VerifyARQC_Test_09(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int  nIccType;
	  BYTE bKey[32];
	  BYTE bCardFactor[16];
	  BYTE bSessionFactor[16];
	  BYTE bData[64];
	  int  nDataLen;
	  BYTE bARQC[8];

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bData);
    bufclr(bARQC);

    nIccType = 0x00000401;
    memcpy(bKey,
           "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4"
           , 16);
    memcpy(bCardFactor,
           "\x25\x00\x00\x00\x00\x00\x89\x01" \
           "\xDA\xFF\xFF\xFF\xFF\xFF\x76\xFE" \
           , 16);
    memcpy(bSessionFactor,
           "\x00\x00\x00\x00\x00\x00\x00\x02" \
           "\x00\x00\x00\x00\x00\x00\xFF\xFD" \
           , 16);
    /* 669D80C23AED1147ACD33BB3E532B2B8 */
    /* 00000001680000000000000001560000008000015607110901DCCD7C167D00000203A000028000000000000000000000 */
    memcpy(bData,
           "\x00\x00\x00\x01\x68\x00\x00\x00\x00\x00\x00\x00\x01\x56\x00\x00"
           "\x00\x80\x00\x01\x56\x07\x11\x09\x01\xDC\xCD\x7C\x16\x7D\x00\x00"
           "\x02\x03\xA0\x00\x02"
           , 37);
    nDataLen = 37;
    /* 378804CC872FCDAD3AAB71EA2BC9E71FAA1180963C126B78F2972305FC8AA919 205BD2A2A1E8E9C4 C9F0B06E8B3DCDDE */
    memcpy(bARQC, "\x20\x5B\xD2\xA2\xA1\xE8\xE9\xC5", 8);

    printf("[IN ]nSock     = %d\n", nSock);
    printf("[IN ]nIccType  = %d\n", nIccType);
    DspHex("[IN ]bKey      =", bKey, 16);
    DspHex("[IN ]bCardFactor =", bCardFactor, 8);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 2);
    DspHex("[IN ]bData     =", bData, 37);
    printf("[IN ]nDataLen  = %d\n", nDataLen);

    /* Call Test Target Function Start */
    nRet = SMAPIVerifyARQC(nSock, nIccType, bKey, bCardFactor, bSessionFactor, \
                    bData, nDataLen, bARQC);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 21, "PBOC卡，SM4, Verify_ARQC测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void VerifyARQC_Test_10(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int  nIccType;
	  BYTE bKey[32];
	  BYTE bCardFactor[16];
	  BYTE bSessionFactor[16];
	  BYTE bData[64];
	  int  nDataLen;
	  BYTE bARQC[8];

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bData);
    bufclr(bARQC);

    nIccType = 0x00000417;
    memcpy(bKey,
           "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4"
           , 16);
    memcpy(bCardFactor,
           "\x25\x00\x00\x00\x00\x00\x89\x01" \
           "\xDA\xFF\xFF\xFF\xFF\xFF\x76\xFE" \
           , 16);
    memcpy(bSessionFactor,
           "\x00\x00\x00\x00\x00\x00\x00\x02" \
           "\x00\x00\x00\x00\x00\x00\xFF\xFD" \
           , 16);
    /* 669D80C23AED1147ACD33BB3E532B2B8 */
    /* 000000016800DCCD7C160002A0800000 */
    memcpy(bData,
           "\x00\x00\x00\x01\x68\x00\xDC\xCD" \
           "\x7C\x16\x00\x02\xA0" \
           , 13);
    nDataLen = 13;
    /* 69250B222FA12A75D25E1477BB48F1D8 */
    memcpy(bARQC, "\x69\x25\x0B\x22\x2F\xA1\x2A\x76", 8);

    printf("[IN ]nSock     = %d\n", nSock);
    printf("[IN ]nIccType  = %d\n", nIccType);
    DspHex("[IN ]bKey      =", bKey, 16);
    DspHex("[IN ]bCardFactor =", bCardFactor, 8);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 2);
    DspHex("[IN ]bData     =", bData, 37);
    printf("[IN ]nDataLen  = %d\n", nDataLen);

    /* Call Test Target Function Start */
    nRet = SMAPIVerifyARQC(nSock, nIccType, bKey, bCardFactor, bSessionFactor, \
                    bData, nDataLen, bARQC);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 21, "PBOC卡，SM4, Verify_ARQC测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void CalcARPC_Test_01(void)
{
   	 XXX_TEST_START_XXX
    	int  nRet;
    	int  nSock = SM_SOCK;

	  int  nIccType;
	  BYTE bKey[32];
	  BYTE bCardFactor[8];
	  BYTE bSessionFactor[8];
	  BYTE bARQC[8];
	  BYTE bARC[2];
	  BYTE bARPCFactorLeft[8];
	  BYTE bARPCFactorRight[8];
	  BYTE bARPC[8];
	  BYTE bARPCExp[8];

    	bufclr(bKey);
    	bufclr(bCardFactor);
    	bufclr(bSessionFactor);
    	bufclr(bARQC);
    	bufclr(bARC);
	bufclr(bARPCFactorLeft);
	bufclr(bARPCFactorRight);
    	bufclr(bARPC);
    	bufclr(bARPCExp);

    	nIccType = 0x00000000;

	memcpy(bKey,
           "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4"
           , 16);
	
    	memcpy(bCardFactor,
           	"\x25\x00\x00\x00\x00\x00\x89\x01"
           	, 8);
		
    	memcpy(bSessionFactor,  "\x00\x02", 2);

	memcpy(bARQC, "\x8B\x6F\x6D\x8F\x49\x64\xA6\x09", 8);
	memcpy(bARC, "\x30\x30", 2);    	
	memcpy(bARPCFactorLeft, "\x8B\x6F\x6D\x8F\x49\x64\xA6\x09", 8);
    	memcpy(bARPCFactorRight, "\x30\x30\x00\x00\x00\x00\x00\x00", 8);
	SSMBinStrXOR(bARPCFactorLeft, bARPCFactorLeft, bARPCFactorRight, 8);
	
    	memcpy(bARPCExp,  "\x09\x12\x44\x22\x2A\x16\x3D\xFA", 8);

    	printf("[IN ]nSock     = %d\n", nSock);
    	printf("[IN ]nIccType  = %x\n", nIccType);
    	DspHex("[IN ]bKey      =", bKey, 16);
    	DspHex("[IN ]bCardFactor =", bCardFactor, 8);
    	DspHex("[IN ]bSessionFactor =", bSessionFactor, 2);
    	DspHex("[IN ]bARPCFactorLeft     =", bARPCFactorLeft, 8);

    	/* Call Test Target Function Start */
    	nRet = SMAPICalcARPC(nSock, nIccType, bKey, bCardFactor, bSessionFactor, \
                  	bARQC, bARC, bARPC);
    	/* Call Test Target Function End */

    	XXX_RESULT_XXX
    	ASSERT_RESULT(nRet, 0, "PBOC卡，Calc_ARPC测试未成功");
   	 XXX_RESULT_XXX

    	XXX_OUTPUT_XXX
    	ASSERT_OUT_HEX(bARPC, bARPCExp, 8);
   	XXX_OUTPUT_XXX

	DspHex("[RESULT ]expected ARPC =", bARPCExp, 8);
	DspHex("[RESULT ]calculated ARPC  =", bARPC, 8);

    	XXX_TEST_END_XXX
}

void CalcARPC_Test_02(void)
{
    	XXX_TEST_START_XXX
    	int  nRet;
    	int  nSock = SM_SOCK;

	  int  nIccType;
	  BYTE bKey[32];
	  BYTE bCardFactor[16];
	  BYTE bSessionFactor[16];
	  BYTE bARQC[8];
	  BYTE bARC[2];
	  BYTE bARPCFactorLeft[8];
	  BYTE bARPCFactorRight[8];
	  BYTE bARPC[8];
	  BYTE bARPCExp[8];

    	bufclr(bKey);
    	bufclr(bCardFactor);
    	bufclr(bSessionFactor);
    	bufclr(bARQC);
    	bufclr(bARC);
	bufclr(bARPCFactorLeft);
	bufclr(bARPCFactorRight);
    	bufclr(bARPC);
    	bufclr(bARPCExp);

    	nIccType = 0x0001000A;
		
    	memcpy(bKey,
           	"\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4"
          	, 16);
	memcpy(bCardFactor,
		"\x25\x00\x00\x00\x00\x00\x89\x01\xDA\xFF\xFF\xFF\xFF\xFF\x76\xFE"
		, 16);

	memcpy(bARQC, "\x8B\x6F\x6D\x8F\x49\x64\xA6\x09", 8);
	memcpy(bARC, "\x30\x30", 2);    	
	memcpy(bARPCFactorLeft, "\x8B\x6F\x6D\x8F\x49\x64\xA6\x09", 8);
    	memcpy(bARPCFactorRight, "\x30\x30\x00\x00\x00\x00\x00\x00", 8);
	SSMBinStrXOR(bARPCFactorLeft, bARPCFactorLeft, bARPCFactorRight, 8);
	
    	memcpy(bARPCExp, "\xD3\x94\x9C\x71\x61\x17\x4A\x48", 8);

    	printf("[IN ]nSock     = %d\n", nSock);
    	printf("[IN ]nIccType  = %x\n", nIccType);
    	DspHex("[IN ]bKey      =", bKey, 16);
    	DspHex("[IN ]bCardFactor =", bCardFactor, 16);
    	DspHex("[IN ]bSessionFactor =", bSessionFactor, 16);
    	DspHex("[IN ]bARPCFactorLeft     =", bARPCFactorLeft, 8);

    	/* Call Test Target Function Start */
    	nRet = SMAPICalcARPC(nSock, nIccType, bKey, bCardFactor, bSessionFactor, \
                  	bARPCFactorLeft, bARC, bARPC);
    	/* Call Test Target Function End */

    	XXX_RESULT_XXX
    	ASSERT_RESULT(nRet, 0, "VISA卡，Calc_ARPC测试未成功");
    	XXX_RESULT_XXX

    	XXX_OUTPUT_XXX
    	ASSERT_OUT_HEX(bARPC, bARPCExp, 8);
    	XXX_OUTPUT_XXX

	DspHex("[RESULT ]expected ARPC =", bARPCExp, 8);
	DspHex("[RESULT ]calculated ARPC  =", bARPC, 8);

    	XXX_TEST_END_XXX
}

void CalcARPC_Test_03(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nIccType;
    BYTE bKey[32];
    BYTE bCardFactor[16];
    BYTE bSessionFactor[16];
    BYTE bARQC[8];
    BYTE bARC[2];
    BYTE bARPCFactorLeft[8];
    BYTE bARPCFactorRight[8];
    BYTE bARPC[8];
    BYTE bARPCExp[8];

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bARQC);
    bufclr(bARC);
    bufclr(bARPCFactorLeft);
    bufclr(bARPCFactorRight);
    bufclr(bARPC);
    bufclr(bARPCExp);

    nIccType = 0x00020014;
        
    memcpy(bKey,
           "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4"
          , 16);
    memcpy(bCardFactor,
        "\x25\x00\x00\x00\x00\x00\x89\x01\xDA\xFF\xFF\xFF\xFF\xFF\x76\xFE"
        , 16);
    memcpy(bSessionFactor,  
        "\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\xFF\xFD"
        , 16);
        
    memcpy(bARQC, "\x8B\x6F\x6D\x8F\x49\x64\xA6\x09", 8);
    memcpy(bARC, "\x30\x30", 2);        
    memcpy(bARPCFactorLeft, "\x8B\x6F\x6D\x8F\x49\x64\xA6\x09", 8);
    memcpy(bARPCFactorRight, "\x30\x30\x00\x00\x00\x00\x00\x00", 8);
    SSMBinStrXOR(bARPCFactorLeft, bARPCFactorLeft, bARPCFactorRight, 8);
    
    memcpy(bARPCExp, "\x09\x12\x44\x22\x2A\x16\x3D\xFA", 8);        

    printf("[IN ]nSock     = %d\n", nSock);
    printf("[IN ]nIccType  = %x\n", nIccType);
    DspHex("[IN ]bKey      =", bKey, 16);
    DspHex("[IN ]bCardFactor =", bCardFactor, 16);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 16);
    DspHex("[IN ]bARPCFactorLeft     =", bARPCFactorLeft, 8);

    /* Call Test Target Function Start */
    nRet = SMAPICalcARPC(nSock, nIccType, bKey, bCardFactor, bSessionFactor, \
                     bARPCFactorLeft, bARC, bARPC);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "MASTER卡，Calc_ARPC测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    ASSERT_OUT_HEX(bARPC, bARPCExp, 8);
    XXX_OUTPUT_XXX

    DspHex("[RESULT ]expected ARPC =", bARPCExp, 8);
    DspHex("[RESULT ]calculated ARPC  =", bARPC, 8);

    XXX_TEST_END_XXX
}

void CalcARPC_Test_04(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nIccType;
    BYTE bKey[32];
    BYTE bCardFactor[16];
    BYTE bSessionFactor[16];
    BYTE bARQC[8];
    BYTE bARC[2];
    BYTE bARPCFactor[16];
    BYTE bARPC[8];
    BYTE bARPCExp[8];

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bARQC);
    bufclr(bARC);
    bufclr(bARPCFactor);
    bufclr(bARPC);
    bufclr(bARPCExp);

    nIccType = 0x00000401;
    memcpy(bKey,
           "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4"
           , 16);
    memcpy(bCardFactor,
           "\x25\x00\x00\x00\x00\x00\x89\x01" \
           "\xDA\xFF\xFF\xFF\xFF\xFF\x76\xFE" \
           , 16);
    memcpy(bSessionFactor,
           "\x00\x00\x00\x00\x00\x00\x00\x02" \
           "\x00\x00\x00\x00\x00\x00\xFF\xFD" \
           , 16);
    memcpy(bARQC, "\x20\x5B\xD2\xA2\xA1\xE8\xE9\xC4", 8);
    
    /* 205BD2A2A1E8E9C4  XOR 3030000000000000 = 106BD2A2A1E8E9C4 */

    memcpy(bARPCFactor, "\x30\x30", 2);
    SSMBinStrXOR(bARPCFactor, bARPCFactor, bARQC, 8);

    /* 669D80C23AED1147ACD33BB3E532B2B8 */
    /* 106BD2A2A1E8E9C40000000000000000 */
    /* ABB623C745BB6BE19CE389255C7D5FF2 */
    memcpy(bARPCExp, "\xAB\xB6\x23\xC7\x45\xBB\x6B\xE1", 8);

    printf("[IN ]nSock     = %d\n", nSock);
    printf("[IN ]nIccType  = %x\n", nIccType);
    DspHex("[IN ]bKey      =", bKey, 16);
    DspHex("[IN ]bCardFactor =", bCardFactor, 16);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 16);
    DspHex("[IN ]bARPCFactor =", bARPCFactor, 16);

    /* Call Test Target Function Start */
    nRet = SMAPICalcARPC(nSock, nIccType, bKey, bCardFactor, bSessionFactor, \
                      bARPCFactor, bARC, bARPC);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "PBOC卡，SM4, Calc_ARPC测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    ASSERT_OUT_HEX(bARPC, bARPCExp, 8);
    XXX_OUTPUT_XXX

//    DspHex("[RESULT ]expected ARPC =", bARPCExp, 8);
//    DspHex("[RESULT ]calculated ARPC  =", bARPC, 8);

    XXX_TEST_END_XXX
}

void CalcARPC_Test_05(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nIccType;
    BYTE bKey[32];
    BYTE bCardFactor[16];
    BYTE bSessionFactor[16];
    BYTE bARQC[8];
    BYTE bARC[2];
    BYTE bARPCFactor[16];
    BYTE bARPC[8];
    BYTE bARPCExp[8];

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bARQC);
    bufclr(bARC);
    bufclr(bARPCFactor);
    bufclr(bARPC);
    bufclr(bARPCExp);

    nIccType = 0x00000417;
    memcpy(bKey,
           "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4"
           , 16);
    memcpy(bCardFactor,
           "\x25\x00\x00\x00\x00\x00\x89\x01" \
           "\xDA\xFF\xFF\xFF\xFF\xFF\x76\xFE" \
           , 16);
    memcpy(bSessionFactor,
           "\x00\x00\x00\x00\x00\x00\x00\x02" \
           "\x00\x00\x00\x00\x00\x00\xFF\xFD" \
           , 16);
    memcpy(bARQC, "\x20\x5B\xD2\xA2\xA1\xE8\xE9\xC4", 8);
    
    /* 205BD2A2A1E8E9C4  XOR 3030000000000000 = 106BD2A2A1E8E9C4 */

    memcpy(bARPCFactor, "\x30\x30", 2);
    SSMBinStrXOR(bARPCFactor, bARPCFactor, bARQC, 8);

    /* 669D80C23AED1147ACD33BB3E532B2B8 */
    /* 106BD2A2A1E8E9C40000000000000000 */
    /* ABB623C745BB6BE19CE389255C7D5FF2 */
    memcpy(bARPCExp, "\xAB\xB6\x23\xC7\x45\xBB\x6B\xE1", 8);

    printf("[IN ]nSock     = %d\n", nSock);
    printf("[IN ]nIccType  = %x\n", nIccType);
    DspHex("[IN ]bKey      =", bKey, 16);
    DspHex("[IN ]bCardFactor =", bCardFactor, 16);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 16);
    DspHex("[IN ]bARPCFactor =", bARPCFactor, 16);

    /* Call Test Target Function Start */
    nRet = SMAPICalcARPC(nSock, nIccType, bKey, bCardFactor, bSessionFactor, \
                      bARPCFactor, bARC, bARPC);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "PBOC卡，SM4, Calc_ARPC测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    ASSERT_OUT_HEX(bARPC, bARPCExp, 8);
    XXX_OUTPUT_XXX

//    DspHex("[RESULT ]expected ARPC =", bARPCExp, 8);
//    DspHex("[RESULT ]calculated ARPC  =", bARPC, 8);

    XXX_TEST_END_XXX
}

void EncryptWithDerivedKey_Test_01(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nType;
    int  nIccType;
    int  nMode;
    BYTE bKey[32];
    BYTE bCardFactor[8];
    BYTE bSessionFactor[8];
    BYTE bIV[8];
    BYTE bInData[256];
    int  nInLen = 0;
    BYTE bOutData[256];
    int  nOutLen = 0;
    BYTE bOutDataExp[256];
    int  nOutLenExp;

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bIV);
    bufclr(bInData);
    bufclr(bOutData);
    bufclr(bOutDataExp);

    nType = 1;
    nIccType = 0x00000000;
    nMode = 0;
        
    memcpy(bKey, "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4", 16);
    memcpy(bCardFactor, "\x25\x00\x00\x00\x00\x00\x89\x01", 8);
    memcpy(bSessionFactor, "\x00\x02", 2);
    memcpy(bInData, "\x04\x12\x34\xFF\x37\x1C\xF2\xA4", 8);
    nInLen = 8;
    memcpy(bOutDataExp, "\x0F\x3D\x99\xC3\xD5\xBB\x85\x8A\xF5\x50\x1C\xDA\x91\x41\xB8\x76", 16);
    nOutLenExp = 16;
    
    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]nIccType  = %x\n", nIccType);
    DspHex("[IN ]bKey      =", bKey, 16);
    DspHex("[IN ]bCardFactor =", bCardFactor, 16);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 16);
    DspHex("[IN ]bInData     =", bInData, nInLen);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIEncryptWithDerivedKey(nSock, nType, nIccType, nMode, bKey, bCardFactor,
                               bSessionFactor, bIV, bInData, nInLen, bOutData, &nOutLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "PBOC卡，ECB加密，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    DspHex("[OUT]bOutData =", bOutData, 16);
    printf("[OUT]nOutLen  = %d\n", nOutLen);
    ASSERT_OUT_HEX(bOutData, bOutDataExp, nOutLenExp);
    ASSERT_OUT(nOutLen, nOutLenExp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void EncryptWithDerivedKey_Test_02(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nType;
    int  nIccType;
    int  nMode;
    BYTE bKey[32];
    BYTE bCardFactor[8];
    BYTE bSessionFactor[8];
    BYTE bIV[8];
    BYTE bInData[256];
    int  nInLen;
    BYTE bOutData[256];
    int  nOutLen;
    BYTE bOutDataExp[256];
    int  nOutLenExp;

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bIV);
    bufclr(bInData);
    bufclr(bOutData);
    bufclr(bOutDataExp);

    nType = 0;
    nIccType = 0x00000000;
    nMode = 0;
        
    memcpy(bKey, "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4", 16);
    memcpy(bCardFactor, "\x25\x00\x00\x00\x00\x00\x89\x01", 8);
    memcpy(bSessionFactor, "\x00\x02", 2);
    memcpy(bInData, "\x0F\x3D\x99\xC3\xD5\xBB\x85\x8A\xF5\x50\x1C\xDA\x91\x41\xB8\x76", 16);
    nInLen = 16;
    memcpy(bOutDataExp, "\x04\x12\x34\xFF\x37\x1C\xF2\xA4", 8); 
    nOutLenExp = 8;   
    
    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]nIccType  = %x\n", nIccType);
    DspHex("[IN ]bKey      =", bKey, 16);
    DspHex("[IN ]bCardFactor =", bCardFactor, 16);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 16);
    DspHex("[IN ]bInData     =", bInData, nInLen);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIEncryptWithDerivedKey(nSock, nType, nIccType, nMode, bKey, bCardFactor,
                               bSessionFactor, bIV, bInData, nInLen, bOutData, &nOutLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "PBOC卡，ECB解密，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    DspHex("[OUT]bOutData =", bOutData, 8);
    printf("[OUT]nOutLen  = %d\n", nOutLen);
    ASSERT_OUT_HEX(bOutData, bOutDataExp, nOutLenExp);
    ASSERT_OUT(nOutLen, nOutLenExp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void EncryptWithDerivedKey_Test_03(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nType;
    int  nIccType;
    int  nMode;
    BYTE bKey[32];
    BYTE bCardFactor[16];
    BYTE bSessionFactor[16];
    BYTE bIV[8];
    BYTE bInData[256];
    int  nInLen;
    BYTE bOutData[256];
    int  nOutLen;
    BYTE bOutDataExp[256];
    int  nOutLenExp;

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bIV);
    bufclr(bInData);
    bufclr(bOutData);
    bufclr(bOutDataExp);

    nType = 1;
    nIccType = 0x0001000A;
    nMode = 0;

    memcpy(bKey, 
        "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4", 
        16);
    memcpy(bCardFactor, \
        "\x25\x00\x00\x00\x00\x00\x89\x01\xDA\xFF\xFF\xFF\xFF\xFF\x76\xFE", 
        16);        
    memcpy(bSessionFactor, \
        "\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\xFF\xFD", 
        16);        
    memcpy(bInData, "\x04\x12\x34\xFF\x37\x1C\xF2\xA4", 8);        
        nInLen = 8;
    memcpy(bOutDataExp,"\x94\x85\xC1\x25\xFF\xA7\x9C\x3E\x68\x55\x0E\xB2\x4C\xF6\x91\x4E", 16);
    nOutLenExp = 16;

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]nIccType  = %x\n", nIccType);
    DspHex("[IN ]bKey       =", bKey, 16);
    DspHex("[IN ]bCardFactor =", bCardFactor, 16);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 16);
    DspHex("[IN ]bInData     =", bInData, nInLen);
    DspHex("[IN ]bIV     =", bIV, 8);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIEncryptWithDerivedKey(nSock, nType, nIccType, nMode, bKey, bCardFactor,
                               bSessionFactor, bIV, bInData, nInLen, bOutData, &nOutLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "VISA卡，ECB加密，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    DspHex("[OUT]bOutData =", bOutData, 16);
    printf("[OUT]nOutLen  = %d\n", nOutLen);
    ASSERT_OUT_HEX(bOutData, bOutDataExp, nOutLenExp);
    ASSERT_OUT(nOutLen, nOutLenExp);
    XXX_OUTPUT_XXX
            
    XXX_TEST_END_XXX
}

void EncryptWithDerivedKey_Test_04(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nType;
    int  nIccType;
    int  nMode;
    BYTE bKey[32];
    BYTE bCardFactor[16];
    BYTE bSessionFactor[16];
    BYTE bIV[8];
    BYTE bInData[256];
    int  nInLen;
    BYTE bOutData[256];
    int  nOutLen;
    BYTE bOutDataExp[256];
    int  nOutLenExp;

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bIV);
    bufclr(bInData);
    bufclr(bOutData);
    bufclr(bOutDataExp);

    nType = 0;
    nIccType = 0x0001000A;
    nMode = 0;

    memcpy(bKey, 
        "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4", 
        16);
    memcpy(bCardFactor, \
        "\x25\x00\x00\x00\x00\x00\x89\x01\xDA\xFF\xFF\xFF\xFF\xFF\x76\xFE", 
        16);        
    memcpy(bSessionFactor, \
        "\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\xFF\xFD", 
        16);        
    memcpy(bInData, "\x94\x85\xC1\x25\xFF\xA7\x9C\x3E\x68\x55\x0E\xB2\x4C\xF6\x91\x4E", 16);        
    nInLen = 16;
    memcpy(bOutDataExp,"\x04\x12\x34\xFF\x37\x1C\xF2\xA4",8);
    nOutLenExp = 8;

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]nIccType  = %x\n", nIccType);
    DspHex("[IN ]bKey       =", bKey, 16);
    DspHex("[IN ]bCardFactor =", bCardFactor, 16);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 16);
    DspHex("[IN ]bInData     =", bInData, nInLen);
    DspHex("[IN ]bIV     =", bIV, 8);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIEncryptWithDerivedKey(nSock, nType, nIccType, nMode, bKey, bCardFactor,
                               bSessionFactor, bIV, bInData, nInLen, bOutData, &nOutLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "VISA卡，ECB解密，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    DspHex("[OUT]bOutData =", bOutData, 8);
    printf("[OUT]nOutLen  = %d\n", nOutLen);
    ASSERT_OUT_HEX(bOutData, bOutDataExp, nOutLenExp);
    ASSERT_OUT(nOutLen, nOutLenExp);
    XXX_OUTPUT_XXX
            
    XXX_TEST_END_XXX
}

void EncryptWithDerivedKey_Test_05(void)
{
   	XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int  nType;
	  int  nIccType;
	  int  nMode;
	  BYTE bKey[32];
	  BYTE bCardFactor[8];
	  BYTE bSessionFactor[8];
	  BYTE bIV[8];
	  BYTE bInData[256];
	  int  nInLen;
	  BYTE bOutData[256];
	  int  nOutLen;
	  BYTE bOutDataExp[256];
    int  nOutLenExp;

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bIV);
    bufclr(bInData);
    bufclr(bOutData);
    bufclr(bOutDataExp);

    nType = 1;
    nIccType = 0x00000000;
    nMode = 1;
    
    /* Key = F431623E499789C8C2F1F725AD7F8949 */
    /* CF = 2500000000008901DAFFFFFFFFFF76FE */
    /* SF = 0000000000000002000000000000FFFD */
    /* Data = 08 041234FF371CF2A4 80000000000000 */
    /* Key1 = 89E8 1ECA 276C 7D50 A537 AE51 2E11 5224 */
    /* Key2 = 4FA1 BB65 DC84 58BF ED43 C210 F4FD 4711 */
    /* Out = 0F3D 99C3 D5BB 858A C6BE B65E 97E6 1C7C */

    memcpy(bKey, "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4", 16);
    memcpy(bCardFactor, "\x25\x00\x00\x00\x00\x00\x89\x01", 8);
    memcpy(bSessionFactor, "\x00\x02", 2);
    memcpy(bInData, "\x04\x12\x34\xFF\x37\x1C\xF2\xA4", 8);
    nInLen = 8;
    memcpy(bOutDataExp, "\x0F\x3D\x99\xC3\xD5\xBB\x85\x8A\xC6\xBE\xB6\x5E\x97\xE6\x1C\x7C", 16);
    nOutLenExp = 16;

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]nIccType  = %x\n", nIccType);
    DspHex("[IN ]bKey      =", bKey, 16);
    DspHex("[IN ]bCardFactor =", bCardFactor, 16);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 16);
    DspHex("[IN ]bIV =", bIV, 8);
    DspHex("[IN ]bInData     =", bInData, nInLen);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIEncryptWithDerivedKey(nSock, nType, nIccType, nMode, bKey, bCardFactor,
                              bSessionFactor, bIV, bInData, nInLen, bOutData, &nOutLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "PBOC卡，CBC加密，初始向量0x00，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    DspHex("[OUT]bOutData =", bOutData, 8);
    printf("[OUT]nOutLen  = %d\n", nOutLen);
    ASSERT_OUT_HEX(bOutData, bOutDataExp, nOutLenExp);
    ASSERT_OUT(nOutLen, nOutLenExp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void EncryptWithDerivedKey_Test_06(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int  nType;
	  int  nIccType;
	  int  nMode;
	  BYTE bKey[32];
	  BYTE bCardFactor[8];
	  BYTE bSessionFactor[8];
	  BYTE bIV[8];
	  BYTE bInData[256];
	  int  nInLen;
	  BYTE bOutData[256];
	  int  nOutLen;
	  BYTE bOutDataExp[8];
    int  nOutLenExp;

    /* Key = F431623E499789C8C2F1F725AD7F8949 */
    /* CF = 2500000000008901DAFFFFFFFFFF76FE */
    /* SF = 0000000000000002000000000000FFFD */
    /* Data = 08 041234FF371CF2A4 80000000000000 */
    /* Key1 = 89E8 1ECA 276C 7D50 A537 AE51 2E11 5224 */
    /* Key2 = 4FA1 BB65 DC84 58BF ED43 C210 F4FD 4711 */
    /* Out = 0F3D 99C3 D5BB 858A C6BE B65E 97E6 1C7C */

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bIV);
    bufclr(bInData);
    bufclr(bOutData);
    bufclr(bOutDataExp);

    nType = 0;
    nIccType = 0x00000000;
    nMode = 1;
		
    memcpy(bKey, "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4", 16);
    memcpy(bCardFactor, "\x25\x00\x00\x00\x00\x00\x89\x01", 8);
    memcpy(bSessionFactor, "\x00\x02", 2);
    memcpy(bInData, "\x0F\x3D\x99\xC3\xD5\xBB\x85\x8A\xC6\xBE\xB6\x5E\x97\xE6\x1C\x7C", 16);
    nInLen = 16;
    memcpy(bOutDataExp, "\x04\x12\x34\xFF\x37\x1C\xF2\xA4", 8);
    nOutLenExp = 8;
	
    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]nIccType  = %x\n", nIccType);
    DspHex("[IN ]bKey      =", bKey, 16);
    DspHex("[IN ]bCardFactor =", bCardFactor, 16);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 16);
    DspHex("[IN ]bInData     =", bInData, nInLen);
    DspHex("[IN ]bIV     =", bIV, 8);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIEncryptWithDerivedKey(nSock, nType, nIccType, nMode, bKey, bCardFactor,
                              bSessionFactor, bIV, bInData, nInLen, bOutData, &nOutLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "PBOC卡，CBC解密，初始向量0x00，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    DspHex("[OUT]bOutData =", bOutData, 8);
    printf("[OUT]nOutLen  = %d\n", nOutLen);
    ASSERT_OUT_HEX(bOutData, bOutDataExp, nOutLenExp);
    ASSERT_OUT(nOutLen, nOutLenExp);
    XXX_OUTPUT_XXX

   	XXX_TEST_END_XXX   
}

void EncryptWithDerivedKey_Test_07(void)
{
   	XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int  nType;
	  int  nIccType;
	  int  nMode;
	  BYTE bKey[32];
	  BYTE bCardFactor[8];
	  BYTE bSessionFactor[8];
	  BYTE bIV[8];
	  BYTE bInData[256];
	  int  nInLen;
	  BYTE bOutData[256];
	  int  nOutLen;
	  BYTE bOutDataExp[16];
    int  nOutLenExp;

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bIV);
    bufclr(bInData);
    bufclr(bOutData);
	  bufclr(bOutDataExp);

    /* Key = F431623E499789C8C2F1F725AD7F8949 */
    /* CF = 2500000000008901DAFFFFFFFFFF76FE */
    /* SF = 0000000000000002000000000000FFFD */
    /* Data = 08 041234FF371CF2A4 80000000000000 */
    /* Key1 = 89E8 1ECA 276C 7D50 A537 AE51 2E11 5224 */
    /* Key2 = 4FA1 BB65 DC84 58BF ED43 C210 F4FD 4711 */
    /* IV = 0102030405060708 */
    /* Out = 010B C82E DC01 6755 717B 9EDA C1B3 994C */

    nType = 1;
    nIccType = 0x00000000;
    nMode = 1;
		
    memcpy(bKey, "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4", 16);
    memcpy(bCardFactor, "\x25\x00\x00\x00\x00\x00\x89\x01", 8);
    memcpy(bSessionFactor, "\x00\x02", 2);
    memcpy(bInData, "\x04\x12\x34\xFF\x37\x1C\xF2\xA4", 8);
    nInLen = 8;
    memcpy(bIV, "\x01\x02\x03\x04\x05\x06\x07\x08", 8);
    memcpy(bOutDataExp, "\x01\x0B\xC8\x2E\xDC\x01\x67\x55\x71\x7B\x9E\xDA\xC1\xB3\x99\x4C", 16);
    nOutLenExp = 16;
	
    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]nIccType  = %x\n", nIccType);
    DspHex("[IN ]bKey      =", bKey, 16);
    DspHex("[IN ]bCardFactor =", bCardFactor, 16);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 16);
    DspHex("[IN ]bIV =", bIV, 8);
    DspHex("[IN ]bInData     =", bInData, nInLen);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIEncryptWithDerivedKey(nSock, nType, nIccType, nMode, bKey, bCardFactor,
                              bSessionFactor, bIV, bInData, nInLen, bOutData, &nOutLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "PBOC卡，CBC加密，初始向量0x0n，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    DspHex("[OUT]bOutData =", bOutData, 8);
    printf("[OUT]nOutLen  = %d\n", nOutLen);
    ASSERT_OUT_HEX(bOutData, bOutDataExp, nOutLenExp);
    ASSERT_OUT(nOutLen, nOutLenExp);
    XXX_OUTPUT_XXX
			
    XXX_TEST_END_XXX
}

void EncryptWithDerivedKey_Test_08(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int  nType;
	  int  nIccType;
	  int  nMode;
	  BYTE bKey[32];
	  BYTE bCardFactor[8];
	  BYTE bSessionFactor[8];
	  BYTE bIV[8];
	  BYTE bInData[256];
	  int  nInLen;
	  BYTE bOutData[256];
	  int  nOutLen;
	  BYTE bOutDataExp[8];
    int  nOutLenExp;

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bIV);
    bufclr(bInData);
    bufclr(bOutData);
    bufclr(bOutDataExp);

    /* Key = F431623E499789C8C2F1F725AD7F8949 */
    /* CF = 2500000000008901DAFFFFFFFFFF76FE */
    /* SF = 0000000000000002000000000000FFFD */
    /* Data = 08 041234FF371CF2A4 80000000000000 */
    /* Key1 = 89E8 1ECA 276C 7D50 A537 AE51 2E11 5224 */
    /* Key2 = 4FA1 BB65 DC84 58BF ED43 C210 F4FD 4711 */
    /* IV = 0102030405060708 */
    /* Out = 010B C82E DC01 6755 717B 9EDA C1B3 994C */

    nType = 0;
    nIccType = 0x00000000;
    nMode = 1;
		
    memcpy(bKey, "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4", 16);
    memcpy(bCardFactor, "\x25\x00\x00\x00\x00\x00\x89\x01", 8);
    memcpy(bSessionFactor, "\x00\x02", 2);
    memcpy(bInData, "\x01\x0B\xC8\x2E\xDC\x01\x67\x55\x71\x7B\x9E\xDA\xC1\xB3\x99\x4C", 16);
    nInLen = 16;
    memcpy(bIV, "\x01\x02\x03\x04\x05\x06\x07\x08", 8);
    memcpy(bOutDataExp, "\x04\x12\x34\xFF\x37\x1C\xF2\xA4", 8);
    nOutLenExp = 8;	
	
    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]nIccType  = %x\n", nIccType);
    DspHex("[IN ]bKey      =", bKey, 16);
    DspHex("[IN ]bCardFactor =", bCardFactor, 16);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 16);
    DspHex("[IN ]bIV =", bIV, 8);
    DspHex("[IN ]bInData     =", bInData, nInLen);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIEncryptWithDerivedKey(nSock, nType, nIccType, nMode, bKey, bCardFactor,
                              bSessionFactor, bIV, bInData, nInLen, bOutData, &nOutLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "PBOC卡，CBC解密，初始向量0x0n，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    DspHex("[OUT]bOutData =", bOutData, 8);
    printf("[OUT]nOutLen  = %d\n", nOutLen);
    ASSERT_OUT_HEX(bOutData, bOutDataExp, nOutLenExp);
    ASSERT_OUT(nOutLen, nOutLenExp);
    XXX_OUTPUT_XXX
	
   	XXX_TEST_END_XXX
}

void EncryptWithDerivedKey_Test_09(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int  nType;
	  int  nIccType;
	  int  nMode;
	  BYTE bKey[32];
	  BYTE bCardFactor[8];
	  BYTE bSessionFactor[8];
	  BYTE bIV[8];
	  BYTE bInData[256];
	  int  nInLen;
	  BYTE bOutData[256];
	  int  nOutLen;

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bIV);
    bufclr(bInData);
    bufclr(bOutData);

    nSock = -1;
    nType = 1;
    nIccType = 0;
    nMode = 0;
    memcpy(bKey, "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4", 16);
    memcpy(bCardFactor, "\x25\x00\x00\x00\x00\x00\x89\x01", 8);
    memcpy(bSessionFactor, "\x00\x02", 2);
    memcpy(bInData, "\x04\x12\x34\xFF\x37\x1C\xF2\xA4", 8);
    nInLen = 8;

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIEncryptWithDerivedKey(nSock, nType, nIccType, nMode, bKey, bCardFactor,
                               bSessionFactor, bIV, bInData, nInLen, bOutData, &nOutLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 1, "无效Socket ID[-1]测试未失败");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    nSock = SM_SOCK;

    XXX_TEST_END_XXX
}

void EncryptWithDerivedKey_Test_10(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int  nType;
	  int  nIccType;
	  int  nMode;
	  BYTE bKey[32];
	  BYTE bCardFactor[8];
	  BYTE bSessionFactor[8];
	  BYTE bIV[8];
	  BYTE bInData[256];
	  int  nInLen;
	  BYTE bOutData[256];
	  int  nOutLen;

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bIV);
    bufclr(bInData);
    bufclr(bOutData);

    nSock = 8;
    nType = 1;
    nIccType = 0;
    nMode = 0;
    memcpy(bKey, "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4", 16);
    memcpy(bCardFactor, "\x25\x00\x00\x00\x00\x00\x89\x01", 8);
    memcpy(bSessionFactor, "\x00\x02", 2);
    memcpy(bInData, "\x04\x12\x34\xFF\x37\x1C\xF2\xA4", 8);
    nInLen = 8;

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIEncryptWithDerivedKey(nSock, nType, nIccType, nMode, bKey, bCardFactor,
                               bSessionFactor, bIV, bInData, nInLen, bOutData, &nOutLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 1, "无效Socket ID[8]测试未失败");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    nSock = SM_SOCK;

    XXX_TEST_END_XXX
}

void EncryptWithDerivedKey_Test_11(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int  nType;
	  int  nIccType;
	  int  nMode;
	  BYTE bKey[32];
	  BYTE bCardFactor[8];
	  BYTE bSessionFactor[8];
	  BYTE bIV[8];
	  BYTE bInData[256];
	  int  nInLen;
	  BYTE bOutData[256];
	  int  nOutLen;

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bIV);
    bufclr(bInData);
    bufclr(bOutData);

    nType = -1;
    nIccType = 0;
    nMode = 0;
    memcpy(bKey, "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4", 16);
    memcpy(bCardFactor, "\x25\x00\x00\x00\x00\x00\x89\x01", 8);
    memcpy(bSessionFactor, "\x00\x02", 2);
    memcpy(bInData, "\x04\x12\x34\xFF\x37\x1C\xF2\xA4", 8);
    nInLen = 8;

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIEncryptWithDerivedKey(nSock, nType, nIccType, nMode, bKey, bCardFactor,
                               bSessionFactor, bIV, bInData, nInLen, bOutData, &nOutLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 1, "无效加解密标志[-1]测试未失败");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void EncryptWithDerivedKey_Test_12(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int  nType;
	  int  nIccType;
	  int  nMode;
	  BYTE bKey[32];
	  BYTE bCardFactor[8];
	  BYTE bSessionFactor[8];
	  BYTE bIV[8];
	  BYTE bInData[256];
	  int  nInLen;
	  BYTE bOutData[256];
	  int  nOutLen;

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bIV);
    bufclr(bInData);
    bufclr(bOutData);

    nType = 2;
    nIccType = 0;
    nMode = 0;
    memcpy(bKey, "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4", 16);
    memcpy(bCardFactor, "\x25\x00\x00\x00\x00\x00\x89\x01", 8);
    memcpy(bSessionFactor, "\x00\x02", 2);
    memcpy(bInData, "\x04\x12\x34\xFF\x37\x1C\xF2\xA4", 8);
    nInLen = 8;

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIEncryptWithDerivedKey(nSock, nType, nIccType, nMode, bKey, bCardFactor,
                               bSessionFactor, bIV, bInData, nInLen, bOutData, &nOutLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 1, "无效加解密标志[2]测试未失败");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void EncryptWithDerivedKey_Test_13(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int  nType;
	  int  nIccType;
	  int  nMode;
	  BYTE bKey[32];
	  BYTE bCardFactor[8];
	  BYTE bSessionFactor[8];
	  BYTE bIV[8];
	  BYTE bInData[256];
	  int  nInLen;
	  BYTE bOutData[256];
	  int  nOutLen;

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bIV);
    bufclr(bInData);
    bufclr(bOutData);

    nType = 1;
    nIccType = -1;
    nMode = 0;
    memcpy(bKey, "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4", 16);
    memcpy(bCardFactor, "\x25\x00\x00\x00\x00\x00\x89\x01", 8);
    memcpy(bSessionFactor, "\x00\x02", 2);
    memcpy(bInData, "\x04\x12\x34\xFF\x37\x1C\xF2\xA4", 8);
    nInLen = 8;

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIEncryptWithDerivedKey(nSock, nType, nIccType, nMode, bKey, bCardFactor,
                               bSessionFactor, bIV, bInData, nInLen, bOutData, &nOutLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 1, "无效卡片类型[-1]测试未失败");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void EncryptWithDerivedKey_Test_14(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int  nType;
	  int  nIccType;
	  int  nMode;
	  BYTE bKey[32];
	  BYTE bCardFactor[8];
	  BYTE bSessionFactor[8];
	  BYTE bIV[8];
	  BYTE bInData[256];
	  int  nInLen;
	  BYTE bOutData[256];
	  int  nOutLen;

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bIV);
    bufclr(bInData);
    bufclr(bOutData);

    nType = 1;
    nIccType = 2;
    nMode = 0;
    memcpy(bKey, "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4", 16);
    memcpy(bCardFactor, "\x25\x00\x00\x00\x00\x00\x89\x01", 8);
    memcpy(bSessionFactor, "\x00\x02", 2);
    memcpy(bInData, "\x04\x12\x34\xFF\x37\x1C\xF2\xA4", 8);
    nInLen = 8;

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIEncryptWithDerivedKey(nSock, nType, nIccType, nMode, bKey, bCardFactor,
                               bSessionFactor, bIV, bInData, nInLen, bOutData, &nOutLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 1, "无效卡片类型[2]测试未失败");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void EncryptWithDerivedKey_Test_15(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int  nType;
	  int  nIccType;
	  int  nMode;
	  BYTE bKey[32];
	  BYTE bCardFactor[8];
	  BYTE bSessionFactor[8];
	  BYTE bIV[8];
	  BYTE bInData[256];
	  int  nInLen;
	  BYTE bOutData[256];
	  int  nOutLen;

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bIV);
    bufclr(bInData);
    bufclr(bOutData);

    nType = 1;
    nIccType = 0;
    nMode = -1;
    memcpy(bKey, "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4", 16);
    memcpy(bCardFactor, "\x25\x00\x00\x00\x00\x00\x89\x01", 8);
    memcpy(bSessionFactor, "\x00\x02", 2);
    memcpy(bInData, "\x04\x12\x34\xFF\x37\x1C\xF2\xA4", 8);
    nInLen = 8;

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIEncryptWithDerivedKey(nSock, nType, nIccType, nMode, bKey, bCardFactor,
                               bSessionFactor, bIV, bInData, nInLen, bOutData, &nOutLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 1, "无效加密模式[-1]测试未失败");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void EncryptWithDerivedKey_Test_16(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int  nType;
	  int  nIccType;
	  int  nMode;
	  BYTE bKey[32];
	  BYTE bCardFactor[8];
	  BYTE bSessionFactor[8];
	  BYTE bIV[8];
	  BYTE bInData[256];
	  int  nInLen;
	  BYTE bOutData[256];
	  int  nOutLen;

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bIV);
    bufclr(bInData);
    bufclr(bOutData);

    nType = 1;
    nIccType = 0;
    nMode = 2;
    memcpy(bKey, "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4", 16);
    memcpy(bCardFactor, "\x25\x00\x00\x00\x00\x00\x89\x01", 8);
    memcpy(bSessionFactor, "\x00\x02", 2);
    memcpy(bInData, "\x04\x12\x34\xFF\x37\x1C\xF2\xA4", 8);
    nInLen = 8;

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIEncryptWithDerivedKey(nSock, nType, nIccType, nMode, bKey, bCardFactor,
                               bSessionFactor, bIV, bInData, nInLen, bOutData, &nOutLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 1, "无效加密模式[2]测试未失败");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void EncryptWithDerivedKey_Test_17(void)
{
   	XXX_TEST_START_XXX
    int  nRet;
   	int  nSock = SM_SOCK;

	  int  nType;
	  int  nIccType;
	  int  nMode;
	  BYTE bKey[32];
	  BYTE bCardFactor[16];
	  BYTE bSessionFactor[16];
	  BYTE bIV[8];
	  BYTE bInData[256];
	  int  nInLen;
	  BYTE bOutData[256];
	  int  nOutLen;
	  BYTE bOutDataExp[16];
	  int  nOutLenExp;

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bIV);
    bufclr(bInData);
    bufclr(bOutData);
    bufclr(bOutDataExp);

    nType = 1;
    nIccType = 0x0001000A;
    nMode = 1;

    /* Key = F431623E499789C8C2F1F725AD7F8949 */
    /* CF = 2500000000008901DAFFFFFFFFFF76FE */
    /* SF = 0000000000000002000000000000FFFD */
    /* Data = 08 041234FF371CF2A4 80000000000000 */
    /* Key1 = 89E8 1ECA 276C 7D50 A537 AE51 2E11 5224 */
    /* Key2 = 89E8 1ECA 276C 7D52 A537 AE51 2E11 ADD9 */
    /* Out = 9485 C125 FFA7 9C3E E13E 4B70 782C 707F */

    memcpy(bKey, 
		       "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4", 
		       16);
    memcpy(bCardFactor, \
		       "\x25\x00\x00\x00\x00\x00\x89\x01\xDA\xFF\xFF\xFF\xFF\xFF\x76\xFE", 
		       16);
    memcpy(bSessionFactor, \
		       "\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\xFF\xFD", 
		       16);		
    memcpy(bInData, "\x04\x12\x34\xFF\x37\x1C\xF2\xA4", 8);
    nInLen = 8;
    memcpy(bOutDataExp, "\x94\x85\xC1\x25\xFF\xA7\x9C\x3E\xE1\x3E\x4B\x70\x78\x2C\x70\x7F", 16);
    nOutLenExp = 16;

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]nIccType  = %x\n", nIccType);
    DspHex("[IN ]bKey	   =", bKey, 16);
    DspHex("[IN ]bCardFactor =", bCardFactor, 16);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 16);
    DspHex("[IN ]bInData	 =", bInData, nInLen);
    DspHex("[IN ]bIV	 =", bIV, 8);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIEncryptWithDerivedKey(nSock, nType, nIccType, nMode, bKey, bCardFactor,
                              bSessionFactor, bIV, bInData, nInLen, bOutData, &nOutLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "VISA卡，CBC加密，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    DspHex("[OUT]bOutData =", bOutData, 8);
    printf("[OUT]nOutLen  = %d\n", nOutLen);
    ASSERT_OUT_HEX(bOutData, bOutDataExp, nOutLenExp);
    ASSERT_OUT(nOutLen, nOutLenExp);
   	XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void EncryptWithDerivedKey_Test_18(void)
{
    XXX_TEST_START_XXX
    int  nRet;
   	int  nSock = SM_SOCK;

	  int  nType;
	  int  nIccType;
	  int  nMode;
	  BYTE bKey[32];
	  BYTE bCardFactor[16];
	  BYTE bSessionFactor[16];
	  BYTE bIV[8];
	  BYTE bInData[256];
	  int  nInLen;
	  BYTE bOutData[256];
	  int  nOutLen;
	  BYTE bOutDataExp[16];
	  int  nOutLenExp;

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bIV);
    bufclr(bInData);
    bufclr(bOutData);
    bufclr(bOutDataExp);

    nType = 0;
    nIccType = 0x0001000A;
    nMode = 1;

    /* Key = F431623E499789C8C2F1F725AD7F8949 */
    /* CF = 2500000000008901DAFFFFFFFFFF76FE */
    /* SF = 0000000000000002000000000000FFFD */
    /* Data = 08 041234FF371CF2A4 80000000000000 */
    /* Key1 = 89E8 1ECA 276C 7D50 A537 AE51 2E11 5224 */
    /* Key2 = 89E8 1ECA 276C 7D52 A537 AE51 2E11 ADD9 */
    /* Out = 9485 C125 FFA7 9C3E E13E 4B70 782C 707F */

    memcpy(bKey, 
		       "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4", 
		       16);
    memcpy(bCardFactor, \
		       "\x25\x00\x00\x00\x00\x00\x89\x01\xDA\xFF\xFF\xFF\xFF\xFF\x76\xFE", 
		       16);		
    memcpy(bSessionFactor, \
		       "\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\xFF\xFD", 
		       16);
    memcpy(bInData, "\x94\x85\xC1\x25\xFF\xA7\x9C\x3E\xE1\x3E\x4B\x70\x78\x2C\x70\x7F", 16);
    nInLen = 16;
    memcpy(bOutDataExp, "\x04\x12\x34\xFF\x37\x1C\xF2\xA4", 8);
    nOutLenExp = 8;

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]nIccType  = %x\n", nIccType);
    DspHex("[IN ]bKey	   =", bKey, 16);
    DspHex("[IN ]bCardFactor =", bCardFactor, 16);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 16);
    DspHex("[IN ]bInData	 =", bInData, nInLen);
    DspHex("[IN ]bIV	 =", bIV, 8);
   	XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIEncryptWithDerivedKey(nSock, nType, nIccType, nMode, bKey, bCardFactor,
                              bSessionFactor, bIV, bInData, nInLen, bOutData, &nOutLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "VISA卡，CBC解密，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    DspHex("[OUT]bOutData =", bOutData, 8);
    printf("[OUT]nOutLen  = %d\n", nOutLen);
    ASSERT_OUT_HEX(bOutData, bOutDataExp, nOutLenExp);
    ASSERT_OUT(nOutLen, nOutLenExp);
    XXX_OUTPUT_XXX

   XXX_TEST_END_XXX
}

void EncryptWithDerivedKey_Test_19(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nType;
    int  nIccType;
    int  nMode;
    BYTE bKey[32];
    BYTE bCardFactor[16];
    BYTE bSessionFactor[16];
    BYTE bIV[8];
    BYTE bInData[256];
    int  nInLen;
    BYTE bOutData[256];
    int  nOutLen;
    BYTE bOutDataExp[256];
    int  nOutLenExp;

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bIV);
    bufclr(bInData);
    bufclr(bOutData);
    bufclr(bOutDataExp);

    nType = 1;
    nIccType = 0x00020014;
    nMode = 0;

    /* Key = F431623E499789C8C2F1F725AD7F8949 */
    /* CF = 2500000000008901DAFFFFFFFFFF76FE */
    /* SF = 0000000000000002000000000000FFFD */
    /* Data = 041234FF371CF2A4 */
    /* Key1 = 89E8 1ECA 276C 7D50 A537 AE51 2E11 5224 */
    /* Key2 = 4FA1 BB65 DC84 58BF ED43 C210 F4FD 4711 */
    /* Out = AEF3 B941 5ED5 97FC */

    memcpy(bKey, 
        "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4", 
        16);
    memcpy(bCardFactor, \
        "\x25\x00\x00\x00\x00\x00\x89\x01\xDA\xFF\xFF\xFF\xFF\xFF\x76\xFE", 
        16);        
    memcpy(bSessionFactor, \
        "\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\xFF\xFD", 
        16);        
    memcpy(bInData, "\x04\x12\x34\xFF\x37\x1C\xF2\xA4", 8);        
    nInLen = 8;
    memcpy(bOutDataExp, "\xAE\xF3\xB9\x41\x5E\xD5\x97\xFC", 8);
    nOutLenExp = 8;

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]nIccType  = %x\n", nIccType);
    DspHex("[IN ]bKey       =", bKey, 16);
    DspHex("[IN ]bCardFactor =", bCardFactor, 16);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 16);
    DspHex("[IN ]bInData     =", bInData, nInLen);
    DspHex("[IN ]bIV     =", bIV, 8);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIEncryptWithDerivedKey(nSock, nType, nIccType, nMode, bKey, bCardFactor,
                               bSessionFactor, bIV, bInData, nInLen, bOutData, &nOutLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "MASTER卡，ECB加密，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    DspHex("[OUT]bOutData =", bOutData, 8);
    printf("[OUT]nOutLen  = %d\n", nOutLen);
    ASSERT_OUT_HEX(bOutData, bOutDataExp, nOutLenExp);
    ASSERT_OUT(nOutLen, nOutLenExp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void EncryptWithDerivedKey_Test_20(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nType;
    int  nIccType;
    int  nMode;
    BYTE bKey[32];
    BYTE bCardFactor[16];
    BYTE bSessionFactor[16];
    BYTE bIV[8];
    BYTE bInData[256];
    int  nInLen;
    BYTE bOutData[256];
    int  nOutLen;
    BYTE bOutDataExp[256];
    int  nOutLenExp;

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bIV);
    bufclr(bInData);
    bufclr(bOutData);
    bufclr(bOutDataExp);

    nType = 0;
    nIccType = 0x00020014;
    nMode = 0;

    memcpy(bKey, 
        "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4", 
        16);
    memcpy(bCardFactor, \
        "\x25\x00\x00\x00\x00\x00\x89\x01\xDA\xFF\xFF\xFF\xFF\xFF\x76\xFE", 
        16);        
    memcpy(bSessionFactor, \
        "\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\xFF\xFD", 
        16);        
    memcpy(bInData, "\x04\x12\x34\xFF\x37\x1C\xF2\xA4", 8);        
    nInLen = 8;
    memcpy(bOutDataExp,"\xA8\x22\x93\xDD\x28\xB7\x39\x41",8);
    nOutLenExp = 8;

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]nIccType  = %x\n", nIccType);
    DspHex("[IN ]bKey       =", bKey, 16);
    DspHex("[IN ]bCardFactor =", bCardFactor, 16);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 16);
    DspHex("[IN ]bInData     =", bInData, nInLen);
    DspHex("[IN ]bIV     =", bIV, 8);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIEncryptWithDerivedKey(nSock, nType, nIccType, nMode, bKey, bCardFactor,
                           bSessionFactor, bIV, bInData, nInLen, bOutData, &nOutLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "MASTER卡，ECB解密，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    DspHex("[OUT]bOutData =", bOutData, 8);
    printf("[OUT]nOutLen  = %d\n", nOutLen);
    ASSERT_OUT_HEX(bOutData, bOutDataExp, nOutLenExp);
    ASSERT_OUT(nOutLen, nOutLenExp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void EncryptWithDerivedKey_Test_21(void)
{
    XXX_TEST_START_XXX
    int  nRet;
   	int  nSock = SM_SOCK;

	  int  nType;
	  int  nIccType;
	  int  nMode;
	  BYTE bKey[32];
	  BYTE bCardFactor[16];
	  BYTE bSessionFactor[16];
	  BYTE bIV[8];
	  BYTE bInData[256];
	  int  nInLen;
	  BYTE bOutData[256];
	  int  nOutLen;
	  BYTE bOutDataExp[8];
    int  nOutLenExp;

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bIV);
    bufclr(bInData);
    bufclr(bOutData);
    bufclr(bOutDataExp);

    nType = 1;
    nIccType = 0x0002000E;
    nMode = 1;

    /* Key = F431623E499789C8C2F1F725AD7F8949 */
    /* CF = 2500000000008901DAFFFFFFFFFF76FE */
    /* SF = 0000000000000002000000000000FFFD */
    /* Data = 041234FF371CF2A4 */
    /* Key1 = 89E8 1ECA 276C 7D50 A537 AE51 2E11 5224 */
    /* Key2 = 4FA1 BB65 DC84 58BF ED43 C210 F4FD 4711 */
    /* IV = 0102030405060708 */
    /* Out = 2A21 D6FC FAB7 E05A */

    memcpy(bKey, 
        "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4", 
        16);
    memcpy(bCardFactor, \
        "\x25\x00\x00\x00\x00\x00\x89\x01\xDA\xFF\xFF\xFF\xFF\xFF\x76\xFE", 
        16);        
    memcpy(bSessionFactor, \
        "\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\xFF\xFD", 
        16);        
    memcpy(bInData, "\x04\x12\x34\xFF\x37\x1C\xF2\xA4", 8);        
    nInLen = 8;
    memcpy(bIV, "\x01\x02\x03\x04\x05\x06\x07\x08", 8);
    memcpy(bOutDataExp, "\x2A\x21\xD6\xFC\xFA\xB7\xE0\x5A", 8);
    nOutLenExp = 8;

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]nIccType  = %x\n", nIccType);
    DspHex("[IN ]bKey	   =", bKey, 16);
    DspHex("[IN ]bCardFactor =", bCardFactor, 16);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 16);
    DspHex("[IN ]bInData	 =", bInData, nInLen);
    DspHex("[IN ]bIV	 =", bIV, 8);
   	XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIEncryptWithDerivedKey(nSock, nType, nIccType, nMode, bKey, bCardFactor,
                              bSessionFactor, bIV, bInData, nInLen, bOutData, &nOutLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "MASTER卡，CBC加密，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    DspHex("[OUT]bOutData =", bOutData, 8);
    printf("[OUT]nOutLen  = %d\n", nOutLen);
    ASSERT_OUT_HEX(bOutData, bOutDataExp, nOutLenExp);
    ASSERT_OUT(nOutLen, nOutLenExp);
   	XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void EncryptWithDerivedKey_Test_22(void)
{
    XXX_TEST_START_XXX
    int  nRet;
   	int  nSock = SM_SOCK;

	  int  nType;
	  int  nIccType;
	  int  nMode;
	  BYTE bKey[32];
	  BYTE bCardFactor[16];
	  BYTE bSessionFactor[16];
	  BYTE bIV[8];
	  BYTE bInData[256];
	  int  nInLen;
	  BYTE bOutData[256];
	  int  nOutLen;
	  BYTE bOutDataExp[8];
	  int  nOutLenExp;

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bIV);
    bufclr(bInData);
    bufclr(bOutData);
    bufclr(bOutDataExp);

    nType = 0;
    nIccType = 0x0002000E;
    nMode = 1;

    /* Key = F431623E499789C8C2F1F725AD7F8949 */
    /* CF = 2500000000008901DAFFFFFFFFFF76FE */
    /* SF = 0000000000000002000000000000FFFD */
    /* Data = 041234FF371CF2A4 */
    /* Key1 = 89E8 1ECA 276C 7D50 A537 AE51 2E11 5224 */
    /* Key2 = 4FA1 BB65 DC84 58BF ED43 C210 F4FD 4711 */
    /* IV = 0102030405060708 */
    /* Out = 2A21 D6FC FAB7 E05A */

    memcpy(bKey, 
        "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4", 
        16);
    memcpy(bCardFactor, \
        "\x25\x00\x00\x00\x00\x00\x89\x01\xDA\xFF\xFF\xFF\xFF\xFF\x76\xFE", 
        16);        
    memcpy(bSessionFactor, \
        "\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\xFF\xFD", 
        16);        
    memcpy(bInData, "\x2A\x21\xD6\xFC\xFA\xB7\xE0\x5A", 8);        
    nInLen = 8;
    memcpy(bIV, "\x01\x02\x03\x04\x05\x06\x07\x08", 8);
    memcpy(bOutDataExp, "\x04\x12\x34\xFF\x37\x1C\xF2\xA4", 8);
    nOutLenExp = 8;

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]nIccType  = %x\n", nIccType);
    DspHex("[IN ]bKey	   =", bKey, 16);
    DspHex("[IN ]bCardFactor =", bCardFactor, 16);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 16);
    DspHex("[IN ]bInData	 =", bInData, nInLen);
    DspHex("[IN ]bIV	 =", bIV, 8);
   	XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIEncryptWithDerivedKey(nSock, nType, nIccType, nMode, bKey, bCardFactor,
                              bSessionFactor, bIV, bInData, nInLen, bOutData, &nOutLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "MASTER卡，CBC解密，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    DspHex("[OUT]bOutData =", bOutData, 8);
    printf("[OUT]nOutLen  = %d\n", nOutLen);
    ASSERT_OUT_HEX(bOutData, bOutDataExp, nOutLenExp);
    ASSERT_OUT(nOutLen, nOutLenExp);
   	XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void EncryptWithDerivedKey_Test_23(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nType;
    int  nIccType;
    int  nMode;
    BYTE bKey[32];
    BYTE bCardFactor[16];
    BYTE bSessionFactor[16];
    BYTE bIV[8];
    BYTE bInData[256];
    int  nInLen;
    BYTE bOutData[256];
    int  nOutLen;
    BYTE bOutDataExp[256];
    int  nOutLenExp;

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bIV);
    bufclr(bInData);
    bufclr(bOutData);
    bufclr(bOutDataExp);

    nType = 1;
    nIccType = 0x00000401;
    nMode = 0;

    memcpy(bKey, 
        "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4", 
        16);
    memcpy(bCardFactor, \
        "\x25\x00\x00\x00\x00\x00\x89\x01\xDA\xFF\xFF\xFF\xFF\xFF\x76\xFE", 
        16);        
    memcpy(bSessionFactor, \
        "\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\xFF\xFD", 
        16);        
    memcpy(bInData, "\x04\x12\x34\xFF\x37\x1C\xF2\xA4", 8);
        nInLen = 8;
    /* 669D80C23AED1147ACD33BB3E532B2B8 */
    /* 08 041234FF371CF2A4 80000000000000 */
    /* F99FD238C265976788DDF94AC9D8C264 */
    memcpy(bOutDataExp, \
           "\xF9\x9F\xD2\x38\xC2\x65\x97\x67\x88\xDD\xF9\x4A\xC9\xD8\xC2\x64" \
           , 16);
    nOutLenExp = 16;

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]nIccType  = %x\n", nIccType);
    DspHex("[IN ]bKey       =", bKey, 16);
    DspHex("[IN ]bCardFactor =", bCardFactor, 16);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 16);
    DspHex("[IN ]bInData     =", bInData, 8);
    DspHex("[IN ]bIV     =", bIV, 8);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIEncryptWithDerivedKey(nSock, nType, nIccType, nMode, bKey, bCardFactor,
                               bSessionFactor, bIV, bInData, nInLen, bOutData, &nOutLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "PBOC卡，SM4, ECB加密，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[OUT]nOutLen  = %d\n", nOutLen);
    DspHex("[OUT]bOutData =", bOutData, nOutLen);
    ASSERT_OUT(nOutLen, nOutLenExp);
    ASSERT_OUT_HEX(bOutData, bOutDataExp, nOutLen);
    XXX_OUTPUT_XXX
            
    XXX_TEST_END_XXX
}

void EncryptWithDerivedKey_Test_24(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nType;
    int  nIccType;
    int  nMode;
    BYTE bKey[32];
    BYTE bCardFactor[16];
    BYTE bSessionFactor[16];
    BYTE bIV[8];
    BYTE bInData[256];
    int  nInLen;
    BYTE bOutData[256];
    int  nOutLen;
    BYTE bOutDataExp[256];
    int  nOutLenExp;

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bIV);
    bufclr(bInData);
    bufclr(bOutData);
    bufclr(bOutDataExp);

    nType = 0;
    nIccType = 0x00000417;
    nMode = 0;

    memcpy(bKey, 
        "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4", 
        16);
    memcpy(bCardFactor, \
        "\x25\x00\x00\x00\x00\x00\x89\x01\xDA\xFF\xFF\xFF\xFF\xFF\x76\xFE", 
        16);        
    memcpy(bSessionFactor, \
        "\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\xFF\xFD", 
        16);        
    memcpy(bInData, \
           "\xF9\x9F\xD2\x38\xC2\x65\x97\x67\x88\xDD\xF9\x4A\xC9\xD8\xC2\x64" \
           , 16);
    nInLen = 16;
    /* 669D80C23AED1147ACD33BB3E532B2B8 */
    /* F99FD238C265976788DDF94AC9D8C264 */
    /* 08 041234FF371CF2A4 80000000000000 */
    memcpy(bOutDataExp, "\x04\x12\x34\xFF\x37\x1C\xF2\xA4", 8);
    nOutLenExp = 8;

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]nIccType  = %x\n", nIccType);
    DspHex("[IN ]bKey       =", bKey, 16);
    DspHex("[IN ]bCardFactor =", bCardFactor, 16);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 16);
    DspHex("[IN ]bInData     =", bInData, 8);
    DspHex("[IN ]bIV     =", bIV, 8);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIEncryptWithDerivedKey(nSock, nType, nIccType, nMode, bKey, bCardFactor,
                               bSessionFactor, bIV, bInData, nInLen, bOutData, &nOutLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "PBOC卡，SM4, ECB解密，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[OUT]nOutLen  = %d\n", nOutLen);
    DspHex("[OUT]bOutData =", bOutData, nOutLen);
    ASSERT_OUT(nOutLen, nOutLenExp);
    ASSERT_OUT_HEX(bOutData, bOutDataExp, nOutLen);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void EncryptWithDerivedKey_Test_25(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nType;
    int  nIccType;
    int  nMode;
    BYTE bKey[32];
    BYTE bCardFactor[16];
    BYTE bSessionFactor[16];
    BYTE bIV[16];
    BYTE bInData[256];
    int  nInLen;
    BYTE bOutData[256];
    int  nOutLen;
    BYTE bOutDataExp[256];
    int  nOutLenExp;

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bIV);
    bufclr(bInData);
    bufclr(bOutData);
    bufclr(bOutDataExp);

    nType = 1;
    nIccType = 0x00000401;
    nMode = 1;

    memcpy(bKey, 
        "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4", 
        16);
    memcpy(bCardFactor, \
        "\x25\x00\x00\x00\x00\x00\x89\x01\xDA\xFF\xFF\xFF\xFF\xFF\x76\xFE", 
        16);        
    memcpy(bSessionFactor, \
        "\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\xFF\xFD", 
        16);        
    memcpy(bInData, \
           "\xD1\x6B\x6E\x62\x59\xCF\x9E\x73\x4A\x6F\xA8\xB6\x84\x33\x14\x00" \
           , 16);
    nInLen = 16;
    /* 669D80C23AED1147ACD33BB3E532B2B8 */
    /* 10 D16B6E6259CF9E734A6FA8B684331400 800000000000000000000000000000 */
    /* 4883898C0AD2613F30CD742F4E931959DCE7DE053AA3BD5CF80951E8C325643B */
    memcpy(bOutDataExp, \
           "\x48\x83\x89\x8C\x0A\xD2\x61\x3F\x30\xCD\x74\x2F\x4E\x93\x19\x59" \
           "\xDC\xE7\xDE\x05\x3A\xA3\xBD\x5C\xF8\x09\x51\xE8\xC3\x25\x64\x3B" \
           , 32);
    nOutLenExp = 32;

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]nIccType  = %x\n", nIccType);
    DspHex("[IN ]bKey       =", bKey, 16);
    DspHex("[IN ]bCardFactor =", bCardFactor, 16);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 16);
    DspHex("[IN ]bInData     =", bInData, 8);
    DspHex("[IN ]bIV     =", bIV, 16);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIEncryptWithDerivedKey(nSock, nType, nIccType, nMode, bKey, bCardFactor,
                               bSessionFactor, bIV, bInData, nInLen, bOutData, &nOutLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "PBOC卡，SM4, CBC加密，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[OUT]nOutLen  = %d\n", nOutLen);
    DspHex("[OUT]bOutData =", bOutData, nOutLen);
    ASSERT_OUT(nOutLen, nOutLenExp);
    ASSERT_OUT_HEX(bOutData, bOutDataExp, nOutLen);
    XXX_OUTPUT_XXX
            
    XXX_TEST_END_XXX
}

void EncryptWithDerivedKey_Test_26(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nType;
    int  nIccType;
    int  nMode;
    BYTE bKey[32];
    BYTE bCardFactor[16];
    BYTE bSessionFactor[16];
    BYTE bIV[16];
    BYTE bInData[256];
    int  nInLen;
    BYTE bOutData[256];
    int  nOutLen;
    BYTE bOutDataExp[256];
    int  nOutLenExp;

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bIV);
    bufclr(bInData);
    bufclr(bOutData);
    bufclr(bOutDataExp);

    nType = 0;
    nIccType = 0x00000417;
    nMode = 1;

    memcpy(bKey, 
        "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4", 
        16);
    memcpy(bCardFactor, \
        "\x25\x00\x00\x00\x00\x00\x89\x01\xDA\xFF\xFF\xFF\xFF\xFF\x76\xFE", 
        16);        
    memcpy(bSessionFactor, \
        "\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\xFF\xFD", 
        16);        
    memcpy(bInData, \
           "\x48\x83\x89\x8C\x0A\xD2\x61\x3F\x30\xCD\x74\x2F\x4E\x93\x19\x59" \
           "\xDC\xE7\xDE\x05\x3A\xA3\xBD\x5C\xF8\x09\x51\xE8\xC3\x25\x64\x3B" \
           , 32);
    nInLen = 32;
    /* 669D80C23AED1147ACD33BB3E532B2B8 */
    /* 4883898C0AD2613F30CD742F4E931959DCE7DE053AA3BD5CF80951E8C325643B */
    /* 10 D16B6E6259CF9E734A6FA8B684331400 800000000000000000000000000000 */
    memcpy(bOutDataExp, \
           "\xD1\x6B\x6E\x62\x59\xCF\x9E\x73\x4A\x6F\xA8\xB6\x84\x33\x14\x00" \
           , 16);
    nOutLenExp = 16;

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]nIccType  = %x\n", nIccType);
    DspHex("[IN ]bKey       =", bKey, 16);
    DspHex("[IN ]bCardFactor =", bCardFactor, 16);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 16);
    DspHex("[IN ]bInData     =", bInData, 8);
    DspHex("[IN ]bIV     =", bIV, 16);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIEncryptWithDerivedKey(nSock, nType, nIccType, nMode, bKey, bCardFactor,
                               bSessionFactor, bIV, bInData, nInLen, bOutData, &nOutLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "PBOC卡，SM4, CBC解密，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[OUT]nOutLen  = %d\n", nOutLen);
    DspHex("[OUT]bOutData =", bOutData, nOutLen);
    ASSERT_OUT(nOutLen, nOutLenExp);
    ASSERT_OUT_HEX(bOutData, bOutDataExp, nOutLen);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void CalcMacWithDerivedKey_Test_01(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int  nIccType;
	  BYTE bKey[32];
	  BYTE bCardFactor[8];
	  BYTE bSessionFactor[8];
	  BYTE bData[256];
	  int  nLen;
	  BYTE bMAC[8];
	  BYTE bMACExp[8];

    	bufclr(bKey);
    	bufclr(bCardFactor);
    	bufclr(bSessionFactor);
    	bufclr(bData);
    	bufclr(bMAC);
	bufclr(bMACExp);
	
    	nIccType = 0x00000000;
    	memcpy(bKey, "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4", 16);
    	memcpy(bCardFactor, "\x25\x00\x00\x00\x00\x00\x89\x01", 8);
    	memcpy(bSessionFactor, "\x00\x02", 2);
    	memcpy(bData, "\x04\x12\x34\xFF\x37\x1C\xF2\xA4", 8);
	memcpy(bMACExp,"\x50\x10\x58\xF2\x89\x79\x6E\xDA",8);
    	nLen = 8;

    	XXX_INPUT_XXX
    	printf("[IN ]nSock = %d\n", nSock);
	printf("[IN ]nIccType  = %x\n", nIccType);
	DspHex("[IN ]bKey	   =", bKey, 16);
	DspHex("[IN ]bCardFactor =", bCardFactor, 16);
	DspHex("[IN ]bSessionFactor =", bSessionFactor, 16);
	DspHex("[IN ]bData	 =", bData, 8);
    	XXX_INPUT_XXX

    	/* Call Test Target Function Start */
    	nRet = SMAPICalcMacWithDerivedKey(nSock, nIccType, bKey, bCardFactor,
                               bSessionFactor, bData, nLen, bMAC);
    	/* Call Test Target Function End */

    	XXX_RESULT_XXX
    	ASSERT_RESULT(nRet, 0, "PBOC卡，测试未成功");
	ASSERT_OUT_HEX(bMAC, bMACExp, 8);
    	XXX_RESULT_XXX

    	XXX_OUTPUT_XXX
    	DspHex("[OUT]bMAC =", bMAC, 8);
    	XXX_OUTPUT_XXX
			
	DspHex("[RESULT ]expected MAC =", bMACExp, 8);
	DspHex("[RESULT ]calculated MAC  =", bMAC, 8);

    	XXX_TEST_END_XXX
}

void CalcMacWithDerivedKey_Test_02(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int  nIccType;
	  BYTE bKey[32];
	  BYTE bCardFactor[16];
	  BYTE bSessionFactor[16];
	  BYTE bData[256];
	  int  nLen;
	  BYTE bMAC[8];
	  BYTE bMACExp[8];

   	bufclr(bKey);
    	bufclr(bCardFactor);
    	bufclr(bSessionFactor);
    	bufclr(bData);
    	bufclr(bMAC);
	bufclr(bMACExp);

    	nIccType = 0x0001000A;
    	memcpy(bKey, 
			"\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4", 
			16);
    	memcpy(bCardFactor, 
			"\x25\x00\x00\x00\x00\x00\x89\x01\xDA\xFF\xFF\xFF\xFF\xFF\x76\xFE", 
			16);		
    	memcpy(bSessionFactor, 
			"\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\xFF\xFD", 
			16);		
    	memcpy(bData, "\x04\x12\x34\xFF\x37\x1C\xF2\xA4", 8);
    	nLen = 8;
	memcpy(bMACExp,"\x42\x93\xAA\xC9\x9F\x67\x14\x00",8);

    	XXX_INPUT_XXX
    	printf("[IN ]nSock = %d\n", nSock);
	printf("[IN ]nIccType  = %x\n", nIccType);
	DspHex("[IN ]bKey	   =", bKey, 16);
	DspHex("[IN ]bCardFactor =", bCardFactor, 16);
	DspHex("[IN ]bSessionFactor =", bSessionFactor, 16);
	DspHex("[IN ]bInData	 =", bData, 8);
    	XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPICalcMacWithDerivedKey(nSock, nIccType, bKey, bCardFactor,
                               bSessionFactor, bData, nLen, bMAC);
    /* Call Test Target Function End */

    	XXX_RESULT_XXX
    	ASSERT_RESULT(nRet, 0, "VISA卡，测试未成功");
    	XXX_RESULT_XXX

    	XXX_OUTPUT_XXX
    	DspHex("[OUT]bMAC =", bMAC, 8);
	ASSERT_OUT_HEX(bMAC, bMACExp, 8);
    	XXX_OUTPUT_XXX
			
	DspHex("[RESULT ]expected Data =", bMACExp, 8);
	DspHex("[RESULT ]calculated Data  =", bMAC, 8);

    	XXX_TEST_END_XXX
}

void CalcMacWithDerivedKey_Test_03(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int  nIccType;
	  BYTE bKey[32];
	  BYTE bCardFactor[8];
	  BYTE bSessionFactor[8];
	  BYTE bData[256];
	  int  nLen;
	  BYTE bMAC[8];

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bData);
    bufclr(bMAC);

    nSock = -1;
    nIccType = 0;
    memcpy(bKey, "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4", 16);
    memcpy(bCardFactor, "\x25\x00\x00\x00\x00\x00\x89\x01", 8);
    memcpy(bSessionFactor, "\x00\x02", 2);
    memcpy(bData, "\x04\x12\x34\xFF\x37\x1C\xF2\xA4", 8);
    nLen = 8;

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPICalcMacWithDerivedKey(nSock, nIccType, bKey, bCardFactor,
                               bSessionFactor, bData, nLen, bMAC);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 1, "无效Socket ID[-1]测试未失败");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    nSock = SM_SOCK;

    XXX_TEST_END_XXX
}

void CalcMacWithDerivedKey_Test_04(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int  nIccType;
	  BYTE bKey[32];
	  BYTE bCardFactor[8];
	  BYTE bSessionFactor[8];
	  BYTE bData[256];
	  int  nLen;
	  BYTE bMAC[8];

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bData);
    bufclr(bMAC);

    nSock = 8;
    nIccType = 0;
    memcpy(bKey, "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4", 16);
    memcpy(bCardFactor, "\x25\x00\x00\x00\x00\x00\x89\x01", 8);
    memcpy(bSessionFactor, "\x00\x02", 2);
    memcpy(bData, "\x04\x12\x34\xFF\x37\x1C\xF2\xA4", 8);
    nLen = 8;

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPICalcMacWithDerivedKey(nSock, nIccType, bKey, bCardFactor,
                               bSessionFactor, bData, nLen, bMAC);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 1, "无效Socket ID[8]测试未失败");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    nSock = SM_SOCK;

    XXX_TEST_END_XXX
}

void CalcMacWithDerivedKey_Test_05(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int  nIccType;
	  BYTE bKey[32];
	  BYTE bCardFactor[8];
	  BYTE bSessionFactor[8];
	  BYTE bData[256];
	  int  nLen;
	  BYTE bMAC[8];

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bData);
    bufclr(bMAC);

    nIccType = -1;
    memcpy(bKey, "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4", 16);
    memcpy(bCardFactor, "\x25\x00\x00\x00\x00\x00\x89\x01", 8);
    memcpy(bSessionFactor, "\x00\x02", 2);
    memcpy(bData, "\x04\x12\x34\xFF\x37\x1C\xF2\xA4", 8);
    nLen = 8;

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPICalcMacWithDerivedKey(nSock, nIccType, bKey, bCardFactor,
                               bSessionFactor, bData, nLen, bMAC);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 1, "无效卡片类型[-1]测试未失败");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void CalcMacWithDerivedKey_Test_06(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int  nIccType;
	  BYTE bKey[32];
	  BYTE bCardFactor[8];
	  BYTE bSessionFactor[8];
	  BYTE bData[256];
	  int  nLen;
	  BYTE bMAC[8];

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bData);
    bufclr(bMAC);

    nIccType = 2;
    memcpy(bKey, "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4", 16);
    memcpy(bCardFactor, "\x25\x00\x00\x00\x00\x00\x89\x01", 8);
    memcpy(bSessionFactor, "\x00\x02", 2);
    memcpy(bData, "\x04\x12\x34\xFF\x37\x1C\xF2\xA4", 8);
    nLen = 8;

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPICalcMacWithDerivedKey(nSock, nIccType, bKey, bCardFactor,
                               bSessionFactor, bData, nLen, bMAC);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 1, "无效卡片类型[2]测试未失败");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void CalcMacWithDerivedKey_Test_07(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nIccType;
    BYTE bKey[32];
    BYTE bCardFactor[16];
    BYTE bSessionFactor[16];
    BYTE bData[256];
    int  nLen;
    BYTE bMAC[8];
    BYTE bMACExp[8];

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bData);
    bufclr(bMAC);
    bufclr(bMACExp);

    nIccType = 0x00020014;
    memcpy(bKey, 
            "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4", 
            16);
    memcpy(bCardFactor, 
            "\x25\x00\x00\x00\x00\x00\x89\x01\xDA\xFF\xFF\xFF\xFF\xFF\x76\xFE", 
            16);        
    memcpy(bSessionFactor, 
            "\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\xFF\xFD", 
            16);        
    memcpy(bData, "\x04\x12\x34\xFF\x37\x1C\xF2\xA4", 8);
    nLen = 8;
    memcpy(bMACExp,"\x50\x10\x58\xF2\x89\x79\x6E\xDA",8);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]nIccType  = %x\n", nIccType);
    DspHex("[IN ]bKey       =", bKey, 16);
    DspHex("[IN ]bCardFactor =", bCardFactor, 16);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 16);
    DspHex("[IN ]bInData     =", bData, 8);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPICalcMacWithDerivedKey(nSock, nIccType, bKey, bCardFactor,
                               bSessionFactor, bData, nLen, bMAC);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "MASTER卡，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    DspHex("[OUT]bMAC =", bMAC, 8);
    ASSERT_OUT_HEX(bMAC, bMACExp, 8);
    XXX_OUTPUT_XXX
            
    DspHex("[RESULT ]expected Data =", bMACExp, 8);
    DspHex("[RESULT ]calculated Data  =", bMAC, 8);

    XXX_TEST_END_XXX
}

void CalcMacWithDerivedKey_Test_08(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nIccType;
    BYTE bKey[32];
    BYTE bCardFactor[16];
    BYTE bSessionFactor[16];
    BYTE bData[256];
    int  nLen;
    BYTE bMAC[8];
    BYTE bMACExp[8];

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bData);
    bufclr(bMAC);
    bufclr(bMACExp);

    nIccType = 0x00000401;
    memcpy(bKey, 
        "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4", 
        16);
    memcpy(bCardFactor, 
        "\x25\x00\x00\x00\x00\x00\x89\x01\xDA\xFF\xFF\xFF\xFF\xFF\x76\xFE", 
        16);        
    memcpy(bSessionFactor, 
        "\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\xFF\xFD", 
        16);        
    memcpy(bData, "\x04\x12\x34\xFF\x37\x1C\xF2\xA4", 8);
    nLen = 8;
    /* 669D80C23AED1147ACD33BB3E532B2B8 */
    /* 041234FF371CF2A48000000000000000 */
    /* D16B6E6259CF9E734A6FA8B684331400 */
    memcpy(bMACExp,"\xD1\x6B\x6E\x62\x59\xCF\x9E\x73", 8);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]nIccType  = %x\n", nIccType);
    DspHex("[IN ]bKey       =", bKey, 16);
    DspHex("[IN ]bCardFactor =", bCardFactor, 16);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 16);
    DspHex("[IN ]bInData     =", bData, nLen);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPICalcMacWithDerivedKey(nSock, nIccType, bKey, bCardFactor,
                               bSessionFactor, bData, nLen, bMAC);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "PBOC卡，SM4, 测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    DspHex("[OUT]bMAC =", bMAC, 8);
    ASSERT_OUT_HEX(bMAC, bMACExp, 8);
    XXX_OUTPUT_XXX
            
//    DspHex("[RESULT ]expected Data =", bMACExp, 8);
//    DspHex("[RESULT ]calculated Data  =", bMAC, 8);

    XXX_TEST_END_XXX
}

void CalcMacWithDerivedKey_Test_09(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nIccType;
    BYTE bKey[32];
    BYTE bCardFactor[16];
    BYTE bSessionFactor[16];
    BYTE bData[256];
    int  nLen;
    BYTE bMAC[8];
    BYTE bMACExp[8];

    bufclr(bKey);
    bufclr(bCardFactor);
    bufclr(bSessionFactor);
    bufclr(bData);
    bufclr(bMAC);
    bufclr(bMACExp);

    nIccType = 0x00000417;
    memcpy(bKey, 
        "\x97\xC9\x08\xD8\x38\x0B\xDB\x78\x22\x75\x61\xF4\xF2\x7F\xAB\xB4", 
        16);
    memcpy(bCardFactor, 
        "\x25\x00\x00\x00\x00\x00\x89\x01\xDA\xFF\xFF\xFF\xFF\xFF\x76\xFE", 
        16);        
    memcpy(bSessionFactor, 
        "\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\xFF\xFD", 
        16);        
    memcpy(bData, \
           "\x04\x12\x34\xFF\x37\x1C\xF2\xA4" \
           "\x04\x12\x34\xFF\x37\x1C\xF2\xA4" \
           "\x12" \
           , 17);
    nLen = 17;
    /* 669D80C23AED1147ACD33BB3E532B2B8 */
    /* 041234FF371CF2A4041234FF371CF2A4 12800000000000000000000000000000 */
    /* 23999E471636728FEB96DBD9D4A8EC55 1F16A214 377AD77866BD6E3E47ED2C4D */
    memcpy(bMACExp,"\x1F\x16\xA2\x14\x37\x7A\xD7\x78", 8);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]nIccType  = %x\n", nIccType);
    DspHex("[IN ]bKey       =", bKey, 16);
    DspHex("[IN ]bCardFactor =", bCardFactor, 16);
    DspHex("[IN ]bSessionFactor =", bSessionFactor, 16);
    DspHex("[IN ]bInData     =", bData, nLen);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPICalcMacWithDerivedKey(nSock, nIccType, bKey, bCardFactor,
                               bSessionFactor, bData, nLen, bMAC);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "PBOC卡，SM4, 测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    DspHex("[OUT]bMAC =", bMAC, 8);
    ASSERT_OUT_HEX(bMAC, bMACExp, 8);
    XXX_OUTPUT_XXX

//    DspHex("[RESULT ]expected Data =", bMACExp, 8);
//    DspHex("[RESULT ]calculated Data  =", bMAC, 8);

    XXX_TEST_END_XXX
}

void GenEccKey_Test_01(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nIndex;
    int  nEcMark;
    BYTE bPK[2048];
    int  nPKLen;
    BYTE bSK[2048];
    int  nSKLen;

    bufclr(bPK);
    bufclr(bSK);
    nPKLen = 0;
    nSKLen = 0;

    nIndex = 0;
    nEcMark = 17;

    XXX_INPUT_XXX
    printf("[IN ]nSock   = %d\n", nSock);
    printf("[IN ]nIndex  = %d\n", nIndex);
    printf("[IN ]nEcMark = %d\n", nEcMark);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIGenEccKey(nSock, nIndex, nEcMark, bPK, &nPKLen, bSK, &nSKLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "索引号=0，SM2密钥对生成，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[VERIFY]请确认以下结果:\n");
    DspHexExt("[OUT]bPK     =", bPK, nPKLen);
    printf("[OUT]nPKLen  = %d\n", nPKLen);
    DspHexExt("[OUT]bSK     =", bSK, nSKLen);
    printf("[OUT]nSKLen  = %d\n", nSKLen);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void GenEccKey_Test_02(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nIndex;
    int  nEcMark;
    BYTE bPK[2048];
    int  nPKLen;
    BYTE bSK[2048];
    int  nSKLen;

    bufclr(bPK);
    bufclr(bSK);
    nPKLen = 0;
    nSKLen = 0;

    nIndex = 1;
    nEcMark = 17;

    XXX_INPUT_XXX
    printf("[IN ]nSock   = %d\n", nSock);
    printf("[IN ]nIndex  = %d\n", nIndex);
    printf("[IN ]nEcMark = %d\n", nEcMark);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIGenEccKey(nSock, nIndex, nEcMark, bPK, &nPKLen, bSK, &nSKLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "索引号=1，SM2密钥对生成，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[VERIFY]请确认以下结果:\n");
    DspHexExt("[OUT]bPK     =", bPK, nPKLen + 8);
    printf("[OUT]nPKLen  = %d\n", nPKLen);
    DspHexExt("[OUT]bSK     =", bSK, nSKLen + 8);
    printf("[OUT]nSKLen  = %d\n", nSKLen);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void GenEccKey_Test_03(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nIndex;
    int  nEcMark;
    BYTE bPK[2048];
    int  nPKLen;
    BYTE bSK[2048];
    int  nSKLen;

    bufclr(bPK);
    bufclr(bSK);
    nPKLen = 0;
    nSKLen = 0;

    nIndex = 19;
    nEcMark = 17;

    XXX_INPUT_XXX
    printf("[IN ]nSock   = %d\n", nSock);
    printf("[IN ]nIndex  = %d\n", nIndex);
    printf("[IN ]nEcMark = %d\n", nEcMark);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIGenEccKey(nSock, nIndex, nEcMark, bPK, &nPKLen, bSK, &nSKLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "索引号=19，SM2密钥对生成，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[VERIFY]请确认以下结果:\n");
    DspHexExt("[OUT]bPK     =", bPK, nPKLen + 8);
    printf("[OUT]nPKLen  = %d\n", nPKLen);
    DspHexExt("[OUT]bSK     =", bSK, nSKLen + 8);
    printf("[OUT]nSKLen  = %d\n", nSKLen);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void GenEccKey_Test_04(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nIndex;
    int  nEcMark;
    BYTE bPK[2048];
    int  nPKLen;
    BYTE bSK[2048];
    int  nSKLen;

    bufclr(bPK);
    bufclr(bSK);
    nPKLen = 0;
    nSKLen = 0;

    nIndex = 0;
    nEcMark = 3;

    XXX_INPUT_XXX
    printf("[IN ]nSock   = %d\n", nSock);
    printf("[IN ]nIndex  = %d\n", nIndex);
    printf("[IN ]nEcMark = %d\n", nEcMark);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIGenEccKey(nSock, nIndex, nEcMark, bPK, &nPKLen, bSK, &nSKLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 1, "SM2密钥对生成，异常椭圆曲线标识3，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void GetEccPkBySk_Test_01(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nEcMark;
    BYTE bPK[2048];
    int  nPKLen;
    BYTE bPKExp[2048];
    int  nPKLenExp;
    BYTE bSK[2048];
    int  nSKLen;

    bufclr(bPK);
    bufclr(bPKExp);
    bufclr(bSK);
    nPKLen = 0;
    nSKLen = 0;

    nEcMark = 17;

    /* PK 043D646AB3D38385671D39B5E16E5DD9D50494CBBDF2F572C7EAD7FB19562A794268CA6BAD0ED9DFF174659F3B37C1F602A0B817696CD18E9CB76F9F14071D4E93 */
    /* SK D4DD2D2973965C23038CA4085E80F3E3E1BD400023A9DEDD73BDC91556E65B4E */
    /* 3C8E 44A7 0C79 C17D 936A 3968 0797 ECD1 FB1C 763B 995C F205 3CF8 1E2E B3DB 715E 6BCB 2CCA 658B FD78 */
    memcpy(bPKExp,
           "\x04\x3D\x64\x6A\xB3\xD3\x83\x85" \
           "\x67\x1D\x39\xB5\xE1\x6E\x5D\xD9" \
           "\xD5\x04\x94\xCB\xBD\xF2\xF5\x72" \
           "\xC7\xEA\xD7\xFB\x19\x56\x2A\x79" \
           "\x42\x68\xCA\x6B\xAD\x0E\xD9\xDF" \
           "\xF1\x74\x65\x9F\x3B\x37\xC1\xF6" \
           "\x02\xA0\xB8\x17\x69\x6C\xD1\x8E" \
           "\x9C\xB7\x6F\x9F\x14\x07\x1D\x4E" \
           "\x93", 65);
    nPKLenExp = 65;
    memcpy(bSK,
           "\x3C\x8E\x44\xA7\x0C\x79\xC1\x7D" \
           "\x93\x6A\x39\x68\x07\x97\xEC\xD1" \
           "\xFB\x1C\x76\x3B\x99\x5C\xF2\x05" \
           "\x3C\xF8\x1E\x2E\xB3\xDB\x71\x5E" \
           "\x6B\xCB\x2C\xCA\x65\x8B\xFD\x78" \
           , 40);
    nSKLen = 40;

    XXX_INPUT_XXX
    printf("[IN ]nSock   = %d\n", nSock);
    printf("[IN ]nEcMark = %d\n", nEcMark);
    DspHex("[IN ]bSK     =", bSK, nSKLen);
    printf("[IN ]nSKLen  = %d\n", nSKLen);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIGetEccPkBySk(nSock, nEcMark, bSK, nSKLen, bPK, &nPKLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "根据ECC私钥生成公钥，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    ASSERT_OUT(nPKLen, nPKLenExp);
    ASSERT_OUT_HEX(bPK, bPKExp, nPKLen + 8);
//    DspHex("[OUT]bPK     =", bPK, nPKLen + 8);
//    printf("[OUT]nPKLen  = %d\n", nPKLen);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void GetEccPkBySk_Test_02(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nEcMark;
    BYTE bPK[2048];
    int  nPKLen;
    BYTE bPKExp[2048];
    int  nPKLenExp;
    BYTE bSK[2048];
    int  nSKLen;

    bufclr(bPK);
    bufclr(bPKExp);
    bufclr(bSK);
    nPKLen = 0;
    nSKLen = 0;

    nEcMark = 3;

    /* PK 043D646AB3D38385671D39B5E16E5DD9D50494CBBDF2F572C7EAD7FB19562A794268CA6BAD0ED9DFF174659F3B37C1F602A0B817696CD18E9CB76F9F14071D4E93 */
    /* SK D4DD2D2973965C23038CA4085E80F3E3E1BD400023A9DEDD73BDC91556E65B4E */
    /* 3C8E 44A7 0C79 C17D 936A 3968 0797 ECD1 FB1C 763B 995C F205 3CF8 1E2E B3DB 715E 6BCB 2CCA 658B FD78 */
    memcpy(bPKExp,
           "\x04\x3D\x64\x6A\xB3\xD3\x83\x85" \
           "\x67\x1D\x39\xB5\xE1\x6E\x5D\xD9" \
           "\xD5\x04\x94\xCB\xBD\xF2\xF5\x72" \
           "\xC7\xEA\xD7\xFB\x19\x56\x2A\x79" \
           "\x42\x68\xCA\x6B\xAD\x0E\xD9\xDF" \
           "\xF1\x74\x65\x9F\x3B\x37\xC1\xF6" \
           "\x02\xA0\xB8\x17\x69\x6C\xD1\x8E" \
           "\x9C\xB7\x6F\x9F\x14\x07\x1D\x4E" \
           "\x93", 65);
    nPKLenExp = 65;
    memcpy(bSK,
           "\x3C\x8E\x44\xA7\x0C\x79\xC1\x7D" \
           "\x93\x6A\x39\x68\x07\x97\xEC\xD1" \
           "\xFB\x1C\x76\x3B\x99\x5C\xF2\x05" \
           "\x3C\xF8\x1E\x2E\xB3\xDB\x71\x5E" \
           "\x6B\xCB\x2C\xCA\x65\x8B\xFD\x78" \
           , 40);
    nSKLen = 40;

    XXX_INPUT_XXX
    printf("[IN ]nSock   = %d\n", nSock);
    printf("[IN ]nEcMark = %d\n", nEcMark);
    DspHex("[IN ]bSK     =", bSK, nSKLen);
    printf("[IN ]nSKLen  = %d\n", nSKLen);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIGetEccPkBySk(nSock, nEcMark, bSK, nSKLen, bPK, &nPKLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 1, "根据ECC私钥生成公钥，异常椭圆曲线标识3，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void GetEccPkBySk_Test_03(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nEcMark;
    BYTE bPK[2048];
    int  nPKLen;
    BYTE bPKExp[2048];
    int  nPKLenExp;
    BYTE bSK[2048];
    int  nSKLen;

    bufclr(bPK);
    bufclr(bPKExp);
    bufclr(bSK);
    nPKLen = 0;
    nSKLen = 0;

    nEcMark = 17;

    /* PK 0400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 */
    /* SK FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123 */
    /* 1BB5 163C EFEE D2D0 7B81 70A0 4A60 4D9B 7612 9F21 7D5F 9558 1149 5A1A 9EED C403 6BCB 2CCA 658B FD78 */
    memcpy(bPKExp,
           "\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
           "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
           "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
           "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
           "\x00" \
           , 65);
    nPKLenExp = 65;
    memcpy(bSK,
           "\x1B\xB5\x16\x3C\xEF\xEE\xD2\xD0\x7B\x81\x70\xA0\x4A\x60\x4D\x9B" \
           "\x76\x12\x9F\x21\x7D\x5F\x95\x58\x11\x49\x5A\x1A\x9E\xED\xC4\x03" \
           "\x6B\xCB\x2C\xCA\x65\x8B\xFD\x78" \
           , 40);
    nSKLen = 40;

    XXX_INPUT_XXX
    printf("[IN ]nSock   = %d\n", nSock);
    printf("[IN ]nEcMark = %d\n", nEcMark);
    DspHex("[IN ]bSK     =", bSK, nSKLen);
    printf("[IN ]nSKLen  = %d\n", nSKLen);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIGetEccPkBySk(nSock, nEcMark, bSK, nSKLen, bPK, &nPKLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 1, "根据ECC私钥生成公钥，特殊私钥d=n，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void GetEccPkBySk_Test_04(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nEcMark;
    BYTE bPK[2048];
    int  nPKLen;
    BYTE bPKExp[2048];
    int  nPKLenExp;
    BYTE bSK[2048];
    int  nSKLen;

    bufclr(bPK);
    bufclr(bPKExp);
    bufclr(bSK);
    nPKLen = 0;
    nSKLen = 0;

    nEcMark = 17;

    /* PK 0400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 */
    /* SK 0000000000000000000000000000000000000000000000000000000000000000 */
    /* 1F1E A825 5422 D275 1F1E A825 5422 D275 1F1E A825 5422 D275 1F1E A825 5422 D275 6BCB 2CCA 658B FD78 */
    memcpy(bPKExp,
           "\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
           "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
           "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
           "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
           "\x00" \
           , 65);
    nPKLenExp = 65;
    memcpy(bSK,
           "\x1F\x1E\xA8\x25\x54\x22\xD2\x75\x1F\x1E\xA8\x25\x54\x22\xD2\x75" \
           "\x1F\x1E\xA8\x25\x54\x22\xD2\x75\x1F\x1E\xA8\x25\x54\x22\xD2\x75" \
           "\x6B\xCB\x2C\xCA\x65\x8B\xFD\x78" \
           , 40);
    nSKLen = 40;

    XXX_INPUT_XXX
    printf("[IN ]nSock   = %d\n", nSock);
    printf("[IN ]nEcMark = %d\n", nEcMark);
    DspHex("[IN ]bSK     =", bSK, nSKLen);
    printf("[IN ]nSKLen  = %d\n", nSKLen);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIGetEccPkBySk(nSock, nEcMark, bSK, nSKLen, bPK, &nPKLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 1, "根据ECC私钥生成公钥，特殊私钥d=0，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void GetEccPkBySk_Test_05(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nEcMark;
    BYTE bPK[2048];
    int  nPKLen;
    BYTE bPKExp[2048];
    int  nPKLenExp;
    BYTE bSK[2048];
    int  nSKLen;

    bufclr(bPK);
    bufclr(bPKExp);
    bufclr(bSK);
    nPKLen = 0;
    nSKLen = 0;

    nEcMark = 17;

    /* PK 0432C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C743C8C95C0B098863A642311C9496DEAC2F56788239D5B8C0FD20CD1ADEC60F5F */
    /* SK FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54122 */
    /* 1BB5 163C EFEE D2D0 7B81 70A0 4A60 4D9B 7612 9F21 7D5F 9558 6F7E FC0B 9EC9 E979 6BCB 2CCA 658B FD78 */
    memcpy(bPKExp,
           "\x04\x32\xC4\xAE\x2C\x1F\x19\x81\x19\x5F\x99\x04\x46\x6A\x39\xC9" \
           "\x94\x8F\xE3\x0B\xBF\xF2\x66\x0B\xE1\x71\x5A\x45\x89\x33\x4C\x74" \
           "\xC7\x43\xC8\xC9\x5C\x0B\x09\x88\x63\xA6\x42\x31\x1C\x94\x96\xDE" \
           "\xAC\x2F\x56\x78\x82\x39\xD5\xB8\xC0\xFD\x20\xCD\x1A\xDE\xC6\x0F" \
           "\x5F" \
           , 65);
    nPKLenExp = 65;
    memcpy(bSK,
           "\x1B\xB5\x16\x3C\xEF\xEE\xD2\xD0\x7B\x81\x70\xA0\x4A\x60\x4D\x9B" \
           "\x76\x12\x9F\x21\x7D\x5F\x95\x58\x6F\x7E\xFC\x0B\x9E\xC9\xE9\x79" \
           "\x6B\xCB\x2C\xCA\x65\x8B\xFD\x78" \
           , 40);
    nSKLen = 40;

    XXX_INPUT_XXX
    printf("[IN ]nSock   = %d\n", nSock);
    printf("[IN ]nEcMark = %d\n", nEcMark);
    DspHex("[IN ]bSK     =", bSK, nSKLen);
    printf("[IN ]nSKLen  = %d\n", nSKLen);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIGetEccPkBySk(nSock, nEcMark, bSK, nSKLen, bPK, &nPKLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 1, "根据ECC私钥生成公钥，特殊私钥d=n-1，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void GetEccPkBySk_Test_06(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nEcMark;
    BYTE bPK[2048];
    int  nPKLen;
    BYTE bPKExp[2048];
    int  nPKLenExp;
    BYTE bSK[2048];
    int  nSKLen;

    bufclr(bPK);
    bufclr(bPKExp);
    bufclr(bSK);
    nPKLen = 0;
    nSKLen = 0;

    nEcMark = 17;

    /* PK 0432C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0 */
    /* SK 0000000000000000000000000000000000000000000000000000000000000001 */
    /* 1F1E A825 5422 D275 1F1E A825 5422 D275 1F1E A825 5422 D275 7219 14A9 8C42 3707 6BCB 2CCA 658B FD78 */
    memcpy(bPKExp,
           "\x04\x32\xC4\xAE\x2C\x1F\x19\x81\x19\x5F\x99\x04\x46\x6A\x39\xC9" \
           "\x94\x8F\xE3\x0B\xBF\xF2\x66\x0B\xE1\x71\x5A\x45\x89\x33\x4C\x74" \
           "\xC7\xBC\x37\x36\xA2\xF4\xF6\x77\x9C\x59\xBD\xCE\xE3\x6B\x69\x21" \
           "\x53\xD0\xA9\x87\x7C\xC6\x2A\x47\x40\x02\xDF\x32\xE5\x21\x39\xF0" \
           "\xA0" \
           , 65);
    nPKLenExp = 65;
    memcpy(bSK,
           "\x1F\x1E\xA8\x25\x54\x22\xD2\x75\x1F\x1E\xA8\x25\x54\x22\xD2\x75" \
           "\x1F\x1E\xA8\x25\x54\x22\xD2\x75\x72\x19\x14\xA9\x8C\x42\x37\x07" \
           "\x6B\xCB\x2C\xCA\x65\x8B\xFD\x78" \
           , 40);
    nSKLen = 40;

    XXX_INPUT_XXX
    printf("[IN ]nSock   = %d\n", nSock);
    printf("[IN ]nEcMark = %d\n", nEcMark);
    DspHex("[IN ]bSK     =", bSK, nSKLen);
    printf("[IN ]nSKLen  = %d\n", nSKLen);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIGetEccPkBySk(nSock, nEcMark, bSK, nSKLen, bPK, &nPKLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "根据ECC私钥生成公钥，特殊私钥d=1，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    ASSERT_OUT(nPKLen, nPKLenExp);
    ASSERT_OUT_HEX(bPK, bPKExp, nPKLen + 8);
//    DspHex("[OUT]bPK     =", bPK, nPKLen + 8);
//    printf("[OUT]nPKLen  = %d\n", nPKLen);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void GetEccPkBySk_Test_07(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nEcMark;
    BYTE bPK[2048];
    int  nPKLen;
    BYTE bPKExp[2048];
    int  nPKLenExp;
    BYTE bSK[2048];
    int  nSKLen;

    bufclr(bPK);
    bufclr(bPKExp);
    bufclr(bSK);
    nPKLen = 0;
    nSKLen = 0;

    nEcMark = 17;

    /* PK 0456CEFD60D7C87C000D58EF57FA73BA4D9C0DFA08C08A7331495C2E1DA3F2BD52CE481818337E760997ACA31F07150E429217B3E6D093718F9087F2C568F5DC3C */
    /* SK FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54121 */
    /* 1BB5 163C EFEE D2D0 7B81 70A0 4A60 4D9B 7612 9F21 7D5F 9558 37A6 24EB 5673 85E3 6BCB 2CCA 658B FD78 */
    memcpy(bPKExp,
           "\x04\x56\xCE\xFD\x60\xD7\xC8\x7C\x00\x0D\x58\xEF\x57\xFA\x73\xBA" \
           "\x4D\x9C\x0D\xFA\x08\xC0\x8A\x73\x31\x49\x5C\x2E\x1D\xA3\xF2\xBD" \
           "\x52\xCE\x48\x18\x18\x33\x7E\x76\x09\x97\xAC\xA3\x1F\x07\x15\x0E" \
           "\x42\x92\x17\xB3\xE6\xD0\x93\x71\x8F\x90\x87\xF2\xC5\x68\xF5\xDC" \
           "\x3C" \
           , 65);
    nPKLenExp = 65;
    memcpy(bSK,
           "\x1B\xB5\x16\x3C\xEF\xEE\xD2\xD0\x7B\x81\x70\xA0\x4A\x60\x4D\x9B" \
           "\x76\x12\x9F\x21\x7D\x5F\x95\x58\x37\xA6\x24\xEB\x56\x73\x85\xE3" \
           "\x6B\xCB\x2C\xCA\x65\x8B\xFD\x78" \
           , 40);
    nSKLen = 40;

    XXX_INPUT_XXX
    printf("[IN ]nSock   = %d\n", nSock);
    printf("[IN ]nEcMark = %d\n", nEcMark);
    DspHex("[IN ]bSK     =", bSK, nSKLen);
    printf("[IN ]nSKLen  = %d\n", nSKLen);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIGetEccPkBySk(nSock, nEcMark, bSK, nSKLen, bPK, &nPKLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "根据ECC私钥生成公钥，特殊私钥d=n-2，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    ASSERT_OUT(nPKLen, nPKLenExp);
    ASSERT_OUT_HEX(bPK, bPKExp, nPKLen + 8);
//    DspHex("[OUT]bPK     =", bPK, nPKLen + 8);
//    printf("[OUT]nPKLen  = %d\n", nPKLen);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void GetEccPkBySk_Test_08(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nEcMark;
    BYTE bPK[2048];
    int  nPKLen;
    BYTE bPKExp[2048];
    int  nPKLenExp;
    BYTE bSK[2048];
    int  nSKLen;

    bufclr(bPK);
    bufclr(bPKExp);
    bufclr(bSK);
    nPKLen = 0;
    nSKLen = 0;

    nEcMark = 17;

    /* PK 0432C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0 */
    /* SK FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54124 */
    /* 1BB5 163C EFEE D2D0 7B81 70A0 4A60 4D9B 7612 9F21 7D5F 9558 3871 0260 74BF DCCF 6BCB 2CCA 658B FD78 */
    memcpy(bPKExp,
           "\x04\x32\xC4\xAE\x2C\x1F\x19\x81\x19\x5F\x99\x04\x46\x6A\x39\xC9" \
           "\x94\x8F\xE3\x0B\xBF\xF2\x66\x0B\xE1\x71\x5A\x45\x89\x33\x4C\x74" \
           "\xC7\xBC\x37\x36\xA2\xF4\xF6\x77\x9C\x59\xBD\xCE\xE3\x6B\x69\x21" \
           "\x53\xD0\xA9\x87\x7C\xC6\x2A\x47\x40\x02\xDF\x32\xE5\x21\x39\xF0" \
           "\xA0" \
           , 65);
    nPKLenExp = 65;
    memcpy(bSK,
           "\x1B\xB5\x16\x3C\xEF\xEE\xD2\xD0\x7B\x81\x70\xA0\x4A\x60\x4D\x9B" \
           "\x76\x12\x9F\x21\x7D\x5F\x95\x58\x38\x71\x02\x60\x74\xBF\xDC\xCF" \
           "\x6B\xCB\x2C\xCA\x65\x8B\xFD\x78" \
           , 40);
    nSKLen = 40;

    XXX_INPUT_XXX
    printf("[IN ]nSock   = %d\n", nSock);
    printf("[IN ]nEcMark = %d\n", nEcMark);
    DspHex("[IN ]bSK     =", bSK, nSKLen);
    printf("[IN ]nSKLen  = %d\n", nSKLen);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIGetEccPkBySk(nSock, nEcMark, bSK, nSKLen, bPK, &nPKLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "根据ECC私钥生成公钥，特殊私钥d=n+1，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    ASSERT_OUT(nPKLen, nPKLenExp);
    ASSERT_OUT_HEX(bPK, bPKExp, nPKLen + 8);
//    DspHex("[OUT]bPK     =", bPK, nPKLen + 8);
//    printf("[OUT]nPKLen  = %d\n", nPKLen);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void EccPkEncrypt_Test_01(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nEcMark;
    int  nPad;
    BYTE bPK[256];
    int  nPKLen;
    BYTE bInData[1024];
    int  nInDataLen;
    BYTE bOutData[1024];
    int  nOutDataLen;

    bufclr(bPK);
    bufclr(bInData);
    bufclr(bOutData);
    nPKLen = 0;

    nEcMark = 17;
    nPad = 0;

    /* PK 043D646AB3D38385671D39B5E16E5DD9D50494CBBDF2F572C7EAD7FB19562A794268CA6BAD0ED9DFF174659F3B37C1F602A0B817696CD18E9CB76F9F14071D4E93 */
    /* SK D4DD2D2973965C23038CA4085E80F3E3E1BD400023A9DEDD73BDC91556E65B4E */
    /* 3C8E44A70C79C17D936A39680797ECD1FB1C763B995CF2053CF81E2EB3DB715E6BCB2CCA658BFD78 */
    memcpy(bPK,
           "\x04\x3D\x64\x6A\xB3\xD3\x83\x85" \
           "\x67\x1D\x39\xB5\xE1\x6E\x5D\xD9" \
           "\xD5\x04\x94\xCB\xBD\xF2\xF5\x72" \
           "\xC7\xEA\xD7\xFB\x19\x56\x2A\x79" \
           "\x42\x68\xCA\x6B\xAD\x0E\xD9\xDF" \
           "\xF1\x74\x65\x9F\x3B\x37\xC1\xF6" \
           "\x02\xA0\xB8\x17\x69\x6C\xD1\x8E" \
           "\x9C\xB7\x6F\x9F\x14\x07\x1D\x4E" \
           "\x93", 65);
    nPKLen = 65;

    /* 0BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB9 */
    memset(bInData, 0x42, 64);
    bInData[0] = 0x30;
    bInData[63] = 0x39;
    nInDataLen = 64;

    XXX_INPUT_XXX
    printf("[IN ]nSock   = %d\n", nSock);
    printf("[IN ]nEcMark = %d\n", nEcMark);
    printf("[IN ]nPad    = %d\n", nPad);
    DspHexExt("[IN ]bPK     =", bPK, nPKLen);
    printf("[IN ]nPKLen  = %d\n", nPKLen);
    DspHexExt("[IN ]bInData =", bInData, nInDataLen);
    printf("[IN ]nInDataLen = %d\n", nInDataLen);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIEccPkEncrypt(nSock, nEcMark, nPad, bPK, nPKLen, bInData, nInDataLen, bOutData, &nOutDataLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "ECC公钥加密，64字节数据，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[VERIFY]请确认以下结果:\n");
    DspHexExt("[OUT]bOutData     =", bOutData, nOutDataLen);
    printf("[OUT]nOutDataLen  = %d\n", nOutDataLen);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

char RET[4096];

void EccPkEncrypt_Test_02(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nEcMark;
    int  nPad;
    BYTE bPK[256];
    int  nPKLen;
    BYTE bInData[4000];
    int  nInDataLen;
    BYTE bOutData[4096];
    int  nOutDataLen;

    bufclr(bPK);
    bufclr(bInData);
    bufclr(bOutData);
    nPKLen = 0;

    nEcMark = 17;
    nPad = 0;

    /* PK 043D646AB3D38385671D39B5E16E5DD9D50494CBBDF2F572C7EAD7FB19562A794268CA6BAD0ED9DFF174659F3B37C1F602A0B817696CD18E9CB76F9F14071D4E93 */
    /* SK D4DD2D2973965C23038CA4085E80F3E3E1BD400023A9DEDD73BDC91556E65B4E */
    /* 3C8E44A70C79C17D936A39680797ECD1FB1C763B995CF2053CF81E2EB3DB715E6BCB2CCA658BFD78 */
    memcpy(bPK,
           "\x04\x3D\x64\x6A\xB3\xD3\x83\x85" \
           "\x67\x1D\x39\xB5\xE1\x6E\x5D\xD9" \
           "\xD5\x04\x94\xCB\xBD\xF2\xF5\x72" \
           "\xC7\xEA\xD7\xFB\x19\x56\x2A\x79" \
           "\x42\x68\xCA\x6B\xAD\x0E\xD9\xDF" \
           "\xF1\x74\x65\x9F\x3B\x37\xC1\xF6" \
           "\x02\xA0\xB8\x17\x69\x6C\xD1\x8E" \
           "\x9C\xB7\x6F\x9F\x14\x07\x1D\x4E" \
           "\x93", 65);
    nPKLen = 65;

    memset(bInData, 0x42, 4000);
    bInData[0] = 0x30;
    bInData[3999] = 0x39;
    nInDataLen = 4000;

    XXX_INPUT_XXX
    printf("[IN ]nSock   = %d\n", nSock);
    printf("[IN ]nEcMark = %d\n", nEcMark);
    printf("[IN ]nPad    = %d\n", nPad);
    DspHexExt("[IN ]bPK     =", bPK, nPKLen);
    printf("[IN ]nPKLen  = %d\n", nPKLen);
    DspHexExt("[IN ]bInData =", bInData, nInDataLen);
    printf("[IN ]nInDataLen = %d\n", nInDataLen);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIEccPkEncrypt(nSock, nEcMark, nPad, bPK, nPKLen, bInData, nInDataLen, bOutData, &nOutDataLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "ECC公钥加密，4000字节数据，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[VERIFY]请确认以下结果:\n");
    DspHexExt("[OUT]bOutData     =", bOutData, nOutDataLen);
    printf("[OUT]nOutDataLen  = %d\n", nOutDataLen);
    XXX_OUTPUT_XXX
    
    memcpy(RET, bOutData, 4096);

    XXX_TEST_END_XXX
}

void EccPkEncrypt_Test_03(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nEcMark;
    int  nPad;
    BYTE bPK[256];
    int  nPKLen;
    BYTE bInData[1024];
    int  nInDataLen;
    BYTE bOutData[1024];
    int  nOutDataLen;

    bufclr(bPK);
    bufclr(bInData);
    bufclr(bOutData);
    nPKLen = 0;

    nEcMark = 17;
    nPad = 0;

    /* PK 0400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 */
    /* SK 0000000000000000000000000000000000000000000000000000000000000000 */
    /* 1F1EA8255422D2751F1EA8255422D2751F1EA8255422D2751F1EA8255422D2756BCB2CCA658BFD78 */
    memcpy(bPK,
           "\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
           "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
           "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
           "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
           "\x00" \
           , 65);
    nPKLen = 65;

    /* 0BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB9 */
    memset(bInData, 0x42, 64);
    bInData[0] = 0x30;
    bInData[63] = 0x39;
    nInDataLen = 64;

    XXX_INPUT_XXX
    printf("[IN ]nSock   = %d\n", nSock);
    printf("[IN ]nEcMark = %d\n", nEcMark);
    printf("[IN ]nPad    = %d\n", nPad);
    DspHexExt("[IN ]bPK     =", bPK, nPKLen);
    printf("[IN ]nPKLen  = %d\n", nPKLen);
    DspHexExt("[IN ]bInData =", bInData, nInDataLen);
    printf("[IN ]nInDataLen = %d\n", nInDataLen);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIEccPkEncrypt(nSock, nEcMark, nPad, bPK, nPKLen, bInData, nInDataLen, bOutData, &nOutDataLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 1, "ECC公钥加密，无效公钥，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void EccSkDecrypt_Test_01(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nEcMark;
    int  nPad;
    BYTE bSK[256];
    int  nSKLen;
    BYTE bInData[1024];
    int  nInDataLen;
    BYTE bOutData[1024];
    int  nOutDataLen;
    BYTE bOutDataExp[1024];
    int  nOutDataLenExp;

    bufclr(bSK);
    bufclr(bInData);
    bufclr(bOutData);
    nSKLen = 0;

    nEcMark = 17;
    nPad = 0;

    /* PK 043D646AB3D38385671D39B5E16E5DD9D50494CBBDF2F572C7EAD7FB19562A794268CA6BAD0ED9DFF174659F3B37C1F602A0B817696CD18E9CB76F9F14071D4E93 */
    /* SK D4DD2D2973965C23038CA4085E80F3E3E1BD400023A9DEDD73BDC91556E65B4E */
    /* SKByHMK 3C8E44A70C79C17D936A39680797ECD1FB1C763B995CF2053CF81E2EB3DB715E6BCB2CCA658BFD78 */
    memcpy(bSK,
           "\x3C\x8E\x44\xA7\x0C\x79\xC1\x7D" \
           "\x93\x6A\x39\x68\x07\x97\xEC\xD1" \
           "\xFB\x1C\x76\x3B\x99\x5C\xF2\x05" \
           "\x3C\xF8\x1E\x2E\xB3\xDB\x71\x5E" \
           "\x6B\xCB\x2C\xCA\x65\x8B\xFD\x78" \
           , 40);
    nSKLen = 40;

    /* 0BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB9 */
    /* 30424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424239 */
    /* 33444C86A46ED7FADB2DA1203331B59EB53597CF5E6FE9CC7058852CC9642088C59EC6B87E59474936B41222F81DEB9A04A377592B17F11A68715F5018FA18F57A05B29CE628DDBACC219E8E53D4B690233675CF9922D6E227BBC1567DF1E73D3D4941653F691F20D1E923D39CC844AF0AF9F120E04F7639A4C03D4D89A154250BAB9240EB55339DBC4186CAF1D6D5F9E298C557A5BA41B35EF07BA6D2573544 */
    memcpy(bInData,
           "\x33\x44\x4C\x86\xA4\x6E\xD7\xFA\xDB\x2D\xA1\x20\x33\x31\xB5\x9E" \
           "\xB5\x35\x97\xCF\x5E\x6F\xE9\xCC\x70\x58\x85\x2C\xC9\x64\x20\x88" \
           "\xC5\x9E\xC6\xB8\x7E\x59\x47\x49\x36\xB4\x12\x22\xF8\x1D\xEB\x9A" \
           "\x04\xA3\x77\x59\x2B\x17\xF1\x1A\x68\x71\x5F\x50\x18\xFA\x18\xF5" \
           "\x7A\x05\xB2\x9C\xE6\x28\xDD\xBA\xCC\x21\x9E\x8E\x53\xD4\xB6\x90" \
           "\x23\x36\x75\xCF\x99\x22\xD6\xE2\x27\xBB\xC1\x56\x7D\xF1\xE7\x3D" \
           "\x3D\x49\x41\x65\x3F\x69\x1F\x20\xD1\xE9\x23\xD3\x9C\xC8\x44\xAF" \
           "\x0A\xF9\xF1\x20\xE0\x4F\x76\x39\xA4\xC0\x3D\x4D\x89\xA1\x54\x25" \
           "\x0B\xAB\x92\x40\xEB\x55\x33\x9D\xBC\x41\x86\xCA\xF1\xD6\xD5\xF9" \
           "\xE2\x98\xC5\x57\xA5\xBA\x41\xB3\x5E\xF0\x7B\xA6\xD2\x57\x35\x44" \
           , 160);
    nInDataLen = 160;
    memset(bOutDataExp, 0x42, 64);
    bOutDataExp[0] = 0x30;
    bOutDataExp[63] = 0x39;
    nOutDataLenExp = 64;

    XXX_INPUT_XXX
    printf("[IN ]nSock   = %d\n", nSock);
    printf("[IN ]nEcMark = %d\n", nEcMark);
    printf("[IN ]nPad    = %d\n", nPad);
    DspHex("[IN ]bSK     =", bSK, nSKLen);
    printf("[IN ]nSKLen  = %d\n", nSKLen);
    DspHex("[IN ]bInData =", bInData, nInDataLen);
    printf("[IN ]nInDataLen = %d\n", nInDataLen);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIEccSkDecrypt(nSock, nEcMark, nPad, bSK, nSKLen, bInData, nInDataLen, bOutData, &nOutDataLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "ECC私钥解密，64字节数据，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    ASSERT_OUT(nOutDataLen, nOutDataLenExp);
    ASSERT_OUT_HEX(bOutData, bOutDataExp, nOutDataLenExp);
    DspHex("[OUT]bOutData     =", bOutData, nOutDataLen);
    printf("[OUT]nOutDataLen  = %d\n", nOutDataLen);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void EccSkDecrypt_Test_02(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nEcMark;
    int  nPad;
    BYTE bSK[256];
    int  nSKLen;
    BYTE bInData[4096];
    int  nInDataLen;
    BYTE bOutData[4096];
    int  nOutDataLen;
    BYTE bOutDataExp[4096];
    int  nOutDataLenExp;

    bufclr(bSK);
    bufclr(bInData);
    bufclr(bOutData);
    nSKLen = 0;

    nEcMark = 17;
    nPad = 0;

    /* PK 043D646AB3D38385671D39B5E16E5DD9D50494CBBDF2F572C7EAD7FB19562A794268CA6BAD0ED9DFF174659F3B37C1F602A0B817696CD18E9CB76F9F14071D4E93 */
    /* SK D4DD2D2973965C23038CA4085E80F3E3E1BD400023A9DEDD73BDC91556E65B4E */
    /* 3C8E44A70C79C17D936A39680797ECD1FB1C763B995CF2053CF81E2EB3DB715E6BCB2CCA658BFD78 */
    memcpy(bSK,
           "\x3C\x8E\x44\xA7\x0C\x79\xC1\x7D" \
           "\x93\x6A\x39\x68\x07\x97\xEC\xD1" \
           "\xFB\x1C\x76\x3B\x99\x5C\xF2\x05" \
           "\x3C\xF8\x1E\x2E\xB3\xDB\x71\x5E" \
           "\x6B\xCB\x2C\xCA\x65\x8B\xFD\x78" \
           , 40);
    nSKLen = 40;
/*
    memcpy(bInData,
           "\x74\xFD\xDA\x99\x40\x65\x80\x13\x3B\xB8\xE8\x80\x4C\xE5\x88\xFE" \
           "\x6A\x4D\x36\x1F\x9C\x17\x82\xBC\x65\x40\x4C\x34\xC4\xAA\x97\xB9" \
           "\x46\x8E\x55\xB2\x0A\x00\x05\xCB\xB6\xDD\xAC\x55\x5D\x5C\x7D\xF3" \
           "\x20\xA6\x42\x2E\x5E\xFC\xE9\xEB\x7A\x7F\x86\x02\xB2\xED\xA7\x6F" \
           "\xE3\xC8\xE3\x40\x9A\x79\xC8\x77\xF7\xEB\x58\xB9\x91\x4A\xFB\x24" \
           "\xB0\x4A\x62\xE4\x8F\x17\x19\xEB\x94\xC9\x92\x20\xF8\x63\x46\xDA" \
           "\xBA\x66\x8B\x5A\xA2\xE1\xA0\x04\x42\x54\x24\x64\x2F\x61\x4A\x52" \
           "\x9E\x39\xF0\xBB\xBC\x63\x21\x5C\x9D\xA2\xC4\x86\x2B\x05\xA0\xCE" \
           "\x99\x0E\xC5\xFE\xC5\xB3\x96\x92\x45\xE6\x6C\xC9\x51\x48\x57\xE9" \
           "\xBF\xA0\xE6\x1C\x3C\x41\xB3\xD4\xAB\x72\x97\xDE\x22\xD3\x91\x4B" \
           "\xC6\x1B\x33\x96\x41\x7B\xD6\x6C\xA1\x2C\xED\xB7\xA7\xA6\xD5\x20" \
           "\xC9\x6B\xBB\x29\x51\xCE\x94\xD8\x24\x1D\xB7\xE5\xB8\xD8\xF5\x50" \
           "\x94\x62\x22\x57\x44\x00\xDB\xD6\x8D\x49\xCE\x5A\xB5\x19\x4B\x81" \
           "\xE0\x71\xCE\xEF\xB3\x6E\xBC\xFA\x11\x5C\xA4\xFC\x5A\xB2\x8E\x3A" \
           "\xF2\xDD\xE5\x01\xF9\xB4\xBD\x50\xE0\xB1\xD7\x29\x28\x5B\x49\xB8" \
           "\x67\x2F\x67\xD8\xE4\x33\x36\x6D\x4F\xAB\x71\x02\x4E\xC4\xAD\xAB" \
           "\x31\x55\xE5\xFB\x9D\xE9\xCE\x64\xEE\xE5\xCF\xDD\x03\xB2\x44\xCA" \
           "\x07\xBC\x34\x3C\xCC\x40\x5D\xFF\xDC\xA7\xC1\x7C\x0E\x66\x2E\xCE" \
           "\xB5\xE8\x40\x5C\xEC\xD1\x6B\x29\xF7\x66\x1B\x25\x2C\x27\xDF\xE3" \
           "\x32\xB3\x12\xA5\xC2\xC8\x9E\x02\xEE\x05\x52\x81\x59\x2D\x9F\xA2" \
           "\x85\xC2\x4D\xCE\xD2\xCE\x28\xCF\xAC\x2B\x36\xA0\xE3\xC1\x5C\xFF" \
           "\x2A\x3E\x0A\x65\x20\x2A\x3E\x86\xE7\x4C\x42\xEA\x64\x2D\x52\xB1" \
           "\xA2\x41\xB1\xCC\xC9\xCE\xF5\xC8\xC7\x8F\x06\x1B\x4D\xBC\x5B\xB3" \
           "\x1C\xEB\x10\x66\x01\x56\x0A\x1A\x0F\x80\xE8\x7D\xE6\x65\x91\xB0" \
           "\x24\x69\xC4\xC8\x6D\xC0\x41\xBE\xA1\x7A\xEE\x56\x2A\x80\xC7\x2F" \
           "\xBC\xFE\x9E\x1D\x7A\x7C\x08\x81\x3A\x82\x80\xB2\xB6\x0C\xB5\x5E" \
           "\x35\xD4\x84\xD3\xD6\x76\xA2\x98\xEB\x54\xED\xA1\xA4\xFC\xE5\xB4" \
           "\x7D\x6D\xF1\x96\x73\x2E\x0E\x65\xB8\x8E\xE1\xF6\x4C\x35\x0D\x27" \
           "\x3C\xF7\xBC\x1A\x25\x8A\x15\x4F\xC3\x22\x83\xF0\x3B\x37\x78\x56" \
           "\x5F\x33\xEC\x7B\x16\x1F\x32\x3F\xC1\x5C\x3F\x2B\x79\x48\x35\x74" \
           "\x06\x8B\x25\xC3\x92\x06\x14\xA8\xED\xDB\xC3\xE1\x4A\x77\x10\xC7" \
           "\xCC\x6B\x1B\xF9\xF4\x14\x66\xAB\x9B\xCD\x0D\xC6\xD8\xA2\xDB\xBB" \
           "\xA4\x3A\x9B\xB2\x23\x5B\x6F\xAA\x5D\x80\x45\x60\xB5\x4A\x3E\x9C" \
           "\x26\xB5\xEE\x9A\xE4\x98\x97\xAA\xE1\xD2\xD3\xB0\x65\xF0\x5F\x38" \
           "\xA0\xB9\x44\x05\x66\xAD\xA2\x23\x25\x7E\x86\x0E\x5A\x66\x4E\x5F" \
           "\xB0\x8C\x87\xAD\x38\x58\x20\x00\x98\x4C\x92\x56\x6A\xAC\x4D\x40" \
           "\xE2\xAF\x73\xD0\x84\x81\x01\xE4\xC1\x73\x4A\x32\xC6\xA4\x20\x2C" \
           "\xD9\x7A\x2C\x6C\x51\x7A\x04\x1B\x3E\x63\xC5\x0A\x1B\xBC\x9B\x86" \
           "\xDB\xF1\xFC\x51\xFD\x8F\xE8\x10\x0B\x86\xF7\xF8\x78\x77\x7D\x1B" \
           "\x73\x18\xAC\x0B\x9D\xE2\xC4\xE1\x6A\x5A\x56\x56\x30\xA5\x32\x7F" \
           "\x12\x68\xB1\xD6\x55\x0B\xF9\xDA\x13\xDA\xC5\x93\x88\x4D\xA3\x52" \
           "\x2D\x5E\xDC\x4D\x6B\x3F\x52\x6D\x18\x97\x61\xFB\x17\x22\xE2\xFF" \
           "\xA1\x23\x03\xF6\x68\x3F\x10\x53\x2B\x4E\x86\x6A\x1F\xA1\xC8\xE1" \
           "\x26\xE9\xEC\x77\xB8\x57\x05\x81\x25\x55\xB9\x88\x7B\x79\x62\x96" \
           "\xBD\xCC\xF1\xE3\x48\xCD\xE0\xDB\x98\xE1\x93\x2B\xE9\xE4\xEA\x79" \
           "\x89\x48\x24\x02\x9C\x54\x65\x23\xE5\x35\x4E\xDA\x96\xFE\xFC\x58" \
           "\x34\x86\x34\xEF\x73\xE5\xFD\xC9\x41\x40\x1E\xA8\xBE\xC1\x64\x8B" \
           "\x0D\xCC\xB9\x45\x16\x17\x0B\x3C\x9B\x0E\xC8\x72\x2B\xD9\x8E\x1D" \
           "\x7A\x1F\x5B\x38\xBF\x9D\xBB\x79\x63\xF3\x1B\x61\x04\xF7\xE4\x4F" \
           "\x9E\x41\xBF\x12\x91\xB8\x20\x0B\x6B\x5A\xD0\x6D\x49\x35\x90\xC5" \
           "\x35\x60\x86\x28\x22\x17\x6A\x2B\x5F\x9E\x9B\xAE\xDA\x23\x7F\x2E" \
           "\x7D\xDA\xB6\x12\xD8\xD6\xF7\xA4\x5A\xDD\x54\x80\xFF\x86\xEF\x0C" \
           "\x5C\x10\x4C\x18\x82\xA1\x84\xA1\x5D\xD1\xBE\x8B\xFA\x35\x01\x8A" \
           "\xA5\x6F\x26\x26\xE8\xB0\xD3\x4B\x20\x05\xDD\x5C\x83\x10\xCD\x85" \
           "\x9F\x10\xF9\x27\x86\xD9\x66\xE4\x9C\xBC\x35\x41\x01\x6C\xD1\xC5" \
           "\xCA\x78\x89\xED\x76\x6E\xD2\x45\x72\x75\x4D\xA9\x1F\x8F\xA2\x23" \
           "\x49\xD3\x78\xE1\x25\x09\x94\xA6\xF5\xB2\xE3\x06\xA6\xA6\x40\x2D" \
           "\x2A\xF8\xCB\x7A\x4D\x9D\x97\x81\x58\x8B\xAB\x8E\x2D\xB9\x42\x93" \
           "\x58\xBA\xD9\x52\xCD\x28\xFA\x5F\xB3\xA2\x79\x3A\x12\xD4\x43\x80" \
           "\x17\xD7\x1C\x39\x5D\x95\x9E\x2F\xC2\xAE\x9B\x14\xEE\xD5\x74\x8C" \
           "\x4B\xA7\x29\xE7\x84\x5B\x1B\x47\xD1\x26\x51\xE0\x27\x87\xFA\xB0" \
           "\xDB\x1F\x7E\x31\xE4\x2B\x8E\x78\x0A\x52\x7A\x73\xE4\x61\x68\x3E" \
           "\xDB\x07\x96\x86\x52\xDD\xC6\xA8\x55\x47\x72\xB7\xB3\x8C\xE7\x7E" \
           "\xB4\xA6\x70\xB1\x99\x88\x76\xE9\xD4\xDC\xA9\xCC\x46\xA7\x3D\x55" \
           , 1024);
    memcpy(&bInData[1024],
           "\xE7\x19\xDE\x10\x85\xEB\x18\x07\x66\x4F\xAC\x0B\x18\x12\x03\xBC" \
           "\xBA\xE1\xB4\x12\xF3\x43\x1C\xEB\xAD\xF1\x5A\x81\xFC\x32\x9A\x3B" \
           "\xD3\xA9\x91\x63\x15\xDF\xF8\x1E\x5B\x8B\xA2\x65\x42\xAA\x06\xCD" \
           "\xA9\xCE\x78\x4A\xB7\x3C\xA9\xCD\xE4\xE0\xF3\x9B\x28\xAB\x48\x97" \
           "\x08\xD9\x4A\x19\x43\x2C\x4A\xC2\x52\xB9\x1C\x5A\x51\xF7\x10\xC1" \
           "\x9B\xED\x84\x38\x62\xF7\xEF\x57\x2F\x69\xD5\x21\xB7\x1E\x0C\xD8" \
           "\x8A\x08\x0A\x8C\x20\xFE\x8C\x63\x46\x5F\xE0\x35\x04\x9F\xEC\x0E" \
           "\xFE\x8F\x04\xEB\xD4\x44\x66\x3C\xC8\x72\x46\x3D\xD9\x26\x80\xC1" \
           "\xA0\x0F\xCB\x22\x10\x4D\x62\xC2\xE0\xB0\xD9\x22\x43\xB5\x9B\xF8" \
           "\x45\x17\xB9\xAA\x2F\xB0\x6C\xAF\xB9\x61\xCC\x8E\x2A\x83\xD6\xC1" \
           "\x4D\x3F\x9E\x82\xBC\xDA\xC4\xC8\x8A\x37\x6F\x19\x29\x9C\x8A\xD4" \
           "\x6D\xB3\x0F\x06\x73\xD8\x64\xB0\x15\x66\x46\x63\xF2\xA0\x85\xC6" \
           "\xDE\xB5\xA8\xA8\xD6\x78\xE2\x25\x27\x4A\xCF\xD2\x0B\xE6\x1F\x57" \
           "\xCE\x0A\xD8\xE8\x71\xC8\x7C\x61\x8C\x58\x5F\xAF\x96\x4D\x38\x58" \
           "\xBA\xB5\xE6\xDB\xF8\x86\x6A\xBF\x02\x62\x3C\x94\xB1\xA2\xCF\x12" \
           "\x1B\x29\x20\x94\x20\x2C\xEE\x47\x07\xD4\xAF\xCD\xEC\x94\x0A\x84" \
           "\xD9\x17\x55\x0E\xC1\xFE\xDF\xF2\xF1\xBF\x53\x8A\x00\x7D\x5E\xF7" \
           "\x5B\x30\xC6\x35\xDF\xD8\xF3\xD7\x6F\xB3\x94\x35\x3E\x03\x03\x65" \
           "\x78\x0D\x8A\x7F\x32\x84\xD6\x5A\x9F\xA1\xDE\xC5\xBD\xA2\x94\xAB" \
           "\xF9\xCC\xAA\x11\xD6\xDB\x30\xF2\x75\x56\x70\x79\xFE\x70\xEE\xC8" \
           "\x87\x92\xF2\x94\xF2\x96\xD6\x74\x9A\x9E\x6C\x8F\xA5\x55\xD9\xEF" \
           "\xB5\xBC\xE6\x81\xDF\x4F\xCC\x3C\x41\x04\x48\xD1\x9C\x22\x4C\x0B" \
           "\x72\xC3\xDD\x45\x9A\xC6\xA4\x00\x3F\x68\x15\x91\xEE\x37\xD0\xEA" \
           "\x33\xBE\x74\x43\xB3\x51\x32\xCA\x8B\x97\xBB\x85\x28\x4D\x0B\x28" \
           "\xA8\x6F\x7A\xBF\xB9\xB5\xF1\x71\x11\xCB\x06\x85\x7F\x3F\xBF\xD2" \
           "\xF6\x2C\x87\x87\xD2\x37\x60\x76\x3D\x3B\x00\x04\x20\x49\x8D\x13" \
           "\xC0\xB5\x76\x37\x33\xB3\xE8\x2C\x1D\x8B\xF4\x9D\xFF\xDE\x53\x8C" \
           "\x17\xBA\x07\x75\x33\xC3\xE0\x10\x42\xF7\x91\xAF\xA6\xE9\x2E\x2A" \
           "\xD2\xE7\x8B\x47\xE0\xDC\x36\x00\xD1\x37\xC2\xA9\xA0\x00\xAF\xE8" \
           "\x82\xE8\x5F\x5E\xCB\x18\x9B\x21\x06\x80\x1F\x52\x6B\xFA\xA9\xCA" \
           "\x23\x4A\x58\x44\x83\x31\x9C\xF9\x08\x56\x61\x0C\x64\x65\xB3\xB0" \
           "\xFA\x6E\x26\x53\xFA\x14\xD7\xCA\xA9\x9C\x7A\xC8\xFE\xB2\x6A\xB4" \
           "\x9E\x9C\x6F\x76\x7B\xAE\x53\x07\x65\x89\x3C\x0E\xEF\xEA\x17\xB7" \
           "\x5E\x9E\x1B\xC0\x8C\x8F\xFE\x19\xD3\x15\x9C\x43\x6C\x6E\x45\x5B" \
           "\xE3\xE4\xB7\xDA\xCC\xB8\x83\x4D\x26\x59\x17\xE1\xF5\xC9\x11\x77" \
           "\xA3\xC5\x8E\xF4\xBD\x4E\xD4\xF4\xE2\xF2\xB5\x01\x9A\x16\xA5\xBD" \
           "\x91\x18\xF1\x33\xC6\x2C\x56\x88\x25\x07\xFE\x85\xD5\x18\xFA\x8D" \
           "\x12\x3A\x1E\x09\xD0\xEE\xC3\x06\xE4\x8A\x1D\x5B\x05\x7D\x43\xA1" \
           "\x06\x3A\x8A\x0B\x01\x5C\x9D\xF2\x74\xE4\x5D\xC4\xB2\x56\xC1\xF0" \
           "\xA5\xAE\x11\x12\x9A\xC5\x57\xD6\x6F\x51\xB3\x92\x88\x37\xA7\x4C" \
           "\x93\x74\xF5\x94\xAB\x86\xBD\xBA\xC9\x81\x24\x93\x8C\x11\x69\x91" \
           "\x02\xEA\xBB\x7E\x6A\xD8\x56\x20\x75\x7D\xE6\x27\xDE\x90\x9D\x9C" \
           "\x65\x04\xBF\x4C\x7E\xAF\x48\x2A\xA4\x05\xB4\xEB\xFD\xDE\x19\x3E" \
           "\xE0\xB1\x2E\x5E\xD3\x24\x6B\x03\xDF\xFA\xF5\x3E\x14\x1D\x13\x93" \
           "\x3C\x58\x4B\x1B\x83\xC4\x94\x42\x9B\x90\x5C\xA1\x98\x89\xB0\x9F" \
           "\x59\xE6\xD2\x36\x17\xB3\xE8\x05\x5A\x25\x4E\x52\x5E\x58\xC5\xCD" \
           "\x47\xB3\xC2\xF9\xFF\x2F\x2A\x8C\x96\xFF\xC5\xC2\x26\x8C\xBB\x96" \
           "\x42\xA1\x44\xF9\x53\x46\x94\xC2\x40\x49\xAD\x40\xB5\x67\x26\x66" \
           "\x3B\xE0\x35\x4E\x71\xD3\xE8\x0A\xCA\x2A\x22\x0B\xF0\xF4\xB9\x09" \
           "\xED\x10\x9E\xBF\x0C\x80\x29\x04\x5D\x88\xF6\x33\x61\x7B\x39\x37" \
           "\x42\x2D\x13\xB8\x23\x55\x0F\x9D\x04\xCB\x52\x7D\x77\x60\xAF\x39" \
           "\x5A\x14\x0D\xA4\x24\xA4\xCD\x9A\x3A\xF8\xF0\x30\x8A\x5E\x18\xE2" \
           "\xB3\x94\x74\xA7\xB2\xF7\xF5\x28\xAF\xF2\xA3\xB4\x3B\x79\x37\xE1" \
           "\x8A\xA0\x54\x55\x8B\x47\x18\x54\x71\x4C\x2C\x7D\xF6\x00\xEC\x28" \
           "\x44\x7B\x63\xF1\x59\x7F\xA4\xB4\xC3\x4C\xAD\x4C\xD7\x03\x27\x0F" \
           "\x32\xC0\x45\x3F\x6E\x25\x7A\xC4\x04\xEB\x66\x10\x48\xE4\xAE\x73" \
           "\x87\x88\x3B\x2C\xDF\x1A\xE9\xF6\xF5\xA2\xA1\x3E\x2D\x58\x26\xB5" \
           "\xDA\x38\x2A\xE6\x2D\x75\x9E\xD7\x25\xB1\xF7\xE0\xE5\x93\x6A\x23" \
           "\x91\x73\x10\x4C\x14\x0A\xDC\x3C\x74\x12\x21\x2E\x3B\xAE\xAF\xB3" \
           "\xC0\x71\x93\x7C\xA5\x03\xA4\xC3\x79\x4B\x51\x61\x23\x81\x86\xD7" \
           "\x2B\x55\xE1\x28\x14\xF0\x75\x2D\x93\xC1\xB3\x9E\x7D\x80\x04\xDA" \
           "\xB5\xAC\xF2\xBD\x79\xB3\x19\x26\x44\xE9\xEE\x9E\x23\x22\xAC\x4E" \
           "\xEE\x1B\x22\xEA\x80\xA5\x4A\x8C\x31\xE4\x02\x47\x5F\x81\xFE\x25" \
           "\xFF\x7F\xDF\x28\xEA\x93\x64\x07\xF4\x58\xD3\x5F\xD9\x49\xD9\x27" \
           , 1024);
    memcpy(&bInData[2048],
           "\xBF\x89\x51\xFE\xFB\xA7\xCE\xE6\x13\x17\xD5\x24\xD7\xB5\x02\x0C" \
           "\xCF\x9D\xBA\x83\xC0\xEC\x64\x03\x14\xF7\x0C\xF8\xAD\xD6\xD4\x38" \
           "\xF2\x67\x7E\x7A\x99\xE6\x34\x3C\x0F\xCC\x59\x54\xDA\x71\xAC\x8C" \
           "\x11\x1D\xE9\x2B\x7B\x1D\xDC\xA3\x72\xED\xB2\x7C\x0F\xB2\x22\x03" \
           "\x89\xC8\xC8\xB7\x60\x60\x50\x78\xDA\xBB\x50\xFA\xF0\x4D\x04\xC3" \
           "\x79\xBD\xC9\xDA\xDA\x72\x37\xBD\x01\xEA\x74\x1B\x0A\x23\xB3\x23" \
           "\x2C\xBD\x15\x3B\x97\xD5\x6A\x13\x4F\x3E\x7F\x5A\x66\x1B\xE9\x4E" \
           "\xD4\xA1\x5B\x08\x09\x61\x82\xA0\x0B\x05\xC6\x44\x3B\x20\xAA\x5F" \
           "\x87\x21\xA1\xCE\x77\xE7\x34\x06\x3F\x1A\xC0\xF8\x58\xF7\x93\x6C" \
           "\x1D\x41\x7B\x5D\xD1\xC1\xAC\xD1\x9F\xA1\x38\x6F\xAC\x68\x6C\x68" \
           "\x39\xA8\xD2\x68\xB8\xFC\x98\x5A\xD1\x40\x16\x8B\xB1\xF7\x1B\x55" \
           "\xC4\x61\x91\x2D\xA2\x94\x94\x11\x91\xA5\x59\x51\x30\x0C\xE9\xF6" \
           "\x2C\x33\xDE\x59\xE1\x01\xE2\x43\xBE\x5F\xF9\x53\x22\xE0\xB2\x1D" \
           "\x59\xF6\x4F\x20\x2E\x63\x6D\x6D\xB0\xCF\xED\x3C\x44\xD1\xD1\x13" \
           "\x94\x4E\x48\x32\x03\x11\x73\x9C\xF9\x4F\x54\x3A\x8B\xA1\x10\x19" \
           "\xC3\x96\x8A\xA7\xBB\xF0\xC7\xB0\xF2\xFD\x5B\x4F\x50\x46\x04\x00" \
           "\x48\x03\x76\xAD\xEB\xA5\x71\x83\x66\x68\xC4\x66\x26\xCB\xB8\x3A" \
           "\x8E\x5D\x8E\xCA\xC2\x28\x24\x9F\xC9\xA2\x6E\xF7\x0B\x64\x30\x1F" \
           "\x93\x9A\xD9\xD2\x39\x90\x7C\xEF\x91\x4E\xC2\x05\xD9\x02\xBB\x41" \
           "\x21\x0E\x64\x7B\xFF\x19\x92\x65\xA3\x9A\x3D\x8A\x99\x35\xE5\x59" \
           "\xD6\xA1\xFD\xA9\xF3\x43\x75\x9A\x22\xE6\x23\x2E\x65\x5C\x3D\xF7" \
           "\x5C\xA6\x4A\x8A\x5D\x41\x29\x25\x75\x33\x65\xEE\x44\x14\x3E\x95" \
           "\x52\x34\xE2\x9A\xA1\x2B\xF1\xE6\x56\x87\xCF\xFB\x1E\x0D\x32\xF5" \
           "\x7E\x5B\xDB\x92\xE4\xF8\x82\xF0\x58\x98\x65\xD9\x1C\xE9\x4F\x85" \
           "\xFA\xA5\xDD\x5D\x3C\x56\x3E\x89\x85\x2E\x9D\xFC\xD7\x03\xDB\x5C" \
           "\x30\xCB\x83\x11\xBD\x1B\xC4\x2F\x3C\x32\x04\x8E\x40\xC3\xBE\xCE" \
           "\xD2\xDD\xC1\xBC\x90\xD1\x68\xFB\x06\x56\x79\x37\xD8\x70\x0C\x6F" \
           "\x9A\x4E\xA5\x5B\x53\xE5\xB6\x02\x3C\x32\x4B\xA4\x9F\x3B\x42\x42" \
           "\x09\x70\x60\xC8\x49\x41\xB7\x01\x7F\x4B\xC4\x57\x04\xCB\xD6\x83" \
           "\xE5\xA7\xF8\xFD\xFE\x48\xD5\x32\x61\x42\x9A\x67\x56\xC5\x28\x3E" \
           "\x20\x57\xA8\x6A\xAD\x7E\x19\x37\x54\x46\xA6\xAE\xF4\x15\xBE\x17" \
           "\x67\x2B\x97\xA2\x71\x85\x11\x69\xC0\x1E\x98\x8D\xF6\x34\xCB\x43" \
           "\xCF\x3A\x9D\x44\x25\x6E\x05\xA9\x2E\x42\x55\x39\xF0\xF1\xC0\x61" \
           "\x4C\xA9\xE4\x7B\x06\x0A\x88\x78\x96\x00\xBB\x96\x22\x47\x42\x3A" \
           "\xBC\x8C\x62\x34\x69\x59\xA1\x88\x64\x5C\xAE\x86\xEB\xBF\xF9\xEC" \
           "\x48\x47\xC7\xC4\xA2\xA0\x7C\x9E\x1E\xCD\x7A\xD5\x2E\x92\xB3\x1E" \
           "\x49\x09\x86\x1C\xFA\xE8\x27\x47\x51\x10\xA3\x2A\xF9\xD1\x36\xA8" \
           "\x9C\xE1\x0B\x40\x9B\x6A\x88\x15\x71\x49\xBF\x89\x54\x42\x0A\x0A" \
           "\xB0\x3D\xB1\x43\xCD\x62\xA1\x37\x57\x80\xDA\x89\x10\x42\xEA\x10" \
           "\x55\x25\x33\x8D\xDD\x5E\x6E\xF4\x5B\x82\x36\xC7\xAF\xE9\xC6\x5E" \
           "\x7A\x79\xF0\x05\x9F\x30\x58\xBA\xB4\xE6\xD7\xC6\xD1\xB2\x04\x5C" \
           "\xDA\x5F\xFF\x16\x6A\x91\x27\xEF\x68\xED\xF5\xA0\x4A\x22\xCA\xBD" \
           "\xA1\x09\xB7\xE4\x04\xDF\x5C\xD5\x6F\xEC\xD0\xB7\x71\xF9\xDB\x05" \
           "\x50\xA8\x82\x99\x29\x8F\xD3\xFA\x5C\x6A\xE0\x5B\x62\xC4\x4B\x52" \
           "\x75\x50\xC6\x39\xE6\x89\x06\xB9\xF3\xDC\x78\x38\x06\x1A\x00\x98" \
           "\xE7\x28\x64\x48\xE9\xC6\x3B\x6E\x29\x21\xFB\x07\x74\x9B\x34\xCF" \
           "\xC1\x85\x9A\x39\x7A\xDD\x2D\x6C\xB1\xCC\x5F\x7E\xB8\x6D\x42\x8E" \
           "\x1F\xDF\x13\xA4\x3E\xBC\xFB\x4E\x88\x00\x42\xA4\x85\xA1\x65\x84" \
           "\xD2\x3A\xC8\x57\x78\x72\xBE\x19\x7D\x79\xBC\x26\xE8\xCD\x1D\xA6" \
           "\x13\x0D\x26\xA9\xA0\x20\x60\xAB\x6D\x20\x7E\x10\x70\x99\x72\xA5" \
           "\x0B\x51\xB6\x15\x25\xC9\x9C\x04\x55\xD1\x6B\x3E\xC0\xEB\x94\x9A" \
           "\x95\x95\xB4\xEF\xEF\xCC\xF7\x0B\xE1\x04\xE6\x7B\x1B\x8D\x02\x30" \
           "\xB8\xDC\x06\x38\x07\x99\xCD\x6C\x88\xDA\xF0\xF7\x1A\x7D\x20\x5F" \
           "\x2E\xC0\xF7\x34\xE0\x17\x2D\x4E\xE2\x07\x61\x91\xA4\x91\xF0\xE6" \
           "\x33\xD4\x61\xD4\xAD\xF2\xE5\x36\x91\x46\xE9\x92\x2F\x3B\x67\x1C" \
           "\xAE\x54\x8D\xB8\x79\xF4\x18\xA7\x2A\xF4\xC3\x05\x40\x4F\x6F\x16" \
           "\x82\x62\x80\x9C\x1D\x46\x92\x3D\x4F\x46\x1D\xF1\x71\xC2\x66\xC6" \
           "\xC1\x02\x8D\xAC\x88\xEC\x61\x5D\x9B\x19\xDF\x0D\x7C\x87\x22\xBA" \
           "\xAC\xDD\x45\x12\x65\x34\x19\x52\x3A\x07\xA9\x41\x53\x78\xD0\xDB" \
           "\xA1\xBD\xD3\x64\x13\x6E\xA1\x0A\x33\xE5\x49\xA3\x19\x68\x59\xBC" \
           "\x75\xAB\x16\x40\x2A\x2E\x60\x56\x3A\x84\x2E\x5F\x71\x1A\xFE\xB8" \
           "\x97\x71\xAF\x6B\xDD\x20\x26\xC3\x81\x68\xC1\xE9\x75\x76\x3D\x86" \
           "\x0D\x03\xC0\xA8\xE7\xEA\x8B\x51\x9B\x53\x87\x43\xD3\x5C\xF0\x21" \
           "\x6B\xFE\x71\xDC\x89\x0F\x50\x7C\x7B\x5E\x22\x69\xC3\x93\x6F\x92" \
           , 1024);
    memcpy(&bInData[3072],
           "\xF9\xA0\x75\x01\x47\xD2\x73\xA6\x4C\xE8\xDF\xB8\xAE\xA5\xB3\xDD" \
           "\x1E\x39\x05\x37\x80\xE9\xC4\xE1\xB3\x46\x51\xC7\x10\x89\xE3\x9A" \
           "\xEE\x93\x07\x92\x47\x9B\x66\x8D\xD2\x66\xD4\x99\xF8\xC8\x6B\x64" \
           "\x12\x04\xEF\xE2\xF1\x50\x00\x8B\xDC\x4D\xB3\x05\xB4\x37\xD6\x45" \
           "\x16\x8C\x78\x50\xE9\xFA\x64\x0E\xDC\x5F\x2A\x34\xB5\x76\xEA\xD9" \
           "\xC1\x28\xF2\xA3\xBE\x0F\x60\x04\x3E\xAD\x1E\x39\xAB\x37\x4C\xF8" \
           "\x25\x64\x7F\x10\x64\x67\x7F\xE7\xE7\xD2\xBD\xA6\xC4\x18\x44\x39" \
           "\xD0\x64\x28\xC8\x97\x6B\x59\xB9\xE2\xB7\x49\xC9\x90\x03\xBB\xB2" \
           "\x20\xB2\x87\xB6\x69\x5E\x60\x70\x5C\x08\xE7\x2B\x91\x38\x85\x8E" \
           "\x3E\xAE\x25\xAA\x45\x93\xAB\xD1\xA3\x43\xB6\x96\x39\xA7\xC5\x1D" \
           "\xDB\x0B\xA8\x51\xD3\xD7\xD8\x5C\xF4\xCB\xAA\x78\x53\xEE\xEB\x7C" \
           "\x61\x52\x90\x6A\xB0\x8D\x1B\x28\xE6\xAB\xC8\xEF\x43\xF7\x24\x92" \
           "\x94\x81\xCC\x23\x6B\x02\x15\x42\xDE\x7B\xCE\x5B\x2E\x14\x75\xEE" \
           "\x73\xE2\xAF\x42\xD6\x3B\xAF\xCB\x41\xDF\xD3\x17\x6A\xE8\x88\x42" \
           "\xDC\x51\xB3\x22\x1F\x9E\xCE\x5C\x86\xAE\xE4\xD4\xBC\x43\xBA\xAD" \
           "\xD5\x9C\x47\x64\xC1\x7A\x60\x73\x07\xD3\x19\x7C\x6E\x2F\xAF\x7E" \
           "\x90\xFB\x7E\xC1\x18\xC2\x66\x9B\x43\x57\xC9\x03\x14\x8F\xEE\x45" \
           "\x05\x4D\x28\xDE\x01\x57\x51\xBA\x9E\xC1\x6D\x96\x6D\x77\x0D\x97" \
           "\x4D\x40\x26\x2B\x68\xA5\x1C\x58\x10\x5F\x8C\x19\x51\xE6\x60\x9D" \
           "\x53\x27\x37\x69\xE2\x17\x76\xB5\xD9\x54\xC2\x2B\x9B\x5D\xC5\xFB" \
           "\xD5\xCA\x52\x07\xD6\xB6\xF4\xF9\x4E\x83\x54\x38\xB3\xEC\x4D\xD4" \
           "\x0E\xF8\x52\xDF\xFE\x2F\xE3\x96\xFC\x61\x78\xCB\x6A\x31\x02\x22" \
           "\x51\xA7\xFA\xC3\xD2\x11\x96\x21\x85\x55\xB1\xE9\xC2\xFC\x14\xD3" \
           "\x47\xDA\xD6\xF6\x10\x19\xFC\x99\xA6\x92\x86\x4E\x7F\x35\x64\xB6" \
           "\x11\xDC\x3A\x53\xA7\x84\x46\x8B\x59\x26\xA5\xDA\x5D\xB4\x09\x8F" \
           "\x6C\x36\x8B\x7E\x5E\x2A\x98\xB6\x7E\x2E\x5F\x27\x5A\x77\x77\xC2" \
           "\x22\x65\x33\xAD\xC7\x90\x0F\x42\xE6\xB6\xC6\x98\x5D\xFF\x28\xA0" \
           "\x7A\x11\x6A\x96\x56\x43\x73\x83\xC2\x11\x85\x07\x23\xD1\x25\xB0" \
           "\x63\x7F\x67\xF1\x89\x0F\xC1\x92\x68\x48\x61\x19\x2E\x3F\xF3\xF6" \
           "\x6D\x6B\x59\x7F\x48\x66\x64\xE4\x28\xF0\x11\xF2\x67\xCC\xBD\xD3" \
           "\x35\xF1\xE9\xA4\xD3\x55\xC0\x97\xC1\x5F\x49\xD2\x60\x40\x63\x73" \
           "\xDC\xEB\x25\x9F\xCB\xD3\x98\xF9\x1B\xA6\x5C\x98\xB8\x23\x7B\x89" \
           "\x86\x8B\x42\x9F\x2B\x47\x03\x61\x6A\xF4\x0F\x24\x79\x19\x98\x8D" \
           "\xCE\xA6\x8D\x2B\xDE\x23\xC5\x1F\x6F\x0B\x9C\xA6\x8B\xBF\x4D\x55" \
           "\x42\x35\x37\xCA\x74\xB4\x92\x0D\x87\x13\x8F\xD2\xF3\x02\x82\x8E" \
           "\x75\x57\x1E\xFA\x9D\xF3\x17\x20\xC9\x5A\x46\x95\x41\x89\x75\x02" \
           "\x00\x83\x2A\x33\x24\x90\x39\xDF\x53\x8F\x14\x51\xC8\x5C\xBD\xE2" \
           "\x27\x4B\xBC\x90\x30\x08\x00\x7B\xFA\x58\x87\xCA\x4E\x8E\x92\x5E" \
           "\xAB\xF5\xB7\x00\xFD\xB9\xAE\x7C\x5F\x82\x82\x6C\xB8\x79\xA0\x09" \
           "\x8C\x1E\xEB\xFB\xED\x72\x5B\x4D\x05\x8D\x18\xD6\x79\xB2\x11\xF3" \
           "\x2D\x86\xE5\x5E\xC4\x68\xAB\x41\x2F\xE2\xCC\x3A\x4A\x0D\x19\xAD" \
           "\x87\x5D\x28\xCC\xD9\xA0\x09\x56\x5D\xBE\x31\x3C\xD0\x80\x47\x53" \
           "\x7E\x0B\xEB\x43\xFA\x80\x95\x4E\xCB\x3F\x38\x1A\xD3\xA2\x39\x96" \
           "\x79\x6E\x6E\xF8\x6A\x1B\x5C\x11\x9C\xB0\xC2\x53\x2F\xC5\x0F\x78" \
           "\x19\x20\x99\x26\x3A\x54\x1A\xF1\x5B\x99\x96\x62\x43\xF6\xBE\x98" \
           "\x10\x93\xC0\x10\xD5\xE9\xD4\xC1\x38\xE9\x36\x3E\x88\x0C\x4F\xD1" \
           "\xB0\x5F\x2E\xB9\xB6\x78\xEF\x0C\x3F\x34\xF6\x6C\x5E\x81\x55\xE8" \
           "\x8C\x5E\xA6\x21\x7F\x38\x75\x63\xA8\x2E\x90\x27\x6A\x3B\xC4\x9F" \
           "\x27\x06\xEF\x4F\x86\x80\x4B\x2F\x81\xAB\x8A\x0D\xDD\x1E\x1E\x8F" \
           "\xCF\x16\xC4\xA2\x64\x27\xA4\xC0\x10\xFC\x21\xEB\x5E\x3D\x80\x04" \
           "\x80\x64\xBC\x1B\xAA\xD5\xB2\xFE\xD1\x34\x75\x6D\x93\xF1\x81\x9F" \
           "\x65\x3E\x72\xF0\xDD\xC8\x89\xC0\xA9\x96\xE9\x0E\x59\x31\xA6\x60" \
           "\x8A\x6D\xCE\x9B\x8B\xDF\x7A\x17\xD9\x00\xA3\x30\x12\x05\xA8\xFF" \
           "\xA3\x71\x06\xB0\x06\xAF\x3A\xE8\x1D\xB5\x24\x54\x0B\xD9\xD6\x58" \
           "\xCA\x1A\xDE\x43\x0A\x83\xC3\x3F\x4E\x71\x59\xB5\x4A\x2E\x53\x85" \
           "\x23\xC6\x0C\x5A\xA9\x19\xD4\xB3\x4E\x69\x8B\x57\x3A\xDC\x13\x5D" \
           "\xFE\x41\x65\xC7\xB4\x92\x8B\x37\xF2\x01\x06\x50\x37\x68\x77\x1E" \
           "\xCC\x7A\xC9\x20\xA8\xA5\xD9\xD4\x0B\x36\x05\x97\xB6\x08\x13\x70" \
           "\xB7\x08\x1E\x4C\x1C\x31\x90\xE1\x74\xA1\x0B\xA5\x4A\x18\x62\xC8" \
           "\x3A\x65\x79\x2B\x21\x6B\xA6\x10\x0C\x95\xF4\xD4\xE5\x36\x29\x22" \
           "\x00\x42\x20\x95\x17\xF1\xCB\x30\xFD\x84\x16\x98\xC9\xC7\x79\x8B" \
           "\xDF\x31\x03\x14\x88\xB7\xD9\x6B\x3D\xDE\xBE\x55\x32\x9A\xCD\x77" \
           "\xE2\x13\x0E\xD2\x7B\xEC\x07\xB6\x36\xBF\x80\x74\xBF\xBC\x9A\x54" \
           "\xF4\x7A\xDB\x11\x1F\x89\x79\x03\x7E\xC2\x52\x23\x14\x69\x1F\x65" \
           , 1024);
*/

    memcpy(bInData, RET, 4096);

    nInDataLen = 4096;
    memset(bOutDataExp, 0x42, 4000);
    bOutDataExp[0] = 0x30;
    bOutDataExp[3999] = 0x39;
    nOutDataLenExp = 4000;

    XXX_INPUT_XXX
    printf("[IN ]nSock   = %d\n", nSock);
    printf("[IN ]nEcMark = %d\n", nEcMark);
    printf("[IN ]nPad    = %d\n", nPad);
    DspHex("[IN ]bSK     =", bSK, nSKLen);
    printf("[IN ]nSKLen  = %d\n", nSKLen);
    DspHex("[IN ]bInData =", bInData, nInDataLen);
    printf("[IN ]nInDataLen = %d\n", nInDataLen);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIEccSkDecrypt(nSock, nEcMark, nPad, bSK, nSKLen, bInData, nInDataLen, bOutData, &nOutDataLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "ECC私钥解密，4000字节数据，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    ASSERT_OUT(nOutDataLen, nOutDataLenExp);
    ASSERT_OUT_HEX(bOutData, bOutDataExp, nOutDataLen);
    DspHex("[OUT]bOutData     =", bOutData, nOutDataLen);
    printf("[OUT]nOutDataLen  = %d\n", nOutDataLen);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void EccSkDecrypt_Test_03(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nEcMark;
    int  nPad;
    BYTE bSK[256];
    int  nSKLen;
    BYTE bInData[1024];
    int  nInDataLen;
    BYTE bOutData[1024];
    int  nOutDataLen;
    BYTE bOutDataExp[1024];
    int  nOutDataLenExp;

    bufclr(bSK);
    bufclr(bInData);
    bufclr(bOutData);
    nSKLen = 0;

    nEcMark = 17;
    nPad = 0;

    /* PK 0400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 */
    /* SK 0000000000000000000000000000000000000000000000000000000000000000 */
    /* 1F1EA8255422D2751F1EA8255422D2751F1EA8255422D2751F1EA8255422D2756BCB2CCA658BFD78 */
    memcpy(bSK,
           "\x1F\x1E\xA8\x25\x54\x22\xD2\x75\x1F\x1E\xA8\x25\x54\x22\xD2\x75" \
           "\x1F\x1E\xA8\x25\x54\x22\xD2\x75\x1F\x1E\xA8\x25\x54\x22\xD2\x75" \
           "\x6B\xCB\x2C\xCA\x65\x8B\xFD\x78" \
           , 40);
    nSKLen = 40;

    /* 0BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB9 */
    /* 30424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424239 */
    /* 218F10DE6B269E2483F03BC2B1A8FE3046F16508D206A6F5EB1375070D0438166F6F9C20BA2FF267EFB42B0028190923C1187AF563D64E62564C409E40F976D739515B0969124EBC9722E7D7B906C5B603D1E220BB834322E797302AFC2337AFCC39EBC0F0BBE35127B515B91CF416730AC608CAEB0AD8FAAC2A359EF08A5F8DF405769CE8D15FCBECACDF1D1CC5B3BF4CCFF29739690EC590A08E9DC673EFFD */
    memcpy(bInData,
           "\x21\x8F\x10\xDE\x6B\x26\x9E\x24\x83\xF0\x3B\xC2\xB1\xA8\xFE\x30" \
           "\x46\xF1\x65\x08\xD2\x06\xA6\xF5\xEB\x13\x75\x07\x0D\x04\x38\x16" \
           "\x6F\x6F\x9C\x20\xBA\x2F\xF2\x67\xEF\xB4\x2B\x00\x28\x19\x09\x23" \
           "\xC1\x18\x7A\xF5\x63\xD6\x4E\x62\x56\x4C\x40\x9E\x40\xF9\x76\xD7" \
           "\x39\x51\x5B\x09\x69\x12\x4E\xBC\x97\x22\xE7\xD7\xB9\x06\xC5\xB6" \
           "\x03\xD1\xE2\x20\xBB\x83\x43\x22\xE7\x97\x30\x2A\xFC\x23\x37\xAF" \
           "\xCC\x39\xEB\xC0\xF0\xBB\xE3\x51\x27\xB5\x15\xB9\x1C\xF4\x16\x73" \
           "\x0A\xC6\x08\xCA\xEB\x0A\xD8\xFA\xAC\x2A\x35\x9E\xF0\x8A\x5F\x8D" \
           "\xF4\x05\x76\x9C\xE8\xD1\x5F\xCB\xEC\xAC\xDF\x1D\x1C\xC5\xB3\xBF" \
           "\x4C\xCF\xF2\x97\x39\x69\x0E\xC5\x90\xA0\x8E\x9D\xC6\x73\xEF\xFD" \
           , 160);
    nInDataLen = 160;
    memset(bOutDataExp, 0x42, 64);
    bOutDataExp[0] = 0x30;
    bOutDataExp[63] = 0x39;
    nOutDataLenExp = 64;

    XXX_INPUT_XXX
    printf("[IN ]nSock   = %d\n", nSock);
    printf("[IN ]nEcMark = %d\n", nEcMark);
    printf("[IN ]nPad    = %d\n", nPad);
    DspHex("[IN ]bSK     =", bSK, nSKLen);
    printf("[IN ]nSKLen  = %d\n", nSKLen);
    DspHex("[IN ]bInData =", bInData, nInDataLen);
    printf("[IN ]nInDataLen = %d\n", nInDataLen);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIEccSkDecrypt(nSock, nEcMark, nPad, bSK, nSKLen, bInData, nInDataLen, bOutData, &nOutDataLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 1, "ECC私钥解密，无效私钥，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void EccSign_Test_01(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int  nEcMark;
	  int  nPad;
	  BYTE bPK[1280];
	  int  nPKLen;
	  BYTE bSK[540];
	  int  nSKLen;
	  BYTE bData[2048];
	  int  nDataLen;
	  BYTE bSign[512];
	  int  nSignLen;

    bufclr(bPK);
    bufclr(bSK);
    bufclr(bData);
    bufclr(bSign);

    nEcMark = 17;
    nPad = 0;
    /* PK 04695BC3452B4DF79EBA188AC61C51A33A243F497A4D76D272F3771827BD80A944E1DA925A4853860EE0D883F3A2F43AA8F265C95F60A9102A7495551034D6C021 */
    /* SK 7BAD1BC2D566F4AC0F93E830E2E9A1E756C063E94FBDEABF68A29DD720B44B30 */
    memcpy(bPK,
           "\x04\x69\x5B\xC3\x45\x2B\x4D\xF7\x9E\xBA\x18\x8A\xC6\x1C\x51\xA3" \
           "\x3A\x24\x3F\x49\x7A\x4D\x76\xD2\x72\xF3\x77\x18\x27\xBD\x80\xA9" \
           "\x44\xE1\xDA\x92\x5A\x48\x53\x86\x0E\xE0\xD8\x83\xF3\xA2\xF4\x3A" \
           "\xA8\xF2\x65\xC9\x5F\x60\xA9\x10\x2A\x74\x95\x55\x10\x34\xD6\xC0" \
           "\x21" \
           , 65);
    nPKLen = 65;
    memcpy(bSK,
           "\xC3\xE0\x99\x39\x13\x86\x91\xAA\x60\x90\x31\xAA\xDA\x12\x31\x49"
           "\x5D\x23\xD8\x9A\xA3\x2D\x7B\x3E\x4C\x4D\x10\xD4\x63\x13\x08\xFD"
           "\x6B\xCB\x2C\xCA\x65\x8B\xFD\x78"
           , 40);
    nSKLen = 40;
    /* 0BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB9 */
    memset(bData, 0x42, 256);
    bData[0] = 0x30;
    bData[255] = 0x39;
    nDataLen = 256;

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]nEcMark = %d\n", nEcMark);
    printf("[IN ]nPad = %d\n", nPad);
    DspHexExt("[IN ]bPK =", bPK, nPKLen);
    printf("[IN ]nPKLen = %d\n", nPKLen);
    DspHexExt("[IN ]bSK =", bSK, nSKLen);
    printf("[IN ]nSKLen = %d\n", nSKLen);
    DspHexExt("[IN ]bData =", bData, 256);
    printf("[IN ]nDataLen = %d\n", nDataLen);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIEccSign(nSock, nEcMark, nPad, bPK, nPKLen, bSK, nSKLen, bData, \
                           nDataLen, bSign, &nSignLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "SM2签名，256字节数据，测试失败");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[VERIFY]请确认以下结果:\n");
    DspHexExt("[OUT]bSign    =", bSign, nSignLen);
    printf("[OUT]nSignLen = %d", nSignLen);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void EccSign_Test_02(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int  nEcMark;
	  int  nPad;
	  BYTE bPK[1280];
	  int  nPKLen;
	  BYTE bSK[540];
	  int  nSKLen;
	  BYTE bData[2048];
	  int  nDataLen;
	  BYTE bSign[512];
	  int  nSignLen;

    bufclr(bPK);
    bufclr(bSK);
    bufclr(bData);
    bufclr(bSign);

    nEcMark = 17;
    nPad = 0;
    /* PK 0400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 */
    /* SK 0000000000000000000000000000000000000000000000000000000000000000 */
    /* 1F1EA8255422D2751F1EA8255422D2751F1EA8255422D2751F1EA8255422D2756BCB2CCA658BFD78 */
    memcpy(bPK,
           "\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
           "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
           "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
           "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
           "\x00" \
           , 65);
    nPKLen = 65;
    memcpy(bSK,
           "\x1F\x1E\xA8\x25\x54\x22\xD2\x75\x1F\x1E\xA8\x25\x54\x22\xD2\x75" \
           "\x1F\x1E\xA8\x25\x54\x22\xD2\x75\x1F\x1E\xA8\x25\x54\x22\xD2\x75" \
           "\x6B\xCB\x2C\xCA\x65\x8B\xFD\x78" \
           , 40);
    nSKLen = 40;
    /* 0BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB9 */
    memset(bData, 0x42, 256);
    bData[0] = 0x30;
    bData[255] = 0x39;
    nDataLen = 256;

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]nEcMark = %d\n", nEcMark);
    printf("[IN ]nPad = %d\n", nPad);
    DspHexExt("[IN ]bPK =", bPK, nPKLen);
    printf("[IN ]nPKLen = %d\n", nPKLen);
    DspHexExt("[IN ]bSK =", bSK, nSKLen);
    printf("[IN ]nSKLen = %d\n", nSKLen);
    DspHexExt("[IN ]bData =", bData, 256);
    printf("[IN ]nDataLen = %d\n", nDataLen);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIEccSign(nSock, nEcMark, nPad, bPK, nPKLen, bSK, nSKLen, bData, \
                           nDataLen, bSign, &nSignLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 1, "SM2签名，无效私钥，测试失败");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void EccVerify_Test_01(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int  nEcMark;
	  int  nPad;
	  BYTE bPK[1280];
	  int  nPKLen;
	  BYTE bData[2048];
	  int  nDataLen;
	  BYTE bSign[512];
	  int  nSignLen;

    bufclr(bPK);
    bufclr(bData);
    bufclr(bSign);

    nEcMark = 17;
    nPad = 0;
    /* PK 04695BC3452B4DF79EBA188AC61C51A33A243F497A4D76D272F3771827BD80A944E1DA925A4853860EE0D883F3A2F43AA8F265C95F60A9102A7495551034D6C021 */
    /* SK 7BAD1BC2D566F4AC0F93E830E2E9A1E756C063E94FBDEABF68A29DD720B44B30 */
    memcpy(bPK,
           "\x04\x69\x5B\xC3\x45\x2B\x4D\xF7\x9E\xBA\x18\x8A\xC6\x1C\x51\xA3" \
           "\x3A\x24\x3F\x49\x7A\x4D\x76\xD2\x72\xF3\x77\x18\x27\xBD\x80\xA9" \
           "\x44\xE1\xDA\x92\x5A\x48\x53\x86\x0E\xE0\xD8\x83\xF3\xA2\xF4\x3A" \
           "\xA8\xF2\x65\xC9\x5F\x60\xA9\x10\x2A\x74\x95\x55\x10\x34\xD6\xC0" \
           "\x21" \
           , 65);
    nPKLen = 65;
    /* 0BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB9 */
    memset(bData, 0x42, 256);
    bData[0] = 0x30;
    bData[255] = 0x39;
    nDataLen = 256;
    /* B3FEFD820E1B0F3096CDEEA2C134CF10162D39EC88F0BACB8539E3EA41DF701D355CC1A73CEBDF02B694BA465107789FCC4BB29A126AD338F3B55DF0CE751D0C */
    memcpy(bSign, 
           "\xB3\xFE\xFD\x82\x0E\x1B\x0F\x30\x96\xCD\xEE\xA2\xC1\x34\xCF\x10" \
           "\x16\x2D\x39\xEC\x88\xF0\xBA\xCB\x85\x39\xE3\xEA\x41\xDF\x70\x1D" \
           "\x35\x5C\xC1\xA7\x3C\xEB\xDF\x02\xB6\x94\xBA\x46\x51\x07\x78\x9F" \
           "\xCC\x4B\xB2\x9A\x12\x6A\xD3\x38\xF3\xB5\x5D\xF0\xCE\x75\x1D\x0C" \
           , 64);
    nSignLen = 64;

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]nEcMark = %d\n", nEcMark);
    printf("[IN ]nPad = %d\n", nPad);
    DspHex("[IN ]bPK =", bPK, nPKLen);
    printf("[IN ]nPKLen = %d\n", nPKLen);
    DspHex("[IN ]bData =", bData, nDataLen);
    printf("[IN ]nDataLen = %d\n", nDataLen);
    DspHex("[IN ]bSign =", bSign, nSignLen);
    printf("[IN ]nSignLen = %d\n", nSignLen);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIEccVerify(nSock, nEcMark, nPad, bPK, nPKLen, bData, \
                           nDataLen, bSign, nSignLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "SM2签名验证，256字节数据，测试失败");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void EccVerify_Test_02(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int  nEcMark;
	  int  nPad;
	  BYTE bPK[1280];
	  int  nPKLen;
	  BYTE bData[2048];
	  int  nDataLen;
	  BYTE bSign[512];
	  int  nSignLen;

    bufclr(bPK);
    bufclr(bData);
    bufclr(bSign);

    nEcMark = 17;
    nPad = 0;
    /* PK 04695BC3452B4DF79EBA188AC61C51A33A243F497A4D76D272F3771827BD80A944E1DA925A4853860EE0D883F3A2F43AA8F265C95F60A9102A7495551034D6C021 */
    /* SK 7BAD1BC2D566F4AC0F93E830E2E9A1E756C063E94FBDEABF68A29DD720B44B30 */
    memcpy(bPK,
           "\x04\x69\x5B\xC3\x45\x2B\x4D\xF7\x9E\xBA\x18\x8A\xC6\x1C\x51\xA3" \
           "\x3A\x24\x3F\x49\x7A\x4D\x76\xD2\x72\xF3\x77\x18\x27\xBD\x80\xA9" \
           "\x44\xE1\xDA\x92\x5A\x48\x53\x86\x0E\xE0\xD8\x83\xF3\xA2\xF4\x3A" \
           "\xA8\xF2\x65\xC9\x5F\x60\xA9\x10\x2A\x74\x95\x55\x10\x34\xD6\xC0" \
           "\x21" \
           , 65);
    nPKLen = 65;
    /* 0BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB9 */
    memset(bData, 0x42, 256);
    bData[0] = 0x30;
    bData[255] = 0x39;
    nDataLen = 256;
    /* B3FEFD820E1B0F3096CDEEA2C134CF10162D39EC88F0BACB8539E3EA41DF701D355CC1A73CEBDF02B694BA465107789FCC4BB29A126AD338F3B55DF0CE751D0D */
    memcpy(bSign, 
           "\xB3\xFE\xFD\x82\x0E\x1B\x0F\x30\x96\xCD\xEE\xA2\xC1\x34\xCF\x10" \
           "\x16\x2D\x39\xEC\x88\xF0\xBA\xCB\x85\x39\xE3\xEA\x41\xDF\x70\x1D" \
           "\x35\x5C\xC1\xA7\x3C\xEB\xDF\x02\xB6\x94\xBA\x46\x51\x07\x78\x9F" \
           "\xCC\x4B\xB2\x9A\x12\x6A\xD3\x38\xF3\xB5\x5D\xF0\xCE\x75\x1D\x0D" \
           , 64);
    nSignLen = 64;

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]nEcMark = %d\n", nEcMark);
    printf("[IN ]nPad = %d\n", nPad);
    DspHex("[IN ]bPK =", bPK, nPKLen);
    printf("[IN ]nPKLen = %d\n", nPKLen);
    DspHex("[IN ]bData =", bData, nDataLen);
    printf("[IN ]nDataLen = %d\n", nDataLen);
    DspHex("[IN ]bSign =", bSign, nSignLen);
    printf("[IN ]nSignLen = %d\n", nSignLen);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIEccVerify(nSock, nEcMark, nPad, bPK, nPKLen, bData, \
                           nDataLen, bSign, nSignLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 21, "SM2签名验证，256字节数据，测试失败");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void EccVerify_Test_03(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int  nEcMark;
	  int  nPad;
	  BYTE bPK[1280];
	  int  nPKLen;
	  BYTE bData[2048];
	  int  nDataLen;
	  BYTE bSign[512];
	  int  nSignLen;

    bufclr(bPK);
    bufclr(bData);
    bufclr(bSign);

    nEcMark = 17;
    nPad = 0;
    /* PK 0400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 */
    /* SK 0000000000000000000000000000000000000000000000000000000000000000 */
    memcpy(bPK,
           "\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
           "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
           "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
           "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
           "\x00" \
           , 65);
    nPKLen = 65;
    /* 0BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB9 */
    memset(bData, 0x42, 256);
    bData[0] = 0x30;
    bData[255] = 0x39;
    nDataLen = 256;
    /* S   B5099BA83EA9CFFFA44E999925768B648025FE21AF8A6FD30D98210A9AB08F30FDBA1FA2C36D222871D0336548D303857D5E8FB5753D5447BC5815E3CA1B7B1B */
    /* F   FBE187E1F0F40AD75C6D3D8573E968EA59F9601018C29460CF8C800D07C65129A74AE8BCA6859ECB4B7EE524410EDA6B8AE9ACBE6EB6B8EAD64EFA9E73410581 */
    memcpy(bSign, 
           "\xB5\x09\x9B\xA8\x3E\xA9\xCF\xFF\xA4\x4E\x99\x99\x25\x76\x8B\x64" \
           "\x80\x25\xFE\x21\xAF\x8A\x6F\xD3\x0D\x98\x21\x0A\x9A\xB0\x8F\x30" \
           "\xFD\xBA\x1F\xA2\xC3\x6D\x22\x28\x71\xD0\x33\x65\x48\xD3\x03\x85" \
           "\x7D\x5E\x8F\xB5\x75\x3D\x54\x47\xBC\x58\x15\xE3\xCA\x1B\x7B\x1B" \
           , 64);
    nSignLen = 64;

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]nEcMark = %d\n", nEcMark);
    printf("[IN ]nPad = %d\n", nPad);
    DspHex("[IN ]bPK =", bPK, nPKLen);
    printf("[IN ]nPKLen = %d\n", nPKLen);
    DspHex("[IN ]bData =", bData, nDataLen);
    printf("[IN ]nDataLen = %d\n", nDataLen);
    DspHex("[IN ]bSign =", bSign, nSignLen);
    printf("[IN ]nSignLen = %d\n", nSignLen);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIEccVerify(nSock, nEcMark, nPad, bPK, nPKLen, bData, \
                           nDataLen, bSign, nSignLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 1, "SM2签名验证，无效公钥，测试失败");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void Sm4Calc_Test_01(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nFlag;
    int  nMode;
    BYTE bKey[32];
    BYTE bIndata[4104];
	  BYTE bIV[16];
    int  nDataLen;
    BYTE bOutData[4104];
    BYTE bOutDataExp[4104];

    bufclr(bKey);
    bufclr(bIndata);
    bufclr(bIV);
    bufclr(bOutData);
    bufclr(bOutDataExp);

    nFlag = 1;
    nMode = 0;
    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(bKey, "\xA2\xC0\xB0\xF8\xF7\xF5\xEE\x21" \
                 "\xFB\x5C\x6A\xEB\xE7\x14\xE5\x3A",\
                 16);
    memset(bIndata, 0x42, 1024);
    bIndata[0] = 0x30;
    bIndata[1023] = 0x39;
    nDataLen = 1024;
    memcpy(bOutDataExp, \
           "\x88\xC7\x7F\x3A\xA6\xA2\x9E\x4E" \
           "\x20\x31\x65\x7E\x38\x48\xA4\x63" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\x82\x2A\xD6\xA1\x4D\x0A\x65\x31" \
           "\x38\x12\x07\x8F\x05\x77\x25\xB5" \
           , 1024);

    XXX_INPUT_XXX
    printf("[IN ]nSock          = %d\n", nSock);
    printf("[IN ]nFlag          = %d\n", nFlag);
    printf("[IN ]nMode          = %d\n", nMode);
    DspHex("[IN ]bKey           =", bKey, 16);
    DspHex("[IN ]bIndata        =", bIndata, nDataLen);
    printf("[IN ]nDataLen       = %d\n", nDataLen);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPISm4Calc(nSock, nFlag, nMode, bKey, bIndata, nDataLen, bIV, bOutData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "SM4-ECB加密，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    ASSERT_OUT_HEX(bOutData, bOutDataExp, nDataLen);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void Sm4Calc_Test_02(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nFlag;
    int  nMode;
    BYTE bKey[32];
    BYTE bIndata[4104];
	  BYTE bIV[16];
    int  nDataLen;
    BYTE bOutData[4104];
    BYTE bOutDataExp[4104];

    bufclr(bKey);
    bufclr(bIndata);
    bufclr(bIV);
    bufclr(bOutData);
    bufclr(bOutDataExp);

    nFlag = 1;
    nMode = 1;
    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(bKey, "\xA2\xC0\xB0\xF8\xF7\xF5\xEE\x21" \
                 "\xFB\x5C\x6A\xEB\xE7\x14\xE5\x3A",\
                 16);
    memset(bIndata, 0x42, 1024);
    bIndata[0] = 0x30;
    bIndata[1023] = 0x39;
    nDataLen = 1024;
    memcpy(bOutDataExp, \
           "\x88\xC7\x7F\x3A\xA6\xA2\x9E\x4E" \
           "\x20\x31\x65\x7E\x38\x48\xA4\x63" \
           "\xE2\x63\xA2\xB0\xC4\x3E\xF4\xEF" \
           "\xA9\xF9\xC5\xA7\x22\xA1\x57\xA0" \
           "\xEB\x60\xD8\xE5\xFC\x56\xBA\xB8" \
           "\x36\x62\x0A\x7F\xF5\x40\x46\x68" \
           "\x4A\x30\x05\x1C\xD5\x0E\xED\x3F" \
           "\xD3\xBD\x4A\x15\x93\x03\x7D\xC2" \
           "\xA1\x2F\x65\xB1\x42\x17\xB0\xC9" \
           "\xB7\xAF\x3A\x84\xA1\xEF\xFE\xC1" \
           "\x58\x35\x31\xAF\x36\xC2\x7C\x4F" \
           "\x27\xA7\x8F\x8A\x1A\x1E\x81\x2C" \
           "\x71\x21\x48\xE0\xD5\x77\x7F\xDD" \
           "\x10\x79\x04\xEB\x14\x4F\xF7\x87" \
           "\xA4\xD1\xA7\xA2\xEB\x7D\x21\x59" \
           "\xF6\x43\xED\xB9\x48\x03\xE1\x99" \
           "\x9B\x3C\xEE\xFA\x60\x0C\x3F\xCE" \
           "\x30\x7B\xD3\x34\x51\xEC\xB8\xEC" \
           "\xCF\xB2\x04\x11\xF8\x98\xEE\x79" \
           "\x62\x83\xC7\x81\x98\xF6\x77\xA6" \
           "\x2E\x3C\x4C\x82\xA0\xF0\x43\x2B" \
           "\x7C\x05\x86\x1B\x0E\xAC\xC2\x09" \
           "\xF8\x5C\x35\x31\x53\x51\x2B\x96" \
           "\x6A\x8D\x16\x6C\xB9\xA1\xB9\x0A" \
           "\x55\x67\x53\xC6\x32\xF5\x3B\xAD" \
           "\x6B\xBF\x0B\x2C\xE0\xA8\xC9\x20" \
           "\xC2\xE6\xA0\x2D\x9B\x41\x8D\xFB" \
           "\x6E\x56\x31\xD7\xA4\xA1\xE6\xAC" \
           "\xF5\xCA\xC1\x74\xAC\x35\x2D\x2E" \
           "\x5E\xC3\x27\xFC\xBD\xAB\x82\x43" \
           "\xC3\x5D\x52\x86\x9E\x9C\x4F\xDB" \
           "\xD0\xB8\x55\x13\x12\x0F\xC6\x67" \
           "\xC1\xAE\x21\xD4\x78\x79\xA0\xB5" \
           "\x66\x2F\x10\x6A\x67\xA7\x22\x2C" \
           "\xDA\xE0\x32\xB7\x86\x15\x5B\x26" \
           "\x29\xB9\x60\x6A\xDC\xF6\x73\x9E" \
           "\xD7\xED\xA7\x8C\xCC\x83\x53\x24" \
           "\xDE\x45\xCD\x5E\x68\x7A\x7C\xFF" \
           "\x24\xA2\x16\xC9\x58\xD5\x28\x70" \
           "\xC8\x23\xDA\xE5\xE3\x95\x93\xB2" \
           "\xD3\x73\x13\x68\x87\x0F\xB1\x42" \
           "\x14\x37\xD3\x5F\xB0\x2D\xAA\x45" \
           "\xF5\xE4\x1D\xF8\xCD\x89\x5F\x17" \
           "\xB6\x78\x4F\x21\xA3\x2D\x77\xCF" \
           "\x98\xDE\x44\x0C\x0E\xDE\x01\x75" \
           "\xF2\x4F\x40\x09\xDB\xAD\xF0\xEE" \
           "\x5B\xCF\x40\x35\x6C\xEA\xCD\x29" \
           "\x35\xAE\x6C\x9E\xB4\x96\x4D\xC4" \
           "\x8E\x6D\x17\xC3\xB2\x8A\xDF\xC8" \
           "\x03\x91\xF3\x90\xCE\x34\xA0\x90" \
           "\xDF\x8F\x56\x3A\x9A\x3D\x02\x17" \
           "\xD8\xA1\xFD\x00\xED\x36\x13\xD5" \
           "\xA2\xA1\x53\x7E\x42\x3D\x24\x80" \
           "\xA3\xF7\x84\x84\x3C\x22\x2B\x15" \
           "\x7A\xAA\xA2\x87\x89\xEA\xB3\x02" \
           "\xE5\xFC\x6C\xE0\xB9\x46\x29\xCA" \
           "\x82\x94\x19\x44\x1B\xA5\x9C\x71" \
           "\xC9\xFA\xF7\x3A\xEA\x06\xCA\xC2" \
           "\x59\x1A\xB5\xD9\x9D\x4B\x75\x67" \
           "\x43\x82\x86\x63\x38\xDB\xD4\x75" \
           "\x0E\x88\x0E\x6E\x6F\xAC\xDA\xA3" \
           "\x8E\x67\xB0\xAF\x45\x4F\x6C\xC1" \
           "\xFF\xC2\xFA\x1A\xAC\xBF\xDA\x0B" \
           "\x7B\x0B\xC2\x99\x46\x61\x03\x3B" \
           "\x2B\x6A\x46\xDC\xF6\x70\x66\x14" \
           "\xFE\x2D\x94\xAE\x88\xCA\x85\x49" \
           "\xD5\x10\xB8\xA0\xBC\x87\x61\x83" \
           "\x3E\x14\xCD\xE1\xCD\x7C\x01\x27" \
           "\x58\xC5\x0C\x1D\x4B\xF8\xD9\xDC" \
           "\x73\xB4\x54\xEE\xDE\x31\x5D\x4B" \
           "\xBD\x77\xF7\xAE\xCD\x71\x43\xD0" \
           "\x63\x85\x29\x51\x0D\x85\xA9\x13" \
           "\x0F\x1E\xDF\xF6\x69\x32\x61\x8E" \
           "\x8E\xB3\xEF\x7A\xE7\x9A\x11\xD2" \
           "\x1C\x1B\x9F\xBD\xEA\x54\xD7\x22" \
           "\x8A\x84\x5F\x43\x7D\x66\x6E\x8D" \
           "\xB3\xCF\xE7\x0A\x38\x3F\xFD\x0C" \
           "\xC7\x0A\x2B\x42\xBD\xC1\xFD\xBE" \
           "\x69\xAF\x10\x06\xA6\x29\xA9\x9F" \
           "\xB1\x00\x95\x56\x9E\x15\x6C\xDD" \
           "\xBD\xED\xA4\x86\x34\xE3\x0B\x4F" \
           "\x3D\xD5\x57\xE0\x87\x4C\x9C\x27" \
           "\x83\xE2\xF7\x92\x6D\xC8\x3A\x0D" \
           "\x60\xC5\x58\x1F\x68\x2A\xFE\x56" \
           "\xE4\x26\x03\xCF\x98\x18\xC8\x79" \
           "\xF2\x4D\x51\x59\xAA\xAC\xB1\x8C" \
           "\x1C\x04\xD6\xD1\x0E\x15\xA0\xBC" \
           "\x09\x75\x2B\x23\x59\xDC\x67\x68" \
           "\x60\x0A\x2D\x34\x00\x5C\x91\x20" \
           "\xB2\xCC\xDC\x00\x63\xA1\x4D\x38" \
           "\x74\x1E\xD2\x8B\xAB\x86\xA6\x86" \
           "\xB8\x9C\xC1\x0D\x95\xCB\x24\x1E" \
           "\xBB\x95\xC3\x97\xB6\xCC\xB3\xA7" \
           "\x1E\x22\xF3\xBA\xB3\x18\x02\xED" \
           "\x0D\xB6\x38\x30\x5D\x8B\x40\x31" \
           "\x00\xBF\x25\x23\x43\x07\x8F\x14" \
           "\x7D\xE3\x5D\xD3\xD2\xFC\x94\xED" \
           "\xC0\xA0\xD9\x1B\x1F\x6F\x6A\x32" \
           "\x4F\x78\x05\x98\xF2\xA2\x03\xDA" \
           "\x0E\x44\x05\x35\xA0\x55\x26\x35" \
           "\x07\xEB\xD0\xDC\xCD\x71\xE5\x3F" \
           "\x9A\xC6\xFF\x60\x94\x4B\x54\xD6" \
           "\x10\xE2\x9A\x97\x4A\xED\x8D\xE7" \
           "\x7C\x0C\x17\x80\x7D\x4E\x22\x36" \
           "\xEF\xF1\x3D\x91\x7B\x02\xA6\x37" \
           "\x14\x28\xB5\x91\x67\xD4\x0F\xDB" \
           "\x1C\x24\x09\x00\xD5\x3A\xB5\x15" \
           "\xF9\x50\xB2\x8B\x55\x48\x57\x1C" \
           "\xF6\x40\x5A\xA2\x9A\xDB\xDF\xDE" \
           "\x0F\x39\x5E\x0E\x30\x7B\x74\x2A" \
           "\x61\xD4\x64\x39\x65\xB4\x14\x5B" \
           "\xB9\xD4\x2D\xBB\x74\x8B\xA9\x79" \
           "\xB9\x05\x3B\x22\xC1\x35\xDC\xB2" \
           "\xD4\xDC\x2A\xB4\xFA\x6F\x33\x00" \
           "\xB9\x0A\xEF\x63\x98\x5D\x19\xD5" \
           "\xC7\x5B\xBB\x6D\x65\x1F\x41\x19" \
           "\xC3\xD1\xC1\xA4\x21\x08\xED\x00" \
           "\xC0\x02\x1B\xDD\x0F\xEE\x3F\x60" \
           "\xE9\x2E\x1B\xF6\xBF\x12\xF3\xFB" \
           "\xDA\x05\x2E\x40\x4C\x77\x30\x8D" \
           "\xF0\x46\xEC\xAE\x05\x18\x2D\x7F" \
           "\x04\x97\xAD\x9F\x5C\x62\x6D\x90" \
           "\x96\xFA\x38\x1F\x31\x86\x2F\xCC" \
           "\xB0\x98\x50\x98\x82\xA0\x3F\x52" \
           "\xEF\xC6\x23\x7F\xCB\xD4\xEB\xC1" \
           "\x6C\xF0\xA8\xED\xE1\xC0\x58\x86" \
           "\x51\x4D\x12\xE7\xA8\x70\xDD\xAF" \
           "\x4F\x65\x7E\x20\xCC\x16\x7C\xF1" \
           , 1024);
    XXX_INPUT_XXX
    printf("[IN ]nSock          = %d\n", nSock);
    printf("[IN ]nFlag          = %d\n", nFlag);
    printf("[IN ]nMode          = %d\n", nMode);
    DspHex("[IN ]bKey           =", bKey, 16);
    DspHex("[IN ]bIndata        =", bIndata, nDataLen);
    printf("[IN ]nDataLen       = %d\n", nDataLen);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPISm4Calc(nSock, nFlag, nMode, bKey, bIndata, nDataLen, bIV, bOutData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "SM4-CBC加密，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    ASSERT_OUT_HEX(bOutData, bOutDataExp, nDataLen);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void Sm4Calc_Test_03(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nFlag;
    int  nMode;
    BYTE bKey[32];
    BYTE bInData[4104];
	  BYTE bIV[16];
    int  nDataLen;
    BYTE bOutData[4104];
    BYTE bOutDataExp[4104];

    bufclr(bKey);
    bufclr(bInData);
    bufclr(bIV);
    bufclr(bOutData);
    bufclr(bOutDataExp);

    nFlag = 0;
    nMode = 0;
    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(bKey, "\xA2\xC0\xB0\xF8\xF7\xF5\xEE\x21" \
                 "\xFB\x5C\x6A\xEB\xE7\x14\xE5\x3A",\
                 16);
    nDataLen = 1024;
    memcpy(bInData, \
           "\x88\xC7\x7F\x3A\xA6\xA2\x9E\x4E" \
           "\x20\x31\x65\x7E\x38\x48\xA4\x63" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\x82\x2A\xD6\xA1\x4D\x0A\x65\x31" \
           "\x38\x12\x07\x8F\x05\x77\x25\xB5" \
           , 1024);
    memset(bOutDataExp, 0x42, 1024);
    bOutDataExp[0] = 0x30;
    bOutDataExp[1023] = 0x39;

    XXX_INPUT_XXX
    printf("[IN ]nSock          = %d\n", nSock);
    printf("[IN ]nFlag          = %d\n", nFlag);
    printf("[IN ]nMode          = %d\n", nMode);
    DspHex("[IN ]bKey           =", bKey, 16);
    DspHex("[IN ]bInData        =", bInData, nDataLen);
    printf("[IN ]nDataLen       = %d\n", nDataLen);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPISm4Calc(nSock, nFlag, nMode, bKey, bInData, nDataLen, bIV, bOutData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "SM4-ECB解密，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    ASSERT_OUT_HEX(bOutData, bOutDataExp, nDataLen);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void Sm4Calc_Test_04(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nFlag;
    int  nMode;
    BYTE bKey[32];
    BYTE bInData[4104];
	  BYTE bIV[16];
    int  nDataLen;
    BYTE bOutData[4104];
    BYTE bOutDataExp[4104];

    bufclr(bKey);
    bufclr(bInData);
    bufclr(bIV);
    bufclr(bOutData);
    bufclr(bOutDataExp);

    nFlag = 0;
    nMode = 1;
    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(bKey, "\xA2\xC0\xB0\xF8\xF7\xF5\xEE\x21" \
                 "\xFB\x5C\x6A\xEB\xE7\x14\xE5\x3A",\
                 16);
    nDataLen = 1024;
    memcpy(bInData, \
           "\x88\xC7\x7F\x3A\xA6\xA2\x9E\x4E" \
           "\x20\x31\x65\x7E\x38\x48\xA4\x63" \
           "\xE2\x63\xA2\xB0\xC4\x3E\xF4\xEF" \
           "\xA9\xF9\xC5\xA7\x22\xA1\x57\xA0" \
           "\xEB\x60\xD8\xE5\xFC\x56\xBA\xB8" \
           "\x36\x62\x0A\x7F\xF5\x40\x46\x68" \
           "\x4A\x30\x05\x1C\xD5\x0E\xED\x3F" \
           "\xD3\xBD\x4A\x15\x93\x03\x7D\xC2" \
           "\xA1\x2F\x65\xB1\x42\x17\xB0\xC9" \
           "\xB7\xAF\x3A\x84\xA1\xEF\xFE\xC1" \
           "\x58\x35\x31\xAF\x36\xC2\x7C\x4F" \
           "\x27\xA7\x8F\x8A\x1A\x1E\x81\x2C" \
           "\x71\x21\x48\xE0\xD5\x77\x7F\xDD" \
           "\x10\x79\x04\xEB\x14\x4F\xF7\x87" \
           "\xA4\xD1\xA7\xA2\xEB\x7D\x21\x59" \
           "\xF6\x43\xED\xB9\x48\x03\xE1\x99" \
           "\x9B\x3C\xEE\xFA\x60\x0C\x3F\xCE" \
           "\x30\x7B\xD3\x34\x51\xEC\xB8\xEC" \
           "\xCF\xB2\x04\x11\xF8\x98\xEE\x79" \
           "\x62\x83\xC7\x81\x98\xF6\x77\xA6" \
           "\x2E\x3C\x4C\x82\xA0\xF0\x43\x2B" \
           "\x7C\x05\x86\x1B\x0E\xAC\xC2\x09" \
           "\xF8\x5C\x35\x31\x53\x51\x2B\x96" \
           "\x6A\x8D\x16\x6C\xB9\xA1\xB9\x0A" \
           "\x55\x67\x53\xC6\x32\xF5\x3B\xAD" \
           "\x6B\xBF\x0B\x2C\xE0\xA8\xC9\x20" \
           "\xC2\xE6\xA0\x2D\x9B\x41\x8D\xFB" \
           "\x6E\x56\x31\xD7\xA4\xA1\xE6\xAC" \
           "\xF5\xCA\xC1\x74\xAC\x35\x2D\x2E" \
           "\x5E\xC3\x27\xFC\xBD\xAB\x82\x43" \
           "\xC3\x5D\x52\x86\x9E\x9C\x4F\xDB" \
           "\xD0\xB8\x55\x13\x12\x0F\xC6\x67" \
           "\xC1\xAE\x21\xD4\x78\x79\xA0\xB5" \
           "\x66\x2F\x10\x6A\x67\xA7\x22\x2C" \
           "\xDA\xE0\x32\xB7\x86\x15\x5B\x26" \
           "\x29\xB9\x60\x6A\xDC\xF6\x73\x9E" \
           "\xD7\xED\xA7\x8C\xCC\x83\x53\x24" \
           "\xDE\x45\xCD\x5E\x68\x7A\x7C\xFF" \
           "\x24\xA2\x16\xC9\x58\xD5\x28\x70" \
           "\xC8\x23\xDA\xE5\xE3\x95\x93\xB2" \
           "\xD3\x73\x13\x68\x87\x0F\xB1\x42" \
           "\x14\x37\xD3\x5F\xB0\x2D\xAA\x45" \
           "\xF5\xE4\x1D\xF8\xCD\x89\x5F\x17" \
           "\xB6\x78\x4F\x21\xA3\x2D\x77\xCF" \
           "\x98\xDE\x44\x0C\x0E\xDE\x01\x75" \
           "\xF2\x4F\x40\x09\xDB\xAD\xF0\xEE" \
           "\x5B\xCF\x40\x35\x6C\xEA\xCD\x29" \
           "\x35\xAE\x6C\x9E\xB4\x96\x4D\xC4" \
           "\x8E\x6D\x17\xC3\xB2\x8A\xDF\xC8" \
           "\x03\x91\xF3\x90\xCE\x34\xA0\x90" \
           "\xDF\x8F\x56\x3A\x9A\x3D\x02\x17" \
           "\xD8\xA1\xFD\x00\xED\x36\x13\xD5" \
           "\xA2\xA1\x53\x7E\x42\x3D\x24\x80" \
           "\xA3\xF7\x84\x84\x3C\x22\x2B\x15" \
           "\x7A\xAA\xA2\x87\x89\xEA\xB3\x02" \
           "\xE5\xFC\x6C\xE0\xB9\x46\x29\xCA" \
           "\x82\x94\x19\x44\x1B\xA5\x9C\x71" \
           "\xC9\xFA\xF7\x3A\xEA\x06\xCA\xC2" \
           "\x59\x1A\xB5\xD9\x9D\x4B\x75\x67" \
           "\x43\x82\x86\x63\x38\xDB\xD4\x75" \
           "\x0E\x88\x0E\x6E\x6F\xAC\xDA\xA3" \
           "\x8E\x67\xB0\xAF\x45\x4F\x6C\xC1" \
           "\xFF\xC2\xFA\x1A\xAC\xBF\xDA\x0B" \
           "\x7B\x0B\xC2\x99\x46\x61\x03\x3B" \
           "\x2B\x6A\x46\xDC\xF6\x70\x66\x14" \
           "\xFE\x2D\x94\xAE\x88\xCA\x85\x49" \
           "\xD5\x10\xB8\xA0\xBC\x87\x61\x83" \
           "\x3E\x14\xCD\xE1\xCD\x7C\x01\x27" \
           "\x58\xC5\x0C\x1D\x4B\xF8\xD9\xDC" \
           "\x73\xB4\x54\xEE\xDE\x31\x5D\x4B" \
           "\xBD\x77\xF7\xAE\xCD\x71\x43\xD0" \
           "\x63\x85\x29\x51\x0D\x85\xA9\x13" \
           "\x0F\x1E\xDF\xF6\x69\x32\x61\x8E" \
           "\x8E\xB3\xEF\x7A\xE7\x9A\x11\xD2" \
           "\x1C\x1B\x9F\xBD\xEA\x54\xD7\x22" \
           "\x8A\x84\x5F\x43\x7D\x66\x6E\x8D" \
           "\xB3\xCF\xE7\x0A\x38\x3F\xFD\x0C" \
           "\xC7\x0A\x2B\x42\xBD\xC1\xFD\xBE" \
           "\x69\xAF\x10\x06\xA6\x29\xA9\x9F" \
           "\xB1\x00\x95\x56\x9E\x15\x6C\xDD" \
           "\xBD\xED\xA4\x86\x34\xE3\x0B\x4F" \
           "\x3D\xD5\x57\xE0\x87\x4C\x9C\x27" \
           "\x83\xE2\xF7\x92\x6D\xC8\x3A\x0D" \
           "\x60\xC5\x58\x1F\x68\x2A\xFE\x56" \
           "\xE4\x26\x03\xCF\x98\x18\xC8\x79" \
           "\xF2\x4D\x51\x59\xAA\xAC\xB1\x8C" \
           "\x1C\x04\xD6\xD1\x0E\x15\xA0\xBC" \
           "\x09\x75\x2B\x23\x59\xDC\x67\x68" \
           "\x60\x0A\x2D\x34\x00\x5C\x91\x20" \
           "\xB2\xCC\xDC\x00\x63\xA1\x4D\x38" \
           "\x74\x1E\xD2\x8B\xAB\x86\xA6\x86" \
           "\xB8\x9C\xC1\x0D\x95\xCB\x24\x1E" \
           "\xBB\x95\xC3\x97\xB6\xCC\xB3\xA7" \
           "\x1E\x22\xF3\xBA\xB3\x18\x02\xED" \
           "\x0D\xB6\x38\x30\x5D\x8B\x40\x31" \
           "\x00\xBF\x25\x23\x43\x07\x8F\x14" \
           "\x7D\xE3\x5D\xD3\xD2\xFC\x94\xED" \
           "\xC0\xA0\xD9\x1B\x1F\x6F\x6A\x32" \
           "\x4F\x78\x05\x98\xF2\xA2\x03\xDA" \
           "\x0E\x44\x05\x35\xA0\x55\x26\x35" \
           "\x07\xEB\xD0\xDC\xCD\x71\xE5\x3F" \
           "\x9A\xC6\xFF\x60\x94\x4B\x54\xD6" \
           "\x10\xE2\x9A\x97\x4A\xED\x8D\xE7" \
           "\x7C\x0C\x17\x80\x7D\x4E\x22\x36" \
           "\xEF\xF1\x3D\x91\x7B\x02\xA6\x37" \
           "\x14\x28\xB5\x91\x67\xD4\x0F\xDB" \
           "\x1C\x24\x09\x00\xD5\x3A\xB5\x15" \
           "\xF9\x50\xB2\x8B\x55\x48\x57\x1C" \
           "\xF6\x40\x5A\xA2\x9A\xDB\xDF\xDE" \
           "\x0F\x39\x5E\x0E\x30\x7B\x74\x2A" \
           "\x61\xD4\x64\x39\x65\xB4\x14\x5B" \
           "\xB9\xD4\x2D\xBB\x74\x8B\xA9\x79" \
           "\xB9\x05\x3B\x22\xC1\x35\xDC\xB2" \
           "\xD4\xDC\x2A\xB4\xFA\x6F\x33\x00" \
           "\xB9\x0A\xEF\x63\x98\x5D\x19\xD5" \
           "\xC7\x5B\xBB\x6D\x65\x1F\x41\x19" \
           "\xC3\xD1\xC1\xA4\x21\x08\xED\x00" \
           "\xC0\x02\x1B\xDD\x0F\xEE\x3F\x60" \
           "\xE9\x2E\x1B\xF6\xBF\x12\xF3\xFB" \
           "\xDA\x05\x2E\x40\x4C\x77\x30\x8D" \
           "\xF0\x46\xEC\xAE\x05\x18\x2D\x7F" \
           "\x04\x97\xAD\x9F\x5C\x62\x6D\x90" \
           "\x96\xFA\x38\x1F\x31\x86\x2F\xCC" \
           "\xB0\x98\x50\x98\x82\xA0\x3F\x52" \
           "\xEF\xC6\x23\x7F\xCB\xD4\xEB\xC1" \
           "\x6C\xF0\xA8\xED\xE1\xC0\x58\x86" \
           "\x51\x4D\x12\xE7\xA8\x70\xDD\xAF" \
           "\x4F\x65\x7E\x20\xCC\x16\x7C\xF1" \
           , 1024);
    memset(bOutDataExp, 0x42, 1024);
    bOutDataExp[0] = 0x30;
    bOutDataExp[1023] = 0x39;
    XXX_INPUT_XXX
    printf("[IN ]nSock          = %d\n", nSock);
    printf("[IN ]nFlag          = %d\n", nFlag);
    printf("[IN ]nMode          = %d\n", nMode);
    DspHex("[IN ]bKey           =", bKey, 16);
    DspHex("[IN ]bInData        =", bInData, nDataLen);
    printf("[IN ]nDataLen       = %d\n", nDataLen);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPISm4Calc(nSock, nFlag, nMode, bKey, bInData, nDataLen, bIV, bOutData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "SM4-CBC解密，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    ASSERT_OUT_HEX(bOutData, bOutDataExp, nDataLen);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void Sm4Calc_Test_05(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nFlag;
    int  nMode;
    BYTE bKey[32];
    BYTE bInData[4104];
	  BYTE bIV[16];
    int  nDataLen;
    BYTE bOutData[4104];
    BYTE bOutDataExp[4104];

    bufclr(bKey);
    bufclr(bInData);
    bufclr(bIV);
    bufclr(bOutData);
    bufclr(bOutDataExp);

    nFlag = 2;
    nMode = 1;
    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(bKey, "\xA2\xC0\xB0\xF8\xF7\xF5\xEE\x21" \
                 "\xFB\x5C\x6A\xEB\xE7\x14\xE5\x3A",\
                 16);
    nDataLen = 1024;
    memcpy(bInData, \
           "\x88\xC7\x7F\x3A\xA6\xA2\x9E\x4E" \
           "\x20\x31\x65\x7E\x38\x48\xA4\x63" \
           "\xE2\x63\xA2\xB0\xC4\x3E\xF4\xEF" \
           "\xA9\xF9\xC5\xA7\x22\xA1\x57\xA0" \
           "\xEB\x60\xD8\xE5\xFC\x56\xBA\xB8" \
           "\x36\x62\x0A\x7F\xF5\x40\x46\x68" \
           "\x4A\x30\x05\x1C\xD5\x0E\xED\x3F" \
           "\xD3\xBD\x4A\x15\x93\x03\x7D\xC2" \
           "\xA1\x2F\x65\xB1\x42\x17\xB0\xC9" \
           "\xB7\xAF\x3A\x84\xA1\xEF\xFE\xC1" \
           "\x58\x35\x31\xAF\x36\xC2\x7C\x4F" \
           "\x27\xA7\x8F\x8A\x1A\x1E\x81\x2C" \
           "\x71\x21\x48\xE0\xD5\x77\x7F\xDD" \
           "\x10\x79\x04\xEB\x14\x4F\xF7\x87" \
           "\xA4\xD1\xA7\xA2\xEB\x7D\x21\x59" \
           "\xF6\x43\xED\xB9\x48\x03\xE1\x99" \
           "\x9B\x3C\xEE\xFA\x60\x0C\x3F\xCE" \
           "\x30\x7B\xD3\x34\x51\xEC\xB8\xEC" \
           "\xCF\xB2\x04\x11\xF8\x98\xEE\x79" \
           "\x62\x83\xC7\x81\x98\xF6\x77\xA6" \
           "\x2E\x3C\x4C\x82\xA0\xF0\x43\x2B" \
           "\x7C\x05\x86\x1B\x0E\xAC\xC2\x09" \
           "\xF8\x5C\x35\x31\x53\x51\x2B\x96" \
           "\x6A\x8D\x16\x6C\xB9\xA1\xB9\x0A" \
           "\x55\x67\x53\xC6\x32\xF5\x3B\xAD" \
           "\x6B\xBF\x0B\x2C\xE0\xA8\xC9\x20" \
           "\xC2\xE6\xA0\x2D\x9B\x41\x8D\xFB" \
           "\x6E\x56\x31\xD7\xA4\xA1\xE6\xAC" \
           "\xF5\xCA\xC1\x74\xAC\x35\x2D\x2E" \
           "\x5E\xC3\x27\xFC\xBD\xAB\x82\x43" \
           "\xC3\x5D\x52\x86\x9E\x9C\x4F\xDB" \
           "\xD0\xB8\x55\x13\x12\x0F\xC6\x67" \
           "\xC1\xAE\x21\xD4\x78\x79\xA0\xB5" \
           "\x66\x2F\x10\x6A\x67\xA7\x22\x2C" \
           "\xDA\xE0\x32\xB7\x86\x15\x5B\x26" \
           "\x29\xB9\x60\x6A\xDC\xF6\x73\x9E" \
           "\xD7\xED\xA7\x8C\xCC\x83\x53\x24" \
           "\xDE\x45\xCD\x5E\x68\x7A\x7C\xFF" \
           "\x24\xA2\x16\xC9\x58\xD5\x28\x70" \
           "\xC8\x23\xDA\xE5\xE3\x95\x93\xB2" \
           "\xD3\x73\x13\x68\x87\x0F\xB1\x42" \
           "\x14\x37\xD3\x5F\xB0\x2D\xAA\x45" \
           "\xF5\xE4\x1D\xF8\xCD\x89\x5F\x17" \
           "\xB6\x78\x4F\x21\xA3\x2D\x77\xCF" \
           "\x98\xDE\x44\x0C\x0E\xDE\x01\x75" \
           "\xF2\x4F\x40\x09\xDB\xAD\xF0\xEE" \
           "\x5B\xCF\x40\x35\x6C\xEA\xCD\x29" \
           "\x35\xAE\x6C\x9E\xB4\x96\x4D\xC4" \
           "\x8E\x6D\x17\xC3\xB2\x8A\xDF\xC8" \
           "\x03\x91\xF3\x90\xCE\x34\xA0\x90" \
           "\xDF\x8F\x56\x3A\x9A\x3D\x02\x17" \
           "\xD8\xA1\xFD\x00\xED\x36\x13\xD5" \
           "\xA2\xA1\x53\x7E\x42\x3D\x24\x80" \
           "\xA3\xF7\x84\x84\x3C\x22\x2B\x15" \
           "\x7A\xAA\xA2\x87\x89\xEA\xB3\x02" \
           "\xE5\xFC\x6C\xE0\xB9\x46\x29\xCA" \
           "\x82\x94\x19\x44\x1B\xA5\x9C\x71" \
           "\xC9\xFA\xF7\x3A\xEA\x06\xCA\xC2" \
           "\x59\x1A\xB5\xD9\x9D\x4B\x75\x67" \
           "\x43\x82\x86\x63\x38\xDB\xD4\x75" \
           "\x0E\x88\x0E\x6E\x6F\xAC\xDA\xA3" \
           "\x8E\x67\xB0\xAF\x45\x4F\x6C\xC1" \
           "\xFF\xC2\xFA\x1A\xAC\xBF\xDA\x0B" \
           "\x7B\x0B\xC2\x99\x46\x61\x03\x3B" \
           "\x2B\x6A\x46\xDC\xF6\x70\x66\x14" \
           "\xFE\x2D\x94\xAE\x88\xCA\x85\x49" \
           "\xD5\x10\xB8\xA0\xBC\x87\x61\x83" \
           "\x3E\x14\xCD\xE1\xCD\x7C\x01\x27" \
           "\x58\xC5\x0C\x1D\x4B\xF8\xD9\xDC" \
           "\x73\xB4\x54\xEE\xDE\x31\x5D\x4B" \
           "\xBD\x77\xF7\xAE\xCD\x71\x43\xD0" \
           "\x63\x85\x29\x51\x0D\x85\xA9\x13" \
           "\x0F\x1E\xDF\xF6\x69\x32\x61\x8E" \
           "\x8E\xB3\xEF\x7A\xE7\x9A\x11\xD2" \
           "\x1C\x1B\x9F\xBD\xEA\x54\xD7\x22" \
           "\x8A\x84\x5F\x43\x7D\x66\x6E\x8D" \
           "\xB3\xCF\xE7\x0A\x38\x3F\xFD\x0C" \
           "\xC7\x0A\x2B\x42\xBD\xC1\xFD\xBE" \
           "\x69\xAF\x10\x06\xA6\x29\xA9\x9F" \
           "\xB1\x00\x95\x56\x9E\x15\x6C\xDD" \
           "\xBD\xED\xA4\x86\x34\xE3\x0B\x4F" \
           "\x3D\xD5\x57\xE0\x87\x4C\x9C\x27" \
           "\x83\xE2\xF7\x92\x6D\xC8\x3A\x0D" \
           "\x60\xC5\x58\x1F\x68\x2A\xFE\x56" \
           "\xE4\x26\x03\xCF\x98\x18\xC8\x79" \
           "\xF2\x4D\x51\x59\xAA\xAC\xB1\x8C" \
           "\x1C\x04\xD6\xD1\x0E\x15\xA0\xBC" \
           "\x09\x75\x2B\x23\x59\xDC\x67\x68" \
           "\x60\x0A\x2D\x34\x00\x5C\x91\x20" \
           "\xB2\xCC\xDC\x00\x63\xA1\x4D\x38" \
           "\x74\x1E\xD2\x8B\xAB\x86\xA6\x86" \
           "\xB8\x9C\xC1\x0D\x95\xCB\x24\x1E" \
           "\xBB\x95\xC3\x97\xB6\xCC\xB3\xA7" \
           "\x1E\x22\xF3\xBA\xB3\x18\x02\xED" \
           "\x0D\xB6\x38\x30\x5D\x8B\x40\x31" \
           "\x00\xBF\x25\x23\x43\x07\x8F\x14" \
           "\x7D\xE3\x5D\xD3\xD2\xFC\x94\xED" \
           "\xC0\xA0\xD9\x1B\x1F\x6F\x6A\x32" \
           "\x4F\x78\x05\x98\xF2\xA2\x03\xDA" \
           "\x0E\x44\x05\x35\xA0\x55\x26\x35" \
           "\x07\xEB\xD0\xDC\xCD\x71\xE5\x3F" \
           "\x9A\xC6\xFF\x60\x94\x4B\x54\xD6" \
           "\x10\xE2\x9A\x97\x4A\xED\x8D\xE7" \
           "\x7C\x0C\x17\x80\x7D\x4E\x22\x36" \
           "\xEF\xF1\x3D\x91\x7B\x02\xA6\x37" \
           "\x14\x28\xB5\x91\x67\xD4\x0F\xDB" \
           "\x1C\x24\x09\x00\xD5\x3A\xB5\x15" \
           "\xF9\x50\xB2\x8B\x55\x48\x57\x1C" \
           "\xF6\x40\x5A\xA2\x9A\xDB\xDF\xDE" \
           "\x0F\x39\x5E\x0E\x30\x7B\x74\x2A" \
           "\x61\xD4\x64\x39\x65\xB4\x14\x5B" \
           "\xB9\xD4\x2D\xBB\x74\x8B\xA9\x79" \
           "\xB9\x05\x3B\x22\xC1\x35\xDC\xB2" \
           "\xD4\xDC\x2A\xB4\xFA\x6F\x33\x00" \
           "\xB9\x0A\xEF\x63\x98\x5D\x19\xD5" \
           "\xC7\x5B\xBB\x6D\x65\x1F\x41\x19" \
           "\xC3\xD1\xC1\xA4\x21\x08\xED\x00" \
           "\xC0\x02\x1B\xDD\x0F\xEE\x3F\x60" \
           "\xE9\x2E\x1B\xF6\xBF\x12\xF3\xFB" \
           "\xDA\x05\x2E\x40\x4C\x77\x30\x8D" \
           "\xF0\x46\xEC\xAE\x05\x18\x2D\x7F" \
           "\x04\x97\xAD\x9F\x5C\x62\x6D\x90" \
           "\x96\xFA\x38\x1F\x31\x86\x2F\xCC" \
           "\xB0\x98\x50\x98\x82\xA0\x3F\x52" \
           "\xEF\xC6\x23\x7F\xCB\xD4\xEB\xC1" \
           "\x6C\xF0\xA8\xED\xE1\xC0\x58\x86" \
           "\x51\x4D\x12\xE7\xA8\x70\xDD\xAF" \
           "\x4F\x65\x7E\x20\xCC\x16\x7C\xF1" \
           , 1024);
    memset(bOutDataExp, 0x42, 1024);
    bOutDataExp[0] = 0x30;
    bOutDataExp[1023] = 0x39;
    XXX_INPUT_XXX
    printf("[IN ]nSock          = %d\n", nSock);
    printf("[IN ]nFlag          = %d\n", nFlag);
    printf("[IN ]nMode          = %d\n", nMode);
    DspHex("[IN ]bKey           =", bKey, 16);
    DspHex("[IN ]bInData        =", bInData, nDataLen);
    printf("[IN ]nDataLen       = %d\n", nDataLen);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPISm4Calc(nSock, nFlag, nMode, bKey, bInData, nDataLen, bIV, bOutData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 1, "SM4加解密，异常加解密标识2，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void Sm4Calc_Test_06(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nFlag;
    int  nMode;
    BYTE bKey[32];
    BYTE bInData[4104];
	  BYTE bIV[16];
    int  nDataLen;
    BYTE bOutData[4104];
    BYTE bOutDataExp[4104];

    bufclr(bKey);
    bufclr(bInData);
    bufclr(bIV);
    bufclr(bOutData);
    bufclr(bOutDataExp);

    nFlag = 0;
    nMode = 0;
    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(bKey, "\xA2\xC0\xB0\xF8\xF7\xF5\xEE\x21" \
                 "\xFB\x5C\x6A\xEB\xE7\x14\xE5\x3A",\
                 16);
    nDataLen = 1016;
    memcpy(bInData, \
           "\x88\xC7\x7F\x3A\xA6\xA2\x9E\x4E" \
           "\x20\x31\x65\x7E\x38\x48\xA4\x63" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\xC5\xF8\x11\xF6\x08\xBB\xF5\x4F" \
           "\x66\x9F\x9D\x1D\xE7\xC1\xE6\xE5" \
           "\x82\x2A\xD6\xA1\x4D\x0A\x65\x31" \
           "\x38\x12\x07\x8F\x05\x77\x25\xB5" \
           , 1024);
    memset(bOutDataExp, 0x42, 1024);
    bOutDataExp[0] = 0x30;
    bOutDataExp[1023] = 0x39;

    XXX_INPUT_XXX
    printf("[IN ]nSock          = %d\n", nSock);
    printf("[IN ]nFlag          = %d\n", nFlag);
    printf("[IN ]nMode          = %d\n", nMode);
    DspHex("[IN ]bKey           =", bKey, 16);
    DspHex("[IN ]bInData        =", bInData, nDataLen);
    printf("[IN ]nDataLen       = %d\n", nDataLen);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPISm4Calc(nSock, nFlag, nMode, bKey, bInData, nDataLen, bIV, bOutData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 1, "SM4加密，数据长度不是16倍数，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void TransKeyIntoSK_Test_01(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int  nPadMode;
	  BYTE bSK[2400];
	  int  nSKLen;
	  BYTE bKeyByPK[260];
	  int  nKeyByPKLen;
	  BYTE bKeyByHMK[2056];
	  int  nKeyByHMKLen;
	  BYTE bKeyByHMKExp[260];
	  int  nKeyByHMKLenExp;

    bufclr(bSK);
    bufclr(bKeyByHMK);
    bufclr(bKeyByPK);
    nKeyByPKLen = 0;
    bufclr(bKeyByHMKExp);

    nPadMode = 1;
    /* PK = 30660261009C393A6CD065344C79A3D2087AD31C8672A9EF5335AD9AD8648DEE83C1D9D500EACCFC88E3A9F9267F3E81F7476659FCF411A8CE626B425F5CD60536887E4ABD49490DA29648BF5475BCC01ECE75AE38A1202029ED963354A1C659CBED5E3DE9020103 */
    /* SK = 308201C90201000261009C393A6CD065344C79A3D2087AD31C8672A9EF5335AD9AD8648DEE83C1D9D500EACCFC88E3A9F9267F3E81F7476659FCF411A8CE626B425F5CD60536887E4ABD49490DA29648BF5475BCC01ECE75AE38A1202029ED963354A1C659CBED5E3DE90201030260682626F33598CD885117E15AFC8CBDAEF71BF4E223C911E5985E9F02813BE355F1DDFDB097C6A619AA29ABFA2F9991524292912755A8728959A284DB0985EA019BF00CBCFF7EACA787B79480A26D4F36845F44D479FE9C009DED27016C7E3903023100CF17A0ED49B8F9404CCAFB5CEDE74E7D2A85A0DA433070FF3F0BEF10B35A0FCFCC4E57C75D0CAE23456E91AD671DAB7B023100C11E2E2618359D51099742910C4E1D3DB4DB59ACD3DA4B59EB1D724D2777A7970E42E123D98B9B306F740D9C63833CEB0231008A0FC09E3125FB803331FCE89E9A345371AE6B3C2CCAF5FF7F5D4A0B223C0A8A88343A84E8B31EC22E49B6739A13C7A702310080BEC96EBACE68E0B10F81B60834137E78923BC88D3C323BF213A188C4FA6FBA0981EB6D3BB267759FA2B3BD97ACD34702301A9FF3F129DD2ED273AAF1727B08123C4A31C3D5BFAE54593A0B778F112EC7046196319FD2FC0F46B4E764BF8C413EAA */
    /* SKByHMK = A06B2552408C86E5B14F586D4B65E875B20A22CCBD44B1E3C1F8B2DBF20E6F52A595C8C9D2BF6F98317DB30978D62132C43855831F04C43F14A32368565A37B3D46E6B38E97BC07CB18FD8D998575D4F62DF2EC5FABF41C7BC3DC0F83B3B57C75C56FC1566549BCBC1C863A14E349837D92A7754C1C4B216E84ED7BA17B47E86F461FB2AABD83C92527A4B55260862F29C22B0F732A28A2DB288DA4D4C178C6BEEAE5150350E238515B1818DAFBA411E7C295B6D93D21D7F6C1BF33229A8AFC77121D7EF1CDD12E877531B6F12D510948F6AEF34188FAEA9478216343E43FC76DF870F2CFC07234C2FD5E643C420357828D474E6F1214F33C8E0F77A160BAF9758EBD31A404B289EB72BFDA38DB5A709FFD01BE679F2316876F19743CC8A5C1F300EAC73213B6F36397FD8EB6CA1D71FE5CB22F9A1D404AE314972DD48208D877A82A6C6B2926AF7D837F2932EA67DC5F9A0DCA2B590A11E4F58003E5F3F921C7CA4A8097FD7F5F684EFBC13DE2D87E22CEB2A04A1B5F2C849943945F50F575FDC0F5724F0F05E2BF042F63618C4A09D667C5BA44100C0E498C2AF42F08B1EAB77CF8BABF332EF537D0C076DAF0D03F4AE084C7A01DEB5B145EB212FB60B472DBBAC7C9330459EAB85642B8FEAC161A0 */
    /* Key = 0123456789ABCDEFFEDCBA9876543210 */
    /* KeyByPK = 52C2DFC88A8207AD162F3D87D4760CAB930D4DA4D56357CA382A790E5DF64C4F0BBC3275D5B2F8B5188B2BE153A393AED57C8BF3B4D1A0D487AF4B32157754AA311A92BAE7042E0C53D17FA2ED6FDE532861E490C0B06A7D6F3B8283E42A0892 */
    /* KeyByHMK = A2C0B0F8F7F5EE21FB5C6AEBE714E53A */

    memcpy(bSK,
           "\xA0\x6B\x25\x52\x40\x8C\x86\xE5" \
           "\xB1\x4F\x58\x6D\x4B\x65\xE8\x75" \
           "\xB2\x0A\x22\xCC\xBD\x44\xB1\xE3" \
           "\xC1\xF8\xB2\xDB\xF2\x0E\x6F\x52" \
           "\xA5\x95\xC8\xC9\xD2\xBF\x6F\x98" \
           "\x31\x7D\xB3\x09\x78\xD6\x21\x32" \
           "\xC4\x38\x55\x83\x1F\x04\xC4\x3F" \
           "\x14\xA3\x23\x68\x56\x5A\x37\xB3" \
           "\xD4\x6E\x6B\x38\xE9\x7B\xC0\x7C" \
           "\xB1\x8F\xD8\xD9\x98\x57\x5D\x4F" \
           "\x62\xDF\x2E\xC5\xFA\xBF\x41\xC7" \
           "\xBC\x3D\xC0\xF8\x3B\x3B\x57\xC7" \
           "\x5C\x56\xFC\x15\x66\x54\x9B\xCB" \
           "\xC1\xC8\x63\xA1\x4E\x34\x98\x37" \
           "\xD9\x2A\x77\x54\xC1\xC4\xB2\x16" \
           "\xE8\x4E\xD7\xBA\x17\xB4\x7E\x86" \
           "\xF4\x61\xFB\x2A\xAB\xD8\x3C\x92" \
           "\x52\x7A\x4B\x55\x26\x08\x62\xF2" \
           "\x9C\x22\xB0\xF7\x32\xA2\x8A\x2D" \
           "\xB2\x88\xDA\x4D\x4C\x17\x8C\x6B" \
           "\xEE\xAE\x51\x50\x35\x0E\x23\x85" \
           "\x15\xB1\x81\x8D\xAF\xBA\x41\x1E" \
           "\x7C\x29\x5B\x6D\x93\xD2\x1D\x7F" \
           "\x6C\x1B\xF3\x32\x29\xA8\xAF\xC7" \
           "\x71\x21\xD7\xEF\x1C\xDD\x12\xE8" \
           "\x77\x53\x1B\x6F\x12\xD5\x10\x94" \
           "\x8F\x6A\xEF\x34\x18\x8F\xAE\xA9" \
           "\x47\x82\x16\x34\x3E\x43\xFC\x76" \
           "\xDF\x87\x0F\x2C\xFC\x07\x23\x4C" \
           "\x2F\xD5\xE6\x43\xC4\x20\x35\x78" \
           "\x28\xD4\x74\xE6\xF1\x21\x4F\x33" \
           "\xC8\xE0\xF7\x7A\x16\x0B\xAF\x97" \
           "\x58\xEB\xD3\x1A\x40\x4B\x28\x9E" \
           "\xB7\x2B\xFD\xA3\x8D\xB5\xA7\x09" \
           "\xFF\xD0\x1B\xE6\x79\xF2\x31\x68" \
           "\x76\xF1\x97\x43\xCC\x8A\x5C\x1F" \
           "\x30\x0E\xAC\x73\x21\x3B\x6F\x36" \
           "\x39\x7F\xD8\xEB\x6C\xA1\xD7\x1F" \
           "\xE5\xCB\x22\xF9\xA1\xD4\x04\xAE" \
           "\x31\x49\x72\xDD\x48\x20\x8D\x87" \
           "\x7A\x82\xA6\xC6\xB2\x92\x6A\xF7" \
           "\xD8\x37\xF2\x93\x2E\xA6\x7D\xC5" \
           "\xF9\xA0\xDC\xA2\xB5\x90\xA1\x1E" \
           "\x4F\x58\x00\x3E\x5F\x3F\x92\x1C" \
           "\x7C\xA4\xA8\x09\x7F\xD7\xF5\xF6" \
           "\x84\xEF\xBC\x13\xDE\x2D\x87\xE2" \
           "\x2C\xEB\x2A\x04\xA1\xB5\xF2\xC8" \
           "\x49\x94\x39\x45\xF5\x0F\x57\x5F" \
           "\xDC\x0F\x57\x24\xF0\xF0\x5E\x2B" \
           "\xF0\x42\xF6\x36\x18\xC4\xA0\x9D" \
           "\x66\x7C\x5B\xA4\x41\x00\xC0\xE4" \
           "\x98\xC2\xAF\x42\xF0\x8B\x1E\xAB" \
           "\x77\xCF\x8B\xAB\xF3\x32\xEF\x53" \
           "\x7D\x0C\x07\x6D\xAF\x0D\x03\xF4" \
           "\xAE\x08\x4C\x7A\x01\xDE\xB5\xB1" \
           "\x45\xEB\x21\x2F\xB6\x0B\x47\x2D" \
           "\xBB\xAC\x7C\x93\x30\x45\x9E\xAB" \
           "\x85\x64\x2B\x8F\xEA\xC1\x61\xA0" \
           , 464);
    nSKLen = 464;

    memcpy(bKeyByPK,
           "\x52\xC2\xDF\xC8\x8A\x82\x07\xAD" \
           "\x16\x2F\x3D\x87\xD4\x76\x0C\xAB" \
           "\x93\x0D\x4D\xA4\xD5\x63\x57\xCA" \
           "\x38\x2A\x79\x0E\x5D\xF6\x4C\x4F" \
           "\x0B\xBC\x32\x75\xD5\xB2\xF8\xB5" \
           "\x18\x8B\x2B\xE1\x53\xA3\x93\xAE" \
           "\xD5\x7C\x8B\xF3\xB4\xD1\xA0\xD4" \
           "\x87\xAF\x4B\x32\x15\x77\x54\xAA" \
           "\x31\x1A\x92\xBA\xE7\x04\x2E\x0C" \
           "\x53\xD1\x7F\xA2\xED\x6F\xDE\x53" \
           "\x28\x61\xE4\x90\xC0\xB0\x6A\x7D" \
           "\x6F\x3B\x82\x83\xE4\x2A\x08\x92" \
           , 96);
    nKeyByPKLen = 96;

    memcpy(bKeyByHMKExp,
           "\xA2\xC0\xB0\xF8\xF7\xF5\xEE\x21" \
           "\xFB\x5C\x6A\xEB\xE7\x14\xE5\x3A" \
           , 16);
    nKeyByHMKLenExp = 16;

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]nPadMode = %d\n", nPadMode);
    DspHex("[IN ]bSK =", bSK, nSKLen);
    printf("[IN ]nPKLen = %d\n", nSKLen);
    DspHex("[IN ]bKeyByPK =", bKeyByPK, nKeyByPKLen);
    printf("[IN ]nKeyByPKLen = %d\n", nKeyByPKLen);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPITransKeyIntoSK(nSock, nPadMode, bSK, nSKLen, bKeyByPK, \
                                nKeyByPKLen, bKeyByHMK, &nKeyByHMKLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "私钥转加密，RSA-768，PKCS#1，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    DspHex("[OUT]bKeyByHMK    =", bKeyByHMK, nKeyByHMKLen);
    DspHex("[OUT]bKeyByHMKExp =", bKeyByHMKExp, nKeyByHMKLenExp);
    ASSERT_OUT_HEX(bKeyByHMK, bKeyByHMKExp, nKeyByHMKLenExp);
    ASSERT_OUT(nKeyByHMKLen, nKeyByHMKLenExp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void TransKeyIntoSK_Test_02(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int  nPadMode;
	  BYTE bSK[2400];
	  int  nSKLen;
	  BYTE bKeyByPK[260];
	  int  nKeyByPKLen;
	  BYTE bKeyByHMK[2056];
	  int  nKeyByHMKLen;
	  BYTE bKeyByHMKExp[260];
	  int  nKeyByHMKLenExp;

    bufclr(bSK);
    bufclr(bKeyByHMK);
    bufclr(bKeyByPK);
    nKeyByPKLen = 0;
    bufclr(bKeyByHMKExp);

    nPadMode = 1;
    /* PK = 30818702818100ACEAA1BBBD502B57DDC03818E5E868138DB129C4CAC53B2429A8D9032BD2E9685F1825BDD4D6264A1259427C72D40A53BD684B4C2983F4DCF5B0B26A6E95FC5FC35BF7F58AEBB21DFB205864D76F8890D454DA513A24F815FCFA17B28CB2C0B32F4C71833FDF2790B5AA0AF59F66940A3E42D660D9F146F6653ABAC64D253B83020103 */
    /* SK = 3082025C02010002818100ACEAA1BBBD502B57DDC03818E5E868138DB129C4CAC53B2429A8D9032BD2E9685F1825BDD4D6264A1259427C72D40A53BD684B4C2983F4DCF5B0B26A6E95FC5FC35BF7F58AEBB21DFB205864D76F8890D454DA513A24F815FCFA17B28CB2C0B32F4C71833FDF2790B5AA0AF59F66940A3E42D660D9F146F6653ABAC64D253B830201030281807347167D28E01CE53E802565EE9AF00D0920C68331D8D2181BC5E6021D37464594BAC3D3E3396EDC0C3B81A84C8D5C37D39ADCDD7102A33DF92076F19F0EA83EBEC5FC716034AB19DC2D5E86F0F110AFF6DD5498E83423CD8B13A8C538191F8DF4A15B0DCE91A0310689C8A93452ACCC915F94C03ABE967B9339FAD7C413775B024100DBD9641882E2C40D5F0C2BD4B90DE22881A1E19FC917F87802732AEB197E911BBF9C9FF9B42BA26F8D9C02D4EE95BE9D1EC8EE98C0F8A17B7913665A1AD6DDFF024100C9599932F7B9ED69D1D01EC5B4F80D606066F9CC14BEC9E9A9E96F9F9F0E804280BDC8F4D5D914D79E3F5B22E254D23A456A88A7C0DAC3C18F505C288C312A7D0241009290ED65AC972D5E3F5D728DD0B3EC1B0116966A860FFAFAAC4CC747665460BD2A686AA6781D16F50912AC8DF463D468BF309F1080A5C0FCFB62443C11E493FF024100863BBB774FD148F1368ABF2E78A55E404044A6880DD4869BC69B9FBFBF5F002C55D3DB4DE3E60DE5142A3CC1EC388C26D8F1B06FD5E72D2BB4E03D705D761C53024100B1BACE868528C216A7B4EB92F1F22091899D2E15E58C0BEA76BDA5474742869DA76013D77CEFF155518D148BAC268728E1DD10FF58BE23A8F464E786B7267DE3 */
    /* SKByHMK = 3BD4505C7E8610CE9A5ACB256CCD0B9E3ED481CAD63DB6E7D3CFABA8FC3F18A507C8A8B552806C2A4F436B94F1C59CA85944E9FD3EAEAE79AFE08C25B2512AE88D3A606B27DAAF57D77DB58344369B62EB673A9F59945B28832833A6A1ED26BCB3CF31FF3BB644B6C54F7427339C37CA9BC60DE40AD13A522F2470F6F9CEBBB3581DD31C73725391123F7E29DC08A70B7E9CA482A6F2D1551F658314D7A3A6D8F86455E6EC4809486F1E14DBE12407DD04D3B26911FFDDC122676150E216A4672F1346E7958708E02D01F65A7213AA4FA723E1E72A6C6FD018AD2B01286E95C0B808B69F98B4FFF0428B9C360484949C8035A4AB1EFFC414E2803E3A604C3C288DB9C796CAAB95DEED8A210F24C52125E907EDA3DB36D0C72418C36452201E45387BDC0852690E358DFEC3D28516BBA41E7B7C7FDE14CEA99505584DF8053655EF50A761E6C5C5EF79C3D91F29EB486055AC91DC751FFDE561130A1FD5D006D25FDFAA6A12593224B72A22C6FCB24C9C1A12D3CC12EEFEE1DBD5F930EED7EF2FF93778C9048369CB8ED40A63CA246B8D5CD94B2836E594E478CF7BEFE5CF1AD7FEE1332B8AC42206AE422292D93572E0308AFBA0E8B6117828B710EC3A4EFCDDAA1511AFB1EB416B00C53510A2933AC283D2119B6791403015348A9003CE8A43B3DB8D078E3C371377FB411E902D29FE81CA13171E32EC60D1E0BB810E992CE55B898031D7032DF7328303A2D5B323E988311251BF185C258B2D39243C8D84591AA93D82E37919BBBF5B4DD9199F5F9ACF43407C2FC4171C4A781BD6561C14A70F6983DB5AC1531322717ABE22B2234F1E9DE332AA1BE2E85CBFB68C346E6E4E6BCB2CCA658BFD78 */
    /* Key = 0123456789ABCDEFFEDCBA9876543210 */
    /* KeyByPK = 8BB63AA0D69C0D57E9A3D7EE9A9F7E32C1B3E4A9DF6DD7A4510FD5DE5885A03950ECA08CC4430D9D867ED30778DA255ECA8E4C6011D4196263BC53BF75D33190D6FD7D2712B3A9E1D8F666AD6836F8E68CCA4AD55DD7EA26DDD5065927A44A7B0CEDD80656E3E19A245D853856FA04C0C417B29131FA1AC352E1D0FAFFA13F74 */
    /* KeyByHMK = A2C0B0F8F7F5EE21FB5C6AEBE714E53A */

    memcpy(bSK,
           "\x3B\xD4\x50\x5C\x7E\x86\x10\xCE" \
           "\x9A\x5A\xCB\x25\x6C\xCD\x0B\x9E" \
           "\x3E\xD4\x81\xCA\xD6\x3D\xB6\xE7" \
           "\xD3\xCF\xAB\xA8\xFC\x3F\x18\xA5" \
           "\x07\xC8\xA8\xB5\x52\x80\x6C\x2A" \
           "\x4F\x43\x6B\x94\xF1\xC5\x9C\xA8" \
           "\x59\x44\xE9\xFD\x3E\xAE\xAE\x79" \
           "\xAF\xE0\x8C\x25\xB2\x51\x2A\xE8" \
           "\x8D\x3A\x60\x6B\x27\xDA\xAF\x57" \
           "\xD7\x7D\xB5\x83\x44\x36\x9B\x62" \
           "\xEB\x67\x3A\x9F\x59\x94\x5B\x28" \
           "\x83\x28\x33\xA6\xA1\xED\x26\xBC" \
           "\xB3\xCF\x31\xFF\x3B\xB6\x44\xB6" \
           "\xC5\x4F\x74\x27\x33\x9C\x37\xCA" \
           "\x9B\xC6\x0D\xE4\x0A\xD1\x3A\x52" \
           "\x2F\x24\x70\xF6\xF9\xCE\xBB\xB3" \
           "\x58\x1D\xD3\x1C\x73\x72\x53\x91" \
           "\x12\x3F\x7E\x29\xDC\x08\xA7\x0B" \
           "\x7E\x9C\xA4\x82\xA6\xF2\xD1\x55" \
           "\x1F\x65\x83\x14\xD7\xA3\xA6\xD8" \
           "\xF8\x64\x55\xE6\xEC\x48\x09\x48" \
           "\x6F\x1E\x14\xDB\xE1\x24\x07\xDD" \
           "\x04\xD3\xB2\x69\x11\xFF\xDD\xC1" \
           "\x22\x67\x61\x50\xE2\x16\xA4\x67" \
           "\x2F\x13\x46\xE7\x95\x87\x08\xE0" \
           "\x2D\x01\xF6\x5A\x72\x13\xAA\x4F" \
           "\xA7\x23\xE1\xE7\x2A\x6C\x6F\xD0" \
           "\x18\xAD\x2B\x01\x28\x6E\x95\xC0" \
           "\xB8\x08\xB6\x9F\x98\xB4\xFF\xF0" \
           "\x42\x8B\x9C\x36\x04\x84\x94\x9C" \
           "\x80\x35\xA4\xAB\x1E\xFF\xC4\x14" \
           "\xE2\x80\x3E\x3A\x60\x4C\x3C\x28" \
           "\x8D\xB9\xC7\x96\xCA\xAB\x95\xDE" \
           "\xED\x8A\x21\x0F\x24\xC5\x21\x25" \
           "\xE9\x07\xED\xA3\xDB\x36\xD0\xC7" \
           "\x24\x18\xC3\x64\x52\x20\x1E\x45" \
           "\x38\x7B\xDC\x08\x52\x69\x0E\x35" \
           "\x8D\xFE\xC3\xD2\x85\x16\xBB\xA4" \
           "\x1E\x7B\x7C\x7F\xDE\x14\xCE\xA9" \
           "\x95\x05\x58\x4D\xF8\x05\x36\x55" \
           "\xEF\x50\xA7\x61\xE6\xC5\xC5\xEF" \
           "\x79\xC3\xD9\x1F\x29\xEB\x48\x60" \
           "\x55\xAC\x91\xDC\x75\x1F\xFD\xE5" \
           "\x61\x13\x0A\x1F\xD5\xD0\x06\xD2" \
           "\x5F\xDF\xAA\x6A\x12\x59\x32\x24" \
           "\xB7\x2A\x22\xC6\xFC\xB2\x4C\x9C" \
           "\x1A\x12\xD3\xCC\x12\xEE\xFE\xE1" \
           "\xDB\xD5\xF9\x30\xEE\xD7\xEF\x2F" \
           "\xF9\x37\x78\xC9\x04\x83\x69\xCB" \
           "\x8E\xD4\x0A\x63\xCA\x24\x6B\x8D" \
           "\x5C\xD9\x4B\x28\x36\xE5\x94\xE4" \
           "\x78\xCF\x7B\xEF\xE5\xCF\x1A\xD7" \
           "\xFE\xE1\x33\x2B\x8A\xC4\x22\x06" \
           "\xAE\x42\x22\x92\xD9\x35\x72\xE0" \
           "\x30\x8A\xFB\xA0\xE8\xB6\x11\x78" \
           "\x28\xB7\x10\xEC\x3A\x4E\xFC\xDD" \
           "\xAA\x15\x11\xAF\xB1\xEB\x41\x6B" \
           "\x00\xC5\x35\x10\xA2\x93\x3A\xC2" \
           "\x83\xD2\x11\x9B\x67\x91\x40\x30" \
           "\x15\x34\x8A\x90\x03\xCE\x8A\x43" \
           "\xB3\xDB\x8D\x07\x8E\x3C\x37\x13" \
           "\x77\xFB\x41\x1E\x90\x2D\x29\xFE" \
           "\x81\xCA\x13\x17\x1E\x32\xEC\x60" \
           "\xD1\xE0\xBB\x81\x0E\x99\x2C\xE5" \
           "\x5B\x89\x80\x31\xD7\x03\x2D\xF7" \
           "\x32\x83\x03\xA2\xD5\xB3\x23\xE9" \
           "\x88\x31\x12\x51\xBF\x18\x5C\x25" \
           "\x8B\x2D\x39\x24\x3C\x8D\x84\x59" \
           "\x1A\xA9\x3D\x82\xE3\x79\x19\xBB" \
           "\xBF\x5B\x4D\xD9\x19\x9F\x5F\x9A" \
           "\xCF\x43\x40\x7C\x2F\xC4\x17\x1C" \
           "\x4A\x78\x1B\xD6\x56\x1C\x14\xA7" \
           "\x0F\x69\x83\xDB\x5A\xC1\x53\x13" \
           "\x22\x71\x7A\xBE\x22\xB2\x23\x4F" \
           "\x1E\x9D\xE3\x32\xAA\x1B\xE2\xE8" \
           "\x5C\xBF\xB6\x8C\x34\x6E\x6E\x4E" \
           "\x6B\xCB\x2C\xCA\x65\x8B\xFD\x78" \
           , 616);
    nSKLen = 616;

    memcpy(bKeyByPK,
           "\x8B\xB6\x3A\xA0\xD6\x9C\x0D\x57" \
           "\xE9\xA3\xD7\xEE\x9A\x9F\x7E\x32" \
           "\xC1\xB3\xE4\xA9\xDF\x6D\xD7\xA4" \
           "\x51\x0F\xD5\xDE\x58\x85\xA0\x39" \
           "\x50\xEC\xA0\x8C\xC4\x43\x0D\x9D" \
           "\x86\x7E\xD3\x07\x78\xDA\x25\x5E" \
           "\xCA\x8E\x4C\x60\x11\xD4\x19\x62" \
           "\x63\xBC\x53\xBF\x75\xD3\x31\x90" \
           "\xD6\xFD\x7D\x27\x12\xB3\xA9\xE1" \
           "\xD8\xF6\x66\xAD\x68\x36\xF8\xE6" \
           "\x8C\xCA\x4A\xD5\x5D\xD7\xEA\x26" \
           "\xDD\xD5\x06\x59\x27\xA4\x4A\x7B" \
           "\x0C\xED\xD8\x06\x56\xE3\xE1\x9A" \
           "\x24\x5D\x85\x38\x56\xFA\x04\xC0" \
           "\xC4\x17\xB2\x91\x31\xFA\x1A\xC3" \
           "\x52\xE1\xD0\xFA\xFF\xA1\x3F\x74" \
           , 128);
    nKeyByPKLen = 128;

    memcpy(bKeyByHMKExp,
           "\xA2\xC0\xB0\xF8\xF7\xF5\xEE\x21" \
           "\xFB\x5C\x6A\xEB\xE7\x14\xE5\x3A" \
           , 16);
    nKeyByHMKLenExp = 16;

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]nPadMode = %d\n", nPadMode);
    DspHex("[IN ]bSK =", bSK, nSKLen);
    printf("[IN ]nPKLen = %d\n", nSKLen);
    DspHex("[IN ]bKeyByPK =", bKeyByPK, nKeyByPKLen);
    printf("[IN ]nKeyByPKLen = %d\n", nKeyByPKLen);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPITransKeyIntoSK(nSock, nPadMode, bSK, nSKLen, bKeyByPK, \
                                nKeyByPKLen, bKeyByHMK, &nKeyByHMKLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "私钥转加密，RSA-1024，PKCS#1，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    DspHex("[OUT]bKeyByHMK    =", bKeyByHMK, nKeyByHMKLen);
    DspHex("[OUT]bKeyByHMKExp =", bKeyByHMKExp, nKeyByHMKLenExp);
    ASSERT_OUT_HEX(bKeyByHMK, bKeyByHMKExp, nKeyByHMKLenExp);
    ASSERT_OUT(nKeyByHMKLen, nKeyByHMKLenExp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void TransKeyIntoSK_Test_03(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int  nPadMode;
	  BYTE bSK[2400];
	  int  nSKLen;
	  BYTE bKeyByPK[260];
	  int  nKeyByPKLen;
	  BYTE bKeyByHMK[2056];
	  int  nKeyByHMKLen;
	  BYTE bKeyByHMKExp[260];
	  int  nKeyByHMKLenExp;

    bufclr(bSK);
    bufclr(bKeyByHMK);
    bufclr(bKeyByPK);
    nKeyByPKLen = 0;
    bufclr(bKeyByHMKExp);

    nPadMode = 1;
    /* PK = 30819702819100D9045225540C7545A0E293192E64ED68119B30FF725BE1F78D9859B734BE26EF4206C90CD52D0DE85D5DE3C6D73979A10F523E4EF855AE1D9E5D97BA9655786ADF394701CBD81F5304C51305F75524E89F66F32AF1119B65E7AE6A7B69211F51B7347E73D84E7FD4503DA37E01CD1071AAAB6A546A7EEEFB36704E296BAA920C5736466CBEA2F18CFB36DD6832B52BED020103 */
    /* SK = 308202A402010002819100D9045225540C7545A0E293192E64ED68119B30FF725BE1F78D9859B734BE26EF4206C90CD52D0DE85D5DE3C6D73979A10F523E4EF855AE1D9E5D97BA9655786ADF394701CBD81F5304C51305F75524E89F66F32AF1119B65E7AE6A7B69211F51B7347E73D84E7FD4503DA37E01CD1071AAAB6A546A7EEEFB36704E296BAA920C5736466CBEA2F18CFB36DD6832B52BED0201030281910090AD8C18E2B2F8D915EC6210C9989E45611220AA4C3D414FB3BAE67A23296F4A2C0486088E1E09459393ED2F3A2651160A36D434A58E7413BEE90FD1B98E50473F7B84ABDD3ABF8B72BDC61930F32CB8BB82572A6C2FD7C7BCBB4072AC83288E7F8E3154CFE43E131500BC5A09EF6D4A2620A4D9F504A5CD75F7F412373A671ACECF6F91C2AB68A8821E0F1474743B6B024900FD8179D82AD728AD6D759FCE4A7830D9E694F325C962B6634967E366CB0A58EE787713659D268FAA8BF6F48A84C44AAAFFA58DC6CE35358FC1685E7765063311FB2944965CA0E749024900DB26F0080311392618ADD09D0451A6E0660096A99CF9AC18AE77510DD56DC9C93845759155BF5CD7E5837E82F633AB9C05D6D2474A9DC1D45F96C09AB59BA17E3CE082332765EB85024900A900FBE571E4C5C8F3A3BFDEDC50209144634CC3DB97244230EFECEF3206E5F4504F6243BE19B51C5D4F4DB1ADD831C75519092F3423790A80F03EFA43597761521B830EE86B44DB0249009219F55AACB6261965C935BE02E119EAEEAB0F1BBDFBC810744F8B5E8E493130D02E4E60E3D4E88FEE57A9ACA422726803E48C2F8713D68D950F2B11CE67C0FED34056CCC4EE9D0302483A4BA1F3F8124C6B3505F3C5CD15B8146F962FE5BE03F4ACD400E8956A91EEF957B2A96D7C07559EE4A78150D1772394794853B54A459F60FE1CA28F3CAB9CE834EC088496F6CEE8 */
    /* SKByHMK = 81F889B5B4830C7B8749C14955199BE14C3062E771BFE5035880F9914E3224AAAE6BEB8CE1A7D6066F563D8B236368EF497F0938E2CF3421508D2E7A0439087BF7E0142D3EA31112EC4B1CA0FBBC97451A7542950A417A2DB8B37804C7C50DD257ACA2879CB9CD4AA581BE8A7A22A83716F7B4C0CDEC8C7D154DC7A0365BD906BD9D2A986E3809018901D3FD77C3C3072E07957D4040E32B3DB5886B961ADA4954CEAD111FB886393E745389955C4B2BCDB31944F0509D0C18206F3CD329D4CC7EFFD40BF47F342C6FF1EC9DDBB7D3AD88F2B3D4DEFE56215F9229B3ADF2EA51E0CF66D57D526A1713C7F5149A8121699D0479721FF88D39587BBA5DDCF164110347000D7535F9587CA6A687746112AEA126C14628ACC00E26F2573BB2BCAEB010B439CC3E4EB2FFBDCE7768DF8DB06CCEE4358C7B0AB5C0131297DD56F61A29B4258F318C74DD59D9C76E264BBFCB19EE5BEF70BAB8EB0B6E17BD61ED32DB419B5B91F3A9E95B3C9485449C7E2501EBE52BFCBC95C5053904929F1DB02486B537CF980A26CD3E88482546DE35A36EB932FE682EBA48F35DBCC32CE2E82FF93DBBAA512B7181A6F9634976997B2445A759C0F099BA5734B251AE65C337F2293CE9011CE90C895CA53E6687E056B2B1FC68D0B9AE3F73970819E526564E9C1607971B14E8221B4477FCD348CE33D75FCBC9C8626DDF7FF7344F9159C578931DA4977ADB3909437F68D94E39C84EE21CA9F3B48FD1CDD624199AA4B72BE3F5C9EC05964EE36736BF547C1695F5575DCF5B7683E9ABDE2E0F7265941393991001F0FF02391456D21162310F559EFF37E743BCF8CF5A9C9FCB1EF072E8745CBA7348A5BC44FC11E5B64F87D93DACE5661012802D70C02E42C41639803538C5779E8D0E545C054E4694CE619CA0DF56101AC805935891B1790AAD41BCFE2A2F5E53C04C7A32995EA1A8EF6BCB2CCA658BFD78 */
    /* Key = 0123456789ABCDEFFEDCBA9876543210 */
    /* KeyByPK = 9E52AC170D4BEC2183A023E70D2B2D0A6C505E86AAEB11800B182DADE60691EE4F5D2E75552E95224863B167C1891EE6FCDAE86FF9DA75E1E767A673A3F77D0FACB9E679278E424FEE3C8D4C735212D458C55D0C7DEC974CB2AA00877F9D3356980F07BE20F241CE2E077E42E024DBD8DE37B54E109CE41016F1DAD78E084F72CD6ED408C19AEE6476515E6A28586710 */
    /* KeyByHMK = A2C0B0F8F7F5EE21FB5C6AEBE714E53A */

    memcpy(bSK,
           "\x81\xF8\x89\xB5\xB4\x83\x0C\x7B" \
           "\x87\x49\xC1\x49\x55\x19\x9B\xE1" \
           "\x4C\x30\x62\xE7\x71\xBF\xE5\x03" \
           "\x58\x80\xF9\x91\x4E\x32\x24\xAA" \
           "\xAE\x6B\xEB\x8C\xE1\xA7\xD6\x06" \
           "\x6F\x56\x3D\x8B\x23\x63\x68\xEF" \
           "\x49\x7F\x09\x38\xE2\xCF\x34\x21" \
           "\x50\x8D\x2E\x7A\x04\x39\x08\x7B" \
           "\xF7\xE0\x14\x2D\x3E\xA3\x11\x12" \
           "\xEC\x4B\x1C\xA0\xFB\xBC\x97\x45" \
           "\x1A\x75\x42\x95\x0A\x41\x7A\x2D" \
           "\xB8\xB3\x78\x04\xC7\xC5\x0D\xD2" \
           "\x57\xAC\xA2\x87\x9C\xB9\xCD\x4A" \
           "\xA5\x81\xBE\x8A\x7A\x22\xA8\x37" \
           "\x16\xF7\xB4\xC0\xCD\xEC\x8C\x7D" \
           "\x15\x4D\xC7\xA0\x36\x5B\xD9\x06" \
           "\xBD\x9D\x2A\x98\x6E\x38\x09\x01" \
           "\x89\x01\xD3\xFD\x77\xC3\xC3\x07" \
           "\x2E\x07\x95\x7D\x40\x40\xE3\x2B" \
           "\x3D\xB5\x88\x6B\x96\x1A\xDA\x49" \
           "\x54\xCE\xAD\x11\x1F\xB8\x86\x39" \
           "\x3E\x74\x53\x89\x95\x5C\x4B\x2B" \
           "\xCD\xB3\x19\x44\xF0\x50\x9D\x0C" \
           "\x18\x20\x6F\x3C\xD3\x29\xD4\xCC" \
           "\x7E\xFF\xD4\x0B\xF4\x7F\x34\x2C" \
           "\x6F\xF1\xEC\x9D\xDB\xB7\xD3\xAD" \
           "\x88\xF2\xB3\xD4\xDE\xFE\x56\x21" \
           "\x5F\x92\x29\xB3\xAD\xF2\xEA\x51" \
           "\xE0\xCF\x66\xD5\x7D\x52\x6A\x17" \
           "\x13\xC7\xF5\x14\x9A\x81\x21\x69" \
           "\x9D\x04\x79\x72\x1F\xF8\x8D\x39" \
           "\x58\x7B\xBA\x5D\xDC\xF1\x64\x11" \
           "\x03\x47\x00\x0D\x75\x35\xF9\x58" \
           "\x7C\xA6\xA6\x87\x74\x61\x12\xAE" \
           "\xA1\x26\xC1\x46\x28\xAC\xC0\x0E" \
           "\x26\xF2\x57\x3B\xB2\xBC\xAE\xB0" \
           "\x10\xB4\x39\xCC\x3E\x4E\xB2\xFF" \
           "\xBD\xCE\x77\x68\xDF\x8D\xB0\x6C" \
           "\xCE\xE4\x35\x8C\x7B\x0A\xB5\xC0" \
           "\x13\x12\x97\xDD\x56\xF6\x1A\x29" \
           "\xB4\x25\x8F\x31\x8C\x74\xDD\x59" \
           "\xD9\xC7\x6E\x26\x4B\xBF\xCB\x19" \
           "\xEE\x5B\xEF\x70\xBA\xB8\xEB\x0B" \
           "\x6E\x17\xBD\x61\xED\x32\xDB\x41" \
           "\x9B\x5B\x91\xF3\xA9\xE9\x5B\x3C" \
           "\x94\x85\x44\x9C\x7E\x25\x01\xEB" \
           "\xE5\x2B\xFC\xBC\x95\xC5\x05\x39" \
           "\x04\x92\x9F\x1D\xB0\x24\x86\xB5" \
           "\x37\xCF\x98\x0A\x26\xCD\x3E\x88" \
           "\x48\x25\x46\xDE\x35\xA3\x6E\xB9" \
           "\x32\xFE\x68\x2E\xBA\x48\xF3\x5D" \
           "\xBC\xC3\x2C\xE2\xE8\x2F\xF9\x3D" \
           "\xBB\xAA\x51\x2B\x71\x81\xA6\xF9" \
           "\x63\x49\x76\x99\x7B\x24\x45\xA7" \
           "\x59\xC0\xF0\x99\xBA\x57\x34\xB2" \
           "\x51\xAE\x65\xC3\x37\xF2\x29\x3C" \
           "\xE9\x01\x1C\xE9\x0C\x89\x5C\xA5" \
           "\x3E\x66\x87\xE0\x56\xB2\xB1\xFC" \
           "\x68\xD0\xB9\xAE\x3F\x73\x97\x08" \
           "\x19\xE5\x26\x56\x4E\x9C\x16\x07" \
           "\x97\x1B\x14\xE8\x22\x1B\x44\x77" \
           "\xFC\xD3\x48\xCE\x33\xD7\x5F\xCB" \
           "\xC9\xC8\x62\x6D\xDF\x7F\xF7\x34" \
           "\x4F\x91\x59\xC5\x78\x93\x1D\xA4" \
           "\x97\x7A\xDB\x39\x09\x43\x7F\x68" \
           "\xD9\x4E\x39\xC8\x4E\xE2\x1C\xA9" \
           "\xF3\xB4\x8F\xD1\xCD\xD6\x24\x19" \
           "\x9A\xA4\xB7\x2B\xE3\xF5\xC9\xEC" \
           "\x05\x96\x4E\xE3\x67\x36\xBF\x54" \
           "\x7C\x16\x95\xF5\x57\x5D\xCF\x5B" \
           "\x76\x83\xE9\xAB\xDE\x2E\x0F\x72" \
           "\x65\x94\x13\x93\x99\x10\x01\xF0" \
           "\xFF\x02\x39\x14\x56\xD2\x11\x62" \
           "\x31\x0F\x55\x9E\xFF\x37\xE7\x43" \
           "\xBC\xF8\xCF\x5A\x9C\x9F\xCB\x1E" \
           "\xF0\x72\xE8\x74\x5C\xBA\x73\x48" \
           "\xA5\xBC\x44\xFC\x11\xE5\xB6\x4F" \
           "\x87\xD9\x3D\xAC\xE5\x66\x10\x12" \
           "\x80\x2D\x70\xC0\x2E\x42\xC4\x16" \
           "\x39\x80\x35\x38\xC5\x77\x9E\x8D" \
           "\x0E\x54\x5C\x05\x4E\x46\x94\xCE" \
           "\x61\x9C\xA0\xDF\x56\x10\x1A\xC8" \
           "\x05\x93\x58\x91\xB1\x79\x0A\xAD" \
           "\x41\xBC\xFE\x2A\x2F\x5E\x53\xC0" \
           "\x4C\x7A\x32\x99\x5E\xA1\xA8\xEF" \
           "\x6B\xCB\x2C\xCA\x65\x8B\xFD\x78" \
           , 688);
    nSKLen = 688;

    memcpy(bKeyByPK,
           "\x9E\x52\xAC\x17\x0D\x4B\xEC\x21" \
           "\x83\xA0\x23\xE7\x0D\x2B\x2D\x0A" \
           "\x6C\x50\x5E\x86\xAA\xEB\x11\x80" \
           "\x0B\x18\x2D\xAD\xE6\x06\x91\xEE" \
           "\x4F\x5D\x2E\x75\x55\x2E\x95\x22" \
           "\x48\x63\xB1\x67\xC1\x89\x1E\xE6" \
           "\xFC\xDA\xE8\x6F\xF9\xDA\x75\xE1" \
           "\xE7\x67\xA6\x73\xA3\xF7\x7D\x0F" \
           "\xAC\xB9\xE6\x79\x27\x8E\x42\x4F" \
           "\xEE\x3C\x8D\x4C\x73\x52\x12\xD4" \
           "\x58\xC5\x5D\x0C\x7D\xEC\x97\x4C" \
           "\xB2\xAA\x00\x87\x7F\x9D\x33\x56" \
           "\x98\x0F\x07\xBE\x20\xF2\x41\xCE" \
           "\x2E\x07\x7E\x42\xE0\x24\xDB\xD8" \
           "\xDE\x37\xB5\x4E\x10\x9C\xE4\x10" \
           "\x16\xF1\xDA\xD7\x8E\x08\x4F\x72" \
           "\xCD\x6E\xD4\x08\xC1\x9A\xEE\x64" \
           "\x76\x51\x5E\x6A\x28\x58\x67\x10" \
           , 144);
    nKeyByPKLen = 144;

    memcpy(bKeyByHMKExp,
           "\xA2\xC0\xB0\xF8\xF7\xF5\xEE\x21" \
           "\xFB\x5C\x6A\xEB\xE7\x14\xE5\x3A" \
           , 16);
    nKeyByHMKLenExp = 16;

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]nPadMode = %d\n", nPadMode);
    DspHex("[IN ]bSK =", bSK, nSKLen);
    printf("[IN ]nPKLen = %d\n", nSKLen);
    DspHex("[IN ]bKeyByPK =", bKeyByPK, nKeyByPKLen);
    printf("[IN ]nKeyByPKLen = %d\n", nKeyByPKLen);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPITransKeyIntoSK(nSock, nPadMode, bSK, nSKLen, bKeyByPK, \
                                nKeyByPKLen, bKeyByHMK, &nKeyByHMKLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "私钥转加密，RSA-1152，PKCS#1，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    DspHex("[OUT]bKeyByHMK    =", bKeyByHMK, nKeyByHMKLen);
    DspHex("[OUT]bKeyByHMKExp =", bKeyByHMKExp, nKeyByHMKLenExp);
    ASSERT_OUT_HEX(bKeyByHMK, bKeyByHMKExp, nKeyByHMKLenExp);
    ASSERT_OUT(nKeyByHMKLen, nKeyByHMKLenExp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void TransKeyIntoSK_Test_04(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int  nPadMode;
	  BYTE bSK[2400];
	  int  nSKLen;
	  BYTE bKeyByPK[260];
	  int  nKeyByPKLen;
	  BYTE bKeyByHMK[2056];
	  int  nKeyByHMKLen;
	  BYTE bKeyByHMKExp[260];
	  int  nKeyByHMKLenExp;

    bufclr(bSK);
    bufclr(bKeyByHMK);
    bufclr(bKeyByPK);
    nKeyByPKLen = 0;
    bufclr(bKeyByHMKExp);

    nPadMode = 1;
    /* PK = 3081B70281B100C5A3A2EF8B4910C9D79843FDEBD511C81A0B9AFDF3A75186259C61FAF4C43BB32495E604E1162B3CE46F5EA1F9E688AD972CD8693F1109BA172A8D39DD3B60C1129A8D21EE22DE613BC28F788EF16A6587B03947B573C67C3D0697E609979EB52838EAFE66E0AB3B05E84228B1BEF36CEB19F96628E061103CFAA9F27993272C194F6E4811F3647449029C7835DCC17161D5B24F308B24E120E90D340A7E4051D061D55F099A89D0C0D20446A57CB3C3020103 */
    /* SK = 308203350201000281B100C5A3A2EF8B4910C9D79843FDEBD511C81A0B9AFDF3A75186259C61FAF4C43BB32495E604E1162B3CE46F5EA1F9E688AD972CD8693F1109BA172A8D39DD3B60C1129A8D21EE22DE613BC28F788EF16A6587B03947B573C67C3D0697E609979EB52838EAFE66E0AB3B05E84228B1BEF36CEB19F96628E061103CFAA9F27993272C194F6E4811F3647449029C7835DCC17161D5B24F308B24E120E90D340A7E4051D061D55F099A89D0C0D20446A57CB3C30201030281B10083C26C9FB230B5DBE5102D53F28E0BDABC07BCA94D1A36596E684151F882D2776DB9440340B97228984A3F16A699B073BA1DE59B7F60B126BA1C5E26937CEB2B61BC5E169EC1E99627D70A505F4B9C43AFCAD0DA78F7D9A6FC6C1D6F7C718671BC277B4F8FABD8AE0E1D26A0496BD825941A95FD52131DC93E761E7BA1DCD3813C533BC608AF92BDE0150ACB6BD91D5FBEFFC4048092AD7EF48639C0F4BEC27AE40BE8132A127B7FE99D902486C4907B025900EC0B1A5DB59E4D0254E61FF2BC29846E7CCCBE6A51E670A4605D52AD1AFA3FF4CE6001818C87D51CE1137155B6F53535FD6209976700DCA5DE9FAD4890303761D955371D8ECD893D1E11C77915A8447BFCD6289BEFB6B2D5025900D6595161194F080839179214533561C773EFC9CDF1B6BE902C94C5BD12C9746D90E97AB77A4014CD5DBF23494DF6D3217B8102AFAD1638BBE4B65EFFDF7EE940D8CA7F750C92935C5C3E31C934D68C14E58F8373EB9F28370259009D5CBC3E79143356E344154C7D7102F45333299C3699A06D95938C7367517FF8899556565DAFE368960CF63924A378CEA8EC0664EF55E86E946A7385B5757A413B8E24BE5F33B0D369612FA60E702DA7FDE41B129FCF21E30259008EE63640BB8A055AD0BA6162E2239684F7F53133F679D4601DB883D361DBA2F3B5F0FC7A51800DDE3E7F6CDB894F376BA7AB571FC8B97B27EDCEE9FFEA549B809086FFA35DB70CE83D7ECBDB788F080DEE5FACF7F26A1ACF025900E5C5E1AE5B43E2DF317F9A5BEB6D33F81A4F454FC2A508335C3679CD4F52CB3E6F7EE26685095E11D0EFCA7445624CCD0FA680C2160A42789C42197E37197B61A48BE37CD125B1CDF31CAA74499B3AE8F908069E5633902D */
    /* SKByHMK = 000096D62D22C113789C6F1A78533225E113EFC14243EA4B846D45178815D07FCD2719793D64D2559B5F472F0D0B1C0B26A12D5375C1F62E3C4C31D12BAC112C019CD61A67B6939CF6F44F186F2C95F3E6C6D5AA53223565FCE0698B2BDF84070EDA6D8FE46576FCC451EAC4CE4AAE3EF4E581434B6BC93F901322E0AFAA17CCBE71CDE41B97DA8540808AFD7ACCC1B6CB03B1D889C166180389575EDFB8EC139E02FF11233BDE39DD4ACE88E74E31508D0A7D164005FA3149AB381C36EE966FC867CA00E31E838764E90C0F73E2680E6BA4A6752C6330AB1A839D25CF01B864E30AB58BB957B849770AD33FA90B51B69298F12A3CD33C3088ABBA1D00E71C28B400E098C4A381EE8C7908A3C5226BEF14A65EA5A7592AE1069BEC027198F49352553705B1208501B1FDB52B4D4C214994490B195FE80A1495CBB65C3C8807C25A627A6DB0A2C67E81E379B7A902B06C9C6D5CCFBB81A7AD3885D077840106AD31B66A57504BB05DFA3D5C87167FE16B6AE9F04C69F5B50D6D2754F6572EABB77A3D08955C893290C393D4B7961854C9D6A5F3F5D19F6C652631C34B8B988AEADB6CF2F0B04BFE48E0143D0ECC9B68F084402F1DA6CB19ABD84425180E02E9434A03EFF037AEA4041A3B29F478B716B0C70BA730B2F1CE47F6A025FBF6790414B7E48913247FD1EE04B882D7CFF7552F76FB62E922E0BBCDD35D5AC33A6DA9DB26BFD65EAA4859E8BE10D79A5C268350D28FA2038A5E0A26FC4A5084129EEF47AC777D6E5483824D4EE3559B9F27375E1FFA7B925A35D24C1D5D05CB7077995BCD74CB38D78F3E9F8C2154D755AC6968F9FF39885A3F356E30578DA25CB85969A231206038990A72655D2D54DC4D23D5EE14CDC53FFC666605BC8331C4314B27C8FB0D3BCC9FB2F7B778A03A891E5A5E9AE20CA6BC7C0685F47AFB91581DAFF14309B0BB066A489A0346825DC0E3D8635CAEEC23A9239579B23FE20AB5C08FB2211454E5B40A1AE1237AEABECBBE39C6B55B4A77E34E78E72F2B263AD9DAE64DDBE59EFE9E76C050B81AD4B78113BB22087D6FF7547DB4DC485D7FAEEB7AA2BC3B96B1C8745CF61BBE2FC4011032A7899D5B5838F28CF5CC627E60C06AB6FC84B4BE0720B7973497484F719DE36E72955CB1D7E4DC47F8FB44B98628DD0C0D3D */
    /* Key = 0123456789ABCDEFFEDCBA9876543210 */
    /* KeyByPK = 4F3B793F5992B83A7DA24F9F488D58B8AE57031A0BCD487554C13684D6E68801FB8B041BDBBE45B1CF173D58A67DB8289C6752523562B1E8C03B8E5ABC777B4FF3AA1351E1FCAD40C5C7EB3B82B9FDF88EA1BAA3279C78D5E2487C7042338409A246486A4970D7E4BF7107D05B3ADF198F8791FA1660A41EC8D8DA000F621006E8CFC8D293A714D3851673C0FF7080C7284A52F3DC6C51AB1F7F81BFE10C8A39A4CAE1C518628444BBA3918342DC6141 */
    /* KeyByHMK = A2C0B0F8F7F5EE21FB5C6AEBE714E53A */

    memcpy(bSK,
           "\x00\x00\x96\xD6\x2D\x22\xC1\x13" \
           "\x78\x9C\x6F\x1A\x78\x53\x32\x25" \
           "\xE1\x13\xEF\xC1\x42\x43\xEA\x4B" \
           "\x84\x6D\x45\x17\x88\x15\xD0\x7F" \
           "\xCD\x27\x19\x79\x3D\x64\xD2\x55" \
           "\x9B\x5F\x47\x2F\x0D\x0B\x1C\x0B" \
           "\x26\xA1\x2D\x53\x75\xC1\xF6\x2E" \
           "\x3C\x4C\x31\xD1\x2B\xAC\x11\x2C" \
           "\x01\x9C\xD6\x1A\x67\xB6\x93\x9C" \
           "\xF6\xF4\x4F\x18\x6F\x2C\x95\xF3" \
           "\xE6\xC6\xD5\xAA\x53\x22\x35\x65" \
           "\xFC\xE0\x69\x8B\x2B\xDF\x84\x07" \
           "\x0E\xDA\x6D\x8F\xE4\x65\x76\xFC" \
           "\xC4\x51\xEA\xC4\xCE\x4A\xAE\x3E" \
           "\xF4\xE5\x81\x43\x4B\x6B\xC9\x3F" \
           "\x90\x13\x22\xE0\xAF\xAA\x17\xCC" \
           "\xBE\x71\xCD\xE4\x1B\x97\xDA\x85" \
           "\x40\x80\x8A\xFD\x7A\xCC\xC1\xB6" \
           "\xCB\x03\xB1\xD8\x89\xC1\x66\x18" \
           "\x03\x89\x57\x5E\xDF\xB8\xEC\x13" \
           "\x9E\x02\xFF\x11\x23\x3B\xDE\x39" \
           "\xDD\x4A\xCE\x88\xE7\x4E\x31\x50" \
           "\x8D\x0A\x7D\x16\x40\x05\xFA\x31" \
           "\x49\xAB\x38\x1C\x36\xEE\x96\x6F" \
           "\xC8\x67\xCA\x00\xE3\x1E\x83\x87" \
           "\x64\xE9\x0C\x0F\x73\xE2\x68\x0E" \
           "\x6B\xA4\xA6\x75\x2C\x63\x30\xAB" \
           "\x1A\x83\x9D\x25\xCF\x01\xB8\x64" \
           "\xE3\x0A\xB5\x8B\xB9\x57\xB8\x49" \
           "\x77\x0A\xD3\x3F\xA9\x0B\x51\xB6" \
           "\x92\x98\xF1\x2A\x3C\xD3\x3C\x30" \
           "\x88\xAB\xBA\x1D\x00\xE7\x1C\x28" \
           "\xB4\x00\xE0\x98\xC4\xA3\x81\xEE" \
           "\x8C\x79\x08\xA3\xC5\x22\x6B\xEF" \
           "\x14\xA6\x5E\xA5\xA7\x59\x2A\xE1" \
           "\x06\x9B\xEC\x02\x71\x98\xF4\x93" \
           "\x52\x55\x37\x05\xB1\x20\x85\x01" \
           "\xB1\xFD\xB5\x2B\x4D\x4C\x21\x49" \
           "\x94\x49\x0B\x19\x5F\xE8\x0A\x14" \
           "\x95\xCB\xB6\x5C\x3C\x88\x07\xC2" \
           "\x5A\x62\x7A\x6D\xB0\xA2\xC6\x7E" \
           "\x81\xE3\x79\xB7\xA9\x02\xB0\x6C" \
           "\x9C\x6D\x5C\xCF\xBB\x81\xA7\xAD" \
           "\x38\x85\xD0\x77\x84\x01\x06\xAD" \
           "\x31\xB6\x6A\x57\x50\x4B\xB0\x5D" \
           "\xFA\x3D\x5C\x87\x16\x7F\xE1\x6B" \
           "\x6A\xE9\xF0\x4C\x69\xF5\xB5\x0D" \
           "\x6D\x27\x54\xF6\x57\x2E\xAB\xB7" \
           "\x7A\x3D\x08\x95\x5C\x89\x32\x90" \
           "\xC3\x93\xD4\xB7\x96\x18\x54\xC9" \
           "\xD6\xA5\xF3\xF5\xD1\x9F\x6C\x65" \
           "\x26\x31\xC3\x4B\x8B\x98\x8A\xEA" \
           "\xDB\x6C\xF2\xF0\xB0\x4B\xFE\x48" \
           "\xE0\x14\x3D\x0E\xCC\x9B\x68\xF0" \
           "\x84\x40\x2F\x1D\xA6\xCB\x19\xAB" \
           "\xD8\x44\x25\x18\x0E\x02\xE9\x43" \
           "\x4A\x03\xEF\xF0\x37\xAE\xA4\x04" \
           "\x1A\x3B\x29\xF4\x78\xB7\x16\xB0" \
           "\xC7\x0B\xA7\x30\xB2\xF1\xCE\x47" \
           "\xF6\xA0\x25\xFB\xF6\x79\x04\x14" \
           "\xB7\xE4\x89\x13\x24\x7F\xD1\xEE" \
           "\x04\xB8\x82\xD7\xCF\xF7\x55\x2F" \
           "\x76\xFB\x62\xE9\x22\xE0\xBB\xCD" \
           "\xD3\x5D\x5A\xC3\x3A\x6D\xA9\xDB" \
           "\x26\xBF\xD6\x5E\xAA\x48\x59\xE8" \
           "\xBE\x10\xD7\x9A\x5C\x26\x83\x50" \
           "\xD2\x8F\xA2\x03\x8A\x5E\x0A\x26" \
           "\xFC\x4A\x50\x84\x12\x9E\xEF\x47" \
           "\xAC\x77\x7D\x6E\x54\x83\x82\x4D" \
           "\x4E\xE3\x55\x9B\x9F\x27\x37\x5E" \
           "\x1F\xFA\x7B\x92\x5A\x35\xD2\x4C" \
           "\x1D\x5D\x05\xCB\x70\x77\x99\x5B" \
           "\xCD\x74\xCB\x38\xD7\x8F\x3E\x9F" \
           "\x8C\x21\x54\xD7\x55\xAC\x69\x68" \
           "\xF9\xFF\x39\x88\x5A\x3F\x35\x6E" \
           "\x30\x57\x8D\xA2\x5C\xB8\x59\x69" \
           "\xA2\x31\x20\x60\x38\x99\x0A\x72" \
           "\x65\x5D\x2D\x54\xDC\x4D\x23\xD5" \
           "\xEE\x14\xCD\xC5\x3F\xFC\x66\x66" \
           "\x05\xBC\x83\x31\xC4\x31\x4B\x27" \
           "\xC8\xFB\x0D\x3B\xCC\x9F\xB2\xF7" \
           "\xB7\x78\xA0\x3A\x89\x1E\x5A\x5E" \
           "\x9A\xE2\x0C\xA6\xBC\x7C\x06\x85" \
           "\xF4\x7A\xFB\x91\x58\x1D\xAF\xF1" \
           "\x43\x09\xB0\xBB\x06\x6A\x48\x9A" \
           "\x03\x46\x82\x5D\xC0\xE3\xD8\x63" \
           "\x5C\xAE\xEC\x23\xA9\x23\x95\x79" \
           "\xB2\x3F\xE2\x0A\xB5\xC0\x8F\xB2" \
           "\x21\x14\x54\xE5\xB4\x0A\x1A\xE1" \
           "\x23\x7A\xEA\xBE\xCB\xBE\x39\xC6" \
           "\xB5\x5B\x4A\x77\xE3\x4E\x78\xE7" \
           "\x2F\x2B\x26\x3A\xD9\xDA\xE6\x4D" \
           "\xDB\xE5\x9E\xFE\x9E\x76\xC0\x50" \
           "\xB8\x1A\xD4\xB7\x81\x13\xBB\x22" \
           "\x08\x7D\x6F\xF7\x54\x7D\xB4\xDC" \
           "\x48\x5D\x7F\xAE\xEB\x7A\xA2\xBC" \
           "\x3B\x96\xB1\xC8\x74\x5C\xF6\x1B" \
           "\xBE\x2F\xC4\x01\x10\x32\xA7\x89" \
           "\x9D\x5B\x58\x38\xF2\x8C\xF5\xCC" \
           "\x62\x7E\x60\xC0\x6A\xB6\xFC\x84" \
           "\xB4\xBE\x07\x20\xB7\x97\x34\x97" \
           "\x48\x4F\x71\x9D\xE3\x6E\x72\x95" \
           "\x5C\xB1\xD7\xE4\xDC\x47\xF8\xFB" \
           "\x44\xB9\x86\x28\xDD\x0C\x0D\x3D" \
           , 832);
    nSKLen = 832;

    memcpy(bKeyByPK,
           "\x4F\x3B\x79\x3F\x59\x92\xB8\x3A" \
           "\x7D\xA2\x4F\x9F\x48\x8D\x58\xB8" \
           "\xAE\x57\x03\x1A\x0B\xCD\x48\x75" \
           "\x54\xC1\x36\x84\xD6\xE6\x88\x01" \
           "\xFB\x8B\x04\x1B\xDB\xBE\x45\xB1" \
           "\xCF\x17\x3D\x58\xA6\x7D\xB8\x28" \
           "\x9C\x67\x52\x52\x35\x62\xB1\xE8" \
           "\xC0\x3B\x8E\x5A\xBC\x77\x7B\x4F" \
           "\xF3\xAA\x13\x51\xE1\xFC\xAD\x40" \
           "\xC5\xC7\xEB\x3B\x82\xB9\xFD\xF8" \
           "\x8E\xA1\xBA\xA3\x27\x9C\x78\xD5" \
           "\xE2\x48\x7C\x70\x42\x33\x84\x09" \
           "\xA2\x46\x48\x6A\x49\x70\xD7\xE4" \
           "\xBF\x71\x07\xD0\x5B\x3A\xDF\x19" \
           "\x8F\x87\x91\xFA\x16\x60\xA4\x1E" \
           "\xC8\xD8\xDA\x00\x0F\x62\x10\x06" \
           "\xE8\xCF\xC8\xD2\x93\xA7\x14\xD3" \
           "\x85\x16\x73\xC0\xFF\x70\x80\xC7" \
           "\x28\x4A\x52\xF3\xDC\x6C\x51\xAB" \
           "\x1F\x7F\x81\xBF\xE1\x0C\x8A\x39" \
           "\xA4\xCA\xE1\xC5\x18\x62\x84\x44" \
           "\xBB\xA3\x91\x83\x42\xDC\x61\x41" \
           , 176);
    nKeyByPKLen = 176;

    memcpy(bKeyByHMKExp,
           "\xA2\xC0\xB0\xF8\xF7\xF5\xEE\x21" \
           "\xFB\x5C\x6A\xEB\xE7\x14\xE5\x3A" \
           , 16);
    nKeyByHMKLenExp = 16;

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]nPadMode = %d\n", nPadMode);
    DspHex("[IN ]bSK =", bSK, nSKLen);
    printf("[IN ]nPKLen = %d\n", nSKLen);
    DspHex("[IN ]bKeyByPK =", bKeyByPK, nKeyByPKLen);
    printf("[IN ]nKeyByPKLen = %d\n", nKeyByPKLen);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPITransKeyIntoSK(nSock, nPadMode, bSK, nSKLen, bKeyByPK, \
                                nKeyByPKLen, bKeyByHMK, &nKeyByHMKLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "私钥转加密，RSA-1408，PKCS#1，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    DspHex("[OUT]bKeyByHMK    =", bKeyByHMK, nKeyByHMKLen);
    DspHex("[OUT]bKeyByHMKExp =", bKeyByHMKExp, nKeyByHMKLenExp);
    ASSERT_OUT_HEX(bKeyByHMK, bKeyByHMKExp, nKeyByHMKLenExp);
    ASSERT_OUT(nKeyByHMKLen, nKeyByHMKLenExp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void TransKeyIntoSK_Test_05(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int  nPadMode;
	  BYTE bSK[2400];
	  int  nSKLen;
	  BYTE bKeyByPK[260];
	  int  nKeyByPKLen;
	  BYTE bKeyByHMK[2056];
	  int  nKeyByHMKLen;
	  BYTE bKeyByHMKExp[260];
	  int  nKeyByHMKLenExp;

    bufclr(bSK);
    bufclr(bKeyByHMK);
    bufclr(bKeyByPK);
    nKeyByPKLen = 0;
    bufclr(bKeyByHMKExp);

    nPadMode = 1;
    /* PK = 3081FF0281F900A680D2649E6C202ACB88B72F054D00BF642167EA8757EB657D2484BB7EC68B162CD38DEDACB01181197A70644A3C2783DFE964BEF28FA24EC8426F67AD41B01E29AFE8AA7D91757ABF9A5E21CE52EEC2FA8D4972EFE44BD5E391721F578E46BD1227EF4B4971D1A57064652F394BE1F68B1C7549E655B8C0CA6C1701038F2996FAD869723E5589409903D141A854636349A5C47E1DD779320C1A2645FF7FE9747D4370EEB61BF1EFFDE8D9BC58A02B841EEDFC90B59E9197E10F550EFEAC47EDA85CA04B7AEF202CDBAA7D1551016FCA2115DB12229FB3977D35B1FB0BC3A5BCF333082871770B8B373AE4A28D3FB224BD420534B494640F020103 */
    /* SK = 308204770201000281F900A680D2649E6C202ACB88B72F054D00BF642167EA8757EB657D2484BB7EC68B162CD38DEDACB01181197A70644A3C2783DFE964BEF28FA24EC8426F67AD41B01E29AFE8AA7D91757ABF9A5E21CE52EEC2FA8D4972EFE44BD5E391721F578E46BD1227EF4B4971D1A57064652F394BE1F68B1C7549E655B8C0CA6C1701038F2996FAD869723E5589409903D141A854636349A5C47E1DD779320C1A2645FF7FE9747D4370EEB61BF1EFFDE8D9BC58A02B841EEDFC90B59E9197E10F550EFEAC47EDA85CA04B7AEF202CDBAA7D1551016FCA2115DB12229FB3977D35B1FB0BC3A5BCF333082871770B8B373AE4A28D3FB224BD420534B494640F0201030281F86F008C4314481571DD05CF74AE3355D4ED6B9A9C5A3A9CEE536DADD254845CB97337B3F3C8756100BBA6F598317D6FAD3FF0EDD4A1B516DF302C4A451E2BCABEC67545C6FE60F8FC7FBC3EC1343749D751B3864C9FED87E3ED0BA16A3A5ED9D3616FF4DCDBA1366E4AED98CA263296A45CBDA386998E7B2B319D64AA446DD8D1A59CB30522399FC08C7CC3BA825B3ED06AA125138E516AE3DBE7AD44A080044F322763F2BFE1420E832D35CD5CDBD9089A5F4276C8EB9291638355ED71E4DEBB2FCF899FAF939674B07D6AE97594678108A0732AA022A5DEF82F7D2C266F388B10AB98F80350F5B58FB80ECC2592B5C742AE4D7A4D0E040B027D00CE775EE3EA1428C860A490B20B2CBE448F003703B08414BE4DB8F8D08AA4E0FF28C2BBB6B4329AAFB94EF8DACD7B54408275D5E99EBE7FF40C06861E091F948C5F0F084FAA6CCEF2C245BFA0D9146B8E39B754217EF01E36E2FC81BCDFDA7339745F100FC8ECA4452DBCFED220EFA0466B8A816CC43D3EC0E12BF1D9027D00CE730578985934222A5A88EDBB1BED6555CB4E26F92FF8227AA4600BB799C15FE5FD2746FDD5C052DCFB15FF6BA9B4C7CAE0900D98A098EA7C36AF9FC2AABF9E74C5F185363882E9314BFEDCF9D9F128E6EB80671535101B4F6F390C291402FF5DBDC0DC9144FE6F3EC09C28BEB72E29E959200D14FF523C5FD36C27027D0089A4E9ED46B81B30406DB5CC077329830A0024AD20580DD433D0A5E05C6DEB54C5D727CF22CC671FD0DF5091DE52382B01A3E3F1147EFFF8080459695B6A63083F5F5ADFC6F334A1D6D92A6B3B62F25ED124E2C0FF4ABECF41FDABD33FE6F77BA2EA0AB5309DC2D8C928A9E16B4A6AD99D0700F32D7E29D5EB72A13B027D0089A203A5BAE622C17191B09E7CBD48EE39323419FB755016FC6D955D25112B9543FE1A2F53E3D58C93520EAA47C6788531EB0AB3BB15BB46FD79CA6A81C72A69A32EA103797B01F0CB87FF3DFBE6A0C5EF47AAEF6378B5678A4A26081B62ACAA3E7E80930B83544A29D5BD707F24C971463B6AB36354E17D95379D6F027C082248A5B3B6A2788F5A04351F7F2E066DD18E7F665A4D9473B09924C09E1D752760E40FD41CFA5A9264ACAA1F40F22598686227794C7D696D1A5D911A5EE9B9A779F9EE773799E63FD6A1E402A19A9FE9674712B56A3A4FEB7487442D15C2DEE2306B2AD43CB2F8BA2BC093460BC128D6E4A5DDFA792176754796F1 */
    /* SKByHMK = FFF0B57DCB96895AC283CC39200B50B635753C73E35E6C49F81B95402880F4F95FF9393752479E1DC3EBB3A4C242DA3C93B2F88CB179F8E73EB475161E176C1251896508D36D6E1E074D7C41183D203C4CBDADFBE5A828A3E8CD2F261C33D8F9591BF3E2728382EF69937DC5A3C32BF6D2B14F9082FD780B7F9E4EE41C7F08DBBF88888798A274AE8F293D68E2E0626E6170F3206373AFE2487FF629598813EC5B133C8FA89639EDC659392A3342FDDDBC0BFB703F347D640721DF3DC73599F226C81DE6235FD2732FAE7C3FBC2A2B29956F25D4F505D4596922761611EDA659E4FE71161035F61717DBCE344304D7F0DEE1008824E508EFD0856B5A35F84845691B6276B6F30B0E3E7042366A6B14A14C5560455F9E42D62AEC8CB54DA4D13337F128E575D441BEECB11DBBD24DFE8831E8EEBDEAE73C3DE486965EAFBBB3DD8F3C4454988A3C216FBD0FE615218F1551E658408B713171B343A7C8715BECF43B05550BAB67BD899B9DC1D57A3CC115B51A34DA06C36A8A9E637F24246C074FD222BB6962C6997B9E20972E9869E701C694A7D2292ED9FB1E11262713368557C61FF6A71968CFF386E3B29FE1605547F1120508E99190376184667CE4A6FCC3B4CD78F300EB50A5849F8E609B066F108A7845E33DB2FDF6451927FC0023831873A58A6DDF8FA2BDD909EA2068DCBFB830D1AD0BA630293A86000C10967E8F39764663D4FF22E4F0A0EE006840915DE4DA648848AF811311AC14817CD0AFB1C9C5A012B13AE69FFD9B1161A42B22E3CF9E2DA31C51C46B3D6025C5AB39A5FD79D5C016F81B5F9B3B56B260883CE8D16AF8C1EFED5BEFC81E0A8BEC37B83EEAE06A0B30BA9C47A06F585826086AEFF078F3C947E780FB3287B1C0AD4695C1BF216942500ED89BD8352D6CAE891E42FE4B37109431DA63DAED37DA976D942F230D9CC025BF3A2BF53CCAF4FA7801CCDA30959D0ADB9781C5EA8768CF4F4964E123C17E3B1DF23DDF42EA8373D44D1666B7BDD276461591CF4408AD74D39909C7FD1EC9ABA6EE7D9FD17B9AD0D2A4D879BD335FEF9B7F2615F8D90F6967CF81DDBB5AC8CC4746415E65517EAB59752A4F1D897F755F83957F5FD68289BF4217C79CDB775C424271469668E7590B2CDC0810729CE4C01DB2DB2395D5FA0280AD1FE279DCCF5DA468BB33C7160E1A112E47BBE0DF00077AB6798A5FC01ABD633C3F0FC99324F1E9FD936E94AA732C279693A3145B66642F4BE3D46369001385465F109D354F45B57AC68E3CE247D1854073D479FA3F09AF4AD80FCCEBAC6CCB65F4BFC3D534523978CA125BF7721B7F867BE30ED7463C3A6AD642899113C87C0B3EC5A74C86B005D11811C23323F32E107848BE3FAE1BE1561D904E5205B3E2E2E4A5FFDD4FA45B597B883EAEA125B95BB182F41DFC1C6A6806FEDA0A830C52BD2EBF280D105E1290140DC7395202AF33B5CB209B766654FAC22CDC5717F84846E10C7ABE5498FCDA349E5B19642D7EC892827B42D53A18BFB10C8EC8FF163F014FBB38C5E9136BB8269071E352E1A8AB73B7901B1FBF1DC7A0473960E20E221851A092DE9B04FB5E84B73EC9F26471B2E7C55F6FC0CCE115BEA0A9FE383138433F6D */
    /* Key = 0123456789ABCDEFFEDCBA9876543210 */
    /* KeyByPK = 5961AD27394076CC7A2C4FB2D4D724DB4F25FD668A876B4BCBCF5A4699982469507326A1592AAE9C17A3431F530B0B289ED7C34E7FCA2D06AE247831D1D3C0A9AF94D228BA48D56F6757B686CFDAAC3E4554022CA0605A517A758364F1C4B11A4832914C0A59D85747732D0D00E6DF9F670B31F2AE5D89E30F0CA54F6DC09A6691802EAD5BCDC3521F3E4D2900DAFC114F377B99BE14138394D288E8094FF362FF7E57FBC141C7B4E8A40BD7B234A09372DE56CB263BC4081D9FE2E4C4A09A4825FCBD488E4E7773BE3303415F7E8229619E3CE82326C9A21CA9440B7A78E225CE2779463174EDE41786DD196B2B0BD9CF445EECE8EA1382 */
    /* KeyByHMK = A2C0B0F8F7F5EE21FB5C6AEBE714E53A */

    memcpy(bSK,
           "\xFF\xF0\xB5\x7D\xCB\x96\x89\x5A" \
           "\xC2\x83\xCC\x39\x20\x0B\x50\xB6" \
           "\x35\x75\x3C\x73\xE3\x5E\x6C\x49" \
           "\xF8\x1B\x95\x40\x28\x80\xF4\xF9" \
           "\x5F\xF9\x39\x37\x52\x47\x9E\x1D" \
           "\xC3\xEB\xB3\xA4\xC2\x42\xDA\x3C" \
           "\x93\xB2\xF8\x8C\xB1\x79\xF8\xE7" \
           "\x3E\xB4\x75\x16\x1E\x17\x6C\x12" \
           "\x51\x89\x65\x08\xD3\x6D\x6E\x1E" \
           "\x07\x4D\x7C\x41\x18\x3D\x20\x3C" \
           "\x4C\xBD\xAD\xFB\xE5\xA8\x28\xA3" \
           "\xE8\xCD\x2F\x26\x1C\x33\xD8\xF9" \
           "\x59\x1B\xF3\xE2\x72\x83\x82\xEF" \
           "\x69\x93\x7D\xC5\xA3\xC3\x2B\xF6" \
           "\xD2\xB1\x4F\x90\x82\xFD\x78\x0B" \
           "\x7F\x9E\x4E\xE4\x1C\x7F\x08\xDB" \
           "\xBF\x88\x88\x87\x98\xA2\x74\xAE" \
           "\x8F\x29\x3D\x68\xE2\xE0\x62\x6E" \
           "\x61\x70\xF3\x20\x63\x73\xAF\xE2" \
           "\x48\x7F\xF6\x29\x59\x88\x13\xEC" \
           "\x5B\x13\x3C\x8F\xA8\x96\x39\xED" \
           "\xC6\x59\x39\x2A\x33\x42\xFD\xDD" \
           "\xBC\x0B\xFB\x70\x3F\x34\x7D\x64" \
           "\x07\x21\xDF\x3D\xC7\x35\x99\xF2" \
           "\x26\xC8\x1D\xE6\x23\x5F\xD2\x73" \
           "\x2F\xAE\x7C\x3F\xBC\x2A\x2B\x29" \
           "\x95\x6F\x25\xD4\xF5\x05\xD4\x59" \
           "\x69\x22\x76\x16\x11\xED\xA6\x59" \
           "\xE4\xFE\x71\x16\x10\x35\xF6\x17" \
           "\x17\xDB\xCE\x34\x43\x04\xD7\xF0" \
           "\xDE\xE1\x00\x88\x24\xE5\x08\xEF" \
           "\xD0\x85\x6B\x5A\x35\xF8\x48\x45" \
           "\x69\x1B\x62\x76\xB6\xF3\x0B\x0E" \
           "\x3E\x70\x42\x36\x6A\x6B\x14\xA1" \
           "\x4C\x55\x60\x45\x5F\x9E\x42\xD6" \
           "\x2A\xEC\x8C\xB5\x4D\xA4\xD1\x33" \
           "\x37\xF1\x28\xE5\x75\xD4\x41\xBE" \
           "\xEC\xB1\x1D\xBB\xD2\x4D\xFE\x88" \
           "\x31\xE8\xEE\xBD\xEA\xE7\x3C\x3D" \
           "\xE4\x86\x96\x5E\xAF\xBB\xB3\xDD" \
           "\x8F\x3C\x44\x54\x98\x8A\x3C\x21" \
           "\x6F\xBD\x0F\xE6\x15\x21\x8F\x15" \
           "\x51\xE6\x58\x40\x8B\x71\x31\x71" \
           "\xB3\x43\xA7\xC8\x71\x5B\xEC\xF4" \
           "\x3B\x05\x55\x0B\xAB\x67\xBD\x89" \
           "\x9B\x9D\xC1\xD5\x7A\x3C\xC1\x15" \
           "\xB5\x1A\x34\xDA\x06\xC3\x6A\x8A" \
           "\x9E\x63\x7F\x24\x24\x6C\x07\x4F" \
           "\xD2\x22\xBB\x69\x62\xC6\x99\x7B" \
           "\x9E\x20\x97\x2E\x98\x69\xE7\x01" \
           "\xC6\x94\xA7\xD2\x29\x2E\xD9\xFB" \
           "\x1E\x11\x26\x27\x13\x36\x85\x57" \
           "\xC6\x1F\xF6\xA7\x19\x68\xCF\xF3" \
           "\x86\xE3\xB2\x9F\xE1\x60\x55\x47" \
           "\xF1\x12\x05\x08\xE9\x91\x90\x37" \
           "\x61\x84\x66\x7C\xE4\xA6\xFC\xC3" \
           "\xB4\xCD\x78\xF3\x00\xEB\x50\xA5" \
           "\x84\x9F\x8E\x60\x9B\x06\x6F\x10" \
           "\x8A\x78\x45\xE3\x3D\xB2\xFD\xF6" \
           "\x45\x19\x27\xFC\x00\x23\x83\x18" \
           "\x73\xA5\x8A\x6D\xDF\x8F\xA2\xBD" \
           "\xD9\x09\xEA\x20\x68\xDC\xBF\xB8" \
           "\x30\xD1\xAD\x0B\xA6\x30\x29\x3A" \
           "\x86\x00\x0C\x10\x96\x7E\x8F\x39" \
           "\x76\x46\x63\xD4\xFF\x22\xE4\xF0" \
           "\xA0\xEE\x00\x68\x40\x91\x5D\xE4" \
           "\xDA\x64\x88\x48\xAF\x81\x13\x11" \
           "\xAC\x14\x81\x7C\xD0\xAF\xB1\xC9" \
           "\xC5\xA0\x12\xB1\x3A\xE6\x9F\xFD" \
           "\x9B\x11\x61\xA4\x2B\x22\xE3\xCF" \
           "\x9E\x2D\xA3\x1C\x51\xC4\x6B\x3D" \
           "\x60\x25\xC5\xAB\x39\xA5\xFD\x79" \
           "\xD5\xC0\x16\xF8\x1B\x5F\x9B\x3B" \
           "\x56\xB2\x60\x88\x3C\xE8\xD1\x6A" \
           "\xF8\xC1\xEF\xED\x5B\xEF\xC8\x1E" \
           "\x0A\x8B\xEC\x37\xB8\x3E\xEA\xE0" \
           "\x6A\x0B\x30\xBA\x9C\x47\xA0\x6F" \
           "\x58\x58\x26\x08\x6A\xEF\xF0\x78" \
           "\xF3\xC9\x47\xE7\x80\xFB\x32\x87" \
           "\xB1\xC0\xAD\x46\x95\xC1\xBF\x21" \
           "\x69\x42\x50\x0E\xD8\x9B\xD8\x35" \
           "\x2D\x6C\xAE\x89\x1E\x42\xFE\x4B" \
           "\x37\x10\x94\x31\xDA\x63\xDA\xED" \
           "\x37\xDA\x97\x6D\x94\x2F\x23\x0D" \
           "\x9C\xC0\x25\xBF\x3A\x2B\xF5\x3C" \
           "\xCA\xF4\xFA\x78\x01\xCC\xDA\x30" \
           "\x95\x9D\x0A\xDB\x97\x81\xC5\xEA" \
           "\x87\x68\xCF\x4F\x49\x64\xE1\x23" \
           "\xC1\x7E\x3B\x1D\xF2\x3D\xDF\x42" \
           "\xEA\x83\x73\xD4\x4D\x16\x66\xB7" \
           "\xBD\xD2\x76\x46\x15\x91\xCF\x44" \
           "\x08\xAD\x74\xD3\x99\x09\xC7\xFD" \
           "\x1E\xC9\xAB\xA6\xEE\x7D\x9F\xD1" \
           "\x7B\x9A\xD0\xD2\xA4\xD8\x79\xBD" \
           "\x33\x5F\xEF\x9B\x7F\x26\x15\xF8" \
           "\xD9\x0F\x69\x67\xCF\x81\xDD\xBB" \
           "\x5A\xC8\xCC\x47\x46\x41\x5E\x65" \
           "\x51\x7E\xAB\x59\x75\x2A\x4F\x1D" \
           "\x89\x7F\x75\x5F\x83\x95\x7F\x5F" \
           "\xD6\x82\x89\xBF\x42\x17\xC7\x9C" \
           "\xDB\x77\x5C\x42\x42\x71\x46\x96" \
           "\x68\xE7\x59\x0B\x2C\xDC\x08\x10" \
           "\x72\x9C\xE4\xC0\x1D\xB2\xDB\x23" \
           "\x95\xD5\xFA\x02\x80\xAD\x1F\xE2" \
           "\x79\xDC\xCF\x5D\xA4\x68\xBB\x33" \
           "\xC7\x16\x0E\x1A\x11\x2E\x47\xBB" \
           "\xE0\xDF\x00\x07\x7A\xB6\x79\x8A" \
           "\x5F\xC0\x1A\xBD\x63\x3C\x3F\x0F" \
           "\xC9\x93\x24\xF1\xE9\xFD\x93\x6E" \
           "\x94\xAA\x73\x2C\x27\x96\x93\xA3" \
           "\x14\x5B\x66\x64\x2F\x4B\xE3\xD4" \
           "\x63\x69\x00\x13\x85\x46\x5F\x10" \
           "\x9D\x35\x4F\x45\xB5\x7A\xC6\x8E" \
           "\x3C\xE2\x47\xD1\x85\x40\x73\xD4" \
           "\x79\xFA\x3F\x09\xAF\x4A\xD8\x0F" \
           "\xCC\xEB\xAC\x6C\xCB\x65\xF4\xBF" \
           "\xC3\xD5\x34\x52\x39\x78\xCA\x12" \
           "\x5B\xF7\x72\x1B\x7F\x86\x7B\xE3" \
           "\x0E\xD7\x46\x3C\x3A\x6A\xD6\x42" \
           "\x89\x91\x13\xC8\x7C\x0B\x3E\xC5" \
           "\xA7\x4C\x86\xB0\x05\xD1\x18\x11" \
           "\xC2\x33\x23\xF3\x2E\x10\x78\x48" \
           "\xBE\x3F\xAE\x1B\xE1\x56\x1D\x90" \
           "\x4E\x52\x05\xB3\xE2\xE2\xE4\xA5" \
           "\xFF\xDD\x4F\xA4\x5B\x59\x7B\x88" \
           "\x3E\xAE\xA1\x25\xB9\x5B\xB1\x82" \
           "\xF4\x1D\xFC\x1C\x6A\x68\x06\xFE" \
           "\xDA\x0A\x83\x0C\x52\xBD\x2E\xBF" \
           "\x28\x0D\x10\x5E\x12\x90\x14\x0D" \
           "\xC7\x39\x52\x02\xAF\x33\xB5\xCB" \
           "\x20\x9B\x76\x66\x54\xFA\xC2\x2C" \
           "\xDC\x57\x17\xF8\x48\x46\xE1\x0C" \
           "\x7A\xBE\x54\x98\xFC\xDA\x34\x9E" \
           "\x5B\x19\x64\x2D\x7E\xC8\x92\x82" \
           "\x7B\x42\xD5\x3A\x18\xBF\xB1\x0C" \
           "\x8E\xC8\xFF\x16\x3F\x01\x4F\xBB" \
           "\x38\xC5\xE9\x13\x6B\xB8\x26\x90" \
           "\x71\xE3\x52\xE1\xA8\xAB\x73\xB7" \
           "\x90\x1B\x1F\xBF\x1D\xC7\xA0\x47" \
           "\x39\x60\xE2\x0E\x22\x18\x51\xA0" \
           "\x92\xDE\x9B\x04\xFB\x5E\x84\xB7" \
           "\x3E\xC9\xF2\x64\x71\xB2\xE7\xC5" \
           "\x5F\x6F\xC0\xCC\xE1\x15\xBE\xA0" \
           "\xA9\xFE\x38\x31\x38\x43\x3F\x6D" \
           , 1152);
    nSKLen = 1152;

    memcpy(bKeyByPK,
           "\x59\x61\xAD\x27\x39\x40\x76\xCC" \
           "\x7A\x2C\x4F\xB2\xD4\xD7\x24\xDB" \
           "\x4F\x25\xFD\x66\x8A\x87\x6B\x4B" \
           "\xCB\xCF\x5A\x46\x99\x98\x24\x69" \
           "\x50\x73\x26\xA1\x59\x2A\xAE\x9C" \
           "\x17\xA3\x43\x1F\x53\x0B\x0B\x28" \
           "\x9E\xD7\xC3\x4E\x7F\xCA\x2D\x06" \
           "\xAE\x24\x78\x31\xD1\xD3\xC0\xA9" \
           "\xAF\x94\xD2\x28\xBA\x48\xD5\x6F" \
           "\x67\x57\xB6\x86\xCF\xDA\xAC\x3E" \
           "\x45\x54\x02\x2C\xA0\x60\x5A\x51" \
           "\x7A\x75\x83\x64\xF1\xC4\xB1\x1A" \
           "\x48\x32\x91\x4C\x0A\x59\xD8\x57" \
           "\x47\x73\x2D\x0D\x00\xE6\xDF\x9F" \
           "\x67\x0B\x31\xF2\xAE\x5D\x89\xE3" \
           "\x0F\x0C\xA5\x4F\x6D\xC0\x9A\x66" \
           "\x91\x80\x2E\xAD\x5B\xCD\xC3\x52" \
           "\x1F\x3E\x4D\x29\x00\xDA\xFC\x11" \
           "\x4F\x37\x7B\x99\xBE\x14\x13\x83" \
           "\x94\xD2\x88\xE8\x09\x4F\xF3\x62" \
           "\xFF\x7E\x57\xFB\xC1\x41\xC7\xB4" \
           "\xE8\xA4\x0B\xD7\xB2\x34\xA0\x93" \
           "\x72\xDE\x56\xCB\x26\x3B\xC4\x08" \
           "\x1D\x9F\xE2\xE4\xC4\xA0\x9A\x48" \
           "\x25\xFC\xBD\x48\x8E\x4E\x77\x73" \
           "\xBE\x33\x03\x41\x5F\x7E\x82\x29" \
           "\x61\x9E\x3C\xE8\x23\x26\xC9\xA2" \
           "\x1C\xA9\x44\x0B\x7A\x78\xE2\x25" \
           "\xCE\x27\x79\x46\x31\x74\xED\xE4" \
           "\x17\x86\xDD\x19\x6B\x2B\x0B\xD9" \
           "\xCF\x44\x5E\xEC\xE8\xEA\x13\x82" \
           , 248);
    nKeyByPKLen = 248;

    memcpy(bKeyByHMKExp,
           "\xA2\xC0\xB0\xF8\xF7\xF5\xEE\x21" \
           "\xFB\x5C\x6A\xEB\xE7\x14\xE5\x3A" \
           , 16);
    nKeyByHMKLenExp = 16;

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]nPadMode = %d\n", nPadMode);
    DspHex("[IN ]bSK =", bSK, nSKLen);
    printf("[IN ]nPKLen = %d\n", nSKLen);
    DspHex("[IN ]bKeyByPK =", bKeyByPK, nKeyByPKLen);
    printf("[IN ]nKeyByPKLen = %d\n", nKeyByPKLen);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPITransKeyIntoSK(nSock, nPadMode, bSK, nSKLen, bKeyByPK, \
                                nKeyByPKLen, bKeyByHMK, &nKeyByHMKLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "私钥转加密，RSA-1984，PKCS#1，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    DspHex("[OUT]bKeyByHMK    =", bKeyByHMK, nKeyByHMKLen);
    DspHex("[OUT]bKeyByHMKExp =", bKeyByHMKExp, nKeyByHMKLenExp);
    ASSERT_OUT_HEX(bKeyByHMK, bKeyByHMKExp, nKeyByHMKLenExp);
    ASSERT_OUT(nKeyByHMKLen, nKeyByHMKLenExp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void TransKeyIntoSK_Test_06(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int  nPadMode;
	  BYTE bSK[2400];
	  int  nSKLen;
	  BYTE bKeyByPK[260];
	  int  nKeyByPKLen;
	  BYTE bKeyByHMK[2056];
	  int  nKeyByHMKLen;
	  BYTE bKeyByHMKExp[260];
	  int  nKeyByHMKLenExp;

    bufclr(bSK);
    bufclr(bKeyByHMK);
    bufclr(bKeyByPK);
    nKeyByPKLen = 0;
    bufclr(bKeyByHMKExp);

    nPadMode = 1;
    /* PK = 308201080282010100AC9BD2F8FAA26398CF3D1B3589A194AF0D25DA587DCEC197B1AD289526B95C1282111F6DD4A48B4C74B4B94DC0F97EA58552A5DECD677A1C31E39849277BA7105B4A1D626DC5FCD8B3AB979085C032955174BBAC1DFC382CB09D944480314431598AABE9D26AA437BB3C2F2DF9112F1323AA85707481C3CA1791EC5F813F30C7EDA6EB1D840BC02DDD1B0A0B074E88A9EA08F7680D0E48E6E5889634B472B28FCEE1BC4414D69D92AB80BD54966F383B8B95B530BBFF3E17CC4FDDE5668BC4E2E1D2941B447EB5A063ED9DD0D8C26FF7F29F0388B127C239602D17604D49B730F31957A4BC006FDE0B535F0E470200C213B8D0E818AAF31618A98EAFB114CFA7020103 */
    /* SK = 308204A20201000282010100AC9BD2F8FAA26398CF3D1B3589A194AF0D25DA587DCEC197B1AD289526B95C1282111F6DD4A48B4C74B4B94DC0F97EA58552A5DECD677A1C31E39849277BA7105B4A1D626DC5FCD8B3AB979085C032955174BBAC1DFC382CB09D944480314431598AABE9D26AA437BB3C2F2DF9112F1323AA85707481C3CA1791EC5F813F30C7EDA6EB1D840BC02DDD1B0A0B074E88A9EA08F7680D0E48E6E5889634B472B28FCEE1BC4414D69D92AB80BD54966F383B8B95B530BBFF3E17CC4FDDE5668BC4E2E1D2941B447EB5A063ED9DD0D8C26FF7F29F0388B127C239602D17604D49B730F31957A4BC006FDE0B535F0E470200C213B8D0E818AAF31618A98EAFB114CFA70201030282010073128CA5FC6C4265DF7E1223B116631F5E193C3AFE89D665211E1B0E19D0E80C56B614F3E3185CDDA3232633D5FBA9C3AE37193F339A5168214265861A526F603CDC1396F3D9533B2272650B03D5770E364DD272BEA8257320690D830020D820E65C729BE19C6D7A7CD2CA1EA60B74B76D1C58F5A3012D31650BF2EA562A208430AFFC202F8C206B39A964F4340BA23EE8340C246D81A0C75600862D3D6F2F91A3B97EF7CB202B87E905AD1F6230E0CAC1759DDCFC985400F2689D22CFAFD74454FD7A3F346BCCC34FABA7139ED13E87F89B7A41CAE36DDBCC66F7BEF59B3C2FBB7ED2D63DE5208761F8141DC3BC88AAA99E8A1DA6D4D617AE3C40D527051A6B02818100D8D7667CE1B88197049D3CD3C0E57C9092B8116D7907C3E308A0F76DE538AFEAFA7A9E46414D2DB6D7AA83837479D828F170028AE81FE6D47219980AFDA02C83D9B0D9105A2C274EA449B996ED88B08A5D2D6F0A8282D3C6B94ABE0694ACCC890B1D079B0419DDCCFB719E7B9BBD96192C375000124F54EE406623EA3BA69E9702818100CBC78A705B010DF601FFB5C8F85798BAFB02D3C3EFC413D8DBE6D582F3133B4A5ED0DF8A22D92E8FF64DB6220EAC0EE277F545DA58FAD941EE995A263163D57888A583AC1BB0DB2CC822699C7CFFE1A1A0885D1B7E4FC9A8F447E5BB483410604EBE13C85B0EE145FCEDA26605A99DA8E913B1BB8C1C5D0452E90985BAE6897102818100908F99A8967B010F5868D337D5EE530B0C7AB648FB5A82975B15FA49437B1FF1FC51BED980DE1E79E51C57ACF8513AC5F64AAC5C9ABFEF384C11100753C01DAD3BCB3B603C1D6F89C2DBD10F4905CB06E8C8F4B1AC5737D9D0DC7EAF0DC8885B5CBE051202BBE933524BBEFD127E6410C824E0000C34E349804417F17D19BF0F0281810087DA5C4AE756094EABFFCE85FAE5107CA75737D7F52D62909299E3ACA20CD231948B3FB16C90C9B54EDE796C09C809EC4FF8D93C3B51E62BF4663C1976428E505B190272BD20921DDAC19BBDA8AA966BC05AE8BCFEDFDBC5F82FEE7CDACD6040347EB7DAE75F40D9534916EEAE7113C5F0B7CBD25D683E02E1F0B103D1EF064B0281800C27E1097CEB5B2007466B3CF7B9111DD11715C1388619414E910687577483DA014EDAD1DAF0DCCF04DC445495ACCC09C376F3B49146CA4C1BDF847DF80CDEC932EFE883D3E412099D86A093B6FAF536C1856D41F1135DDF4DD84BA3E80EC5429CA5D6C7CC80AE41BF018F70FD21C8AB9994DA2FC01DB5483D79DB51C7CF5E67 */
    /* SKByHMK = 5CBB649D1E0156463C21ADA719ABA77AD54F613636FEB8B6111B29C4D569A5E2868ED03316FD1D99DB95C6B8708D723F36A8A294B03D0CD3E911B87345FEFD01D78B101665F539F5CDCB23A3DAB858D9569A6E3E1AEC1ED2E26FFEC1F51E0A8AFA67B9F90B96DEBF3E28ECFA1F9EA51BB2FECE89F1DAD845299F070C5CE9D04935702933F3FFD70AC7820FE246E1A5ACCF7B615B4C976B464A9E887CA6C6F773E9C02F3CBB0B14CD8630187A2B18DFA7B6B987EF5FF7836DC435B6268E6AFD3D6AFF6B0E95247842386E3BF110018CAE1F9897C8A07507A4A9A6B64A8DCD68128CB199DC4F8F21AEC908FE994B641FCE7F24B82DD7B2CBA7DC26EF2F0582555413C0E5A31DB4E09A5198170C3E1E1FCB617E1787DAFB7E17FFF66B011765ACA86098D980586599EAB5912E25CDB9B547FAA969CE111259EA24029207FCD98509E7CA858F96F7D02A51869A07DFCEAAB417DEE1AA907E4BE98A3B44462716CAE9C0A98F09961BE8235AB137CEBF86415186724845517792CD25EC908F8C057581199B34CA9BCE8DFA7F8AA6E807F716DD22F03B50806CFAE0B761D5DCB8D5768271F0DBD93E062348EDC58A456CFA2C47AC0A498C49F074E672631076725EF4C6AE44D2D528EAF075BD1C2E43F745F4CE309DC2150CB0122CA8E973C8FF151BE9E8F4B63879681FAB40C165D22239C984F02FBAC1A532854713CC4ABA4CBBFF8E8B81E160F0328C48C04A7784C95EC65548BE92847E0D54B9E0D85E9B26FCE5577F7A26D7E37D6689C5BFC9412BED5B0D1955574907896873C03A3E69118D7DEFCCDC4675AFC7A2F04AA1AC1CABC0816FAE16F396228647D9EE11BD79FDBEBF06BA979C748EE675042A41BC59A86B64566DB7391D7994108AE378AC771B108E025FC5E582E027A00AA59663EC531717C3CDD075862D440867ECEA39B9C28D24E740090566B09C909DD4C7436D6E746AFC969054A46F06BEAF481AB85569EFA076EA6EF5C4030357602416E765B33EDEE4907D3599BAC967484FA5D732A7230A754D1413E43B8D08BB4DBEFAF49C59702CDD017C8F39E1157B7742C8A69A32FDBB9EAA5DB156FC57612AED56A44A71DBA20B42F3333EC22E835D4CDCF599004E16BB3D1133243BA44CE7EBDCF4675DE120CEF792EEFC44FC8EF2D7D73C7EAA9B2DB2BAADB44B722850040EFA4DFE72A57520017497990F31C724C01B0345910FEA9C286B78B33D725132E3C817805F7EB31C65A7B8BECAC38908C9AF2E2087A60EBD9BDE4BB3D8A07C8A03D3C561BE5DDCD6B58FDE9DA610577DA0A3536D90EC57E5C8C9F7C2AE03B9D68038810F2D34F6F063B0CC97E6050DB15934B6CDEDB7826A42C8196D4FAD59F023D91588CAB5ABB0412E1C3D7413F8DDFD72AA08611EFE7BCC48FD17D24D6695EB8035449DF8DC2BACB1D9FFD58FF67463A7C9BF2460DAFA3FE4632409043D3D4FEC62A6C6FA5116640875F62FF5E06FC00FCDA940C53CE4F8DF553D1D01E9068721F4EE434A2CE12C75F6264483682421931713529BDAEFE5F6F48C7A2732AFC4C4F2F098A84D0F58E0A845ADE0107B8A8158DD7C9B830E08C037008333860495CDCFCE1A54788B1E701FE54E1C4B122C08EDECD6DA682975C170F78B5106B57F80016971311CFC1C3ABBE3A760BAC20D5359CDCA397B5D997FA81E2AD03B */
    /* Key = 0123456789ABCDEFFEDCBA9876543210 */
    /* KeyByPK = 3DED547A1CCBD6BBE65C9498929A9ADD0FF2E2C3ED9D029EEB80078D159BEEF133AB6A29A233FE523280EAD7EF236421EB433698796AD7E3B65ACBA39ED1E5CE97D8D5AC6E091E1C7AC635FBE83C01E990FE62213106ACDA966D0D14BC9EB1FA2500C3ED91F07F366F5E9D9EB4D5CA27AC2BBC54A03525D65704EFE9776EB12973B8E4971D64DB487B7AAB1537EC3CCADAA61C525B934A45EA8D198FBDA978FE75B784CD6A091EC3582D44A3060E33E38FD730B622B86BEFD18B8DE01BF3D475C2DB447EDDF4D6A1812C99461340AE741C0AAE4066EBFB5CDD582E5E5639935033532BBE245EBA1BB38CD97F5D3B39286A5EEA6A8F3F2C644447EBDAB530F3E2 */
    /* KeyByHMK = A2C0B0F8F7F5EE21FB5C6AEBE714E53A */

    memcpy(bSK,
           "\x5C\xBB\x64\x9D\x1E\x01\x56\x46" \
           "\x3C\x21\xAD\xA7\x19\xAB\xA7\x7A" \
           "\xD5\x4F\x61\x36\x36\xFE\xB8\xB6" \
           "\x11\x1B\x29\xC4\xD5\x69\xA5\xE2" \
           "\x86\x8E\xD0\x33\x16\xFD\x1D\x99" \
           "\xDB\x95\xC6\xB8\x70\x8D\x72\x3F" \
           "\x36\xA8\xA2\x94\xB0\x3D\x0C\xD3" \
           "\xE9\x11\xB8\x73\x45\xFE\xFD\x01" \
           "\xD7\x8B\x10\x16\x65\xF5\x39\xF5" \
           "\xCD\xCB\x23\xA3\xDA\xB8\x58\xD9" \
           "\x56\x9A\x6E\x3E\x1A\xEC\x1E\xD2" \
           "\xE2\x6F\xFE\xC1\xF5\x1E\x0A\x8A" \
           "\xFA\x67\xB9\xF9\x0B\x96\xDE\xBF" \
           "\x3E\x28\xEC\xFA\x1F\x9E\xA5\x1B" \
           "\xB2\xFE\xCE\x89\xF1\xDA\xD8\x45" \
           "\x29\x9F\x07\x0C\x5C\xE9\xD0\x49" \
           "\x35\x70\x29\x33\xF3\xFF\xD7\x0A" \
           "\xC7\x82\x0F\xE2\x46\xE1\xA5\xAC" \
           "\xCF\x7B\x61\x5B\x4C\x97\x6B\x46" \
           "\x4A\x9E\x88\x7C\xA6\xC6\xF7\x73" \
           "\xE9\xC0\x2F\x3C\xBB\x0B\x14\xCD" \
           "\x86\x30\x18\x7A\x2B\x18\xDF\xA7" \
           "\xB6\xB9\x87\xEF\x5F\xF7\x83\x6D" \
           "\xC4\x35\xB6\x26\x8E\x6A\xFD\x3D" \
           "\x6A\xFF\x6B\x0E\x95\x24\x78\x42" \
           "\x38\x6E\x3B\xF1\x10\x01\x8C\xAE" \
           "\x1F\x98\x97\xC8\xA0\x75\x07\xA4" \
           "\xA9\xA6\xB6\x4A\x8D\xCD\x68\x12" \
           "\x8C\xB1\x99\xDC\x4F\x8F\x21\xAE" \
           "\xC9\x08\xFE\x99\x4B\x64\x1F\xCE" \
           "\x7F\x24\xB8\x2D\xD7\xB2\xCB\xA7" \
           "\xDC\x26\xEF\x2F\x05\x82\x55\x54" \
           "\x13\xC0\xE5\xA3\x1D\xB4\xE0\x9A" \
           "\x51\x98\x17\x0C\x3E\x1E\x1F\xCB" \
           "\x61\x7E\x17\x87\xDA\xFB\x7E\x17" \
           "\xFF\xF6\x6B\x01\x17\x65\xAC\xA8" \
           "\x60\x98\xD9\x80\x58\x65\x99\xEA" \
           "\xB5\x91\x2E\x25\xCD\xB9\xB5\x47" \
           "\xFA\xA9\x69\xCE\x11\x12\x59\xEA" \
           "\x24\x02\x92\x07\xFC\xD9\x85\x09" \
           "\xE7\xCA\x85\x8F\x96\xF7\xD0\x2A" \
           "\x51\x86\x9A\x07\xDF\xCE\xAA\xB4" \
           "\x17\xDE\xE1\xAA\x90\x7E\x4B\xE9" \
           "\x8A\x3B\x44\x46\x27\x16\xCA\xE9" \
           "\xC0\xA9\x8F\x09\x96\x1B\xE8\x23" \
           "\x5A\xB1\x37\xCE\xBF\x86\x41\x51" \
           "\x86\x72\x48\x45\x51\x77\x92\xCD" \
           "\x25\xEC\x90\x8F\x8C\x05\x75\x81" \
           "\x19\x9B\x34\xCA\x9B\xCE\x8D\xFA" \
           "\x7F\x8A\xA6\xE8\x07\xF7\x16\xDD" \
           "\x22\xF0\x3B\x50\x80\x6C\xFA\xE0" \
           "\xB7\x61\xD5\xDC\xB8\xD5\x76\x82" \
           "\x71\xF0\xDB\xD9\x3E\x06\x23\x48" \
           "\xED\xC5\x8A\x45\x6C\xFA\x2C\x47" \
           "\xAC\x0A\x49\x8C\x49\xF0\x74\xE6" \
           "\x72\x63\x10\x76\x72\x5E\xF4\xC6" \
           "\xAE\x44\xD2\xD5\x28\xEA\xF0\x75" \
           "\xBD\x1C\x2E\x43\xF7\x45\xF4\xCE" \
           "\x30\x9D\xC2\x15\x0C\xB0\x12\x2C" \
           "\xA8\xE9\x73\xC8\xFF\x15\x1B\xE9" \
           "\xE8\xF4\xB6\x38\x79\x68\x1F\xAB" \
           "\x40\xC1\x65\xD2\x22\x39\xC9\x84" \
           "\xF0\x2F\xBA\xC1\xA5\x32\x85\x47" \
           "\x13\xCC\x4A\xBA\x4C\xBB\xFF\x8E" \
           "\x8B\x81\xE1\x60\xF0\x32\x8C\x48" \
           "\xC0\x4A\x77\x84\xC9\x5E\xC6\x55" \
           "\x48\xBE\x92\x84\x7E\x0D\x54\xB9" \
           "\xE0\xD8\x5E\x9B\x26\xFC\xE5\x57" \
           "\x7F\x7A\x26\xD7\xE3\x7D\x66\x89" \
           "\xC5\xBF\xC9\x41\x2B\xED\x5B\x0D" \
           "\x19\x55\x57\x49\x07\x89\x68\x73" \
           "\xC0\x3A\x3E\x69\x11\x8D\x7D\xEF" \
           "\xCC\xDC\x46\x75\xAF\xC7\xA2\xF0" \
           "\x4A\xA1\xAC\x1C\xAB\xC0\x81\x6F" \
           "\xAE\x16\xF3\x96\x22\x86\x47\xD9" \
           "\xEE\x11\xBD\x79\xFD\xBE\xBF\x06" \
           "\xBA\x97\x9C\x74\x8E\xE6\x75\x04" \
           "\x2A\x41\xBC\x59\xA8\x6B\x64\x56" \
           "\x6D\xB7\x39\x1D\x79\x94\x10\x8A" \
           "\xE3\x78\xAC\x77\x1B\x10\x8E\x02" \
           "\x5F\xC5\xE5\x82\xE0\x27\xA0\x0A" \
           "\xA5\x96\x63\xEC\x53\x17\x17\xC3" \
           "\xCD\xD0\x75\x86\x2D\x44\x08\x67" \
           "\xEC\xEA\x39\xB9\xC2\x8D\x24\xE7" \
           "\x40\x09\x05\x66\xB0\x9C\x90\x9D" \
           "\xD4\xC7\x43\x6D\x6E\x74\x6A\xFC" \
           "\x96\x90\x54\xA4\x6F\x06\xBE\xAF" \
           "\x48\x1A\xB8\x55\x69\xEF\xA0\x76" \
           "\xEA\x6E\xF5\xC4\x03\x03\x57\x60" \
           "\x24\x16\xE7\x65\xB3\x3E\xDE\xE4" \
           "\x90\x7D\x35\x99\xBA\xC9\x67\x48" \
           "\x4F\xA5\xD7\x32\xA7\x23\x0A\x75" \
           "\x4D\x14\x13\xE4\x3B\x8D\x08\xBB" \
           "\x4D\xBE\xFA\xF4\x9C\x59\x70\x2C" \
           "\xDD\x01\x7C\x8F\x39\xE1\x15\x7B" \
           "\x77\x42\xC8\xA6\x9A\x32\xFD\xBB" \
           "\x9E\xAA\x5D\xB1\x56\xFC\x57\x61" \
           "\x2A\xED\x56\xA4\x4A\x71\xDB\xA2" \
           "\x0B\x42\xF3\x33\x3E\xC2\x2E\x83" \
           "\x5D\x4C\xDC\xF5\x99\x00\x4E\x16" \
           "\xBB\x3D\x11\x33\x24\x3B\xA4\x4C" \
           "\xE7\xEB\xDC\xF4\x67\x5D\xE1\x20" \
           "\xCE\xF7\x92\xEE\xFC\x44\xFC\x8E" \
           "\xF2\xD7\xD7\x3C\x7E\xAA\x9B\x2D" \
           "\xB2\xBA\xAD\xB4\x4B\x72\x28\x50" \
           "\x04\x0E\xFA\x4D\xFE\x72\xA5\x75" \
           "\x20\x01\x74\x97\x99\x0F\x31\xC7" \
           "\x24\xC0\x1B\x03\x45\x91\x0F\xEA" \
           "\x9C\x28\x6B\x78\xB3\x3D\x72\x51" \
           "\x32\xE3\xC8\x17\x80\x5F\x7E\xB3" \
           "\x1C\x65\xA7\xB8\xBE\xCA\xC3\x89" \
           "\x08\xC9\xAF\x2E\x20\x87\xA6\x0E" \
           "\xBD\x9B\xDE\x4B\xB3\xD8\xA0\x7C" \
           "\x8A\x03\xD3\xC5\x61\xBE\x5D\xDC" \
           "\xD6\xB5\x8F\xDE\x9D\xA6\x10\x57" \
           "\x7D\xA0\xA3\x53\x6D\x90\xEC\x57" \
           "\xE5\xC8\xC9\xF7\xC2\xAE\x03\xB9" \
           "\xD6\x80\x38\x81\x0F\x2D\x34\xF6" \
           "\xF0\x63\xB0\xCC\x97\xE6\x05\x0D" \
           "\xB1\x59\x34\xB6\xCD\xED\xB7\x82" \
           "\x6A\x42\xC8\x19\x6D\x4F\xAD\x59" \
           "\xF0\x23\xD9\x15\x88\xCA\xB5\xAB" \
           "\xB0\x41\x2E\x1C\x3D\x74\x13\xF8" \
           "\xDD\xFD\x72\xAA\x08\x61\x1E\xFE" \
           "\x7B\xCC\x48\xFD\x17\xD2\x4D\x66" \
           "\x95\xEB\x80\x35\x44\x9D\xF8\xDC" \
           "\x2B\xAC\xB1\xD9\xFF\xD5\x8F\xF6" \
           "\x74\x63\xA7\xC9\xBF\x24\x60\xDA" \
           "\xFA\x3F\xE4\x63\x24\x09\x04\x3D" \
           "\x3D\x4F\xEC\x62\xA6\xC6\xFA\x51" \
           "\x16\x64\x08\x75\xF6\x2F\xF5\xE0" \
           "\x6F\xC0\x0F\xCD\xA9\x40\xC5\x3C" \
           "\xE4\xF8\xDF\x55\x3D\x1D\x01\xE9" \
           "\x06\x87\x21\xF4\xEE\x43\x4A\x2C" \
           "\xE1\x2C\x75\xF6\x26\x44\x83\x68" \
           "\x24\x21\x93\x17\x13\x52\x9B\xDA" \
           "\xEF\xE5\xF6\xF4\x8C\x7A\x27\x32" \
           "\xAF\xC4\xC4\xF2\xF0\x98\xA8\x4D" \
           "\x0F\x58\xE0\xA8\x45\xAD\xE0\x10" \
           "\x7B\x8A\x81\x58\xDD\x7C\x9B\x83" \
           "\x0E\x08\xC0\x37\x00\x83\x33\x86" \
           "\x04\x95\xCD\xCF\xCE\x1A\x54\x78" \
           "\x8B\x1E\x70\x1F\xE5\x4E\x1C\x4B" \
           "\x12\x2C\x08\xED\xEC\xD6\xDA\x68" \
           "\x29\x75\xC1\x70\xF7\x8B\x51\x06" \
           "\xB5\x7F\x80\x01\x69\x71\x31\x1C" \
           "\xFC\x1C\x3A\xBB\xE3\xA7\x60\xBA" \
           "\xC2\x0D\x53\x59\xCD\xCA\x39\x7B" \
           "\x5D\x99\x7F\xA8\x1E\x2A\xD0\x3B" \
           , 1192);
    nSKLen = 1192;

    memcpy(bKeyByPK,
           "\x3D\xED\x54\x7A\x1C\xCB\xD6\xBB" \
           "\xE6\x5C\x94\x98\x92\x9A\x9A\xDD" \
           "\x0F\xF2\xE2\xC3\xED\x9D\x02\x9E" \
           "\xEB\x80\x07\x8D\x15\x9B\xEE\xF1" \
           "\x33\xAB\x6A\x29\xA2\x33\xFE\x52" \
           "\x32\x80\xEA\xD7\xEF\x23\x64\x21" \
           "\xEB\x43\x36\x98\x79\x6A\xD7\xE3" \
           "\xB6\x5A\xCB\xA3\x9E\xD1\xE5\xCE" \
           "\x97\xD8\xD5\xAC\x6E\x09\x1E\x1C" \
           "\x7A\xC6\x35\xFB\xE8\x3C\x01\xE9" \
           "\x90\xFE\x62\x21\x31\x06\xAC\xDA" \
           "\x96\x6D\x0D\x14\xBC\x9E\xB1\xFA" \
           "\x25\x00\xC3\xED\x91\xF0\x7F\x36" \
           "\x6F\x5E\x9D\x9E\xB4\xD5\xCA\x27" \
           "\xAC\x2B\xBC\x54\xA0\x35\x25\xD6" \
           "\x57\x04\xEF\xE9\x77\x6E\xB1\x29" \
           "\x73\xB8\xE4\x97\x1D\x64\xDB\x48" \
           "\x7B\x7A\xAB\x15\x37\xEC\x3C\xCA" \
           "\xDA\xA6\x1C\x52\x5B\x93\x4A\x45" \
           "\xEA\x8D\x19\x8F\xBD\xA9\x78\xFE" \
           "\x75\xB7\x84\xCD\x6A\x09\x1E\xC3" \
           "\x58\x2D\x44\xA3\x06\x0E\x33\xE3" \
           "\x8F\xD7\x30\xB6\x22\xB8\x6B\xEF" \
           "\xD1\x8B\x8D\xE0\x1B\xF3\xD4\x75" \
           "\xC2\xDB\x44\x7E\xDD\xF4\xD6\xA1" \
           "\x81\x2C\x99\x46\x13\x40\xAE\x74" \
           "\x1C\x0A\xAE\x40\x66\xEB\xFB\x5C" \
           "\xDD\x58\x2E\x5E\x56\x39\x93\x50" \
           "\x33\x53\x2B\xBE\x24\x5E\xBA\x1B" \
           "\xB3\x8C\xD9\x7F\x5D\x3B\x39\x28" \
           "\x6A\x5E\xEA\x6A\x8F\x3F\x2C\x64" \
           "\x44\x47\xEB\xDA\xB5\x30\xF3\xE2" \
           , 256);
    nKeyByPKLen = 256;

    memcpy(bKeyByHMKExp,
           "\xA2\xC0\xB0\xF8\xF7\xF5\xEE\x21" \
           "\xFB\x5C\x6A\xEB\xE7\x14\xE5\x3A" \
           , 16);
    nKeyByHMKLenExp = 16;

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]nPadMode = %d\n", nPadMode);
    DspHex("[IN ]bSK =", bSK, nSKLen);
    printf("[IN ]nPKLen = %d\n", nSKLen);
    DspHex("[IN ]bKeyByPK =", bKeyByPK, nKeyByPKLen);
    printf("[IN ]nKeyByPKLen = %d\n", nKeyByPKLen);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPITransKeyIntoSK(nSock, nPadMode, bSK, nSKLen, bKeyByPK, \
                                nKeyByPKLen, bKeyByHMK, &nKeyByHMKLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "私钥转加密，RSA-2048，PKCS#1，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    DspHex("[OUT]bKeyByHMK    =", bKeyByHMK, nKeyByHMKLen);
    DspHex("[OUT]bKeyByHMKExp =", bKeyByHMKExp, nKeyByHMKLenExp);
    ASSERT_OUT_HEX(bKeyByHMK, bKeyByHMKExp, nKeyByHMKLenExp);
    ASSERT_OUT(nKeyByHMKLen, nKeyByHMKLenExp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void Sm2PKTransOutof_Test_01(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nEcMark;
	  int  nPadMode;
	  BYTE bPK[512];
	  int  nPKLen;
	  BYTE bKeyByHMK[2056];
	  int  nKeyLen;
	  BYTE bKeyByPK[260];
	  int  nKeyByPKLen;
	  BYTE bKeyByPKExp[260];
	  int  nKeyByPKLenExp;

    bufclr(bPK);
    bufclr(bKeyByHMK);
    bufclr(bKeyByPK);
    nKeyByPKLen = 0;
    bufclr(bKeyByPKExp);
    
    /* PK = 04695BC3452B4DF79EBA188AC61C51A33A243F497A4D76D272F3771827BD80A944E1DA925A4853860EE0D883F3A2F43AA8F265C95F60A9102A7495551034D6C021 */
    /* SK = 7BAD1BC2D566F4AC0F93E830E2E9A1E756C063E94FBDEABF68A29DD720B44B30 */
    /* SKByHMK = C3E09939138691AA609031AADA1231495D23D89AA32D7B3E4C4D10D4631308FD6BCB2CCA658BFD78 */
    /* Key = 0123456789ABCDEFFEDCBA9876543210 */
    /* KeyByPK = 893173F4DDD695C466F8280251FE097E887C5CC4EC3E86EB101CA4A66BD5A8D54FE9280137C999CB0C9057A272723B1C6308F6FB0890549F65B1A470BF85607A19E2CE8F74298F29D0B3A6B624D5254807024B2449EC52AED4B6AC2B42186C73B38E848D5819ABFD8075A4D4A16502E5 */
    /* KeyByHMK = A2C0B0F8F7F5EE21FB5C6AEBE714E53A */

    nEcMark = 17;
    nPadMode = 0;
    memcpy(bPK,
           "\x04\x69\x5B\xC3\x45\x2B\x4D\xF7\x9E\xBA\x18\x8A\xC6\x1C\x51\xA3" \
           "\x3A\x24\x3F\x49\x7A\x4D\x76\xD2\x72\xF3\x77\x18\x27\xBD\x80\xA9" \
           "\x44\xE1\xDA\x92\x5A\x48\x53\x86\x0E\xE0\xD8\x83\xF3\xA2\xF4\x3A" \
           "\xA8\xF2\x65\xC9\x5F\x60\xA9\x10\x2A\x74\x95\x55\x10\x34\xD6\xC0" \
           "\x21" \
           , 65);
    nPKLen = 65;
    memcpy(bKeyByHMK,
           "\xA2\xC0\xB0\xF8\xF7\xF5\xEE\x21\xFB\x5C\x6A\xEB\xE7\x14\xE5\x3A" \
           , 16);
    nKeyLen = 16;
    memcpy(bKeyByPKExp,
           "\x89\x31\x73\xF4\xDD\xD6\x95\xC4\x66\xF8\x28\x02\x51\xFE\x09\x7E" \
           "\x88\x7C\x5C\xC4\xEC\x3E\x86\xEB\x10\x1C\xA4\xA6\x6B\xD5\xA8\xD5" \
           "\x4F\xE9\x28\x01\x37\xC9\x99\xCB\x0C\x90\x57\xA2\x72\x72\x3B\x1C" \
           "\x63\x08\xF6\xFB\x08\x90\x54\x9F\x65\xB1\xA4\x70\xBF\x85\x60\x7A" \
           "\x19\xE2\xCE\x8F\x74\x29\x8F\x29\xD0\xB3\xA6\xB6\x24\xD5\x25\x48" \
           "\x07\x02\x4B\x24\x49\xEC\x52\xAE\xD4\xB6\xAC\x2B\x42\x18\x6C\x73" \
           "\xB3\x8E\x84\x8D\x58\x19\xAB\xFD\x80\x75\xA4\xD4\xA1\x65\x02\xE5" \
           , 112);
    nKeyByPKLenExp = 112;

    XXX_INPUT_XXX
    printf("[IN ]nSock       = %d\n", nSock);
    printf("[IN ]nEcMark = %d\n", nEcMark);
    printf("[IN ]nPadMode    = %d\n", nPadMode);
    DspHexExt("[IN ]bPK         =", bPK, nPKLen);
    printf("[IN ]nPKLen      = %d\n", nPKLen);
    DspHexExt("[IN ]bKeyByHMK   =", bKeyByHMK, nKeyLen);
    printf("[IN ]nKeyLen     = %d\n", nKeyLen);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPISm2PKTransOutof(nSock, nEcMark, nPadMode, bPK, nPKLen, bKeyByHMK, \
                                nKeyLen, bKeyByPK, &nKeyByPKLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "SM2公钥转加密，无填充，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[VERIFY]请确认以下结果:\n");
    printf("[OUT]nKeyByPKLen = %d\n", nKeyByPKLen);
    DspHexExt("[OUT]bKeyByPK    =", bKeyByPK, nKeyByPKLen);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void Sm2SKTransInto_Test_01(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  nEcMark;
	  int  nPadMode;
	  BYTE bSK[2400];
	  int  nSKLen;
	  BYTE bKeyByPK[260];
	  int  nKeyByPKLen;
	  BYTE bKeyByHMK[2056];
	  int  nKeyByHMKLen;
	  BYTE bKeyByHMKExp[260];
	  int  nKeyByHMKLenExp;

    bufclr(bSK);
    bufclr(bKeyByHMK);
    bufclr(bKeyByPK);
    nKeyByPKLen = 0;
    bufclr(bKeyByHMKExp);

    nEcMark = 17;
    nPadMode = 0;
    /* PK = 04695BC3452B4DF79EBA188AC61C51A33A243F497A4D76D272F3771827BD80A944E1DA925A4853860EE0D883F3A2F43AA8F265C95F60A9102A7495551034D6C021 */
    /* SK = 7BAD1BC2D566F4AC0F93E830E2E9A1E756C063E94FBDEABF68A29DD720B44B30 */
    /* SKByHMK = C3E09939138691AA609031AADA1231495D23D89AA32D7B3E4C4D10D4631308FD6BCB2CCA658BFD78 */
    /* Key = 0123456789ABCDEFFEDCBA9876543210 */
    /* KeyByPK = 893173F4DDD695C466F8280251FE097E887C5CC4EC3E86EB101CA4A66BD5A8D54FE9280137C999CB0C9057A272723B1C6308F6FB0890549F65B1A470BF85607A19E2CE8F74298F29D0B3A6B624D5254807024B2449EC52AED4B6AC2B42186C73B38E848D5819ABFD8075A4D4A16502E5 */
    /* KeyByHMK = A2C0B0F8F7F5EE21FB5C6AEBE714E53A */

    memcpy(bSK,
           "\xC3\xE0\x99\x39\x13\x86\x91\xAA\x60\x90\x31\xAA\xDA\x12\x31\x49"
           "\x5D\x23\xD8\x9A\xA3\x2D\x7B\x3E\x4C\x4D\x10\xD4\x63\x13\x08\xFD"
           "\x6B\xCB\x2C\xCA\x65\x8B\xFD\x78"
           , 40);
    nSKLen = 40;

    memcpy(bKeyByPK,
           "\x89\x31\x73\xF4\xDD\xD6\x95\xC4\x66\xF8\x28\x02\x51\xFE\x09\x7E" \
           "\x88\x7C\x5C\xC4\xEC\x3E\x86\xEB\x10\x1C\xA4\xA6\x6B\xD5\xA8\xD5" \
           "\x4F\xE9\x28\x01\x37\xC9\x99\xCB\x0C\x90\x57\xA2\x72\x72\x3B\x1C" \
           "\x63\x08\xF6\xFB\x08\x90\x54\x9F\x65\xB1\xA4\x70\xBF\x85\x60\x7A" \
           "\x19\xE2\xCE\x8F\x74\x29\x8F\x29\xD0\xB3\xA6\xB6\x24\xD5\x25\x48" \
           "\x07\x02\x4B\x24\x49\xEC\x52\xAE\xD4\xB6\xAC\x2B\x42\x18\x6C\x73" \
           "\xB3\x8E\x84\x8D\x58\x19\xAB\xFD\x80\x75\xA4\xD4\xA1\x65\x02\xE5" \
           , 112);
    nKeyByPKLen = 112;

    memcpy(bKeyByHMKExp,
           "\xA2\xC0\xB0\xF8\xF7\xF5\xEE\x21\xFB\x5C\x6A\xEB\xE7\x14\xE5\x3A" \
           , 16);
    nKeyByHMKLenExp = 16;

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]nEcMark = %d\n", nEcMark);
    printf("[IN ]nPadMode = %d\n", nPadMode);
    DspHex("[IN ]bSK =", bSK, nSKLen);
    printf("[IN ]nPKLen = %d\n", nSKLen);
    DspHex("[IN ]bKeyByPK =", bKeyByPK, nKeyByPKLen);
    printf("[IN ]nKeyByPKLen = %d\n", nKeyByPKLen);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPISm2SKTransInto(nSock, nEcMark, nPadMode, bSK, nSKLen, bKeyByPK, \
                                nKeyByPKLen, bKeyByHMK, &nKeyByHMKLen);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "SM2私钥转加密，无填充，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    DspHex("[OUT]bKeyByHMK    =", bKeyByHMK, nKeyByHMKLen);
    DspHex("[OUT]bKeyByHMKExp =", bKeyByHMKExp, nKeyByHMKLenExp);
    ASSERT_OUT_HEX(bKeyByHMK, bKeyByHMKExp, nKeyByHMKLenExp);
    ASSERT_OUT(nKeyByHMKLen, nKeyByHMKLenExp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void TransKeyDesToSm4_Test_01(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int  nAlgo;
	  BYTE bDesKey[24];
	  int  nDesKeyLen;
	  BYTE bKeyUnderDes[16];
	  BYTE bSm4Key[16];
	  BYTE bKeyUnderSm4[16];
	  BYTE bKeyUnderSm4Exp[16];

    bufclr(bDesKey);
    bufclr(bKeyUnderDes);
    bufclr(bSm4Key);
    bufclr(bKeyUnderSm4);
    bufclr(bKeyUnderSm4Exp);

    nAlgo = 1;
    /* Key = 0123456789ABCDEFFEDCBA9876543210 */
    /* DESK = 72C7E64D5350FD59 */
    /* SM4K = 1AAE084D3316D8E1943E081C3E897D47 */
    /* DESKByHMK = C3827BE853B6BFB8 */
    /* SM4KByHMK = F0F2D67016869403B35D28E3FE7BD638 */
    /* KeyByDES = 3A418967A22CC08FD2B77E60128F692E */
    /* KeyBySM4 = 44A43336F55AAFF948EC19A31E983723 */

    memcpy(bDesKey,
           "\xC3\x82\x7B\xE8\x53\xB6\xBF\xB8" \
           , 8);
    nDesKeyLen = 8;

    memcpy(bKeyUnderDes,
           "\x3A\x41\x89\x67\xA2\x2C\xC0\x8F\xD2\xB7\x7E\x60\x12\x8F\x69\x2E" \
           , 16);

    memcpy(bSm4Key,
           "\xF0\xF2\xD6\x70\x16\x86\x94\x03\xB3\x5D\x28\xE3\xFE\x7B\xD6\x38" \
           , 16);

    memcpy(bKeyUnderSm4Exp,
           "\x44\xA4\x33\x36\xF5\x5A\xAF\xF9\x48\xEC\x19\xA3\x1E\x98\x37\x23" \
           , 16);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]nAlgo = %d\n", nAlgo);
    DspHex("[IN ]bDesKey =", bDesKey, nDesKeyLen);
    DspHex("[IN ]bSm4Key =", bSm4Key, 16);
    DspHex("[IN ]bKeyUnderDes =", bKeyUnderDes, 16);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPITransKeyDesToSm4(nSock, nAlgo, bDesKey, bSm4Key, bKeyUnderDes, \
                                bKeyUnderSm4);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "DES到SM4密钥转加密，ALGO=1，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    DspHex("[OUT]bKeyUnderSm4    =", bKeyUnderSm4, 16);
    DspHex("[OUT]bKeyUnderSm4Exp =", bKeyUnderSm4Exp, 16);
    ASSERT_OUT_HEX(bKeyUnderSm4, bKeyUnderSm4Exp, 16);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void TransKeyDesToSm4_Test_02(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int  nAlgo;
	  BYTE bDesKey[24];
	  int  nDesKeyLen;
	  BYTE bKeyUnderDes[16];
	  BYTE bSm4Key[16];
	  BYTE bKeyUnderSm4[16];
	  BYTE bKeyUnderSm4Exp[16];

    bufclr(bDesKey);
    bufclr(bKeyUnderDes);
    bufclr(bSm4Key);
    bufclr(bKeyUnderSm4);
    bufclr(bKeyUnderSm4Exp);

    nAlgo = 2;
    /* Key = 0123456789ABCDEFFEDCBA9876543210 */
    /* DESK = 72C7E64D5350FD5961E9E79E1A8A099F */
    /* SM4K = 1AAE084D3316D8E1943E081C3E897D47 */
    /* DESKByHMK = C3827BE853B6BFB81D73D8EDCA93F6AC */
    /* SM4KByHMK = F0F2D67016869403B35D28E3FE7BD638 */
    /* KeyByDES = B7540BCCFF0F44FEBA3952E73B01B78C */
    /* KeyBySM4 = 44A43336F55AAFF948EC19A31E983723 */

    memcpy(bDesKey,
           "\xC3\x82\x7B\xE8\x53\xB6\xBF\xB8\x1D\x73\xD8\xED\xCA\x93\xF6\xAC" \
           , 16);
    nDesKeyLen = 16;

    memcpy(bKeyUnderDes,
           "\xB7\x54\x0B\xCC\xFF\x0F\x44\xFE\xBA\x39\x52\xE7\x3B\x01\xB7\x8C" \
           , 16);

    memcpy(bSm4Key,
           "\xF0\xF2\xD6\x70\x16\x86\x94\x03\xB3\x5D\x28\xE3\xFE\x7B\xD6\x38" \
           , 16);

    memcpy(bKeyUnderSm4Exp,
           "\x44\xA4\x33\x36\xF5\x5A\xAF\xF9\x48\xEC\x19\xA3\x1E\x98\x37\x23" \
           , 16);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]nAlgo = %d\n", nAlgo);
    DspHex("[IN ]bDesKey =", bDesKey, nDesKeyLen);
    DspHex("[IN ]bSm4Key =", bSm4Key, 16);
    DspHex("[IN ]bKeyUnderDes =", bKeyUnderDes, 16);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPITransKeyDesToSm4(nSock, nAlgo, bDesKey, bSm4Key, bKeyUnderDes, \
                                bKeyUnderSm4);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "DES到SM4密钥转加密，ALGO=2，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    DspHex("[OUT]bKeyUnderSm4    =", bKeyUnderSm4, 16);
    DspHex("[OUT]bKeyUnderSm4Exp =", bKeyUnderSm4Exp, 16);
    ASSERT_OUT_HEX(bKeyUnderSm4, bKeyUnderSm4Exp, 16);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void TransKeyDesToSm4_Test_03(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int  nAlgo;
	  BYTE bDesKey[24];
	  int  nDesKeyLen;
	  BYTE bKeyUnderDes[16];
	  BYTE bSm4Key[16];
	  BYTE bKeyUnderSm4[16];
	  BYTE bKeyUnderSm4Exp[16];

    bufclr(bDesKey);
    bufclr(bKeyUnderDes);
    bufclr(bSm4Key);
    bufclr(bKeyUnderSm4);
    bufclr(bKeyUnderSm4Exp);

    nAlgo = 3;
    /* Key = 0123456789ABCDEFFEDCBA9876543210 */
    /* DESK = 72C7E64D5350FD5961E9E79E1A8A099F50A1CF897BEB07BA */
    /* SM4K = 1AAE084D3316D8E1943E081C3E897D47 */
    /* DESKByHMK = C3827BE853B6BFB81D73D8EDCA93F6ACFC5CDC212AE4165E */
    /* SM4KByHMK = F0F2D67016869403B35D28E3FE7BD638 */
    /* KeyByDES = 48C87F8BCF878B8D550A998AD614CCB2 */
    /* KeyBySM4 = 44A43336F55AAFF948EC19A31E983723 */

    memcpy(bDesKey,
           "\xC3\x82\x7B\xE8\x53\xB6\xBF\xB8\x1D\x73\xD8\xED\xCA\x93\xF6\xAC" \
           "\xFC\x5C\xDC\x21\x2A\xE4\x16\x5E" \
           , 24);
    nDesKeyLen = 24;

    memcpy(bKeyUnderDes,
           "\x48\xC8\x7F\x8B\xCF\x87\x8B\x8D\x55\x0A\x99\x8A\xD6\x14\xCC\xB2" \
           , 16);

    memcpy(bSm4Key,
           "\xF0\xF2\xD6\x70\x16\x86\x94\x03\xB3\x5D\x28\xE3\xFE\x7B\xD6\x38" \
           , 16);

    memcpy(bKeyUnderSm4Exp,
           "\x44\xA4\x33\x36\xF5\x5A\xAF\xF9\x48\xEC\x19\xA3\x1E\x98\x37\x23" \
           , 16);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]nAlgo = %d\n", nAlgo);
    DspHex("[IN ]bDesKey =", bDesKey, nDesKeyLen);
    DspHex("[IN ]bSm4Key =", bSm4Key, 16);
    DspHex("[IN ]bKeyUnderDes =", bKeyUnderDes, 16);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPITransKeyDesToSm4(nSock, nAlgo, bDesKey, bSm4Key, bKeyUnderDes, \
                                bKeyUnderSm4);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "DES到SM4密钥转加密，ALGO=3，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    DspHex("[OUT]bKeyUnderSm4    =", bKeyUnderSm4, 16);
    DspHex("[OUT]bKeyUnderSm4Exp =", bKeyUnderSm4Exp, 16);
    ASSERT_OUT_HEX(bKeyUnderSm4, bKeyUnderSm4Exp, 16);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void TransKeyDesToSm4_Test_04(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int  nAlgo;
	  BYTE bDesKey[24];
	  int  nDesKeyLen;
	  BYTE bKeyUnderDes[16];
	  BYTE bSm4Key[16];
	  BYTE bKeyUnderSm4[16];
	  BYTE bKeyUnderSm4Exp[16];

    bufclr(bDesKey);
    bufclr(bKeyUnderDes);
    bufclr(bSm4Key);
    bufclr(bKeyUnderSm4);
    bufclr(bKeyUnderSm4Exp);

    nAlgo = 4;
    /* Key = 0123456789ABCDEFFEDCBA9876543210 */
    /* DESK = 72C7E64D5350FD5961E9E79E1A8A099F50A1CF897BEB07BA */
    /* SM4K = 1AAE084D3316D8E1943E081C3E897D47 */
    /* DESKByHMK = C3827BE853B6BFB81D73D8EDCA93F6ACFC5CDC212AE4165E */
    /* SM4KByHMK = F0F2D67016869403B35D28E3FE7BD638 */
    /* KeyByDES = 48C87F8BCF878B8D550A998AD614CCB2 */
    /* KeyBySM4 = 44A43336F55AAFF948EC19A31E983723 */

    memcpy(bDesKey,
           "\xC3\x82\x7B\xE8\x53\xB6\xBF\xB8\x1D\x73\xD8\xED\xCA\x93\xF6\xAC" \
           "\xFC\x5C\xDC\x21\x2A\xE4\x16\x5E" \
           , 24);
    nDesKeyLen = 24;

    memcpy(bKeyUnderDes,
           "\x48\xC8\x7F\x8B\xCF\x87\x8B\x8D\x55\x0A\x99\x8A\xD6\x14\xCC\xB2" \
           , 16);

    memcpy(bSm4Key,
           "\xF0\xF2\xD6\x70\x16\x86\x94\x03\xB3\x5D\x28\xE3\xFE\x7B\xD6\x38" \
           , 16);

    memcpy(bKeyUnderSm4Exp,
           "\x44\xA4\x33\x36\xF5\x5A\xAF\xF9\x48\xEC\x19\xA3\x1E\x98\x37\x23" \
           , 16);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]nAlgo = %d\n", nAlgo);
    DspHex("[IN ]bDesKey =", bDesKey, nDesKeyLen);
    DspHex("[IN ]bSm4Key =", bSm4Key, 16);
    DspHex("[IN ]bKeyUnderDes =", bKeyUnderDes, 16);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPITransKeyDesToSm4(nSock, nAlgo, bDesKey, bSm4Key, bKeyUnderDes, \
                                bKeyUnderSm4);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 1, "DES到SM4密钥转加密，ALGO=4，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void TransKeySm4ToDes_Test_01(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int  nAlgo;
	  BYTE bDesKey[24];
	  int  nDesKeyLen;
	  BYTE bKeyUnderDes[16];
	  BYTE bSm4Key[16];
	  BYTE bKeyUnderSm4[16];
	  BYTE bKeyUnderDesExp[16];

    bufclr(bDesKey);
    bufclr(bKeyUnderDes);
    bufclr(bSm4Key);
    bufclr(bKeyUnderSm4);
    bufclr(bKeyUnderDesExp);

    nAlgo = 1;
    /* Key = 0123456789ABCDEFFEDCBA9876543210 */
    /* DESK = 72C7E64D5350FD59 */
    /* SM4K = 1AAE084D3316D8E1943E081C3E897D47 */
    /* DESKByHMK = C3827BE853B6BFB8 */
    /* SM4KByHMK = F0F2D67016869403B35D28E3FE7BD638 */
    /* KeyByDES = 3A418967A22CC08FD2B77E60128F692E */
    /* KeyBySM4 = 44A43336F55AAFF948EC19A31E983723 */

    memcpy(bDesKey,
           "\xC3\x82\x7B\xE8\x53\xB6\xBF\xB8" \
           , 8);
    nDesKeyLen = 8;

    memcpy(bKeyUnderSm4,
           "\x44\xA4\x33\x36\xF5\x5A\xAF\xF9\x48\xEC\x19\xA3\x1E\x98\x37\x23" \
           , 16);

    memcpy(bSm4Key,
           "\xF0\xF2\xD6\x70\x16\x86\x94\x03\xB3\x5D\x28\xE3\xFE\x7B\xD6\x38" \
           , 16);

    memcpy(bKeyUnderDesExp,
           "\x3A\x41\x89\x67\xA2\x2C\xC0\x8F\xD2\xB7\x7E\x60\x12\x8F\x69\x2E" \
           , 16);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]nAlgo = %d\n", nAlgo);
    DspHex("[IN ]bDesKey =", bDesKey, nDesKeyLen);
    DspHex("[IN ]bSm4Key =", bSm4Key, 16);
    DspHex("[IN ]bKeyUnderSm4 =", bKeyUnderSm4, 16);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPITransKeySm4ToDes(nSock, nAlgo, bSm4Key, bDesKey, bKeyUnderSm4, \
                                bKeyUnderDes);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "DES到SM4密钥转加密，ALGO=1，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    DspHex("[OUT]bKeyUnderDes    =", bKeyUnderDes, 16);
    DspHex("[OUT]bKeyUnderDesExp =", bKeyUnderDesExp, 16);
    ASSERT_OUT_HEX(bKeyUnderDes, bKeyUnderDesExp, 16);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void TransKeySm4ToDes_Test_02(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int  nAlgo;
	  BYTE bDesKey[24];
	  int  nDesKeyLen;
	  BYTE bKeyUnderDes[16];
	  BYTE bSm4Key[16];
	  BYTE bKeyUnderSm4[16];
	  BYTE bKeyUnderDesExp[16];

    bufclr(bDesKey);
    bufclr(bKeyUnderDes);
    bufclr(bSm4Key);
    bufclr(bKeyUnderSm4);
    bufclr(bKeyUnderDesExp);

    nAlgo = 2;
    /* Key = 0123456789ABCDEFFEDCBA9876543210 */
    /* DESK = 72C7E64D5350FD5961E9E79E1A8A099F */
    /* SM4K = 1AAE084D3316D8E1943E081C3E897D47 */
    /* DESKByHMK = C3827BE853B6BFB81D73D8EDCA93F6AC */
    /* SM4KByHMK = F0F2D67016869403B35D28E3FE7BD638 */
    /* KeyByDES = B7540BCCFF0F44FEBA3952E73B01B78C */
    /* KeyBySM4 = 44A43336F55AAFF948EC19A31E983723 */

    memcpy(bDesKey,
           "\xC3\x82\x7B\xE8\x53\xB6\xBF\xB8\x1D\x73\xD8\xED\xCA\x93\xF6\xAC" \
           , 16);
    nDesKeyLen = 16;

    memcpy(bKeyUnderSm4,
           "\x44\xA4\x33\x36\xF5\x5A\xAF\xF9\x48\xEC\x19\xA3\x1E\x98\x37\x23" \
           , 16);

    memcpy(bSm4Key,
           "\xF0\xF2\xD6\x70\x16\x86\x94\x03\xB3\x5D\x28\xE3\xFE\x7B\xD6\x38" \
           , 16);

    memcpy(bKeyUnderDesExp,
           "\xB7\x54\x0B\xCC\xFF\x0F\x44\xFE\xBA\x39\x52\xE7\x3B\x01\xB7\x8C" \
           , 16);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]nAlgo = %d\n", nAlgo);
    DspHex("[IN ]bDesKey =", bDesKey, nDesKeyLen);
    DspHex("[IN ]bSm4Key =", bSm4Key, 16);
    DspHex("[IN ]bKeyUnderSm4 =", bKeyUnderSm4, 16);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPITransKeySm4ToDes(nSock, nAlgo, bSm4Key, bDesKey, bKeyUnderSm4, \
                                bKeyUnderDes);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "DES到SM4密钥转加密，ALGO=2，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    DspHex("[OUT]bKeyUnderDes    =", bKeyUnderDes, 16);
    DspHex("[OUT]bKeyUnderDesExp =", bKeyUnderDesExp, 16);
    ASSERT_OUT_HEX(bKeyUnderDes, bKeyUnderDesExp, 16);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void TransKeySm4ToDes_Test_03(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int  nAlgo;
	  BYTE bDesKey[24];
	  int  nDesKeyLen;
	  BYTE bKeyUnderDes[16];
	  BYTE bSm4Key[16];
	  BYTE bKeyUnderSm4[16];
	  BYTE bKeyUnderDesExp[16];

    bufclr(bDesKey);
    bufclr(bKeyUnderDes);
    bufclr(bSm4Key);
    bufclr(bKeyUnderSm4);
    bufclr(bKeyUnderDesExp);

    nAlgo = 3;
    /* Key = 0123456789ABCDEFFEDCBA9876543210 */
    /* DESK = 72C7E64D5350FD5961E9E79E1A8A099F50A1CF897BEB07BA */
    /* SM4K = 1AAE084D3316D8E1943E081C3E897D47 */
    /* DESKByHMK = C3827BE853B6BFB81D73D8EDCA93F6ACFC5CDC212AE4165E */
    /* SM4KByHMK = F0F2D67016869403B35D28E3FE7BD638 */
    /* KeyByDES = 48C87F8BCF878B8D550A998AD614CCB2 */
    /* KeyBySM4 = 44A43336F55AAFF948EC19A31E983723 */

    memcpy(bDesKey,
           "\xC3\x82\x7B\xE8\x53\xB6\xBF\xB8\x1D\x73\xD8\xED\xCA\x93\xF6\xAC" \
           "\xFC\x5C\xDC\x21\x2A\xE4\x16\x5E" \
           , 24);
    nDesKeyLen = 24;

    memcpy(bKeyUnderSm4,
           "\x44\xA4\x33\x36\xF5\x5A\xAF\xF9\x48\xEC\x19\xA3\x1E\x98\x37\x23" \
           , 16);

    memcpy(bSm4Key,
           "\xF0\xF2\xD6\x70\x16\x86\x94\x03\xB3\x5D\x28\xE3\xFE\x7B\xD6\x38" \
           , 16);

    memcpy(bKeyUnderDesExp,
           "\x48\xC8\x7F\x8B\xCF\x87\x8B\x8D\x55\x0A\x99\x8A\xD6\x14\xCC\xB2" \
           , 16);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]nAlgo = %d\n", nAlgo);
    DspHex("[IN ]bDesKey =", bDesKey, nDesKeyLen);
    DspHex("[IN ]bSm4Key =", bSm4Key, 16);
    DspHex("[IN ]bKeyUnderSm4 =", bKeyUnderSm4, 16);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPITransKeySm4ToDes(nSock, nAlgo, bSm4Key, bDesKey, bKeyUnderSm4, \
                                bKeyUnderDes);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "DES到SM4密钥转加密，ALGO=3，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    DspHex("[OUT]bKeyUnderDes    =", bKeyUnderDes, 16);
    DspHex("[OUT]bKeyUnderDesExp =", bKeyUnderDesExp, 16);
    ASSERT_OUT_HEX(bKeyUnderDes, bKeyUnderDesExp, 16);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void TransKeySm4ToDes_Test_04(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

	  int  nAlgo;
	  BYTE bDesKey[24];
	  int  nDesKeyLen;
	  BYTE bKeyUnderDes[16];
	  BYTE bSm4Key[16];
	  BYTE bKeyUnderSm4[16];
	  BYTE bKeyUnderDesExp[16];

    bufclr(bDesKey);
    bufclr(bKeyUnderDes);
    bufclr(bSm4Key);
    bufclr(bKeyUnderSm4);
    bufclr(bKeyUnderDesExp);

    nAlgo = 4;
    /* Key = 0123456789ABCDEFFEDCBA9876543210 */
    /* DESK = 72C7E64D5350FD5961E9E79E1A8A099F50A1CF897BEB07BA */
    /* SM4K = 1AAE084D3316D8E1943E081C3E897D47 */
    /* DESKByHMK = C3827BE853B6BFB81D73D8EDCA93F6ACFC5CDC212AE4165E */
    /* SM4KByHMK = F0F2D67016869403B35D28E3FE7BD638 */
    /* KeyByDES = 48C87F8BCF878B8D550A998AD614CCB2 */
    /* KeyBySM4 = 44A43336F55AAFF948EC19A31E983723 */

    memcpy(bDesKey,
           "\xC3\x82\x7B\xE8\x53\xB6\xBF\xB8\x1D\x73\xD8\xED\xCA\x93\xF6\xAC" \
           "\xFC\x5C\xDC\x21\x2A\xE4\x16\x5E" \
           , 24);
    nDesKeyLen = 24;

    memcpy(bKeyUnderSm4,
           "\x44\xA4\x33\x36\xF5\x5A\xAF\xF9\x48\xEC\x19\xA3\x1E\x98\x37\x23" \
           , 16);

    memcpy(bSm4Key,
           "\xF0\xF2\xD6\x70\x16\x86\x94\x03\xB3\x5D\x28\xE3\xFE\x7B\xD6\x38" \
           , 16);

    memcpy(bKeyUnderDesExp,
           "\x48\xC8\x7F\x8B\xCF\x87\x8B\x8D\x55\x0A\x99\x8A\xD6\x14\xCC\xB2" \
           , 16);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]nAlgo = %d\n", nAlgo);
    DspHex("[IN ]bDesKey =", bDesKey, nDesKeyLen);
    DspHex("[IN ]bSm4Key =", bSm4Key, 16);
    DspHex("[IN ]bKeyUnderSm4 =", bKeyUnderSm4, 16);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPITransKeySm4ToDes(nSock, nAlgo, bSm4Key, bDesKey, bKeyUnderSm4, \
                                bKeyUnderDes);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 1, "DES到SM4密钥转加密，ALGO=4，测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void DecryptEncrypt_Test_01(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    BYTE bKey[32];
    char szCheckValue[16];
    int  decryptKeyIndex;
    UINT decryptMech;
    char encryptKey[64];
    UINT encryptMech;
    char data_org[1024];
    char data_tmp[1024];
    char data[1024];
    char decryptIV[32];
    char encryptIV[32];
    char outData[1024];
    char data_exp[1024];

    bufclr(bKey);
    bufclr(szCheckValue);
    bufclr(encryptKey);
    bufclr(data_org);
    bufclr(data_tmp);
    bufclr(data);
    bufclr(decryptIV);
    bufclr(encryptIV);
    bufclr(outData);
    bufclr(data_exp);

    decryptKeyIndex = 258;
    decryptMech = 20;
    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(encryptKey,
           "A2C0B0F8F7F5EE21FB5C6AEBE714E53A",
           32);
    encryptMech = 20;

    nRet = SMAPIGenerateKey(nSock, 16, "ZZZZZZZZZZ", 10, \
                            2, decryptKeyIndex, bKey, szCheckValue);
    ASSERT_RESULT(nRet, 0, "SMAPIGenerateKey NG");

    memcpy(data_org,
           "\x30\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42" \
           "\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42" \
           "\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42" \
           "\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x39" \
           , 64);
    nRet = SMAPIEncryptData(nSock, 1, 0, decryptKeyIndex, data_org, 64, data_tmp);
    ASSERT_RESULT(nRet, 0, "SMAPIEncryptData NG");
    SSMHexToChar(data_tmp, data, 64);

    memcpy(data_exp, "C9AF9A5820243A8F322EA2FA878BC4AE"
                     "322EA2FA878BC4AE322EA2FA878BC4AE"
                     "322EA2FA878BC4AE322EA2FA878BC4AE"
                     "322EA2FA878BC4AE71AA8BE6D7CE2C1E"
                     , 128);

    memset(decryptIV, '0', 16);
    memset(encryptIV, '0', 16);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]decryptKeyIndex = %d\n", decryptKeyIndex);
    printf("[IN ]decryptMech = %d\n", decryptMech);
    printf("[IN ]encryptKey  = %s\n", encryptKey);
    printf("[IN ]encryptMech = %d\n", encryptMech);
    printf("[IN ]data        = %s\n", data);
    printf("[IN ]decryptIV   = %s\n", decryptIV);
    printf("[IN ]encryptIV   = %s\n", encryptIV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIDecryptEncrypt(nSock, decryptKeyIndex, decryptMech, \
                               encryptKey, encryptMech, data, \
                               decryptIV, encryptIV, outData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "ECB转ECB测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    ASSERT_OUT_HEX(outData, data_exp, 128);
    printf("[OUT]outData  = %s\n", outData);
    printf("[OUT]data_exp = %s\n", data_exp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void DecryptEncrypt_Test_02(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    BYTE bKey[32];
    char szCheckValue[16];
    int  decryptKeyIndex;
    UINT decryptMech;
    char encryptKey[64];
    UINT encryptMech;
    char data_org[1024];
    char data_tmp[1024];
    char data[1024];
    char decryptIV[32];
    char encryptIV[32];
    char outData[1024];
    char data_exp[1024];

    bufclr(bKey);
    bufclr(szCheckValue);
    bufclr(encryptKey);
    bufclr(data_org);
    bufclr(data_tmp);
    bufclr(data);
    bufclr(decryptIV);
    bufclr(encryptIV);
    bufclr(outData);
    bufclr(data_exp);

    decryptKeyIndex = 258;
    decryptMech = 17;
    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(encryptKey,
           "A2C0B0F8F7F5EE21FB5C6AEBE714E53A",
           32);
    encryptMech = 17;

    nRet = SMAPIGenerateKey(nSock, 16, "ZZZZZZZZZZ", 10, \
                            2, decryptKeyIndex, bKey, szCheckValue);
    ASSERT_RESULT(nRet, 0, "SMAPIGenerateKey NG");

    memcpy(data_org,
           "\x30\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42" \
           "\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42" \
           "\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42" \
           "\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x39" \
           , 64);
    nRet = SMAPIEncryptData(nSock, 1, 1, decryptKeyIndex, data_org, 64, data_tmp);
    ASSERT_RESULT(nRet, 0, "SMAPIEncryptData NG");
    SSMHexToChar(data_tmp, data, 64);

    memcpy(data_exp, "C9AF9A5820243A8FACED8916C5EDD75A"
                     "15F05A7AB0A03B7BC77393E44B464F4D"
                     "FAF2845DD3EDCFECC4C349829CFD0F2A"
                     "CFD249005B3E6667A7D50E60FD9F0226"
                     , 128);

    memset(decryptIV, '0', 16);
    memset(encryptIV, '0', 16);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]decryptKeyIndex = %d\n", decryptKeyIndex);
    printf("[IN ]decryptMech = %d\n", decryptMech);
    printf("[IN ]encryptKey  = %s\n", encryptKey);
    printf("[IN ]encryptMech = %d\n", encryptMech);
    printf("[IN ]data        = %s\n", data);
    printf("[IN ]decryptIV   = %s\n", decryptIV);
    printf("[IN ]encryptIV   = %s\n", encryptIV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIDecryptEncrypt(nSock, decryptKeyIndex, decryptMech, \
                               encryptKey, encryptMech, data, \
                               decryptIV, encryptIV, outData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "CBC转CBC测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    ASSERT_OUT_HEX(outData, data_exp, 128);
    printf("[OUT]outData  = %s\n", outData);
    printf("[OUT]data_exp = %s\n", data_exp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void DecryptEncrypt_Test_03(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    BYTE bKey[32];
    char szCheckValue[16];
    int  decryptKeyIndex;
    UINT decryptMech;
    char encryptKey[64];
    UINT encryptMech;
    char data_org[1024];
    char data_tmp[1024];
    char data[1024];
    char decryptIV[32];
    char encryptIV[32];
    char outData[1024];
    char data_exp[1024];

    bufclr(bKey);
    bufclr(szCheckValue);
    bufclr(encryptKey);
    bufclr(data_org);
    bufclr(data_tmp);
    bufclr(data);
    bufclr(decryptIV);
    bufclr(encryptIV);
    bufclr(outData);
    bufclr(data_exp);

    decryptKeyIndex = 258;
    decryptMech = 17;
    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(encryptKey,
           "A2C0B0F8F7F5EE21FB5C6AEBE714E53A",
           32);
    encryptMech = 20;

    nRet = SMAPIGenerateKey(nSock, 16, "ZZZZZZZZZZ", 10, \
                            2, decryptKeyIndex, bKey, szCheckValue);
    ASSERT_RESULT(nRet, 0, "SMAPIGenerateKey NG");

    memcpy(data_org,
           "\x30\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42" \
           "\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42" \
           "\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42" \
           "\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x39" \
           , 64);
    nRet = SMAPIEncryptData(nSock, 1, 1, decryptKeyIndex, data_org, 64, data_tmp);
    ASSERT_RESULT(nRet, 0, "SMAPIEncryptData NG");
    SSMHexToChar(data_tmp, data, 64);

    memcpy(data_exp, "C9AF9A5820243A8F322EA2FA878BC4AE"
                     "322EA2FA878BC4AE322EA2FA878BC4AE"
                     "322EA2FA878BC4AE322EA2FA878BC4AE"
                     "322EA2FA878BC4AE71AA8BE6D7CE2C1E"
                     , 128);

    memset(decryptIV, '0', 16);
    memset(encryptIV, '0', 16);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]decryptKeyIndex = %d\n", decryptKeyIndex);
    printf("[IN ]decryptMech = %d\n", decryptMech);
    printf("[IN ]encryptKey  = %s\n", encryptKey);
    printf("[IN ]encryptMech = %d\n", encryptMech);
    printf("[IN ]data        = %s\n", data);
    printf("[IN ]decryptIV   = %s\n", decryptIV);
    printf("[IN ]encryptIV   = %s\n", encryptIV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIDecryptEncrypt(nSock, decryptKeyIndex, decryptMech, \
                               encryptKey, encryptMech, data, \
                               decryptIV, encryptIV, outData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "CBC转ECB测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    ASSERT_OUT_HEX(outData, data_exp, 128);
    printf("[OUT]outData  = %s\n", outData);
    printf("[OUT]data_exp = %s\n", data_exp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void DecryptEncrypt_Test_04(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    BYTE bKey[32];
    char szCheckValue[16];
    int  decryptKeyIndex;
    UINT decryptMech;
    char encryptKey[64];
    UINT encryptMech;
    char data_org[1024];
    char data_tmp[1024];
    char data[1024];
    char decryptIV[33];
    char encryptIV[33];
    char outData[1024];
    char data_exp[1024];

    bufclr(bKey);
    bufclr(szCheckValue);
    bufclr(encryptKey);
    bufclr(data_org);
    bufclr(data_tmp);
    bufclr(data);
    bufclr(decryptIV);
    bufclr(encryptIV);
    bufclr(outData);
    bufclr(data_exp);

    decryptKeyIndex = 258;
    decryptMech = 20;
    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(encryptKey,
           "A2C0B0F8F7F5EE21FB5C6AEBE714E53A",
           32);
    encryptMech = 17;

    nRet = SMAPIGenerateKey(nSock, 16, "ZZZZZZZZZZ", 10, \
                            2, decryptKeyIndex, bKey, szCheckValue);
    ASSERT_RESULT(nRet, 0, "SMAPIGenerateKey NG");

    memcpy(data_org,
           "\x30\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42" \
           "\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42" \
           "\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42" \
           "\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x39" \
           , 64);
    nRet = SMAPIEncryptData(nSock, 1, 0, decryptKeyIndex, data_org, 64, data_tmp);
    ASSERT_RESULT(nRet, 0, "SMAPIEncryptData NG");
    SSMHexToChar(data_tmp, data, 64);

    memcpy(data_exp, "C9AF9A5820243A8FACED8916C5EDD75A"
                     "15F05A7AB0A03B7BC77393E44B464F4D"
                     "FAF2845DD3EDCFECC4C349829CFD0F2A"
                     "CFD249005B3E6667A7D50E60FD9F0226"
                     , 128);

    memset(decryptIV, '0', 16);
    memset(encryptIV, '0', 16);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]decryptKeyIndex = %d\n", decryptKeyIndex);
    printf("[IN ]decryptMech = %d\n", decryptMech);
    printf("[IN ]encryptKey  = %s\n", encryptKey);
    printf("[IN ]encryptMech = %d\n", encryptMech);
    printf("[IN ]data        = %s\n", data);
    printf("[IN ]decryptIV   = %s\n", decryptIV);
    printf("[IN ]encryptIV   = %s\n", encryptIV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIDecryptEncrypt(nSock, decryptKeyIndex, decryptMech, \
                               encryptKey, encryptMech, data, \
                               decryptIV, encryptIV, outData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "ECB转CBC测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    ASSERT_OUT_HEX(outData, data_exp, 128);
    printf("[OUT]outData  = %s\n", outData);
    printf("[OUT]data_exp = %s\n", data_exp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void DecryptEncrypt_Test_05(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    BYTE bKey[32];
    char szCheckValue[16];
    int  decryptKeyIndex;
    UINT decryptMech;
    char encryptKey[64];
    UINT encryptMech;
    char data_org[1024];
    char data[1024];
    char decryptIV[33];
    char encryptIV[33];
    char outData[1024];
    char data_exp[1024];

    bufclr(bKey);
    bufclr(szCheckValue);
    bufclr(encryptKey);
    bufclr(data_org);
    bufclr(data);
    bufclr(decryptIV);
    bufclr(encryptIV);
    bufclr(outData);
    bufclr(data_exp);

    decryptKeyIndex = 258;
    decryptMech = 3;
    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(encryptKey,
           "A2C0B0F8F7F5EE21FB5C6AEBE714E53A",
           32);
    encryptMech = 3;

    nRet = SMAPIGenerateKey(nSock, 16, "ZZZZZZZZZZ", 10, \
                            2, decryptKeyIndex, bKey, szCheckValue);
    ASSERT_RESULT(nRet, 0, "SMAPIGenerateKey NG");
DspHexExt("bKey = ", bKey, 16);
    memcpy(data_org, 
           "30424242424242424242424242424242" \
           "42424242424242424242424242424242" \
           "42424242424242424242424242424242" \
           "42424242424242424242424242424239" \
           , 128);
    nRet = SMAPIEncrypt_index(nSock, decryptKeyIndex, decryptMech, data_org, decryptIV, data);
    ASSERT_RESULT(nRet, 0, "SMAPIEncrypt_index NG");

    /* 88C77F3AA6A29E4E2031657E3848A463C5F811F608BBF54F669F9D1DE7C1E6E5C5F811F608BBF54F669F9D1DE7C1E6E5822AD6A14D0A65313812078F057725B5 */
    memcpy(data_exp, 
           "88C77F3AA6A29E4E2031657E3848A463" \
           "C5F811F608BBF54F669F9D1DE7C1E6E5" \
           "C5F811F608BBF54F669F9D1DE7C1E6E5" \
           "822AD6A14D0A65313812078F057725B5"
           , 128);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]decryptKeyIndex = %d\n", decryptKeyIndex);
    printf("[IN ]decryptMech = %d\n", decryptMech);
    printf("[IN ]encryptKey  = %s\n", encryptKey);
    printf("[IN ]encryptMech = %d\n", encryptMech);
    printf("[IN ]data        = %s\n", data);
    printf("[IN ]decryptIV   = %s\n", decryptIV);
    printf("[IN ]encryptIV   = %s\n", encryptIV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIDecryptEncrypt(nSock, decryptKeyIndex, decryptMech, \
                               encryptKey, encryptMech, data, \
                               decryptIV, encryptIV, outData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "SM4_ECB转SM4_ECB测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    ASSERT_OUT_HEX(outData, data_exp, 128);
    printf("[OUT]outData  = %s\n", outData);
    printf("[OUT]data_exp = %s\n", data_exp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void DecryptEncrypt_Test_06(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    BYTE bKey[32];
    char szCheckValue[16];
    int  decryptKeyIndex;
    UINT decryptMech;
    char encryptKey[64];
    UINT encryptMech;
    char data_org[1024];
    char data[1024];
    char decryptIV[33];
    char encryptIV[33];
    char outData[1024];
    char data_exp[1024];

    bufclr(bKey);
    bufclr(szCheckValue);
    bufclr(encryptKey);
    bufclr(data_org);
    bufclr(data);
    bufclr(decryptIV);
    bufclr(encryptIV);
    bufclr(outData);
    bufclr(data_exp);

    memset(decryptIV, 0x30, 32);
    memset(encryptIV, 0x30, 32);

    decryptKeyIndex = 258;
    decryptMech = 4;
    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(encryptKey,
           "A2C0B0F8F7F5EE21FB5C6AEBE714E53A",
           32);
    encryptMech = 4;

    nRet = SMAPIGenerateKey(nSock, 16, "ZZZZZZZZZZ", 10, \
                            2, decryptKeyIndex, bKey, szCheckValue);
    ASSERT_RESULT(nRet, 0, "SMAPIGenerateKey NG");
DspHexExt("bKey =", bKey, 16);
    memcpy(data_org, 
           "30424242424242424242424242424242" \
           "42424242424242424242424242424242" \
           "42424242424242424242424242424242" \
           "42424242424242424242424242424239" \
           , 128);
    nRet = SMAPIEncrypt_index(nSock, decryptKeyIndex, decryptMech, data_org, decryptIV, data);
    ASSERT_RESULT(nRet, 0, "SMAPIEncrypt_index NG");

    /* 88C77F3AA6A29E4E2031657E3848A463E263A2B0C43EF4EFA9F9C5A722A157A0EB60D8E5FC56BAB836620A7FF5404668A98DB8B683A0819B732428B22A5F4D68 */
    memcpy(data_exp, 
           "88C77F3AA6A29E4E2031657E3848A463" \
           "E263A2B0C43EF4EFA9F9C5A722A157A0" \
           "EB60D8E5FC56BAB836620A7FF5404668" \
           "A98DB8B683A0819B732428B22A5F4D68" \
           , 128);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]decryptKeyIndex = %d\n", decryptKeyIndex);
    printf("[IN ]decryptMech = %d\n", decryptMech);
    printf("[IN ]encryptKey  = %s\n", encryptKey);
    printf("[IN ]encryptMech = %d\n", encryptMech);
    printf("[IN ]data        = %s\n", data);
    printf("[IN ]decryptIV   = %s\n", decryptIV);
    printf("[IN ]encryptIV   = %s\n", encryptIV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIDecryptEncrypt(nSock, decryptKeyIndex, decryptMech, \
                               encryptKey, encryptMech, data, \
                               decryptIV, encryptIV, outData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "SM4_CBC转SM4_CBC测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    ASSERT_OUT_HEX(outData, data_exp, 128);
    printf("[OUT]outData  = %s\n", outData);
    printf("[OUT]data_exp = %s\n", data_exp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void DecryptEncrypt_Test_07(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    BYTE bKey[32];
    char szCheckValue[16];
    int  decryptKeyIndex;
    UINT decryptMech;
    char encryptKey[64];
    UINT encryptMech;
    char data_org[1024];
    char data[1024];
    char decryptIV[32];
    char encryptIV[32];
    char outData[1024];
    char data_exp[1024];

    bufclr(bKey);
    bufclr(szCheckValue);
    bufclr(encryptKey);
    bufclr(data_org);
    bufclr(data);
    bufclr(decryptIV);
    bufclr(encryptIV);
    bufclr(outData);
    bufclr(data_exp);

    memset(decryptIV, 0x30, 32);

    decryptKeyIndex = 258;
    decryptMech = 4;
    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(encryptKey,
           "A2C0B0F8F7F5EE21FB5C6AEBE714E53A",
           32);
    encryptMech = 3;

    nRet = SMAPIGenerateKey(nSock, 16, "ZZZZZZZZZZ", 10, \
                            2, decryptKeyIndex, bKey, szCheckValue);
    ASSERT_RESULT(nRet, 0, "SMAPIGenerateKey NG");
DspHexExt("bKey =", bKey, 16);
    memcpy(data_org, 
           "30424242424242424242424242424242" \
           "42424242424242424242424242424242" \
           "42424242424242424242424242424242" \
           "42424242424242424242424242424239" \
           , 128);
    nRet = SMAPIEncrypt_index(nSock, decryptKeyIndex, decryptMech, data_org, decryptIV, data);
    ASSERT_RESULT(nRet, 0, "SMAPIEncrypt_index NG");

    /* 88C77F3AA6A29E4E2031657E3848A463C5F811F608BBF54F669F9D1DE7C1E6E5C5F811F608BBF54F669F9D1DE7C1E6E5822AD6A14D0A65313812078F057725B5 */
    memcpy(data_exp, 
           "88C77F3AA6A29E4E2031657E3848A463" \
           "C5F811F608BBF54F669F9D1DE7C1E6E5" \
           "C5F811F608BBF54F669F9D1DE7C1E6E5" \
           "822AD6A14D0A65313812078F057725B5"
           , 128);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]decryptKeyIndex = %d\n", decryptKeyIndex);
    printf("[IN ]decryptMech = %d\n", decryptMech);
    printf("[IN ]encryptKey  = %s\n", encryptKey);
    printf("[IN ]encryptMech = %d\n", encryptMech);
    printf("[IN ]data        = %s\n", data);
    printf("[IN ]decryptIV   = %s\n", decryptIV);
    printf("[IN ]encryptIV   = %s\n", encryptIV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIDecryptEncrypt(nSock, decryptKeyIndex, decryptMech, \
                               encryptKey, encryptMech, data, \
                               decryptIV, encryptIV, outData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "SM4_CBC转SM4_ECB测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    ASSERT_OUT_HEX(outData, data_exp, 128);
    printf("[OUT]outData  = %s\n", outData);
    printf("[OUT]data_exp = %s\n", data_exp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void DecryptEncrypt_Test_08(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    BYTE bKey[32];
    char szCheckValue[16];
    int  decryptKeyIndex;
    UINT decryptMech;
    char encryptKey[64];
    UINT encryptMech;
    char data_org[1024];
    char data[1024];
    char decryptIV[32];
    char encryptIV[32];
    char outData[1024];
    char data_exp[1024];

    bufclr(bKey);
    bufclr(szCheckValue);
    bufclr(encryptKey);
    bufclr(data_org);
    bufclr(data);
    bufclr(decryptIV);
    bufclr(encryptIV);
    bufclr(outData);
    bufclr(data_exp);

    memset(encryptIV, 0x30, 32);

    decryptKeyIndex = 258;
    decryptMech = 3;
    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(encryptKey,
           "A2C0B0F8F7F5EE21FB5C6AEBE714E53A",
           32);
    encryptMech = 4;

    nRet = SMAPIGenerateKey(nSock, 16, "ZZZZZZZZZZ", 10, \
                            2, decryptKeyIndex, bKey, szCheckValue);
    ASSERT_RESULT(nRet, 0, "SMAPIGenerateKey NG");
DspHexExt("bKey =", bKey, 16);
    memcpy(data_org, 
           "30424242424242424242424242424242" \
           "42424242424242424242424242424242" \
           "42424242424242424242424242424242" \
           "42424242424242424242424242424239" \
           , 128);
    nRet = SMAPIEncrypt_index(nSock, decryptKeyIndex, decryptMech, data_org, decryptIV, data);
    ASSERT_RESULT(nRet, 0, "SMAPIEncrypt_index NG");

    /* 88C77F3AA6A29E4E2031657E3848A463E263A2B0C43EF4EFA9F9C5A722A157A0EB60D8E5FC56BAB836620A7FF5404668A98DB8B683A0819B732428B22A5F4D68 */
    memcpy(data_exp, 
           "88C77F3AA6A29E4E2031657E3848A463" \
           "E263A2B0C43EF4EFA9F9C5A722A157A0" \
           "EB60D8E5FC56BAB836620A7FF5404668" \
           "A98DB8B683A0819B732428B22A5F4D68" \
           , 128);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]decryptKeyIndex = %d\n", decryptKeyIndex);
    printf("[IN ]decryptMech = %d\n", decryptMech);
    printf("[IN ]encryptKey  = %s\n", encryptKey);
    printf("[IN ]encryptMech = %d\n", encryptMech);
    printf("[IN ]data        = %s\n", data);
    printf("[IN ]decryptIV   = %s\n", decryptIV);
    printf("[IN ]encryptIV   = %s\n", encryptIV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIDecryptEncrypt(nSock, decryptKeyIndex, decryptMech, \
                               encryptKey, encryptMech, data, \
                               decryptIV, encryptIV, outData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "SM4_ECB转SM4_CBC测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    ASSERT_OUT_HEX(outData, data_exp, 128);
    printf("[OUT]outData  = %s\n", outData);
    printf("[OUT]data_exp = %s\n", data_exp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void Encrypt_Test_01(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    char encryptKey[64];
    UINT mech;
    char data[1024];
    char IV[32];
    char outData[1024];
    char outDataExp[1024];

    bufclr(encryptKey);
    bufclr(data);
    bufclr(IV);
    bufclr(outData);
    bufclr(outDataExp);

    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(encryptKey,
           "A2C0B0F8F7F5EE21FB5C6AEBE714E53A",
           32);
    mech = 20;
    memcpy(data, "30424242424242424242424242424242"
                 "42424242424242424242424242424242"
                 "42424242424242424242424242424242"
                 "42424242424242424242424242424239"
                 , 128);
    memset(IV, '0', 16);
    memcpy(outDataExp, "C9AF9A5820243A8F322EA2FA878BC4AE"
                       "322EA2FA878BC4AE322EA2FA878BC4AE"
                       "322EA2FA878BC4AE322EA2FA878BC4AE"
                       "322EA2FA878BC4AE71AA8BE6D7CE2C1E"
                       , 128);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]encryptKey = %s\n", encryptKey);
    printf("[IN ]mech       = %d\n", mech);
    printf("[IN ]data       = %s\n", data);
    printf("[IN ]IV         = %s\n", IV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIEncrypt(nSock, encryptKey, mech, data, IV, outData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "ECB测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[OUT]outData    = %s\n", outData);
    printf("[OUT]outDataExp = %s\n", outDataExp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void Encrypt_Test_02(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    char encryptKey[64];
    UINT mech;
    char data[1024];
    char IV[32];
    char outData[1024];
    char outDataExp[1024];

    bufclr(encryptKey);
    bufclr(data);
    bufclr(IV);
    bufclr(outData);
    bufclr(outDataExp);

    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(encryptKey,
           "A2C0B0F8F7F5EE21FB5C6AEBE714E53A",
           32);
    mech = 17;
    memcpy(data, "30424242424242424242424242424242"
                 "42424242424242424242424242424242"
                 "42424242424242424242424242424242"
                 "42424242424242424242424242424239"
                 , 128);
    memset(IV, '0', 16);
    memcpy(outDataExp, "C9AF9A5820243A8FACED8916C5EDD75A"
                       "15F05A7AB0A03B7BC77393E44B464F4D"
                       "FAF2845DD3EDCFECC4C349829CFD0F2A"
                       "CFD249005B3E6667A7D50E60FD9F0226"
                       , 128);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]encryptKey = %s\n", encryptKey);
    printf("[IN ]mech       = %d\n", mech);
    printf("[IN ]data       = %s\n", data);
    printf("[IN ]IV         = %s\n", IV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIEncrypt(nSock, encryptKey, mech, data, IV, outData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "CBC测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[OUT]outData    = %s\n", outData);
    printf("[OUT]outDataExp = %s\n", outDataExp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void Encrypt_Test_03(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    char encryptKey[64];
    UINT mech;
    char data[1024];
    char IV[33];
    char outData[1024];
    char outDataExp[1024];

    bufclr(encryptKey);
    bufclr(data);
    bufclr(IV);
    bufclr(outData);
    bufclr(outDataExp);

    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(encryptKey,
           "A2C0B0F8F7F5EE21FB5C6AEBE714E53A",
           32);
    mech = 3;
    memcpy(data, "30424242424242424242424242424242"
                 "42424242424242424242424242424242"
                 "42424242424242424242424242424242"
                 "42424242424242424242424242424239"
                 , 128);
    memset(IV, '0', 32);
    /* 88C77F3AA6A29E4E2031657E3848A463C5F811F608BBF54F669F9D1DE7C1E6E5C5F811F608BBF54F669F9D1DE7C1E6E5822AD6A14D0A65313812078F057725B5 */
    memcpy(outDataExp, 
           "88C77F3AA6A29E4E2031657E3848A463" \
           "C5F811F608BBF54F669F9D1DE7C1E6E5" \
           "C5F811F608BBF54F669F9D1DE7C1E6E5" \
           "822AD6A14D0A65313812078F057725B5"
           , 128);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]encryptKey = %s\n", encryptKey);
    printf("[IN ]mech       = %d\n", mech);
    printf("[IN ]data       = %s\n", data);
    printf("[IN ]IV         = %s\n", IV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIEncrypt(nSock, encryptKey, mech, data, IV, outData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "SM4_ECB测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[OUT]outData    = %s\n", outData);
    printf("[OUT]outDataExp = %s\n", outDataExp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void Encrypt_Test_04(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    char encryptKey[64];
    UINT mech;
    char data[1024];
    char IV[33];
    char outData[1024];
    char outDataExp[1024];

    bufclr(encryptKey);
    bufclr(data);
    bufclr(IV);
    bufclr(outData);
    bufclr(outDataExp);

    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(encryptKey,
           "A2C0B0F8F7F5EE21FB5C6AEBE714E53A",
           32);
    mech = 4;
    memcpy(data, "30424242424242424242424242424242"
                 "42424242424242424242424242424242"
                 "42424242424242424242424242424242"
                 "42424242424242424242424242424239"
                 , 128);
    memset(IV, '0', 32);
    /* 88C77F3AA6A29E4E2031657E3848A463E263A2B0C43EF4EFA9F9C5A722A157A0EB60D8E5FC56BAB836620A7FF5404668A98DB8B683A0819B732428B22A5F4D68 */
    memcpy(outDataExp, 
           "88C77F3AA6A29E4E2031657E3848A463" \
           "E263A2B0C43EF4EFA9F9C5A722A157A0" \
           "EB60D8E5FC56BAB836620A7FF5404668" \
           "A98DB8B683A0819B732428B22A5F4D68" \
           , 128);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]encryptKey = %s\n", encryptKey);
    printf("[IN ]mech       = %d\n", mech);
    printf("[IN ]data       = %s\n", data);
    printf("[IN ]IV         = %s\n", IV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIEncrypt(nSock, encryptKey, mech, data, IV, outData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "SM4_CBC测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[OUT]outData    = %s\n", outData);
    printf("[OUT]outDataExp = %s\n", outDataExp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void EncryptIndex_Test_01(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    BYTE bKey[32];
    char szCheckValue[16];
    int  encryptKeyIndex;
    UINT mech;
    char data_tmp[1024];
    char data[1024];
    char inData[1024];
    char IV[32];
    char outData[1024];
    char outDataExp[1024];

    bufclr(bKey);
    bufclr(szCheckValue);
    bufclr(data_tmp);
    bufclr(data);
    bufclr(inData);
    bufclr(IV);
    bufclr(outData);
    bufclr(outDataExp);

    encryptKeyIndex = 258;
    mech = 20;
    memcpy(data,
           "\x30\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42" \
           "\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42" \
           "\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42" \
           "\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x39" \
           , 64);
    memcpy(inData, "30424242424242424242424242424242"
                   "42424242424242424242424242424242"
                   "42424242424242424242424242424242"
                   "42424242424242424242424242424239"
                   , 128);

    nRet = SMAPIGenerateKey(nSock, 16, "ZZZZZZZZZZ", 10, \
                            2, encryptKeyIndex, bKey, szCheckValue);
    ASSERT_RESULT(nRet, 0, "SMAPIGenerateKey NG");

    nRet = SMAPIEncryptData(nSock, 1, 0, encryptKeyIndex, data, 64, data_tmp);
    ASSERT_RESULT(nRet, 0, "SMAPIEncryptData NG");
    SSMHexToChar(data_tmp, outDataExp, 64);

    memset(IV, '0', 16);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]encryptKeyIndex = %d\n", encryptKeyIndex);
    printf("[IN ]mech            = %d\n", mech);
    printf("[IN ]inData          = %s\n", inData);
    printf("[IN ]IV              = %s\n", IV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIEncrypt_index(nSock, encryptKeyIndex, mech, inData, IV, outData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "ECB测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[OUT]outData    = %s\n", outData);
    printf("[OUT]outDataExp = %s\n", outDataExp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void EncryptIndex_Test_02(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    BYTE bKey[32];
    char szCheckValue[16];
    int  encryptKeyIndex;
    UINT mech;
    char data_tmp[1024];
    char data[1024];
    char inData[1024];
    char IV[32];
    char outData[1024];
    char outDataExp[1024];

    bufclr(bKey);
    bufclr(szCheckValue);
    bufclr(data_tmp);
    bufclr(data);
    bufclr(inData);
    bufclr(IV);
    bufclr(outData);
    bufclr(outDataExp);

    encryptKeyIndex = 258;
    mech = 17;
    memcpy(data,
           "\x30\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42" \
           "\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42" \
           "\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42" \
           "\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x39" \
           , 64);
    memcpy(inData, "30424242424242424242424242424242"
                   "42424242424242424242424242424242"
                   "42424242424242424242424242424242"
                   "42424242424242424242424242424239"
                   , 128);

    nRet = SMAPIGenerateKey(nSock, 16, "ZZZZZZZZZZ", 10, \
                            2, encryptKeyIndex, bKey, szCheckValue);
    ASSERT_RESULT(nRet, 0, "SMAPIGenerateKey NG");

    nRet = SMAPIEncryptData(nSock, 1, 1, encryptKeyIndex, data, 64, data_tmp);
    ASSERT_RESULT(nRet, 0, "SMAPIEncryptData NG");
    SSMHexToChar(data_tmp, outDataExp, 64);

    memset(IV, '0', 16);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]encryptKeyIndex = %d\n", encryptKeyIndex);
    printf("[IN ]mech            = %d\n", mech);
    printf("[IN ]inData          = %s\n", inData);
    printf("[IN ]IV              = %s\n", IV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIEncrypt_index(nSock, encryptKeyIndex, mech, inData, IV, outData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "CBC测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[OUT]outData    = %s\n", outData);
    printf("[OUT]outDataExp = %s\n", outDataExp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void EncryptIndex_Test_03(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    BYTE bKey[32];
    char szCheckValue[16];
    int  encryptKeyIndex;
    UINT mech;
    char data_tmp[1024];
    char data[1024];
    char inData[1024];
    char IV[33];
    char outData[1024];
    char outDataExp[1024];

    bufclr(bKey);
    bufclr(szCheckValue);
    bufclr(data_tmp);
    bufclr(data);
    bufclr(inData);
    bufclr(IV);
    bufclr(outData);
    bufclr(outDataExp);

    encryptKeyIndex = 258;
    mech = 3;
    memcpy(data,
           "\x30\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42" \
           "\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42" \
           "\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42" \
           "\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x39" \
           , 64);
    memcpy(inData, "30424242424242424242424242424242"
                   "42424242424242424242424242424242"
                   "42424242424242424242424242424242"
                   "42424242424242424242424242424239"
                   , 128);

    nRet = SMAPIGenerateKey(nSock, 16, "ZZZZZZZZZZ", 10, \
                            2, encryptKeyIndex, bKey, szCheckValue);
    ASSERT_RESULT(nRet, 0, "SMAPIGenerateKey NG");

    nRet = SMAPISm4Calc(nSock, 1, 0, bKey, data, 64, IV, data_tmp);
    ASSERT_RESULT(nRet, 0, "SMAPISm4Calc NG");
    SSMHexToChar(data_tmp, outDataExp, 64);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]encryptKeyIndex = %d\n", encryptKeyIndex);
    printf("[IN ]mech            = %d\n", mech);
    printf("[IN ]inData          = %s\n", inData);
    printf("[IN ]IV              = %s\n", IV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIEncrypt_index(nSock, encryptKeyIndex, mech, inData, IV, outData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "SM4_ECB测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    ASSERT_OUT_HEX(outData, outDataExp, 128);
    printf("[OUT]outData    = %s\n", outData);
    printf("[OUT]outDataExp = %s\n", outDataExp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void EncryptIndex_Test_04(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    BYTE bKey[32];
    char szCheckValue[16];
    int  encryptKeyIndex;
    UINT mech;
    char data_tmp[1024];
    char data[1024];
    char inData[1024];
    char IV[33];
    char outData[1024];
    char outDataExp[1024];

    bufclr(bKey);
    bufclr(szCheckValue);
    bufclr(data_tmp);
    bufclr(data);
    bufclr(inData);
    bufclr(IV);
    bufclr(outData);
    bufclr(outDataExp);

    encryptKeyIndex = 258;
    mech = 4;
    memcpy(data,
           "\x30\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42" \
           "\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42" \
           "\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42" \
           "\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x39" \
           , 64);
    memcpy(inData, "30424242424242424242424242424242"
                   "42424242424242424242424242424242"
                   "42424242424242424242424242424242"
                   "42424242424242424242424242424239"
                   , 128);

    nRet = SMAPIGenerateKey(nSock, 16, "ZZZZZZZZZZ", 10, \
                            2, encryptKeyIndex, bKey, szCheckValue);
    ASSERT_RESULT(nRet, 0, "SMAPIGenerateKey NG");
DspHexExt("bKey =", bKey, 16);
    nRet = SMAPISm4Calc(nSock, 1, 1, bKey, data, 64, IV, data_tmp);
    ASSERT_RESULT(nRet, 0, "SMAPISm4Calc NG");
    SSMHexToChar(data_tmp, outDataExp, 64);

    memset(IV, '0', 32);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]encryptKeyIndex = %d\n", encryptKeyIndex);
    printf("[IN ]mech            = %d\n", mech);
    printf("[IN ]inData          = %s\n", inData);
    printf("[IN ]IV              = %s\n", IV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIEncrypt_index(nSock, encryptKeyIndex, mech, inData, IV, outData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "SM4_CBC测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    ASSERT_OUT_HEX(outData, outDataExp, 128);
    printf("[OUT]outData    = %s\n", outData);
    printf("[OUT]outDataExp = %s\n", outDataExp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void Decrypt_Test_01(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    char DecryptKey[64];
    UINT mech;
    char data[1024];
    char IV[32];
    char outData[1024];
    char outDataExp[1024];

    bufclr(DecryptKey);
    bufclr(data);
    bufclr(IV);
    bufclr(outData);
    bufclr(outDataExp);

    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(DecryptKey,
           "A2C0B0F8F7F5EE21FB5C6AEBE714E53A",
           32);
    mech = 20;
    memcpy(data, "C9AF9A5820243A8F322EA2FA878BC4AE"
                 "322EA2FA878BC4AE322EA2FA878BC4AE"
                 "322EA2FA878BC4AE322EA2FA878BC4AE"
                 "322EA2FA878BC4AE71AA8BE6D7CE2C1E"
                 , 128);
    memset(IV, '0', 16);
    memcpy(outDataExp, "30424242424242424242424242424242"
                       "42424242424242424242424242424242"
                       "42424242424242424242424242424242"
                       "42424242424242424242424242424239"
                       , 128);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]DecryptKey = %s\n", DecryptKey);
    printf("[IN ]mech       = %d\n", mech);
    printf("[IN ]data       = %s\n", data);
    printf("[IN ]IV         = %s\n", IV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIDecrypt(nSock, DecryptKey, mech, data, IV, outData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "ECB测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[OUT]outData    = %s\n", outData);
    printf("[OUT]outDataExp = %s\n", outDataExp);
    ASSERT_OUT_HEX(outData, outDataExp, 128);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void Decrypt_Test_02(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    char DecryptKey[64];
    UINT mech;
    char data[1024];
    char IV[32];
    char outData[1024];
    char outDataExp[1024];

    bufclr(DecryptKey);
    bufclr(data);
    bufclr(IV);
    bufclr(outData);
    bufclr(outDataExp);

    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(DecryptKey,
           "A2C0B0F8F7F5EE21FB5C6AEBE714E53A",
           32);
    mech = 17;
    memcpy(data, "C9AF9A5820243A8FACED8916C5EDD75A"
                 "15F05A7AB0A03B7BC77393E44B464F4D"
                 "FAF2845DD3EDCFECC4C349829CFD0F2A"
                 "CFD249005B3E6667A7D50E60FD9F0226"
                 , 128);
    memset(IV, '0', 16);
    memcpy(outDataExp, "30424242424242424242424242424242"
                       "42424242424242424242424242424242"
                       "42424242424242424242424242424242"
                       "42424242424242424242424242424239"
                       , 128);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]DecryptKey = %s\n", DecryptKey);
    printf("[IN ]mech       = %d\n", mech);
    printf("[IN ]data       = %s\n", data);
    printf("[IN ]IV         = %s\n", IV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIDecrypt(nSock, DecryptKey, mech, data, IV, outData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "CBC测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[OUT]outData    = %s\n", outData);
    printf("[OUT]outDataExp = %s\n", outDataExp);
    ASSERT_OUT_HEX(outData, outDataExp, 128);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void Decrypt_Test_03(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    char DecryptKey[64];
    UINT mech;
    char data[1024];
    char IV[33];
    char outData[1024];
    char outDataExp[1024];

    bufclr(DecryptKey);
    bufclr(data);
    bufclr(IV);
    bufclr(outData);
    bufclr(outDataExp);

    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(DecryptKey,
           "A2C0B0F8F7F5EE21FB5C6AEBE714E53A",
           32);
    mech = 3;
    memcpy(data,
           "88C77F3AA6A29E4E2031657E3848A463" \
           "C5F811F608BBF54F669F9D1DE7C1E6E5" \
           "C5F811F608BBF54F669F9D1DE7C1E6E5" \
           "822AD6A14D0A65313812078F057725B5"
           , 128);
    memset(IV, '0', 32);
    memcpy(outDataExp, "30424242424242424242424242424242"
                       "42424242424242424242424242424242"
                       "42424242424242424242424242424242"
                       "42424242424242424242424242424239"
                       , 128);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]DecryptKey = %s\n", DecryptKey);
    printf("[IN ]mech       = %d\n", mech);
    printf("[IN ]data       = %s\n", data);
    printf("[IN ]IV         = %s\n", IV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIDecrypt(nSock, DecryptKey, mech, data, IV, outData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "SM4_ECB测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[OUT]outData    = %s\n", outData);
    printf("[OUT]outDataExp = %s\n", outDataExp);
    ASSERT_OUT_HEX(outData, outDataExp, 128);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void Decrypt_Test_04(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    char DecryptKey[64];
    UINT mech;
    char data[1024];
    char IV[33];
    char outData[1024];
    char outDataExp[1024];

    bufclr(DecryptKey);
    bufclr(data);
    bufclr(IV);
    bufclr(outData);
    bufclr(outDataExp);

    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(DecryptKey,
           "A2C0B0F8F7F5EE21FB5C6AEBE714E53A",
           32);
    mech = 4;
    memcpy(data,
           "88C77F3AA6A29E4E2031657E3848A463" \
           "E263A2B0C43EF4EFA9F9C5A722A157A0" \
           "EB60D8E5FC56BAB836620A7FF5404668" \
           "A98DB8B683A0819B732428B22A5F4D68" \
           , 128);
    memset(IV, '0', 32);
    memcpy(outDataExp, "30424242424242424242424242424242"
                       "42424242424242424242424242424242"
                       "42424242424242424242424242424242"
                       "42424242424242424242424242424239"
                       , 128);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]DecryptKey = %s\n", DecryptKey);
    printf("[IN ]mech       = %d\n", mech);
    printf("[IN ]data       = %s\n", data);
    printf("[IN ]IV         = %s\n", IV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIDecrypt(nSock, DecryptKey, mech, data, IV, outData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "SM4_CBC测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[OUT]outData    = %s\n", outData);
    printf("[OUT]outDataExp = %s\n", outDataExp);
    ASSERT_OUT_HEX(outData, outDataExp, 128);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void DecryptIndex_Test_01(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    BYTE bKey[32];
    char szCheckValue[16];
    int  DecryptKeyIndex;
    UINT mech;
    char data_tmp[1024];
    char data[1024];
    char inData[1024];
    char IV[32];
    char outData[1024];
    char outDataExp[1024];

    bufclr(bKey);
    bufclr(szCheckValue);
    bufclr(data_tmp);
    bufclr(data);
    bufclr(inData);
    bufclr(IV);
    bufclr(outData);
    bufclr(outDataExp);

    DecryptKeyIndex = 258;
    mech = 20;
    memcpy(data,
           "\x30\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42" \
           "\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42" \
           "\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42" \
           "\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x39" \
           , 64);
    memcpy(inData, "30424242424242424242424242424242"
                   "42424242424242424242424242424242"
                   "42424242424242424242424242424242"
                   "42424242424242424242424242424239"
                   , 128);

    nRet = SMAPIGenerateKey(nSock, 16, "ZZZZZZZZZZ", 10, \
                            2, DecryptKeyIndex, bKey, szCheckValue);
    ASSERT_RESULT(nRet, 0, "SMAPIGenerateKey NG");

    nRet = SMAPIEncryptData(nSock, 0, 0, DecryptKeyIndex, data, 64, data_tmp);
    ASSERT_RESULT(nRet, 0, "SMAPIEncryptData NG");
    SSMHexToChar(data_tmp, outDataExp, 64);

    memset(IV, '0', 16);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]DecryptKeyIndex = %d\n", DecryptKeyIndex);
    printf("[IN ]mech            = %d\n", mech);
    printf("[IN ]inData          = %s\n", inData);
    printf("[IN ]IV              = %s\n", IV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIDecrypt_index(nSock, DecryptKeyIndex, mech, inData, IV, outData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "ECB测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[OUT]outData    = %s\n", outData);
    printf("[OUT]outDataExp = %s\n", outDataExp);
    ASSERT_OUT_HEX(outData, outDataExp, 128);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void DecryptIndex_Test_02(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    BYTE bKey[32];
    char szCheckValue[16];
    int  DecryptKeyIndex;
    UINT mech;
    char data_tmp[1024];
    char data[1024];
    char inData[1024];
    char IV[32];
    char outData[1024];
    char outDataExp[1024];

    bufclr(bKey);
    bufclr(szCheckValue);
    bufclr(data_tmp);
    bufclr(data);
    bufclr(inData);
    bufclr(IV);
    bufclr(outData);
    bufclr(outDataExp);

    DecryptKeyIndex = 258;
    mech = 17;
    memcpy(data,
           "\x30\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42" \
           "\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42" \
           "\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42" \
           "\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x39" \
           , 64);
    memcpy(inData, "30424242424242424242424242424242"
                   "42424242424242424242424242424242"
                   "42424242424242424242424242424242"
                   "42424242424242424242424242424239"
                   , 128);

    nRet = SMAPIGenerateKey(nSock, 16, "ZZZZZZZZZZ", 10, \
                            2, DecryptKeyIndex, bKey, szCheckValue);
    ASSERT_RESULT(nRet, 0, "SMAPIGenerateKey NG");

    nRet = SMAPIEncryptData(nSock, 0, 1, DecryptKeyIndex, data, 64, data_tmp);
    ASSERT_RESULT(nRet, 0, "SMAPIEncryptData NG");
    SSMHexToChar(data_tmp, outDataExp, 64);

    memset(IV, '0', 16);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]DecryptKeyIndex = %d\n", DecryptKeyIndex);
    printf("[IN ]mech            = %d\n", mech);
    printf("[IN ]inData          = %s\n", inData);
    printf("[IN ]IV              = %s\n", IV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIDecrypt_index(nSock, DecryptKeyIndex, mech, inData, IV, outData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "CBC测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[OUT]outData    = %s\n", outData);
    printf("[OUT]outDataExp = %s\n", outDataExp);
    ASSERT_OUT_HEX(outData, outDataExp, 128);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void DecryptIndex_Test_03(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    BYTE bKey[32];
    char szCheckValue[16];
    int  DecryptKeyIndex;
    UINT mech;
    char data_tmp[1024];
    char data[1024];
    char inData[1024];
    char IV[33];
    char outData[1024];
    char outDataExp[1024];

    bufclr(bKey);
    bufclr(szCheckValue);
    bufclr(data_tmp);
    bufclr(data);
    bufclr(inData);
    bufclr(IV);
    bufclr(outData);
    bufclr(outDataExp);

    DecryptKeyIndex = 258;
    mech = 3;
    memcpy(data,
           "\x30\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42" \
           "\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42" \
           "\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42" \
           "\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x39" \
           , 64);
    memcpy(inData, "30424242424242424242424242424242"
                   "42424242424242424242424242424242"
                   "42424242424242424242424242424242"
                   "42424242424242424242424242424239"
                   , 128);

    nRet = SMAPIGenerateKey(nSock, 16, "ZZZZZZZZZZ", 10, \
                            2, DecryptKeyIndex, bKey, szCheckValue);
    ASSERT_RESULT(nRet, 0, "SMAPIGenerateKey NG");
DspHexExt("bKey =", bKey, 16);
    nRet = SMAPISm4Calc(nSock, 0, 0, bKey, data, 64, IV, data_tmp);
    ASSERT_RESULT(nRet, 0, "SMAPISm4Calc NG");
    SSMHexToChar(data_tmp, outDataExp, 64);

    memset(IV, '0', 32);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]DecryptKeyIndex = %d\n", DecryptKeyIndex);
    printf("[IN ]mech            = %d\n", mech);
    printf("[IN ]inData          = %s\n", inData);
    printf("[IN ]IV              = %s\n", IV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIDecrypt_index(nSock, DecryptKeyIndex, mech, inData, IV, outData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "SM4_ECB测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[OUT]outData    = %s\n", outData);
    printf("[OUT]outDataExp = %s\n", outDataExp);
    ASSERT_OUT_HEX(outData, outDataExp, 128);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void DecryptIndex_Test_04(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    BYTE bKey[32];
    char szCheckValue[16];
    int  DecryptKeyIndex;
    UINT mech;
    char data_tmp[1024];
    char data[1024];
    char inData[1024];
    char IV[33];
    char outData[1024];
    char outDataExp[1024];

    bufclr(bKey);
    bufclr(szCheckValue);
    bufclr(data_tmp);
    bufclr(data);
    bufclr(inData);
    bufclr(IV);
    bufclr(outData);
    bufclr(outDataExp);

    DecryptKeyIndex = 258;
    mech = 4;
    memcpy(data,
           "\x30\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42" \
           "\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42" \
           "\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42" \
           "\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x39" \
           , 64);
    memcpy(inData, "30424242424242424242424242424242"
                   "42424242424242424242424242424242"
                   "42424242424242424242424242424242"
                   "42424242424242424242424242424239"
                   , 128);

    nRet = SMAPIGenerateKey(nSock, 16, "ZZZZZZZZZZ", 10, \
                            2, DecryptKeyIndex, bKey, szCheckValue);
    ASSERT_RESULT(nRet, 0, "SMAPIGenerateKey NG");
DspHexExt("bKey =", bKey, 16);
    nRet = SMAPISm4Calc(nSock, 0, 1, bKey, data, 64, IV, data_tmp);
    ASSERT_RESULT(nRet, 0, "SMAPISm4Calc NG");
    SSMHexToChar(data_tmp, outDataExp, 64);

    memset(IV, '0', 32);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]DecryptKeyIndex = %d\n", DecryptKeyIndex);
    printf("[IN ]mech            = %d\n", mech);
    printf("[IN ]inData          = %s\n", inData);
    printf("[IN ]IV              = %s\n", IV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIDecrypt_index(nSock, DecryptKeyIndex, mech, inData, IV, outData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "SM4_CBC测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[OUT]outData    = %s\n", outData);
    printf("[OUT]outDataExp = %s\n", outDataExp);
    ASSERT_OUT_HEX(outData, outDataExp, 128);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void DeriveKey_Test_01(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    char masterKey[64];
    UINT mech;
    char divdata[128];
    char IV[32];
    char derivedKey[128];
    char outDataExp[128];

    bufclr(masterKey);
    bufclr(divdata);
    bufclr(IV);
    bufclr(derivedKey);
    bufclr(outDataExp);

    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(masterKey, "A2C0B0F8F7F5EE21FB5C6AEBE714E53A", 32);
    mech = 20;
    memcpy(divdata, "0123456789ABF001CDEFFEDCBA980F01", 32);
    memset(IV, '0', 16);
    /* 4103248290BA8439884DE503EDF390C9 */
    memcpy(outDataExp, "9C2BEDCF6B7569D37155C5063F2337E9", 32);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]masterKey = %s\n", masterKey);
    printf("[IN ]mech      = %d\n", mech);
    printf("[IN ]divdata   = %s\n", divdata);
    printf("[IN ]IV        = %s\n", IV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIderiveKey(nSock, masterKey, mech, divdata, IV, derivedKey);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "ECB测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[OUT]derivedKey = %s\n", derivedKey);
    printf("[OUT]outDataExp = %s\n", outDataExp);
    ASSERT_OUT_HEX(derivedKey, outDataExp, 32);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void DeriveKey_Test_02(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    char masterKey[64];
    UINT mech;
    char divdata[128];
    char IV[32];
    char derivedKey[128];
    char outDataExp[128];

    bufclr(masterKey);
    bufclr(divdata);
    bufclr(IV);
    bufclr(derivedKey);
    bufclr(outDataExp);

    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(masterKey, "A2C0B0F8F7F5EE21FB5C6AEBE714E53A", 32);
    mech = 17;
    memcpy(divdata, "0123456789ABF001CDEFFEDCBA980F01", 32);
    memset(IV, '0', 16);
    /* 4103248290BA84391D327EF0341ABEC2 */
    memcpy(outDataExp, "9C2BEDCF6B7569D3ADC89F18CF58119F", 32);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]masterKey = %s\n", masterKey);
    printf("[IN ]mech      = %d\n", mech);
    printf("[IN ]divdata   = %s\n", divdata);
    printf("[IN ]IV        = %s\n", IV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIderiveKey(nSock, masterKey, mech, divdata, IV, derivedKey);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "CBC测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[OUT]derivedKey = %s\n", derivedKey);
    printf("[OUT]outDataExp = %s\n", outDataExp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void DeriveKey_Test_03(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    char masterKey[64];
    UINT mech;
    char divdata[128];
    char IV[33];
    char derivedKey[128];
    char outDataExp[128];

    bufclr(masterKey);
    bufclr(divdata);
    bufclr(IV);
    bufclr(derivedKey);
    bufclr(outDataExp);

    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(masterKey, "A2C0B0F8F7F5EE21FB5C6AEBE714E53A", 32);
    mech = 3;
    memcpy(divdata, "0123456789ABF001CDEFFEDCBA980F010123456789ABF001CDEFFEDCBA980F01", 64);
    memset(IV, '0', 32);
    /* 1A4964D4943A036833DEEC1C9E94AD6E1A4964D4943A036833DEEC1C9E94AD6E */
    memcpy(outDataExp, "82A7EAD25706A76BB7EDBAE51B2FD96A82A7EAD25706A76BB7EDBAE51B2FD96A", 64);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]masterKey = %s\n", masterKey);
    printf("[IN ]mech      = %d\n", mech);
    printf("[IN ]divdata   = %s\n", divdata);
    printf("[IN ]IV        = %s\n", IV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIderiveKey(nSock, masterKey, mech, divdata, IV, derivedKey);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "SM4_ECB测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[OUT]derivedKey = %s\n", derivedKey);
    printf("[OUT]outDataExp = %s\n", outDataExp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void DeriveKey_Test_04(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    char masterKey[64];
    UINT mech;
    char divdata[128];
    char IV[33];
    char derivedKey[128];
    char outDataExp[128];

    bufclr(masterKey);
    bufclr(divdata);
    bufclr(IV);
    bufclr(derivedKey);
    bufclr(outDataExp);

    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(masterKey, "A2C0B0F8F7F5EE21FB5C6AEBE714E53A", 32);
    mech = 4;
    memcpy(divdata, "0123456789ABF001CDEFFEDCBA980F010123456789ABF001CDEFFEDCBA980F01", 64);
    memset(IV, '0', 32);
    /* 1A4964D4943A036833DEEC1C9E94AD6E856193B9EF3592CE790924CF8074978C */
    memcpy(outDataExp, "82A7EAD25706A76BB7EDBAE51B2FD96AD5A71E3376BA9F2273813B17D84739C3", 64);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]masterKey = %s\n", masterKey);
    printf("[IN ]mech      = %d\n", mech);
    printf("[IN ]divdata   = %s\n", divdata);
    printf("[IN ]IV        = %s\n", IV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIderiveKey(nSock, masterKey, mech, divdata, IV, derivedKey);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "SM4_CBC测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[OUT]derivedKey = %s\n", derivedKey);
    printf("[OUT]outDataExp = %s\n", outDataExp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void DeriveKeyIndex_Test_01(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    BYTE bKey[32];
    char szCheckValue[16];
    int  masterKeyIndex;
    UINT mech;
    char divdata[128];
    char data[128];
    char IV[32];
    char derivedKey[128];
    char outDataTmp[128];
    char outDataExp[128];

    bufclr(bKey);
    bufclr(szCheckValue);
    bufclr(divdata);
    bufclr(data);
    bufclr(IV);
    bufclr(derivedKey);
    bufclr(outDataTmp);
    bufclr(outDataExp);

    masterKeyIndex = 444;
    mech = 20;

    memcpy(data, "\x01\x23\x45\x67\x89\xAB\xF0\x01\xCD\xEF\xFE\xDC\xBA\x98\x0F\x01", 16);
    nRet = SMAPIGenerateKey(nSock, 16, "ZZZZZZZZZZ", 10, \
                            2, masterKeyIndex, bKey, szCheckValue);
    ASSERT_RESULT(nRet, 0, "SMAPIGenerateKey NG");

    nRet = SMAPIEncryptData(nSock, 1, 0, masterKeyIndex, data, 16, outDataExp);
    ASSERT_RESULT(nRet, 0, "SMAPIEncryptData NG");

    SSMMakeOddBinStr_Test(outDataTmp, 16);
    nRet = SMAPIEncryptKey(nSock, outDataExp, 16, outDataTmp);
    ASSERT_RESULT(nRet, 0, "SMAPIEncryptKey NG");

    SSMHexToChar(outDataTmp, outDataExp, 16);

    memcpy(divdata, "0123456789ABF001CDEFFEDCBA980F01", 32);
    memset(IV, '0', 16);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]masterKeyIndex = %d\n", masterKeyIndex);
    printf("[IN ]mech           = %d\n", mech);
    printf("[IN ]divdata        = %s\n", divdata);
    printf("[IN ]IV             = %s\n", IV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIderiveKey_index(nSock, masterKeyIndex, mech, divdata, IV, derivedKey);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "ECB测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[OUT]derivedKey = %s\n", derivedKey);
    printf("[OUT]outDataExp = %s\n", outDataExp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void DeriveKeyIndex_Test_02(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    BYTE bKey[32];
    char szCheckValue[16];
    int  masterKeyIndex;
    UINT mech;
    char divdata[128];
    char data[128];
    char IV[32];
    char derivedKey[128];
    char outDataTmp[128];
    char outDataExp[128];

    bufclr(bKey);
    bufclr(szCheckValue);
    bufclr(divdata);
    bufclr(data);
    bufclr(IV);
    bufclr(derivedKey);
    bufclr(outDataTmp);
    bufclr(outDataExp);

    masterKeyIndex = 444;
    mech = 17;

    memcpy(data, "\x01\x23\x45\x67\x89\xAB\xF0\x01\xCD\xEF\xFE\xDC\xBA\x98\x0F\x01", 16);
    nRet = SMAPIGenerateKey(nSock, 16, "ZZZZZZZZZZ", 10, \
                            2, masterKeyIndex, bKey, szCheckValue);
    ASSERT_RESULT(nRet, 0, "SMAPIGenerateKey NG");

    nRet = SMAPIEncryptData(nSock, 1, 1, masterKeyIndex, data, 16, outDataExp);
    ASSERT_RESULT(nRet, 0, "SMAPIEncryptData NG");

    SSMMakeOddBinStr_Test(outDataTmp, 16);
    nRet = SMAPIEncryptKey(nSock, outDataExp, 16, outDataTmp);
    ASSERT_RESULT(nRet, 0, "SMAPIEncryptKey NG");

    SSMHexToChar(outDataTmp, outDataExp, 16);

    memcpy(divdata, "0123456789ABF001CDEFFEDCBA980F01", 32);
    memset(IV, '0', 16);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]masterKeyIndex = %d\n", masterKeyIndex);
    printf("[IN ]mech           = %d\n", mech);
    printf("[IN ]divdata        = %s\n", divdata);
    printf("[IN ]IV             = %s\n", IV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIderiveKey_index(nSock, masterKeyIndex, mech, divdata, IV, derivedKey);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "CBC测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[OUT]derivedKey = %s\n", derivedKey);
    printf("[OUT]outDataExp = %s\n", outDataExp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void DeriveKeyIndex_Test_03(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    BYTE bKey[32];
    char szCheckValue[16];
    int  masterKeyIndex;
    UINT mech;
    char divdata[128];
    char data[128];
    char IV[33];
    char derivedKey[128];
    char outDataTmp[128];
    char outDataExp[128];

    bufclr(bKey);
    bufclr(szCheckValue);
    bufclr(divdata);
    bufclr(data);
    bufclr(IV);
    bufclr(derivedKey);
    bufclr(outDataTmp);
    bufclr(outDataExp);

    masterKeyIndex = 444;
    mech = 3;

    memcpy(data, 
           "\x01\x23\x45\x67\x89\xAB\xF0\x01\xCD\xEF\xFE\xDC\xBA\x98\x0F\x01"
           , 16);
    nRet = SMAPIGenerateKey(nSock, 16, "ZZZZZZZZZZ", 10, \
                            2, masterKeyIndex, bKey, szCheckValue);
    ASSERT_RESULT(nRet, 0, "SMAPIGenerateKey NG");

    nRet = SMAPISm4Calc(nSock, 1, 0, bKey, data, 16, IV, outDataExp);
    ASSERT_RESULT(nRet, 0, "SMAPISm4Calc NG");

    nRet = SMAPIEncryptKey(nSock, outDataExp, 16, outDataTmp);
    ASSERT_RESULT(nRet, 0, "SMAPIEncryptKey NG");

    SSMHexToChar(outDataTmp, outDataExp, 16);

    memcpy(divdata, "0123456789ABF001CDEFFEDCBA980F01", 32);
    memset(IV, '0', 32);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]masterKeyIndex = %d\n", masterKeyIndex);
    printf("[IN ]mech           = %d\n", mech);
    printf("[IN ]divdata        = %s\n", divdata);
    printf("[IN ]IV             = %s\n", IV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIderiveKey_index(nSock, masterKeyIndex, mech, divdata, IV, derivedKey);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "SM4_ECB测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[OUT]derivedKey = %s\n", derivedKey);
    printf("[OUT]outDataExp = %s\n", outDataExp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void DeriveKeyIndex_Test_04(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    BYTE bKey[32];
    char szCheckValue[16];
    int  masterKeyIndex;
    UINT mech;
    char divdata[128];
    char data[128];
    char IV[33];
    char derivedKey[128];
    char outDataTmp[128];
    char outDataExp[128];

    bufclr(bKey);
    bufclr(szCheckValue);
    bufclr(divdata);
    bufclr(data);
    bufclr(IV);
    bufclr(derivedKey);
    bufclr(outDataTmp);
    bufclr(outDataExp);

    masterKeyIndex = 444;
    mech = 4;

    memcpy(data, 
           "\x01\x23\x45\x67\x89\xAB\xF0\x01\xCD\xEF\xFE\xDC\xBA\x98\x0F\x01"
           "\x01\x23\x45\x67\x89\xAB\xF0\x01\xCD\xEF\xFE\xDC\xBA\x98\x0F\x01"
           , 32);
    nRet = SMAPIGenerateKey(nSock, 16, "ZZZZZZZZZZ", 10, \
                            2, masterKeyIndex, bKey, szCheckValue);
    ASSERT_RESULT(nRet, 0, "SMAPIGenerateKey NG");

    nRet = SMAPISm4Calc(nSock, 1, 1, bKey, data, 32, IV, outDataExp);
    ASSERT_RESULT(nRet, 0, "SMAPISm4Calc NG");

    nRet = SMAPIEncryptKey(nSock, outDataExp, 16, outDataTmp);
    ASSERT_RESULT(nRet, 0, "SMAPIEncryptKey NG");

    nRet = SMAPIEncryptKey(nSock, &outDataExp[16], 16, &outDataTmp[16]);
    ASSERT_RESULT(nRet, 0, "SMAPIEncryptKey NG");

    SSMHexToChar(outDataTmp, outDataExp, 32);

    memcpy(divdata, "0123456789ABF001CDEFFEDCBA980F010123456789ABF001CDEFFEDCBA980F01", 64);
    memset(IV, '0', 32);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]masterKeyIndex = %d\n", masterKeyIndex);
    printf("[IN ]mech           = %d\n", mech);
    printf("[IN ]divdata        = %s\n", divdata);
    printf("[IN ]IV             = %s\n", IV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIderiveKey_index(nSock, masterKeyIndex, mech, divdata, IV, derivedKey);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "SM4_CBC测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[OUT]derivedKey = %s\n", derivedKey);
    printf("[OUT]outDataExp = %s\n", outDataExp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void GenerateRandom_Test_01(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    int  rdmLength;
    char outData[1024];

    bufclr(outData);

    rdmLength = 31;

    XXX_INPUT_XXX
    printf("[IN ]nSock     = %d\n", nSock);
    printf("[IN ]rdmLength = %d\n", rdmLength);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIGenerateRandom(nSock, rdmLength, outData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "产生31位随机数测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[OUT]outData    = %s\n", outData);
    ASSERT_OUT(strlen(outData), 62);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void Wrap_Test_01(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    char wrapKey[64];
    UINT mech;
    char key[1024];
    char IV[32];
    char outData[1024];
    char outDataExp[1024];

    bufclr(wrapKey);
    bufclr(key);
    bufclr(IV);
    bufclr(outData);
    bufclr(outDataExp);

    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(wrapKey, "A2C0B0F8F7F5EE21FB5C6AEBE714E53A", 32);
    mech = 20;
    /* FEDC BA98 7654 3210 0123 4567 89AB CDEF */
    memcpy(key, "FB5C6AEBE714E53AA2C0B0F8F7F5EE21", 32);
    memset(IV, '0', 16);
    memcpy(outDataExp, "1FD1B02B237AF9AE1A4D672DCA6CB335", 32);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]encryptKey = %s\n", wrapKey);
    printf("[IN ]mech       = %d\n", mech);
    printf("[IN ]key        = %s\n", key);
    printf("[IN ]IV         = %s\n", IV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIwrap(nSock, wrapKey, mech, key, IV, outData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "ECB测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[OUT]outData    = %s\n", outData);
    printf("[OUT]outDataExp = %s\n", outDataExp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void Wrap_Test_02(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    char wrapKey[64];
    UINT mech;
    char key[1024];
    char IV[32];
    char outData[1024];
    char outDataExp[1024];

    bufclr(wrapKey);
    bufclr(key);
    bufclr(IV);
    bufclr(outData);
    bufclr(outDataExp);

    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(wrapKey, "A2C0B0F8F7F5EE21FB5C6AEBE714E53A", 32);
    mech = 17;
    /* FEDC BA98 7654 3210 0123 4567 89AB CDEF */
    memcpy(key, "FB5C6AEBE714E53AA2C0B0F8F7F5EE21", 32);
    memset(IV, '0', 16);
    memcpy(outDataExp, "1FD1B02B237AF9AE3702240E7080EA4C", 32);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]encryptKey = %s\n", wrapKey);
    printf("[IN ]mech       = %d\n", mech);
    printf("[IN ]key        = %s\n", key);
    printf("[IN ]IV         = %s\n", IV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIwrap(nSock, wrapKey, mech, key, IV, outData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "CBC测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[OUT]outData    = %s\n", outData);
    printf("[OUT]outDataExp = %s\n", outDataExp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void WrapIndex_Test_01(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

/////////////////////////////////////////////
    BYTE bKey[32];
    char szCheckValue[16];
    int  masterKeyIndex;
    UINT mech;
    char data[128];
    char IV[32];
    char key[64];
    char outDataTmp[128];
    char outDataExp[128];
    char outData[1024];

    bufclr(bKey);
    bufclr(szCheckValue);
    bufclr(data);
    bufclr(IV);
    bufclr(key);
    bufclr(outDataTmp);
    bufclr(outDataExp);
    bufclr(outData);

    masterKeyIndex = 444;
    mech = 20;

    memcpy(data, "\x01\x23\x45\x67\x89\xAB\xF0\x01\xCD\xEF\xFE\xDC\xBA\x98\x0F\x01", 16);
    SSMMakeOddBinStr_Test(data, 16);
    nRet = SMAPIGenerateKey(nSock, 16, "ZZZZZZZZZZ", 10, \
                            2, masterKeyIndex, bKey, szCheckValue);
    ASSERT_RESULT(nRet, 0, "SMAPIGenerateKey NG");

    nRet = SMAPIEncryptData(nSock, 1, 0, masterKeyIndex, data, 16, outDataTmp);
    ASSERT_RESULT(nRet, 0, "SMAPIEncryptData NG");

    SSMHexToChar(outDataTmp, outDataExp, 16);

    nRet = SMAPIEncryptKey(nSock, data, 16, outDataTmp);
    ASSERT_RESULT(nRet, 0, "SMAPIEncryptKey NG");
    SSMHexToChar(outDataTmp, key, 16);
///////////////////////////////

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]index = %d\n", masterKeyIndex);
    printf("[IN ]mech  = %d\n", mech);
    printf("[IN ]key   = %s\n", key);
    printf("[IN ]IV    = %s\n", IV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIwrap_index(nSock, masterKeyIndex, mech, key, IV, outData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "ECB测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[OUT]outData    = %s\n", outData);
    printf("[OUT]outDataExp = %s\n", outDataExp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void WrapIndex_Test_02(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

/////////////////////////////////////////////
    BYTE bKey[32];
    char szCheckValue[16];
    int  masterKeyIndex;
    UINT mech;
    char data[128];
    char IV[32];
    char key[64];
    char outDataTmp[128];
    char outDataExp[128];
    char outData[1024];

    bufclr(bKey);
    bufclr(szCheckValue);
    bufclr(data);
    bufclr(IV);
    bufclr(key);
    bufclr(outDataTmp);
    bufclr(outDataExp);
    bufclr(outData);

    masterKeyIndex = 444;
    mech = 17;
    
    memset(IV, '0', 16);

    memcpy(data, "\x01\x23\x45\x67\x89\xAB\xF0\x01\xCD\xEF\xFE\xDC\xBA\x98\x0F\x01", 16);
    SSMMakeOddBinStr_Test(data, 16);
    nRet = SMAPIGenerateKey(nSock, 16, "ZZZZZZZZZZ", 10, \
                            2, masterKeyIndex, bKey, szCheckValue);
    ASSERT_RESULT(nRet, 0, "SMAPIGenerateKey NG");

    nRet = SMAPIEncryptData(nSock, 1, 1, masterKeyIndex, data, 16, outDataTmp);
    ASSERT_RESULT(nRet, 0, "SMAPIEncryptData NG");

    SSMHexToChar(outDataTmp, outDataExp, 16);

    nRet = SMAPIEncryptKey(nSock, data, 16, outDataTmp);
    ASSERT_RESULT(nRet, 0, "SMAPIEncryptKey NG");
    SSMHexToChar(outDataTmp, key, 16);
///////////////////////////////

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]index = %d\n", masterKeyIndex);
    printf("[IN ]mech  = %d\n", mech);
    printf("[IN ]key   = %s\n", key);
    printf("[IN ]IV    = %s\n", IV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIwrap_index(nSock, masterKeyIndex, mech, key, IV, outData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "CBC测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[OUT]outData    = %s\n", outData);
    printf("[OUT]outDataExp = %s\n", outDataExp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void PBOCMAC_Test_01(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    char macKey[64];
    UINT mech;
    char data[1024];
    char IV[32];
    char outData[1024];
    char outDataExp[1024];

    bufclr(macKey);
    bufclr(data);
    bufclr(IV);
    bufclr(outData);
    bufclr(outDataExp);

    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(macKey, "A2C0B0F8F7F5EE21FB5C6AEBE714E53A", 32);
    mech = 1;

    memcpy(data, "FB5C6AEBE714E53AA2C0B0F8F7F5EE21", 32);
    memset(IV, '0', 16);
    /* B961 CDDD 0FFA 31DD */
    memcpy(outDataExp, "B961CDDD0FFA31DD", 16);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]encryptKey = %s\n", macKey);
    printf("[IN ]mech       = %d\n", mech);
    printf("[IN ]key        = %s\n", data);
    printf("[IN ]IV         = %s\n", IV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIPBOCMAC(nSock, macKey, mech, data, IV, outData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "X9.19测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[OUT]outData    = %s\n", outData);
    printf("[OUT]outDataExp = %s\n", outDataExp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void PBOCMAC_Test_02(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    char macKey[64];
    UINT mech;
    char data[1024];
    char IV[32];
    char outData[1024];
    char outDataExp[1024];

    bufclr(macKey);
    bufclr(data);
    bufclr(IV);
    bufclr(outData);
    bufclr(outDataExp);

    /* 0123 4567 89AB CDEF */
    memcpy(macKey, "A2C0B0F8F7F5EE21", 16);
    mech = 2;

    memcpy(data, "FB5C6AEBE714E53AA2C0B0F8F7F5EE21", 32);
    memset(IV, '0', 16);
    /* A093 169B ECAE AD38 */
    memcpy(outDataExp, "A093169BECAEAD38", 16);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]encryptKey = %s\n", macKey);
    printf("[IN ]mech       = %d\n", mech);
    printf("[IN ]key        = %s\n", data);
    printf("[IN ]IV         = %s\n", IV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIPBOCMAC(nSock, macKey, mech, data, IV, outData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "X9.9测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[OUT]outData    = %s\n", outData);
    printf("[OUT]outDataExp = %s\n", outDataExp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void PBOCMAC_Test_03(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    char macKey[64];
    UINT mech;
    char data[1024];
    char IV[33];
    char outData[1024];
    char outDataExp[1024];

    bufclr(macKey);
    bufclr(data);
    bufclr(IV);
    bufclr(outData);
    bufclr(outDataExp);

    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(macKey, "A2C0B0F8F7F5EE21FB5C6AEBE714E53A", 32);
    mech = 3;

    memcpy(data, "B8C833FC470446C9C2B694CAF675E3882AED6A93BF279B07E0675269588B", 60);
    memset(IV, '0', 32);
    /* 1C99169517F7E2A8C67C077BFECC8117D0366BF3D7C588907E4C12BE3BF0824D */
    memcpy(outDataExp, "D0366BF3D7C588907E4C12BE3BF0824D", 32);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]encryptKey = %s\n", macKey);
    printf("[IN ]mech       = %d\n", mech);
    printf("[IN ]key        = %s\n", data);
    printf("[IN ]IV         = %s\n", IV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIPBOCMAC(nSock, macKey, mech, data, IV, outData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "PBOC MAC SM4测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[OUT]outData    = %s\n", outData);
    printf("[OUT]outDataExp = %s\n", outDataExp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void PBOCMACIndex_Test_01(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

/////////////////////////////////////////////
    BYTE bKey[32];
    char szCheckValue[16];
    int  masterKeyIndex;
    UINT mech;
    char data[128];
    char IV[32];
    char key[64];
    char outDataTmp[128];
    char outDataExp[128];
    char outData[1024];

    bufclr(bKey);
    bufclr(szCheckValue);
    bufclr(data);
    bufclr(IV);
    bufclr(key);
    bufclr(outDataTmp);
    bufclr(outDataExp);
    bufclr(outData);

    masterKeyIndex = 444;
    mech = 1;
    memset(IV, '0', 16);

    memcpy(data, "\x01\x23\x45\x67\x89\xAB\xF0\x01" \
                 "\xCD\xEF\xFE\xDC\xBA\x98\x0F\x01" \
                 "\x80\x00\x00\x00\x00\x00\x00\x00", 24);
    nRet = SMAPIGenerateKey(nSock, 16, "ZZZZZZZZZZ", 10, \
                            2, masterKeyIndex, bKey, szCheckValue);
    ASSERT_RESULT(nRet, 0, "SMAPIGenerateKey NG");

    nRet = SMAPICalcMac(nSock, 3, bKey, 16, data, 24, outDataTmp);
    ASSERT_RESULT(nRet, 0, "SMAPICalcMac NG");

    SSMHexToChar(outDataTmp, outDataExp, 8);

    SSMHexToChar(data, outDataTmp, 16);
///////////////////////////////

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]index = %d\n", masterKeyIndex);
    printf("[IN ]mech  = %d\n", mech);
    printf("[IN ]data  = %s\n", outDataTmp);
    printf("[IN ]IV    = %s\n", IV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIPBOCMAC_index(nSock, masterKeyIndex, mech, outDataTmp, IV, outData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "X9.9测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    ASSERT_OUT_HEX(outData, outDataExp, 16);
    printf("[OUT]outData    = %s\n", outData);
    printf("[OUT]outDataExp = %s\n", outDataExp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void PBOCMACIndex_Test_02(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

/////////////////////////////////////////////
    BYTE bKey[32];
    char szCheckValue[16];
    int  masterKeyIndex;
    UINT mech;
    char data[128];
    char IV[32];
    char key[64];
    char outDataTmp[128];
    char outDataExp[128];
    char outData[1024];

    bufclr(bKey);
    bufclr(szCheckValue);
    bufclr(data);
    bufclr(IV);
    bufclr(key);
    bufclr(outDataTmp);
    bufclr(outDataExp);
    bufclr(outData);

    masterKeyIndex = 444;
    mech = 2;
    memset(IV, '0', 16);

    memcpy(data, "\x01\x23\x45\x67\x89\xAB\xF0\x01" \
                 "\xCD\xEF\xFE\xDC\xBA\x98\x0F\x01" \
                 "\x80\x00\x00\x00\x00\x00\x00\x00", 24);
    nRet = SMAPIGenerateKey(nSock, 8, "ZZZZZZZZZZ", 10, \
                            2, masterKeyIndex, bKey, szCheckValue);
    ASSERT_RESULT(nRet, 0, "SMAPIGenerateKey NG");
    DspHex("bKey =", bKey, 8);

    nRet = SMAPICalcMac(nSock, 2, bKey, 8, data, 24, outDataTmp);
    ASSERT_RESULT(nRet, 0, "SMAPICalcMac NG");

    SSMHexToChar(outDataTmp, outDataExp, 8);

    SSMHexToChar(data, outDataTmp, 16);
///////////////////////////////

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]index = %d\n", masterKeyIndex);
    printf("[IN ]mech  = %d\n", mech);
    printf("[IN ]data  = %s\n", outDataTmp);
    printf("[IN ]IV    = %s\n", IV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIPBOCMAC_index(nSock, masterKeyIndex, mech, outDataTmp, IV, outData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "X9.19测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    ASSERT_OUT_HEX(outData, outDataExp, 16);
    printf("[OUT]outData    = %s\n", outData);
    printf("[OUT]outDataExp = %s\n", outDataExp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void PBOCMACIndex_Test_03(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

/////////////////////////////////////////////
    BYTE bKey[32];
    char szCheckValue[16];
    int  masterKeyIndex;
    UINT mech;
    char data[128];
    char IV[33];
    char key[64];
    char outDataTmp[128];
    char outDataExp[128];
    char outData[1024];

    bufclr(bKey);
    bufclr(szCheckValue);
    bufclr(data);
    bufclr(IV);
    bufclr(key);
    bufclr(outDataTmp);
    bufclr(outDataExp);
    bufclr(outData);

    masterKeyIndex = 444;
    mech = 3;
    memset(IV, '0', 32);

    memcpy(data, "B8C833FC470446C9C2B694CAF675E3882AED6A93BF279B07E0675269588B", 62);
    nRet = SMAPIGenerateKey(nSock, 16, "ZZZZZZZZZZ", 10, \
                            2, masterKeyIndex, bKey, szCheckValue);
    ASSERT_RESULT(nRet, 0, "SMAPIGenerateKey NG");
DspHexExt("bKey =", bKey, 16);
    SSMHexToChar(bKey, outDataTmp, 16);


    nRet = SMAPIPBOCMAC(nSock, outDataTmp, mech, data, IV, outDataExp);
    ASSERT_RESULT(nRet, 0, "SMAPIPBOCMAC NG");

///////////////////////////////

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]index = %d\n", masterKeyIndex);
    printf("[IN ]mech  = %d\n", mech);
    printf("[IN ]data  = %s\n", data);
    printf("[IN ]IV    = %s\n", IV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIPBOCMAC_index(nSock, masterKeyIndex, mech, data, IV, outData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "PBOC MAC SM4测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    ASSERT_OUT_HEX(outData, outDataExp, 32);
    printf("[OUT]outData    = %s\n", outData);
    printf("[OUT]outDataExp = %s\n", outDataExp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void WrapEnhance_Test_01(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    char wrapKey[64];
    UINT mech;
    char key[1024];
    char IV[32];
    char outData[1024];
    char outDataExp[1024];
    char prePix[64];

    bufclr(wrapKey);
    bufclr(key);
    bufclr(IV);
    bufclr(outData);
    bufclr(outDataExp);
    bufclr(prePix);

    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(wrapKey, "A2C0B0F8F7F5EE21FB5C6AEBE714E53A", 32);
    mech = 20;
    /* FEDC BA98 7654 3210 0123 4567 89AB CDEF */
    memcpy(key, "FB5C6AEBE714E53AA2C0B0F8F7F5EE21", 32);
    memset(IV, '0', 16);
    memcpy(prePix, "0987654321", 10);
    /* 15 0987654321 FEDCBA98765432100123456789ABCDEF 8000*/
    memcpy(outDataExp, "344ECA0E117EE934942211E4290682DBB1092A25993BD5C6", 48);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]encryptKey = %s\n", wrapKey);
    printf("[IN ]mech       = %d\n", mech);
    printf("[IN ]key        = %s\n", key);
    printf("[IN ]IV         = %s\n", IV);
    printf("[IN ]prePix     = %s\n", prePix);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIwrapEnhance(nSock, wrapKey, mech, key, IV, prePix, outData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "ECB测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[OUT]outData    = %s\n", outData);
    printf("[OUT]outDataExp = %s\n", outDataExp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void WrapEnhance_Test_02(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    char wrapKey[64];
    UINT mech;
    char key[1024];
    char IV[32];
    char outData[1024];
    char outDataExp[1024];
    char prePix[64];

    bufclr(wrapKey);
    bufclr(key);
    bufclr(IV);
    bufclr(outData);
    bufclr(outDataExp);
    bufclr(prePix);

    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(wrapKey, "A2C0B0F8F7F5EE21FB5C6AEBE714E53A", 32);
    mech = 17;
    /* FEDC BA98 7654 3210 0123 4567 89AB CDEF */
    memcpy(key, "FB5C6AEBE714E53AA2C0B0F8F7F5EE21", 32);
    memset(IV, '0', 16);
    memcpy(prePix, "0987654321", 10);
    /* 15 0987654321 FEDCBA98765432100123456789ABCDEF 8000*/
    memcpy(outDataExp, "344ECA0E117EE93418A70A2A3F0565B108255AE9DCE945A5", 48);

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]encryptKey = %s\n", wrapKey);
    printf("[IN ]mech       = %d\n", mech);
    printf("[IN ]key        = %s\n", key);
    printf("[IN ]IV         = %s\n", IV);
    printf("[IN ]prePix     = %s\n", prePix);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIwrapEnhance(nSock, wrapKey, mech, key, IV, prePix, outData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "CBC测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[OUT]outData    = %s\n", outData);
    printf("[OUT]outDataExp = %s\n", outDataExp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void WrapEnhanceIndex_Test_01(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

/////////////////////////////////////////////
    BYTE bKey[32];
    char szCheckValue[16];
    int  masterKeyIndex;
    UINT mech;
    char data[128];
    char dataTmp[128];
    char IV[32];
    char key[64];
    char outDataTmp[128];
    char outDataExp[128];
    char outData[1024];
    char prePix[64];

    bufclr(bKey);
    bufclr(szCheckValue);
    bufclr(data);
    bufclr(dataTmp);
    bufclr(IV);
    bufclr(key);
    bufclr(outDataTmp);
    bufclr(outDataExp);
    bufclr(outData);
    bufclr(prePix);

    masterKeyIndex = 444;
    mech = 20;

    memcpy(data, "\x01\x23\x45\x67\x89\xAB\xF1\x01\xCD\xEF\xFE\xDC\xBA\x98\x0E\x01", 16);
    SSMMakeOddBinStr_Test(data, 16);
    nRet = SMAPIEncryptKey(nSock, data, 16, outDataTmp);
    ASSERT_RESULT(nRet, 0, "SMAPIEncryptKey NG");
    SSMHexToChar(outDataTmp, key, 16);
    memset(IV, '0', 16);

    nRet = SMAPIGenerateKey(nSock, 16, "ZZZZZZZZZZ", 10, \
                            2, masterKeyIndex, bKey, szCheckValue);
    ASSERT_RESULT(nRet, 0, "SMAPIGenerateKey NG");
    DspHex("bKey =", bKey, 16);

    memcpy(prePix, "0987654321", 10);

    memcpy(dataTmp, "\x15\x09\x87\x65\x43\x21\x01\x23"
                    "\x45\x67\x89\xAB\xF1\x01\xCD\xEF"
                    "\xFE\xDC\xBA\x98\x0E\x01\x80\x00", 24);
    nRet = SMAPIEncryptData(nSock, 1, 0, masterKeyIndex, dataTmp, 24, outDataTmp);
    ASSERT_RESULT(nRet, 0, "SMAPIEncryptData NG");

    SSMHexToChar(outDataTmp, outDataExp, 24);

///////////////////////////////

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]index = %d\n", masterKeyIndex);
    printf("[IN ]mech  = %d\n", mech);
    printf("[IN ]key   = %s\n", key);
    printf("[IN ]IV    = %s\n", IV);
    printf("[IN ]prePix     = %s\n", prePix);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIwrapEnhance_index(nSock, masterKeyIndex, mech, key, IV, prePix, outData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "ECB测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[OUT]outData    = %s\n", outData);
    printf("[OUT]outDataExp = %s\n", outDataExp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void WrapEnhanceIndex_Test_02(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

/////////////////////////////////////////////
    BYTE bKey[32];
    char szCheckValue[16];
    int  masterKeyIndex;
    UINT mech;
    char data[128];
    char dataTmp[128];
    char IV[32];
    char key[64];
    char outDataTmp[128];
    char outDataExp[128];
    char outData[1024];
    char prePix[64];

    bufclr(bKey);
    bufclr(szCheckValue);
    bufclr(data);
    bufclr(dataTmp);
    bufclr(IV);
    bufclr(key);
    bufclr(outDataTmp);
    bufclr(outDataExp);
    bufclr(outData);
    bufclr(prePix);

    masterKeyIndex = 444;
    mech = 17;

    memcpy(data, "\x01\x23\x45\x67\x89\xAB\xF1\x01\xCD\xEF\xFE\xDC\xBA\x98\x0E\x01", 16);
    SSMMakeOddBinStr_Test(data, 16);
    nRet = SMAPIEncryptKey(nSock, data, 16, outDataTmp);
    ASSERT_RESULT(nRet, 0, "SMAPIEncryptKey NG");
    SSMHexToChar(outDataTmp, key, 16);
    memset(IV, '0', 16);

    nRet = SMAPIGenerateKey(nSock, 16, "ZZZZZZZZZZ", 10, \
                            2, masterKeyIndex, bKey, szCheckValue);
    ASSERT_RESULT(nRet, 0, "SMAPIGenerateKey NG");
    DspHex("bKey =", bKey, 16);

    memcpy(prePix, "0987654321", 10);

    memcpy(dataTmp, "\x15\x09\x87\x65\x43\x21\x01\x23"
                    "\x45\x67\x89\xAB\xF1\x01\xCD\xEF"
                    "\xFE\xDC\xBA\x98\x0E\x01\x80\x00", 24);
    nRet = SMAPIEncryptData(nSock, 1, 1, masterKeyIndex, dataTmp, 24, outDataTmp);
    ASSERT_RESULT(nRet, 0, "SMAPIEncryptData NG");

    SSMHexToChar(outDataTmp, outDataExp, 24);

///////////////////////////////

    XXX_INPUT_XXX
    printf("[IN ]nSock = %d\n", nSock);
    printf("[IN ]index = %d\n", masterKeyIndex);
    printf("[IN ]mech  = %d\n", mech);
    printf("[IN ]key   = %s\n", key);
    printf("[IN ]IV    = %s\n", IV);
    printf("[IN ]prePix     = %s\n", prePix);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIwrapEnhance_index(nSock, masterKeyIndex, mech, key, IV, prePix, outData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "ECB测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[OUT]outData    = %s\n", outData);
    printf("[OUT]outDataExp = %s\n", outDataExp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void WrapExt_Test_01(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    char wrapKey[64];
    UINT mech;
    char keyMac[128];
    char keyEnc[128];
    char keyDek[128];
    char keyTmp[256];
    char IV[32];
    char outData[1024];
    char outDataExp[1024];
    char KeyHeader[64];

    bufclr(wrapKey);
    bufclr(keyMac);
    bufclr(keyEnc);
    bufclr(keyDek);
    bufclr(keyTmp);
    bufclr(IV);
    bufclr(outData);
    bufclr(outDataExp);
    bufclr(KeyHeader);

    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(wrapKey, "A2C0B0F8F7F5EE21FB5C6AEBE714E53A", 32);
    mech = 20;
    /* FEDC BA98 7654 3210 0123 4567 89AB CDEF */
    /* 88F7 8BB7 9D61 436D 9C05 0C92 E6A8 E031 */
    /* 89F7 8AB6 9D61 436D 9D04 0D92 E6A8 E031 */
    memcpy(keyMac, "753BCB191136C1489875E273DC3447C9", 32);
    /* CE37 5619 0B2C 9548 9A16 69DA 6B2C 8928 */
    /* CE37 5719 0B2C 9449 9B16 68DA 6B2C 8929 */
    memcpy(keyEnc, "6A6014F8C0E94945866FAE94B6547E33", 32);
    /* 51F5 367B 7286 C9BA 847E 5C6A B3D4 87FB */
    /* 51F4 377A 7386 C8BA 857F 5D6B B3D5 86FB */
    memcpy(keyDek, "0B0879A346D705AB1C530B5EE7BB0446", 32);
    memcpy(keyTmp, "1634EAD5E5CB1F9E836D38233E51EFE3", 32);
    memset(IV, '0', 16);
    memcpy(KeyHeader, "0987654321", 10);
    /* 15 0987654321 1634EAD5E5CB1F9E836D38233E51EFE3 8000*/
    memcpy(outDataExp, "8FBEDB484785F53E66C9E4BDB324F7711EB98E4BBFD2B1DA", 48);

    XXX_INPUT_XXX
    printf("[IN ]nSock     = %d\n", nSock);
    printf("[IN ]keyMac    = %s\n", keyMac);
    printf("[IN ]keyEnc    = %s\n", keyEnc);
    printf("[IN ]keyDek    = %s\n", keyDek);
    printf("[IN ]KeyHeader = %s\n", KeyHeader);
    printf("[IN ]wrapKey   = %s\n", wrapKey);
    printf("[IN ]mech      = %d\n", mech);
    printf("[IN ]IV        = %s\n", IV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIwrap_ext(nSock, keyMac, keyEnc, keyDek, KeyHeader, wrapKey, mech, IV, outData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "ECB测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[OUT]outData    = %s\n", outData);
    printf("[OUT]outDataExp = %s\n", outDataExp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void WrapExt_Test_02(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

    char wrapKey[64];
    UINT mech;
    char keyMac[128];
    char keyEnc[128];
    char keyDek[128];
    char keyTmp[256];
    char IV[32];
    char outData[1024];
    char outDataExp[1024];
    char KeyHeader[64];

    bufclr(wrapKey);
    bufclr(keyMac);
    bufclr(keyEnc);
    bufclr(keyDek);
    bufclr(keyTmp);
    bufclr(IV);
    bufclr(outData);
    bufclr(outDataExp);
    bufclr(KeyHeader);

    /* 0123 4567 89AB CDEF FEDC BA98 7654 3210 */
    memcpy(wrapKey, "A2C0B0F8F7F5EE21FB5C6AEBE714E53A", 32);
    mech = 17;
    /* FEDC BA98 7654 3210 0123 4567 89AB CDEF */
    /* 88F7 8BB7 9D61 436D 9C05 0C92 E6A8 E031 */
    /* 89F7 8AB6 9D61 436D 9D04 0D92 E6A8 E031 */
    memcpy(keyMac, "753BCB191136C1489875E273DC3447C9", 32);
    /* CE37 5619 0B2C 9548 9A16 69DA 6B2C 8928 */
    /* CE37 5719 0B2C 9449 9B16 68DA 6B2C 8929 */
    memcpy(keyEnc, "6A6014F8C0E94945866FAE94B6547E33", 32);
    /* 51F5 367B 7286 C9BA 847E 5C6A B3D4 87FB */
    /* 51F4 377A 7386 C8BA 857F 5D6B B3D5 86FB */
    memcpy(keyDek, "0B0879A346D705AB1C530B5EE7BB0446", 32);
    memcpy(keyTmp, "1634EAD5E5CB1F9E836D38233E51EFE3", 32);
    memset(IV, '0', 16);
    memcpy(KeyHeader, "0987654321", 10);
    /* 15 0987654321 1634EAD5E5CB1F9E836D38233E51EFE3 8000*/
    memcpy(outDataExp, "8FBEDB484785F53E63D723446F42EC156F645A073E917568", 48);

    XXX_INPUT_XXX
    printf("[IN ]nSock     = %d\n", nSock);
    printf("[IN ]keyMac    = %s\n", keyMac);
    printf("[IN ]keyEnc    = %s\n", keyEnc);
    printf("[IN ]keyDek    = %s\n", keyDek);
    printf("[IN ]KeyHeader = %s\n", KeyHeader);
    printf("[IN ]wrapKey   = %s\n", wrapKey);
    printf("[IN ]mech      = %d\n", mech);
    printf("[IN ]IV        = %s\n", IV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIwrap_ext(nSock, keyMac, keyEnc, keyDek, KeyHeader, wrapKey, mech, IV, outData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "CBC测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[OUT]outData    = %s\n", outData);
    printf("[OUT]outDataExp = %s\n", outDataExp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void WrapExtIndex_Test_01(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

/////////////////////////////////////////////
    BYTE bKey[32];
    char szCheckValue[16];
    int  masterKeyIndex;
    UINT mech;
    char data[128];
    char dataTmp[128];
    char IV[32];
    char keyMac[64];
    char keyEnc[64];
    char keyDek[64];
    char outDataTmp[128];
    char outDataExp[128];
    char outData[1024];
    char KeyHeader[64];

    bufclr(bKey);
    bufclr(szCheckValue);
    bufclr(data);
    bufclr(dataTmp);
    bufclr(IV);
    bufclr(keyMac);
    bufclr(keyEnc);
    bufclr(keyDek);
    bufclr(outDataTmp);
    bufclr(outDataExp);
    bufclr(outData);
    bufclr(KeyHeader);

    masterKeyIndex = 444;
    mech = 20;

    /* FEDC BA98 7654 3210 0123 4567 89AB CDEF */
    /* 88F7 8BB7 9D61 436D 9C05 0C92 E6A8 E031 */
    /* 89F7 8AB6 9D61 436D 9D04 0D92 E6A8 E031 */
    memcpy(keyMac, "753BCB191136C1489875E273DC3447C9", 32);
    /* CE37 5619 0B2C 9548 9A16 69DA 6B2C 8928 */
    /* CE37 5719 0B2C 9449 9B16 68DA 6B2C 8929 */
    memcpy(keyEnc, "6A6014F8C0E94945866FAE94B6547E33", 32);
    /* 51F5 367B 7286 C9BA 847E 5C6A B3D4 87FB */
    /* 51F4 377A 7386 C8BA 857F 5D6B B3D5 86FB */
    memcpy(keyDek, "0B0879A346D705AB1C530B5EE7BB0446", 32);

    nRet = SMAPIGenerateKey(nSock, 16, "ZZZZZZZZZZ", 10, \
                            2, masterKeyIndex, bKey, szCheckValue);
    ASSERT_RESULT(nRet, 0, "SMAPIGenerateKey NG");

    memcpy(KeyHeader, "0987654321", 10);

    /* 15 0987654321 1634EAD5E5CB1F9E836D38233E51EFE3 8000*/
    memcpy(dataTmp, "\x15\x09\x87\x65\x43\x21\x16\x34"
                    "\xEA\xD5\xE5\xCB\x1F\x9E\x83\x6D"
                    "\x38\x23\x3E\x51\xEF\xE3\x80\x00", 24);
    nRet = SMAPIEncryptData(nSock, 1, 0, masterKeyIndex, dataTmp, 24, outDataTmp);
    ASSERT_RESULT(nRet, 0, "SMAPIEncryptData NG");

    SSMHexToChar(outDataTmp, outDataExp, 24);

    memset(IV, '0', 16);
///////////////////////////////

    XXX_INPUT_XXX
    printf("[IN ]nSock     = %d\n", nSock);
    printf("[IN ]index     = %d\n", masterKeyIndex);
    printf("[IN ]mech      = %d\n", mech);
    printf("[IN ]keyMac    = %s\n", keyMac);
    printf("[IN ]keyEnc    = %s\n", keyEnc);
    printf("[IN ]keyDek    = %s\n", keyDek);
    printf("[IN ]KeyHeader = %s\n", KeyHeader);
    printf("[IN ]IV        = %s\n", IV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIwrap_ext_index(nSock, keyMac, keyEnc, keyDek, KeyHeader, masterKeyIndex, mech, IV, outData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "ECB测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[OUT]outData    = %s\n", outData);
    printf("[OUT]outDataExp = %s\n", outDataExp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void WrapExtIndex_Test_02(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

/////////////////////////////////////////////
    BYTE bKey[32];
    char szCheckValue[16];
    int  masterKeyIndex;
    UINT mech;
    char data[128];
    char dataTmp[128];
    char IV[32];
    char keyMac[64];
    char keyEnc[64];
    char keyDek[64];
    char outDataTmp[128];
    char outDataExp[128];
    char outData[1024];
    char KeyHeader[64];

    bufclr(bKey);
    bufclr(szCheckValue);
    bufclr(data);
    bufclr(dataTmp);
    bufclr(IV);
    bufclr(keyMac);
    bufclr(keyEnc);
    bufclr(keyDek);
    bufclr(outDataTmp);
    bufclr(outDataExp);
    bufclr(outData);
    bufclr(KeyHeader);

    masterKeyIndex = 444;
    mech = 17;

    /* FEDC BA98 7654 3210 0123 4567 89AB CDEF */
    /* 88F7 8BB7 9D61 436D 9C05 0C92 E6A8 E031 */
    /* 89F7 8AB6 9D61 436D 9D04 0D92 E6A8 E031 */
    memcpy(keyMac, "753BCB191136C1489875E273DC3447C9", 32);
    /* CE37 5619 0B2C 9548 9A16 69DA 6B2C 8928 */
    /* CE37 5719 0B2C 9449 9B16 68DA 6B2C 8929 */
    memcpy(keyEnc, "6A6014F8C0E94945866FAE94B6547E33", 32);
    /* 51F5 367B 7286 C9BA 847E 5C6A B3D4 87FB */
    /* 51F4 377A 7386 C8BA 857F 5D6B B3D5 86FB */
    memcpy(keyDek, "0B0879A346D705AB1C530B5EE7BB0446", 32);

    nRet = SMAPIGenerateKey(nSock, 16, "ZZZZZZZZZZ", 10, \
                            2, masterKeyIndex, bKey, szCheckValue);
    ASSERT_RESULT(nRet, 0, "SMAPIGenerateKey NG");

    memcpy(KeyHeader, "0987654321", 10);

    /* 15 0987654321 1634EAD5E5CB1F9E836D38233E51EFE3 8000*/
    memcpy(dataTmp, "\x15\x09\x87\x65\x43\x21\x16\x34"
                    "\xEA\xD5\xE5\xCB\x1F\x9E\x83\x6D"
                    "\x38\x23\x3E\x51\xEF\xE3\x80\x00", 24);
    nRet = SMAPIEncryptData(nSock, 1, 1, masterKeyIndex, dataTmp, 24, outDataTmp);
    ASSERT_RESULT(nRet, 0, "SMAPIEncryptData NG");

    SSMHexToChar(outDataTmp, outDataExp, 24);

    memset(IV, '0', 16);
///////////////////////////////

    XXX_INPUT_XXX
    printf("[IN ]nSock     = %d\n", nSock);
    printf("[IN ]index     = %d\n", masterKeyIndex);
    printf("[IN ]mech      = %d\n", mech);
    printf("[IN ]keyMac    = %s\n", keyMac);
    printf("[IN ]keyEnc    = %s\n", keyEnc);
    printf("[IN ]keyDek    = %s\n", keyDek);
    printf("[IN ]KeyHeader = %s\n", KeyHeader);
    printf("[IN ]IV        = %s\n", IV);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    nRet = SMAPIwrap_ext_index(nSock, keyMac, keyEnc, keyDek, KeyHeader, masterKeyIndex, mech, IV, outData);
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "CBC测试未成功");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    printf("[OUT]outData    = %s\n", outData);
    printf("[OUT]outDataExp = %s\n", outDataExp);
    XXX_OUTPUT_XXX

    XXX_TEST_END_XXX
}

void TestFuncTemplate(void)
{
    XXX_TEST_START_XXX
    int  nRet;
    int  nSock = SM_SOCK;

/*▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼*/
    XXX_CASE_XXX(1)

    XXX_INPUT_XXX
    XXX_INPUT_NONE_XXX
    printf("[IN ]nSock = %d\n", nSock);
    XXX_INPUT_XXX

    /* Call Test Target Function Start */
    /* Call Test Target Function End */

    XXX_RESULT_XXX
    ASSERT_RESULT(nRet, 0, "");
    XXX_RESULT_XXX

    XXX_OUTPUT_XXX
    XXX_OUTPUT_NONE_XXX
    printf("[OUT]\n");
    XXX_OUTPUT_XXX
/*▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲*/

    XXX_TEST_END_XXX
}

/*
 *  <<LEVEL Premise>>
 */
TESTFUNC TestFunc_P[] =
{
    ConnectSM_Test_01,
    DisconnectSM_Test_01,
    NULL
};

/*
 *  <<LEVEL Basic>>
 */
TESTFUNC TestFunc_B[] =
{
    ConnectSM_Test_01,
	GenBigPrime_Test_01,
	GenBigPrime_Test_02,
	GenBigPrime_Test_03,
/*
    DisreteSubKey_Test_01,
    DisreteSubKey_Test_02,
    DisreteSubKey_Test_03,
    DisreteSubKey_Test_04,
    DisreteSubKey_Test_22,
    DisreteSubKey_Test_25,
    DisreteSubKey_Test_27,
    DisreteSubKey_Test_28,
*/
/*
    GenBigPrime_Test_01,
    GenBigPrime_Test_02,
    GenBigPrime_Test_03,
*/
/*
    VerifyARQC_Test_01,
    VerifyARQC_Test_02,
    VerifyARQC_Test_03,
    VerifyARQC_Test_04,
    VerifyARQC_Test_05,

    CalcARPC_Test_01,
    CalcARPC_Test_02,
    CalcARPC_Test_03,
    CalcARPC_Test_04,
    CalcARPC_Test_05,
*/
/*
    EncryptWithDerivedKey_Test_01,
    EncryptWithDerivedKey_Test_02,
    EncryptWithDerivedKey_Test_03,
    EncryptWithDerivedKey_Test_04,
    EncryptWithDerivedKey_Test_19,
    EncryptWithDerivedKey_Test_20,
    EncryptWithDerivedKey_Test_23,
    EncryptWithDerivedKey_Test_24,

    CalcMacWithDerivedKey_Test_01,
    CalcMacWithDerivedKey_Test_02,
    CalcMacWithDerivedKey_Test_07,
    CalcMacWithDerivedKey_Test_08,
    CalcMacWithDerivedKey_Test_09,
*/
/*
    GenEccKey_Test_01,
    
    GetEccPkBySk_Test_01,
    
    EccPkEncrypt_Test_01,

    EccSkDecrypt_Test_01,

    EccSign_Test_01,

    EccVerify_Test_01,
    
    Sm4Calc_Test_01,
    Sm4Calc_Test_02,
    Sm4Calc_Test_03,
    Sm4Calc_Test_04,

    Sm2PKTransOutof_Test_01,

    Sm2SKTransInto_Test_01,
    
    TransKeyDesToSm4_Test_02,
    
    TransKeySm4ToDes_Test_02,
    
    TransKeyIntoSK_Test_02,
    TransKeyIntoSK_Test_03,
*/
    DisconnectSM_Test_01,
    NULL
};

/*
 *  <<LEVEL G>>
 */
TESTFUNC TestFunc_G[] =
{
    ConnectSM_Test_01,
/*
    DisreteSubKey_Test_05,
    DisreteSubKey_Test_06,
    DisreteSubKey_Test_07,
    DisreteSubKey_Test_08,
    DisreteSubKey_Test_17,
    DisreteSubKey_Test_18,
    DisreteSubKey_Test_19,
    DisreteSubKey_Test_20,
    DisreteSubKey_Test_21,
    DisreteSubKey_Test_23,
    DisreteSubKey_Test_24,
    DisreteSubKey_Test_26,
*/
/*
    EncryptWithDerivedKey_Test_05,
    EncryptWithDerivedKey_Test_06,
    EncryptWithDerivedKey_Test_07,
    EncryptWithDerivedKey_Test_08,
    EncryptWithDerivedKey_Test_17,
    EncryptWithDerivedKey_Test_18,
    EncryptWithDerivedKey_Test_21,
    EncryptWithDerivedKey_Test_22,
    EncryptWithDerivedKey_Test_25,
    EncryptWithDerivedKey_Test_26,
*/
/*
    GenEccKey_Test_02,
    GenEccKey_Test_03,
    
    GetEccPkBySk_Test_06,
    GetEccPkBySk_Test_07,
    GetEccPkBySk_Test_08,

    EccPkEncrypt_Test_02,

    EccSkDecrypt_Test_02,
*/
    TransKeyDesToSm4_Test_01,
    TransKeyDesToSm4_Test_03,
    
    TransKeySm4ToDes_Test_01,
    TransKeySm4ToDes_Test_03,
    
    TransKeyIntoSK_Test_01,
    TransKeyIntoSK_Test_04,
    TransKeyIntoSK_Test_05,
    TransKeyIntoSK_Test_06,

/*
    DecryptEncrypt_Test_01,
    DecryptEncrypt_Test_02,
    DecryptEncrypt_Test_03,
    DecryptEncrypt_Test_04,
*/
/*
    DecryptEncrypt_Test_05,
    DecryptEncrypt_Test_06,
    DecryptEncrypt_Test_07,
    DecryptEncrypt_Test_08,

    Encrypt_Test_01,
    Encrypt_Test_02,
    Encrypt_Test_03,
    Encrypt_Test_04,

    EncryptIndex_Test_01,
    EncryptIndex_Test_02,
    EncryptIndex_Test_03,
    EncryptIndex_Test_04,

    Decrypt_Test_01,
    Decrypt_Test_02,
    Decrypt_Test_03,
    Decrypt_Test_04,

    DecryptIndex_Test_01,
    DecryptIndex_Test_02,
    DecryptIndex_Test_03,
    DecryptIndex_Test_04,

    DeriveKey_Test_01,
    DeriveKey_Test_02,
    DeriveKey_Test_03,
    DeriveKey_Test_04,

    DeriveKeyIndex_Test_01,
    DeriveKeyIndex_Test_02,
    DeriveKeyIndex_Test_03,
    DeriveKeyIndex_Test_04,
*/
/*
    GenerateRandom_Test_01,

    Wrap_Test_01,
    Wrap_Test_02,

    WrapIndex_Test_01,
    WrapIndex_Test_02,
    
    PBOCMAC_Test_01,
    PBOCMAC_Test_02,
    PBOCMAC_Test_03,
    
    PBOCMACIndex_Test_01,
    PBOCMACIndex_Test_02,
    PBOCMACIndex_Test_03,

    WrapEnhance_Test_01,
    WrapEnhance_Test_02,
    
    WrapEnhanceIndex_Test_01,
    WrapEnhanceIndex_Test_02,
    
    WrapExt_Test_01,
    WrapExt_Test_02,
    
    WrapExtIndex_Test_01,
    WrapExtIndex_Test_02,
*/
    DisconnectSM_Test_01,
    NULL
};

/*
 *  <<LEVEL Error>>
 */
TESTFUNC TestFunc_E[] =
{
    ConnectSM_Test_01,
/*
    DisreteSubKey_Test_09,
    DisreteSubKey_Test_10,
    DisreteSubKey_Test_11,
    DisreteSubKey_Test_12,
    DisreteSubKey_Test_13,
    DisreteSubKey_Test_14,
    DisreteSubKey_Test_15,
    DisreteSubKey_Test_16,
*/
/*
    VerifyARQC_Test_06,
    VerifyARQC_Test_07,
    VerifyARQC_Test_08,
    VerifyARQC_Test_09,
    VerifyARQC_Test_10,
*/
/*
    EncryptWithDerivedKey_Test_09,
    EncryptWithDerivedKey_Test_10,
    EncryptWithDerivedKey_Test_11,
    EncryptWithDerivedKey_Test_12,
    EncryptWithDerivedKey_Test_13,
    EncryptWithDerivedKey_Test_14,
    EncryptWithDerivedKey_Test_15,
    EncryptWithDerivedKey_Test_16,

    CalcMacWithDerivedKey_Test_03,
    CalcMacWithDerivedKey_Test_04,
    CalcMacWithDerivedKey_Test_05,
    CalcMacWithDerivedKey_Test_06,
*/

    GenEccKey_Test_04,

    GetEccPkBySk_Test_02,
    GetEccPkBySk_Test_03,
    GetEccPkBySk_Test_04,
    GetEccPkBySk_Test_05,
    
    EccPkEncrypt_Test_03,
    
    EccSkDecrypt_Test_03,
    
    EccSign_Test_02,

    EccVerify_Test_02,
    EccVerify_Test_03,

    Sm4Calc_Test_05,
    Sm4Calc_Test_06,
    
    TransKeyDesToSm4_Test_04,
    
    TransKeySm4ToDes_Test_04,

    DisconnectSM_Test_01,
    NULL
};

void finish(int sig)
{
    iscontinue = 0;
    fprintf(stdout, "SYSTEM SIGNAL = %d \n", sig);
    fflush(stdout);
}

#define TEST_CYCLE(c, f, s) \
    { \
        c = 0; \
        while(iscontinue) \
        { \
            f = s[c++]; \
            if(f == NULL) break; \
            f(); \
        } \
    }

RESULT main(int argc, char **argv)
{
TIMEDECLEAR
    TESTFUNC pFunc = NULL;
    unsigned int seed = (unsigned int)getpid();
    int cnt = 0;
    
    iscontinue = 1;

    signal(SIGPIPE, finish);
    signal(SIGINT, finish);
    signal(SIGQUIT, finish);
    signal(SIGTERM, finish);
    
    TEST_CYCLE(cnt, pFunc, TestFunc_P)

    TEST_CYCLE(cnt, pFunc, TestFunc_B)

    TEST_CYCLE(cnt, pFunc, TestFunc_E)

    TEST_CYCLE(cnt, pFunc, TestFunc_G)

//TIMESTART

//    ConnectSM_Test_01();

//TIMEEND("connect")

    /*********** SP Test ***********/
/*    ConnectSM_Test_01();

sleep(4);

TIMESTART
    CalcMacWithDerivedKey_Test_08();
TIMEEND("process")
//    CalcMacWithDerivedKey_Test_09();

   	DisconnectSM_Test_01();
*/
    /*********** SP Test ***********/

    return NORMAL;
}



/* End of this file */

