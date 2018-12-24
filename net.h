#ifndef _NETNET_H_
#define _NETNET_H_ 1

#ifdef __cplusplus
extern "C"{
#endif


#if defined(WIN32) || defined(WIN64)
#define SAF_EXPORT extern __declspec(dllexport)
#else
#define SAF_EXPORT
#endif

#if defined(WIN32) || defined(WIN64)
#define CloseSocket(fd) do{ shutdown(fd, 2); closesocket(fd); }while(0)
#else
#define CloseSocket(fd) do{ shutdown(fd,2); close(fd); }while(0)
#endif 

#define SO_SNDBUF_SIZE (20480)
#define SO_RCVBUF_SIZE (20480)

#define MAX_BUFFER_SIZE_EX      (33*1024)
#define MAX_BUFFER_SIZE         8128
#define MESSAGE_HEADER_LEN	0    //0字节

/*数据类型定义*/
typedef unsigned char  byte;
typedef unsigned int   UINT;

/*错误码定义*/
#define SDR_OK           0              /*成功*/
#define SDR_PARAMETERS   5		/*参数错误*/
#define SWR_SOCKET_SEND  2		/*发送数据错误*/
#define SDR_TIMEOUT      3		/*超时*/
#define SWR_SOCKET_RECV  4		/*接收数据错误*/
#define SDR_UNKNOWERR    35		/*其他错误*/
#define SWR_CONNECT_ERR  1              /*连接错误*/

UINT CheckServer(char *sServerAddr, UINT nPort, UINT unTimeout);
UINT SocketCommunication_Racal(UINT nSock, byte *pbReqParas,UINT unReqParasLen,byte *pbResParas,UINT *punResParasLen,UINT unTimeout);

SAF_EXPORT int SMAPIConnectSM(char  *pszAddr,  UINT nPort, UINT nTimeout, UINT *pnSock,  char  szDeviceInfo[100]);
SAF_EXPORT int SMAPIDisconnectSM (UINT  nSock);

SAF_EXPORT int SMAPIEncryptData (UINT nSock, int nEncrypt, int nMode, int nIndex, byte *bIndata, int nDatalen, byte *bOutdata);
SAF_EXPORT int SMAPIEncrypt(UINT  nSock ,char * encryptKey, UINT mech, char *data, char *IV , char *outData);
SAF_EXPORT int SMAPIEncrypt_index(UINT  nSock ,int encryptKeyIndex, UINT mech, char *data, char *IV, char *outData);
SAF_EXPORT int SMAPIDecrypt(UINT  nSock ,char * DecryptKey, UINT mech, char *data, char *IV,char *outData);
SAF_EXPORT int SMAPIDecrypt_index(UINT  nSock ,int DecryptKeyIndex, UINT mech, char *data, char *IV , char *outData);
SAF_EXPORT int SMAPIGenerateRandom(UINT  nSock, int rdmLength,char * outData);
SAF_EXPORT int SMAPIPBOCMAC(UINT  nSock , char *MACKey, UINT mech,char *data,char *IV, char * Mac);
SAF_EXPORT int SMAPIPBOCMAC_index(UINT  nSock , int MACKeyIndex, UINT mech,char *data, char *IV,  char * Mac);
SAF_EXPORT int SMAPIderiveKey(UINT  nSock, char *masterKey, UINT mech, char *divdata, char *IV , char *derivedKey);
SAF_EXPORT int SMAPIderiveKey_index(UINT  nSock,int masterKeyIndex, UINT mech, char *data, char *IV ,char *derivedKey);
SAF_EXPORT int SMAPIwrap(UINT  nSock ,char * wrapKey, UINT mech, char *key, char *IV , char *outData);
SAF_EXPORT int SMAPIwrap_index (UINT  nSock , int wrapKeyIndex, UINT mech, char *key, char *IV , char *outData);
SAF_EXPORT int SMAPIwrap_ext (UINT  nSock , char  *KeyMac, char  * KeyEnc, char  *KeyDek , char  *KeyHeader,char  *wrapKey, UINT mech,  char *IV , char *outData);
SAF_EXPORT int SMAPIwrap_ext_index (UINT  nSock , char  *KeyMac, char  * KeyEnc, char  *KeyDek , char  *KeyHeader,UINT  wrapKeyIndex, UINT mech,  char *IV , char *outData);
SAF_EXPORT int SMAPIwrapEnhance(UINT  nSock ,char * wrapKey, UINT mech, char *key, char *IV, char *prePix , char *outData);
SAF_EXPORT int SMAPIwrapEnhance_index (UINT  nSock ,int wrapKeyIndex, UINT mech, char *key, char *IV, char *prePix ,  char *outData);
SAF_EXPORT int SMAPIEncryptKeyExt (UINT  nSock,char  *pszKeyMac, char  * pszKeyEnc, char  *pszKeyDek , char  *pszKeyUnderLMK);
SAF_EXPORT int SMAPIImportKey(UINT nSock, int nKekIndex, byte *bKeyByKek, int nKeyLen, char szCheckValue[8 + 1],  int nDestIndex);
SAF_EXPORT int SMAPIExportKey(UINT nSock, int nIndex, byte *bKeyByHMK, int *pnKeyLen, char szCheckValue[8 + 1]);
SAF_EXPORT int SMAPIDecryptEncrypt(UINT nSock , int decryptKeyIndex, UINT decryptMech, char  *encryptKey, UINT encryptMech, char *data, char *decryptIV, char *encryptIV, char *outData);
SAF_EXPORT int SMAPIExportKey_GM(UINT nSock, int nIndex,byte *bKeyByHMK, int *pnKeyLen, char szCheckValue[8 + 1]);
SAF_EXPORT int SMAPIDisreteSubKeyExt1(UINT nSock, byte *pbMasterKey, byte *pbFactor, byte *pbSubKey, char pszCheckValue[8 + 1]);
SAF_EXPORT int SMAPIDisreteSubKeyExt2(UINT nSock, byte *pbKek, byte *pbMasterKey, byte *pbFactor, byte *pbSubKey, char pszCheckValue[8 + 1]);
SAF_EXPORT int SMAPIConvertPinX98B_DoublePan(UINT nSock, int nMode, char *pszSrcPan, int nSrcPanLen, char *pszDstPan, int nDstPanLen, byte *pbSrcPinKey, int nSrcPinKeyLen, byte *pbDestPinKey, int nDestPinKeyLen, byte *pszSrcPinCipher, byte pbDes1tPinCipher[16]);
SAF_EXPORT int SMAPIConvertPinX98ToIBM3624(UINT nSock, int nMode, int nX98Algo, char *pszSrcPan, int nSrcPanLen, char *pszDstPan, int nDstPanLen, byte *pbPinKey, int nPinKeyLen, byte *pbIBM3624Key, int nIBM3624KeyLen, byte *pszSrcPinCipher, char pbDestPinCipher[13]);
SAF_EXPORT int SMAPIEncryptKey_LMK (UINT nSock, char *pszPlainKey,char *pszKeyUnderLMK);
#ifdef __cplusplus
}
#endif

#endif
