#ifndef __SOCK_PUB_H__
#define __SOCK_PUB_H__

#define HSM_MAX_BUFFER_SIZE       1024*64

#define SOCK_ERR_SOCK_HANDLE      0x21
#define SOCK_ERR_SOCKET           0x22
#define SOCK_ERR_BIND             0x23
#define SOCK_ERR_LISTEN           0x24
#define SOCK_ERR_CONNECT          0x25
#define SOCK_ERR_SELECT           0x26
#define SOCK_ERR_SEND             0x27
#define SOCK_ERR_RECV             0x28
#define SOCK_ERR_SETSOCKOPT       0x29
#define SOCK_ERR_FCNTL            0x2A
#define SOCK_ERR_IOCTL            0x2B

#define SOCK_ERR_INPUT_DATA_NULL  0x31
#define SOCK_ERR_DATA_LEN         0x32
#define SOCK_ERR_DATA_NULL        0x34
#define SOCK_ERR_TIMEOUT          0x33
#define SOCK_ERR_MSGHEADLEN       0x34
#define SOCK_ERR_TOOSHORT         0x35
#define SOCK_ERR_TOOLONG          0x36


/***************************************************************/
/*                 Socket public routines                      */
/***************************************************************/

extern int PSocketCreate(char *chrIP, unsigned short chrPort, int *nSockfd);

extern int PSocketConnect(unsigned long nAdderss, unsigned short nPort, int nTimeout, int *nSockfd);

extern int PSocketSendData(int nSockfd, int pkgheadlen, unsigned char *pData, int nBufLen, int nTimeout);

extern int PSocketRecvData(int nSockfd, int nPkgHeadLen, unsigned char *pszRecvBuf, int nTimeOut);

extern int PSocketRelease(int nSockfd);

#endif /* end __SOCK_PUB_H__ */

