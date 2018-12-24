#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/shm.h>
#include <sys/sem.h>
#include <time.h>
#ifndef LINUX
#include <sys/wait.h>
#endif
#include <sys/time.h>

#include <errno.h>


#include "sockpub.h"
#include "type.h"


/***************************************************************/
/*                 Socket public routines                      */
/***************************************************************/

int SetServerSockOpt(int sockfd)
{
    int bReuseaddr = 1;
    struct linger LingerVar;

    /* no time wait */
    LingerVar.l_onoff = 1;
    LingerVar.l_linger = 0; /* SO_DONTLINGER */

    if (setsockopt(sockfd, SOL_SOCKET, SO_LINGER, (const char *)&LingerVar, sizeof(LingerVar)) != 0)
        return SOCK_ERR_SETSOCKOPT;


    /* no time wait  */
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&bReuseaddr, sizeof(int)))
        return SOCK_ERR_SETSOCKOPT;


    return 0;
}


int SetClientSockOpt(int sockfd)
{
    struct linger LingerVar;
#if 1
	int rcvBufSize;


	rcvBufSize = 8192 * 2;
	if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvBufSize, sizeof(int)) != 0){
		return SOCK_ERR_SETSOCKOPT;
	}
#endif

    /* no time wait */
    LingerVar.l_onoff = 1;
    LingerVar.l_linger = 0; /* SO_DONTLINGER */

    if (setsockopt(sockfd, SOL_SOCKET, SO_LINGER, (const char *)&LingerVar, sizeof(LingerVar)) != 0)
    {
        return SOCK_ERR_SETSOCKOPT;
    }

    return 0;
}


int PSocketCreate(char *chrIP, unsigned short chrPort, int *sockfd)
{
    int sHandle = -1;
    struct sockaddr_in my_addr;
    int nRet;

    sHandle = socket(AF_INET, SOCK_STREAM, 0);

    if (sHandle <= 0)
    {
        perror("socket");
        return SOCK_ERR_SOCKET;
    }

    memset((char *)&my_addr, 0, sizeof(my_addr));

    my_addr.sin_family = AF_INET;

    if (chrIP == NULL)
        my_addr.sin_addr.s_addr = INADDR_ANY;
    else
        my_addr.sin_addr.s_addr = inet_addr(chrIP);

    my_addr.sin_port = htons(chrPort);

    if (bind(sHandle, (struct sockaddr *)&my_addr, sizeof(struct sockaddr)))
    {

        perror("bind");
        close(sHandle);

        return SOCK_ERR_BIND;
    }

    if (listen(sHandle, SOMAXCONN))
    {

        perror("listen");
        close(sHandle);

        return SOCK_ERR_LISTEN;
    }

    *sockfd = sHandle;

    nRet = SetServerSockOpt(sHandle);
    if (nRet)
    {
        close(sHandle);

        return nRet;
    }

    return 0;
}


/* connect server */
int PSocketConnect(unsigned long nAdderss, unsigned short nPort, int nTimeout, int *nSockfd)
{
    struct sockaddr_in dest_addr;
    int sockfd = -1;
    fd_set  rset, wset;
    struct timeval tv;
    int nRet = -1, len = -1, errcode = -1, flags = -1;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd <= 0)
        return -1;

    memset((char *)&dest_addr, 0, sizeof(struct sockaddr_in));

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(nPort);
    dest_addr.sin_addr.s_addr = nAdderss;

    flags = fcntl(sockfd, F_GETFL, 0);
    if (flags >= 0)
    {
        flags = fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
    }
	else
    {
        close(sockfd);
        return SOCK_ERR_FCNTL;
    }

    nRet = connect(sockfd, (struct sockaddr *)&dest_addr, sizeof(struct sockaddr));
    if (nRet < 0)
    {
        if (errno != EINPROGRESS)
        {
            close(sockfd);
            return SOCK_ERR_CONNECT;
        }

        FD_ZERO(&rset);
        FD_ZERO(&wset);

        FD_SET(sockfd, &rset);
        FD_SET(sockfd, &wset);

        tv.tv_sec = nTimeout;
        tv.tv_usec = 0;

        nRet = select(sockfd+ 1, &rset, &wset, NULL, &tv);
        if (nRet > 0)
        {
            len = sizeof (int);
            nRet = getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &errcode, (socklen_t *)&len);
            if (!(nRet >= 0 && errcode == 0))
            {
                close(sockfd);
                return SOCK_ERR_SELECT;
            }
        }
        else if (nRet == 0)
        {
            close(sockfd);
            return SOCK_ERR_TIMEOUT;
        }
        else
        {
            close(sockfd);
            return SOCK_ERR_SELECT;
        }
    }

    nRet = SetClientSockOpt(sockfd);

    if (nRet)
    {
        close(sockfd);
        return nRet;
    }

    *nSockfd = sockfd;

    return 0;

}

int PSocketSendData(int nSockfd, int nPkgHeadLen, unsigned char *pbSndBuf, int nBufLen, int nTimeout)
{
    int count, ret;
    fd_set w_fds;
    struct timeval tv;
	unsigned char tmpbuf[HSM_MAX_BUFFER_SIZE] = {'\0'};


    if (NULL == pbSndBuf)
        return SOCK_ERR_DATA_NULL;

    if (nBufLen > HSM_MAX_BUFFER_SIZE)
        return SOCK_ERR_DATA_LEN;

    if (nSockfd <= 0)
        return SOCK_ERR_SOCK_HANDLE;

    if (nTimeout < 0)
        return SOCK_ERR_TIMEOUT;

    if ((nPkgHeadLen != 0) && (nPkgHeadLen != 2) && (nPkgHeadLen != 4))
        return SOCK_ERR_MSGHEADLEN;	

    FD_ZERO(&w_fds);
    FD_SET(nSockfd, &w_fds);

    if (nTimeout > 0)
    {
        tv.tv_sec = nTimeout;
        tv.tv_usec = 0;

        ret = select(nSockfd + 1, NULL, &w_fds, NULL, &tv);
        if ((ret == 0) || !FD_ISSET(nSockfd, &w_fds))
        {
            return SOCK_ERR_SELECT;
        }
    }
	else
	{
        ret = select(nSockfd + 1, NULL, &w_fds, NULL, NULL);        
		if ((ret == 0) || !FD_ISSET(nSockfd, &w_fds))            
			return -SOCK_ERR_SELECT;	
	}

    /* 处理报文头... */
    if (nPkgHeadLen != 0)
    {
        /* 报文长度域为2字节 */
        memset(tmpbuf, 0x00, sizeof(tmpbuf));
        if (2 == nPkgHeadLen)
        {
            tmpbuf[0] = (nBufLen >> 8) & 0xff;
            tmpbuf[1] = nBufLen & 0xff;
            memcpy((u8 *)&tmpbuf[2], pbSndBuf, nBufLen);
            nBufLen += 2;
        }
        else if (4 == nPkgHeadLen)
        {
            tmpbuf[0] = (nBufLen >> 24) & 0xff;
            tmpbuf[1] = (nBufLen >> 16) & 0xff;
            tmpbuf[2] = (nBufLen >> 8) & 0xff;
            tmpbuf[3] = nBufLen & 0xff;
            memcpy((u8 *)&tmpbuf[4], pbSndBuf, nBufLen);
            nBufLen += 4;
        }

        memset(pbSndBuf, 0x00, sizeof(pbSndBuf));
        memcpy(pbSndBuf, tmpbuf, nBufLen);
    }

    count = 0;
    while (count != nBufLen)
    { 
        ret = send(nSockfd, pbSndBuf, nBufLen - count, 0);
        if (ret <= 0)
            return -SOCK_ERR_SEND;

        count += ret;
    }

    return 0;
}


#if 1
int PSocketRecvData(int nSockfd, int nPkgHeadLen, unsigned char *pszRecvBuf, int nTimeOut)
{
    int ret = -1;
    int trylen, rlen;
    fd_set r_fds;
    struct timeval tv;
    unsigned char tmpbuf[8] = {'\0'};
    int iMsgLen = 0;
    int iMaxRecvLen = 0;

    if (pszRecvBuf == NULL)
        return SOCK_ERR_DATA_NULL;

    if (nSockfd <= 0)
        return SOCK_ERR_SOCK_HANDLE;

    if ((nPkgHeadLen != 0) && (nPkgHeadLen != 2) && (nPkgHeadLen != 4))
        return SOCK_ERR_MSGHEADLEN;

    if (nTimeOut < 0)
        return SOCK_ERR_TIMEOUT;
	

    FD_ZERO(&r_fds);
    FD_SET(nSockfd, &r_fds);

    if (nTimeOut > 0)
    {
        tv.tv_sec = nTimeOut;
        tv.tv_usec = 0;

        ret = select(nSockfd + 1, &r_fds, NULL, NULL, &tv);
        if (ret == 0 || !FD_ISSET(nSockfd, &r_fds))
            return SOCK_ERR_SELECT;
    }
    else
    {
        ret = select(nSockfd + 1, &r_fds, NULL, NULL, NULL);
        if (ret == 0 || !FD_ISSET(nSockfd, &r_fds))
            return SOCK_ERR_SELECT;
    }

    if (nPkgHeadLen != 0)
    {
        /* 先接收报文头: 报文长度域(2字节或4字节) */
        memset(tmpbuf, 0x00, sizeof(tmpbuf));
	 trylen = 0;
	 while (trylen < nPkgHeadLen)
    	{
	        rlen = recv(nSockfd, &tmpbuf[trylen], nPkgHeadLen, 0);
		 if (rlen < 0)
	 		rlen = 0;
        	else if (rlen == 0)
	        {
	        	//errlog("recv 11 nTimeOut=%d",  nTimeOut);
	        	//errlog("recv 12  rlen=%d",  rlen);
	        	//errlog("recv 13 errno=%d",  errno);
	          	return SOCK_ERR_RECV;
	        }
		trylen += rlen;
	 }
	
        if(trylen != nPkgHeadLen)
            return SOCK_ERR_TOOSHORT;
	
	iMsgLen = (tmpbuf[0] << 8 | tmpbuf[1]);	
	if(iMsgLen > 5120)
	 {
	 	errlog("recv iMsgLen=%d errno=%d", iMsgLen, errno);
	 	return SOCK_ERR_TOOLONG;
	}
    }

    trylen = rlen = 0;
    iMaxRecvLen = iMsgLen;

    while (trylen < iMsgLen)
    {
        rlen = recv(nSockfd, pszRecvBuf + trylen, iMaxRecvLen - trylen, 0);
	 if (rlen < 0)
	 	rlen = 0;
        else if (rlen == 0)
        {
        	//perror("recv fail");
        	//printf("%s():%d [********* rlen = %d **********]\n", __func__, __LINE__, rlen);
        	//errlog("recv rlen=%d errno=%d", rlen, errno);
			//errlog("recv 21 iMsgLen=%d",  iMsgLen);

		//errlog("recv 22  trylen=%d",  trylen);
        	//errlog("recv 23 errno=%d",  errno);
            return SOCK_ERR_RECV;
        }	

        trylen += rlen;
    }

    return 0;
}
#endif

#if 0
int PSocketRecvData(int nSockfd, int nPkgHeadLen, unsigned char *pszRecvBuf, int nTimeOut)
{
    int ret = -1;
    int trylen, rlen;
    fd_set r_fds;
    struct timeval tv;
    unsigned char tmpbuf[8] = {'\0'};
    int iMsgLen = 0;
    int iMaxRecvLen = 0;

    if (pszRecvBuf == NULL)
        return SOCK_ERR_DATA_NULL;

    if (nSockfd <= 0)
        return SOCK_ERR_SOCK_HANDLE;

    if ((nPkgHeadLen != 0) && (nPkgHeadLen != 2) && (nPkgHeadLen != 4))
        return SOCK_ERR_MSGHEADLEN;

    if (nTimeOut < 0)
        return SOCK_ERR_TIMEOUT;
	

    FD_ZERO(&r_fds);
    FD_SET(nSockfd, &r_fds);

    if (nTimeOut > 0)
    {
        tv.tv_sec = nTimeOut;
        tv.tv_usec = 0;

        ret = select(nSockfd + 1, &r_fds, NULL, NULL, &tv);
        if (ret == 0 || !FD_ISSET(nSockfd, &r_fds))
            return SOCK_ERR_SELECT;
    }
    else
    {
        ret = select(nSockfd + 1, &r_fds, NULL, NULL, NULL);
        if (ret == 0 || !FD_ISSET(nSockfd, &r_fds))
            return SOCK_ERR_SELECT;
    }

    if (nPkgHeadLen != 0)
    {
        /* 先接收报文头: 报文长度域(2字节或4字节) */
        memset(tmpbuf, 0x00, sizeof(tmpbuf));
        rlen = recv(nSockfd, tmpbuf, nPkgHeadLen, 0);
        if (rlen <= 0)
            return SOCK_ERR_RECV;
	
        if(rlen != nPkgHeadLen)
            return SOCK_ERR_TOOSHORT;
	
	iMsgLen = (tmpbuf[0] << 8 | tmpbuf[1]);	
	if(iMsgLen > 5120)
	    return SOCK_ERR_TOOLONG;
    }

    trylen = rlen = 0;
    iMaxRecvLen = 1460;

    while (trylen < iMsgLen)
    {
        rlen = recv(nSockfd, pszRecvBuf + trylen, iMaxRecvLen, 0);
        if (rlen <= 0)
        {
        	//perror("recv fail");
        	//printf("%s():%d [********* rlen = %d **********]\n", __func__, __LINE__, rlen);
            return -SOCK_ERR_RECV;
        }	

        trylen += rlen;

        if((HSM_MAX_BUFFER_SIZE - trylen) < 1460)
        {
            iMaxRecvLen = HSM_MAX_BUFFER_SIZE - trylen;
        }
    }

    return 0;
}
#endif

int PSocketRelease(int nSockfd)
{
    if (nSockfd > 0)
    {
        close(nSockfd);
        nSockfd = -1;
    }
	
    return 0;
}


