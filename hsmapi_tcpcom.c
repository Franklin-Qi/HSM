/*----------------------------------------------------------------------|
|    hsmapi_tcpcom.c                                                    |
|    Version :     1.0                                                  |
|    Author:       Luo Cangjian.                                        |
|    Description:  SJJ1310ÃÜÂë»úœÓ¿ÚÍšÑ¶Ä£¿é¡£                          |
|    Copyright :   Beijing JN TASS Technology Co., Ltd.                 |
|    data:         2015-05-26. Create                                   |
|-----------------------------------------------------------------------|
|    Modify History:                                                    |
|----------------------------------------------------------------------*/
#include <stdlib.h>
#include <memory.h>
#include <stdio.h>
//#define WIN32
#ifdef WIN32
#include <Winsock2.h>
#include <windows.h>
#include <WinSock.h>
#pragma comment(lib,"ws2_32.lib")
#define    WSA_MAKEWORD(x,y) ((y)*256+(x))
#else
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#endif

//#include "hsmapi_tcpcom.h"
#include "internal_structs.h"
#include "hsmapi_define.h"
#include "hsmapi_log.h"



extern int  g_iInitFlg;
extern int  g_iTimeout;
extern int  g_iMsgHeadLen;
extern int  g_iPort1;
extern int  g_iPort2;              /*** žÃ¶Ë¿ÚÎªÓÃÓÚÐÅº¯ŽòÓ¡Ïà¹ØœÓ¿Ú ***/
extern char g_szHost1[16 + 1];
extern char g_szHost2[16 + 1];     /*** žÃIPÓÃÓÚÐÅº¯ŽòÓ¡Ïà¹ØœÓ¿Ú ***/

/***************************************************************************
* Subroutine: TCP_Init
* Function:   ³õÊŒ»¯windows»·Ÿ³µÄsocket
* Input:
*   ÎÞ
*
* Output:
*   ÎÞ
*
* Return:       ³É¹Š·µ»Ø0
* Description:
* Date:         2015.05.26
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int TCP_Init()
{

#if defined(WIN32) || defined(WIN64)
    int             iStatus;
    WORD            wMajorVersion;
    WORD            wMinorVersion;
    WSADATA         lpmyWSAData;
    WORD            VersionReqd;

    wMajorVersion = 1;
    wMinorVersion = 0;

    VersionReqd = WSA_MAKEWORD(wMajorVersion, wMinorVersion);

    iStatus = WSAStartup(VersionReqd, &lpmyWSAData);
    if (iStatus != 0)
    {
        LOG_ERROR("%s", "Windows sockets asynchronous start up failed.");
        return HAR_SOCK_INIT;
    }
#endif

    return HAR_OK;
}

/***************************************************************************
* Subroutine: DisconnectTcpServer
* Function:   ¹Ø±ÕsocketÁ¬œÓ
* Input:
*   @iSockfd  socketÃèÊö·û
*
* Output:
*   ÎÞ
*
* Return:       ³É¹Š·µ»Ø0
* Description:
* Date:         2015.05.26
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int DisconnectTcpServer(int iSockfd)
{
    shutdown(iSockfd, 2);
#ifdef WIN32
    closesocket(iSockfd);
#else
    close(iSockfd);
#endif
    return HAR_OK;
}

/***************************************************************************
* Subroutine: ConnectTcpServer
* Function:   Á¬œÓ·þÎñÆ÷
* Input:
*   @pcHostIp     ·þÎñÆ÷IP
*   @iPort        ·þÎñÆ÷¶Ë¿Ú
* Output:
*   @piSockfd   socketÃèÊö·ûÖžÕë
*
* Return:       ³É¹Š·µ»Ø0£¬ Ê§°Ü·µ»ØÆäËû
* Description:
* Date:         2015.05.26
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int ConnectTcpServer(char *pcHostIp, int iPort, int *piSockfd)
{
    int    rv = HAR_OK;
    struct sockaddr_in  serv_addr;
    memset(&serv_addr, 0x00, sizeof(struct sockaddr_in));

    rv = TCP_Init();
    if(rv)
    {
        LOG_ERROR("Error: Socket initialization failed, return code = [%#010X].", rv);
        return rv;
    }

    serv_addr.sin_family        = AF_INET;
    serv_addr.sin_addr.s_addr   = inet_addr(pcHostIp);
    serv_addr.sin_port          = htons(iPort);

    *piSockfd = socket(AF_INET, SOCK_STREAM, 0);
 
    if(*piSockfd < 0 )
    {
        LOG_ERROR("%s", "Error: Creat socket failed.");
        return HAR_SOCK_CREATE;
    }

    rv = SetSocket(*piSockfd);

    if(rv)
    {
        LOG_ERROR("%s", "Error: Set the socket attribute failure.");
        return rv;
    }

    rv = connect(*piSockfd, (struct sockaddr *)&serv_addr, sizeof(struct sockaddr_in));

    if (rv < 0)
    {
        LOG_ERROR("%s", "Connect to the server device failed.");
        DisconnectTcpServer(*piSockfd);
        return HAR_SOCK_CONNECT;
    }

    return rv;
}

/***************************************************************************
* Subroutine: SetSocket
* Function:   ÉèÖÃsocketÊôÐÔ
* Input:
*   @iSockfd     socketÃèÊö·û
* Output:
*   ÎÞ
*
* Return:       ³É¹Š·µ»Ø0£¬ Ê§°Ü·µ»ØÆäËû
* Description:
* Date:         2015.05.29
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int SetSocket(int iSockfd)
{
    int     rv = HAR_OK;
    struct  timeval stTimeOut;
    struct  linger  stLinger;

    /*** ÉèÖÃÌ×œÓ×Ö¶Ï¿ª·œÊœÎª¹Ø±ÕsocketÁ¢ŒŽÍË³ö ***/
    stLinger.l_onoff = 1;
    stLinger.l_linger = 0;
    rv = setsockopt(iSockfd,SOL_SOCKET,SO_LINGER,(const char *)&stLinger,sizeof(stLinger));

    stTimeOut.tv_sec = g_iTimeout;
    stTimeOut.tv_usec=0;

    rv = setsockopt(iSockfd, SOL_SOCKET, SO_SNDTIMEO, (const char  *)&stTimeOut, sizeof(stTimeOut));
    stTimeOut.tv_sec = g_iTimeout;
    rv = setsockopt(iSockfd, SOL_SOCKET, SO_RCVTIMEO, (const char  *)&stTimeOut, sizeof(stTimeOut));

    return rv;
}

/***************************************************************************
* Subroutine: HsmSendToSocket
* Function:   ·¢ËÍÊýŸÝ
* Input:
*   @iSockfd        socketÃèÊö·û
*   @pucSendBuf     Žý·¢ËÍÊýŸÝ»º³åÇø
*   @iSendBufLen    Žý·¢ËÍµÄÊýŸÝ³€¶È
* Output:
*   ÎÞ
*
* Return:       ³É¹Š·µ»Ø0£¬ Ê§°Ü·µ»ØÆäËû
* Description:
* Date:         2015.05.28
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int HsmSendToSocket(int iSockfd, unsigned char *pucSendBuf, int iSendBufLen)
{
    int   rv  = HAR_OK;
    int   len = 0;
    unsigned char  *p  = pucSendBuf;
    struct  timeval stTimeOut;
    fd_set  stSockReady;

    FD_ZERO(&stSockReady);
    FD_SET(iSockfd, &stSockReady);

    /*** ÉèÖÃ³¬Ê±Ê±Œä ***/
    if (g_iTimeout > 0)
    {
        stTimeOut.tv_sec = g_iTimeout;
        stTimeOut.tv_usec = 0;
        rv = select(iSockfd + 1, NULL, &stSockReady, NULL, &stTimeOut);
    }
    else
    {
        rv = select(iSockfd + 1, NULL, &stSockReady, NULL, NULL);
    }

    if (rv <= 0)
    {
        LOG_ERROR("Error: Set timeout failed, socket id = [%d], timeout = [%d]s, return code = [%d].", iSockfd, g_iTimeout,rv);
        return HAR_SOCK_SELECT;
    }

    if(!(FD_ISSET(iSockfd, &stSockReady)))
    {
        LOG_ERROR("Error: socket id = [%d] is invalid. errno = [%#010X]", iSockfd, errno);
        return HAR_SOCK_INVALID;
    }

    do
    {
#ifdef LINUX
        len = send(iSockfd, p, iSendBufLen, MSG_NOSIGNAL);
#else
        len = send(iSockfd, p, iSendBufLen, 0);
#endif
        if(len <= 0)
        {
            LOG_ERROR("%s", "Error: send data failed.");
            return HAR_SOCK_SEND;
        }

        p += len;
        iSendBufLen -= len;
    }while (iSendBufLen > 0);

    return rv;
}

/***************************************************************************
* Subroutine: HsmReceiveFromSocket
* Function:   œÓÊÕÊýŸÝ
* Input:
*   @iSockfd         socketÃèÊö·û
* Output:
*   @pucRspBuf       ÏìÓŠ±šÎÄ»ºŽæÇø
*   @piRspBufLen     ÏìÓŠ±šÎÄ³€¶È
*
* Return:       ³É¹Š·µ»Ø0£¬ Ê§°Ü·µ»ØÆäËû
* Description:
* Date:         2015.05.26
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int HsmReceiveFromSocket(int iSockfd, unsigned char *pucRspBuf, int *piRspBufLen)
{
    int     rv = HAR_OK;
    int     rcvlen = 0;
    int     len = 0;
    int     rspBufLen = 0;
    unsigned char *p = pucRspBuf;
    struct  timeval stTimeOut;
    fd_set  stSockReady;

    FD_ZERO(&stSockReady);
    FD_SET(iSockfd, &stSockReady);

    /*** ÉèÖÃ³¬Ê±Ê±Œä ***/
    if (g_iTimeout > 0)
    {
        stTimeOut.tv_sec = g_iTimeout;
        stTimeOut.tv_usec = 0;
        rv = select(iSockfd + 1, &stSockReady, NULL, NULL, &stTimeOut);
    }
    else
    {
        rv = select(iSockfd + 1, &stSockReady, NULL, NULL, NULL);
    }

    if (rv <= 0)
    {
        LOG_ERROR("Error: Set timeout failed, socket id = [%d], timeout = [%d]s, return code = [%d].", iSockfd, g_iTimeout,rv);
        return HAR_SOCK_SELECT;
    }

    if(!(FD_ISSET(iSockfd, &stSockReady)))
    {
        LOG_ERROR("Error: socket id = [%d] is invalid. errno = [%#010X]", iSockfd, errno);
        return HAR_SOCK_INVALID;
    }

    len = recv(iSockfd, (char*)p, 2, 0);
    if (len != 2)
    {
        LOG_ERROR("%s", "Error: Get the length of the response packet error.");
        return HAR_SOCK_RECV;
    }

    rspBufLen = p[0] * 256 + p[1];
    if(rspBufLen > SOCKET_MAXDATALEN)
    {
        LOG_ERROR("%s", "Error: Response packet length identification error.");
        return HAR_SOCK_RECV;
    }
    p += 2;

    len = recv(iSockfd, (char*)p, rspBufLen, 0);
    if ((len > 0) && (len < rspBufLen))
    {
        rcvlen = len;
        while(rcvlen < rspBufLen)
        {
            p += len;

            len = recv(iSockfd, (char*)p, rspBufLen - rcvlen, 0);
            if(len < 0)
            {
                LOG_ERROR("%s", "Error: Response packet receive failed.");
                return HAR_SOCK_RECV;
            }
            rcvlen += len;
        }
    }
    else if(len == rspBufLen)
    {
        rcvlen = len;
    }
    else
    {
        LOG_ERROR("Error: Response packet first receive failed. len = [%d], rspBufLen = [%d]\n", len, rspBufLen);
        return HAR_SOCK_RECV;
    }

    *piRspBufLen = rcvlen + 2;

    return 0;
}

/***************************************************************************
* Subroutine: PackMsgHead
* Function:   ÆŽœÓÏûÏ¢Í·
* Input:
*   @iMsgHeadLen   ÏûÏ¢Í·³€¶È
*   @pucCmdBuf     ÃüÁîŽúÂë + ÊýŸÝÔªËØ
*   @iCmdBufLen    ÃüÁîŽúÂë + ÊýŸÝÔªËØµÄ³€¶È
* Output:
*   @pucDstBuf     TCPÃüÁî±šÎÄ
*   @piDstBufLen   TCPÃüÁî±šÎÄ³€¶È
*
* Return:       ³É¹Š·µ»Ø0£¬ Ê§°Ü·µ»ØÆäËû
* Description: ÆŽœÓ±šÎÄ³€¶ÈÒÔŒ°ÏûÏ¢Í·
* Date:         2015.05.28
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int PackMsgHead(int iMsgHeadLen, unsigned char *pucCmdBuf, int iCmdBufLen, unsigned char *pucDstBuf, unsigned int *piDstBufLen)
{
    int  iHeadLen;
    int  iSendMsgLen = 0;
    unsigned char   sendMsgHead[128];
    unsigned char   *p = pucDstBuf;
    memset(sendMsgHead, '0', 128);

    if(iMsgHeadLen == 9999)
    {
        iHeadLen = g_iMsgHeadLen % 127;
    }
    else
    {
        iHeadLen = iMsgHeadLen % 127;
    }

    iSendMsgLen = iHeadLen + iCmdBufLen;

    if(iSendMsgLen + 2 > SOCKET_MAXDATALEN)
    {
        LOG_ERROR("Error: iSendMsgLen = [%d] is invalid, it must be less than %d.", SOCKET_MAXDATALEN);
        return HAR_SOCK_DATA_LEN;
    }

    /*** 2 Bytes Length ***/
    *p  ++= iSendMsgLen / 256;
    *p  ++= iSendMsgLen % 256;

    memcpy(p, sendMsgHead, iHeadLen);
    p += iHeadLen;

    memcpy(p, pucCmdBuf, iCmdBufLen);
    p += iCmdBufLen;

    *p = 0;
    *piDstBufLen = p - pucDstBuf;

    return HAR_OK;
}

/***************************************************************************
* Subroutine: ParseMsgHead_Print
* Function:   œâÎöÏìÓŠ±šÎÄ
* Input:
*   @iMsgHeadLen    ÏûÏ¢Í·³€¶È
*   @pucCmd         ÃüÁîŽúÂë
*   @pucRspBuf      ÏìÓŠ±šÎÄ
*   @iRspBufLen     ÏìÓŠ±šÎÄ³€¶È
* Output:
*   ÎÞ
*
* Return:       ³É¹Š·µ»Ø0£¬ Ê§°Ü·µ»ØÆäËû
* Description:  žÃº¯ÊýÖ»ÓÃÓÚÐÅº¯ŽòÓ¡
* Date:         2015.05.28
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int ParseMsgHead_Print(int iMsgHeadLen, unsigned char *pucCmd, unsigned char *pucRspBuf, int iRspBufLen)
{
    int  rv = HAR_OK;
    int  len = 0;
    int  iHeadLen;
    unsigned char   sendMsgHead[128];
    memset(sendMsgHead, '0', 128);

    if(iMsgHeadLen == 9999)
    {
        iHeadLen = g_iMsgHeadLen % 127;
    }
    else
    {
        iHeadLen = iMsgHeadLen % 127;
    }

    /***  Response: 2bytes Length + Response Message ***/
    len = pucRspBuf[0] * 256 + pucRspBuf[1];
    if(len != iRspBufLen - 2 || len < iHeadLen + 4)
    {
        LOG_ERROR("%s", "Receive data len error.");
        return HAR_SOCK_RECV;
    }
    pucRspBuf += 2;

    if(memcmp(pucRspBuf, sendMsgHead, iHeadLen))
    {
        LOG_ERROR("%s", "Receive message header is error.");
        return HAR_SOCK_RECV;
    }
    pucRspBuf += iHeadLen;

    /*** ÅÐ¶ÏÏìÓŠŽúÂë ***/
    if((pucCmd[0] != pucRspBuf[0]) || (pucCmd[1] + 1 != pucRspBuf[1]))
    {
        LOG_ERROR("%s", "Response code error.");
        return HAR_MSG_RSPCODE;
    }
    pucRspBuf += 2;

    /*** 2 Bytes Error Code ***/
    rv = (*pucRspBuf - '0') * 10 + (*(pucRspBuf + 1) - '0');
    if(rv)
    {
        LOG_ERROR("%s", "Response packet status code is not 0.");
    }

    return rv;
}

/***************************************************************************
* Subroutine: ParseMsgHead
* Function:   œâÎöÏìÓŠ±šÎÄ
* Input:
*   @iMsgHeadLen    ÏûÏ¢Í·³€¶È
*   @pucCmd         ÃüÁîŽúÂë
*   @pucRspBuf      ÏìÓŠ±šÎÄ
*   @iCmdBufLen     ÏìÓŠ±šÎÄ³€¶È
* Output:
*   @pucDstBuf      ÊýŸÝÔªËØ
*   @piDstBufLen    ÊýŸÝÔªËØµÄ³€¶È
*
* Return:       ³É¹Š·µ»Ø0£¬ Ê§°Ü·µ»ØÆäËû
* Description:
* Date:         2015.05.28
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int ParseMsgHead(int iMsgHeadLen, unsigned char *pucCmd, unsigned char *pucRspBuf, int iRspBufLen, unsigned char *pucDstBuf, int *piDstBufLen)
{
    int rv = HAR_OK;
    int len = 0;
    int  iHeadLen = 0;
    unsigned char   sendMsgHead[128];
    memset(sendMsgHead, '0', 128);

    if(iMsgHeadLen == 9999)
    {
        iHeadLen = g_iMsgHeadLen % 127;
    }
    else
    {
        iHeadLen = iMsgHeadLen % 127;
    }

    /***  Response: 2bytes Length + Response Message ***/
    len = pucRspBuf[0] * 256 + pucRspBuf[1];
    if(len != iRspBufLen - 2 || len < iHeadLen + 4)
    {
        LOG_ERROR("Receive data len error, len = [%d], iRspBufLen = [%d], headLen = [%d].", len, iRspBufLen, iHeadLen);
        return HAR_SOCK_RECV;
    }
    pucRspBuf += 2;

    if(memcmp(pucRspBuf, sendMsgHead, iHeadLen))
    {
        LOG_ERROR("%s", "Receive message header is error.");
        return HAR_SOCK_RECV;
    }
    pucRspBuf += iHeadLen;

    /*** ÅÐ¶ÏÏìÓŠŽúÂë ***/
    if((pucCmd[0] != pucRspBuf[0]) || (pucCmd[1] + 1 != pucRspBuf[1]))
    {
        LOG_ERROR("%s", "Response code error.");
        return HAR_MSG_RSPCODE;
    }
    pucRspBuf += 2;

    /*** 2 Bytes Error Code ***/
    rv = (*pucRspBuf - '0') * 10 + (*(pucRspBuf + 1) - '0');
    if(rv)
    {
        LOG_ERROR("%s", "Response packet status code is not 0.");
        return rv;
    }
    pucRspBuf += 2;

    /*** È¥µôÏûÏ¢Í·¡¢±šÎÄ³€¶È±êÊ¶¡¢ÏìÓŠŽúÂëºÍ×ŽÌ¬Âë ***/
    len = iRspBufLen - 2 - iHeadLen - 4;

    if(*piDstBufLen < len)
    {
        LOG_ERROR("%s", "Insufficient buffer for receiving data.");
        return HAR_MEM_LENLESS;
    }

    *piDstBufLen = len;
    memcpy(pucDstBuf, pucRspBuf, *piDstBufLen);

    return HAR_OK;
}

/***************************************************************************
* Subroutine: HsmCmd_TCP
* Function:   ÓëŒÓÃÜ»úÍšÑ¶
* Input:
*   @iMsgHeadLen    ÏûÏ¢Í·³€¶È
*   @iSockfd        socketÃèÊö·û
*   @pucCmd         ·¢ËÍµÄ±šÎÄ
*   @iCmdLen        ·¢ËÍµÄ±šÎÄ³€¶È
* Output:
*   @pucRsp         ÏìÓŠ±šÎÄ»ºŽæÇø
*   @piRspLen       ÏìÓŠ±šÎÄ³€¶È
*
* Return:       ³É¹Š·µ»Ø0£¬ Ê§°Ü·µ»ØÆäËû
* Description:
* Date:         2015.05.26
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int HsmCmd_TCP(int iMsgHeadLen, int iSockfd, unsigned char *pucCmd, int iCmdLen, unsigned char *pucRsp, int *piRspLen)
{
    int  rv = HAR_OK;
    int  iCmdBufLen = 0;
    int  iRspBufLen = 0;
    unsigned char   pucCmdBuf[SOCKET_MAXDATALEN] = {0};
    unsigned char   pucRspBuf[SOCKET_MAXDATALEN] = {0};
    unsigned char   *p;

    rv = PackMsgHead(iMsgHeadLen, pucCmd, iCmdLen, pucCmdBuf, &iCmdBufLen);
    if(rv)
    {
        LOG_ERROR("Error: PackMsgHead return code = [%#010X].", rv);
        return rv;
    }

    LOG_TRACE("Send Data", pucCmdBuf, iCmdBufLen);

    rv = HsmSendToSocket(iSockfd, pucCmdBuf, iCmdBufLen);
    if (rv < 0)
    {
        LOG_ERROR("Send to socket error, return code = [%#010X].", rv);
        return HAR_SOCK_SEND;
    }

    rv = HsmReceiveFromSocket(iSockfd, pucRspBuf, &iRspBufLen);
    if (rv)
    {
        LOG_ERROR("Receive from socket error, return code = [%#010X].", rv);
        return HAR_SOCK_RECV;
    }

    LOG_TRACE("Receive Data", pucRspBuf, iRspBufLen);

    rv = ParseMsgHead(iMsgHeadLen, pucCmd, pucRspBuf, iRspBufLen, pucRsp, piRspLen);
    if(rv)
    {
        LOG_ERROR("Error: ParseMsgHead return code = [%#010X].", rv);
    }

    return rv;
}


/***************************************************************************
* Subroutine: TCP_CommunicateHsm
* Function:   ÍšÓÃÍšÑ¶œÓ¿Ú
* Input:
*    @pucCmd            ÃüÁî±šÎÄ
*    @iCmdLen           ÃüÁî±šÎÄ³€¶È
*    @pucRsp            ÏìÓŠ±šÎÄ
*    @piRspLen          ÏìÓŠ±šÎÄ³€¶È
* Output:
*    ÎÞ
*
* Return:       0 for success, other is error
* Description:  ¶ÔÏìÓŠ±šÎÄÖÐµÄ×ŽÌ¬ÂëœøÐÐÁËœâÎö£¬²¢Êä³öÓÐÐ§µÄÏìÓŠ±šÎÄ
*
* Author:       Luo Cangjian
* Date:         2014.6.3
* ModifyRecord:
* *************************************************************************/
/*int TCP_CommunicateHsm(unsigned char *pucCmd, int iCmdLen, unsigned char *pucRsp, int *piRspLen)
{
    int rv = HAR_OK;
    int iSockfd = 0;

    if(pucRsp == NULL)
    {
        LOG_ERROR("pucRsp = [%s] is invalid.", "NULL");
        return HAR_MEM_LENLESS;
    }

    rv = ConnectTcpServer(g_szHost1, g_iPort1, &iSockfd);
    if(rv)
    {
        LOG_ERROR("Connection to server failed, return code = [%#010X].", rv);
        return HAR_SOCK_CONNECT;
    }

    rv = HsmCmd_TCP(9999, iSockfd, pucCmd, iCmdLen, pucRsp, piRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with the server return code = [%#010X].", rv);
        return rv;
    }

    rv = DisconnectTcpServer(iSockfd);
    if(rv)
    {
        LOG_ERROR("Disconnect hsm server failed, return code = [%#010X].", rv);
    }
    return rv;
}*/

/***************************************************************************
* Subroutine: TCP_CommunicateHsm_ReceiveTwice
* Function:   ÓÃÓÚÐÅº¯ŽòÓ¡ÖžÁîµÄÍšÑ¶œÓ¿Ú
* Input:
*    @pucCmd            ÃüÁî±šÎÄ
*    @iCmdLen           ÃüÁî±šÎÄ³€¶È
*    @pucRsp            ÏìÓŠ±šÎÄ
*    @piRspLen          ÏìÓŠ±šÎÄ³€¶È
* Output:
*    ÎÞ
*
* Return:       0 for success, other is error
* Description:  ÓÃÓÚŽòÓ¡ÐÅ·âÓÃµÄÍšÑ¶,Öž¶šÄ³ÌšŒÓÃÜ»úžºÔðŽòÓ¡¹€×÷£¬
*               ŽËÍšÑ¶µÄIPÓë·ÇŽòÓ¡ÖžÁîÊ¹ÓÃµÄÃüÁîµÄÍšÑ¶œÓ¿ÚIP¿É²»Í¬¡£
*
* Author:       Luo Cangjian
* Date:         2015.05.29
* ModifyRecord:
* *************************************************************************/
int TCP_CommunicateHsm_ReceiveTwice(unsigned char *pucCmd, int iCmdLen, unsigned char *pucRsp, int *piRspLen)
{
    int rv = HAR_OK;
    int iMsgHeadLen = 9999;
    int iSockfd = 0;
    int iRetLen = 0;
    unsigned char pucReBuffer[512] = {0};

    if(pucRsp == NULL)
    {
        LOG_ERROR("pucRsp = [%s] is invalid.", "NULL");
        return HAR_MEM_LENLESS;
    }

    rv = ConnectTcpServer(g_szHost2, g_iPort2, &iSockfd);
    if(rv)
    {
        LOG_ERROR("Connection to server failed, return code = [%#010X].", rv);
        return HAR_SOCK_CONNECT;
    }

    rv = HsmCmd_TCP(iMsgHeadLen, iSockfd, pucCmd, iCmdLen, pucRsp, piRspLen);
    if(rv != 0)
    {
        LOG_ERROR("Communicate with the server return code = [%#010X].", rv);
        goto end;
    }

    /*** Èç¹ûµÚÒ»ŽÎÏìÓŠ±šÎÄœÓ¿Ú³É¹Š£¬ÇÒ×ŽÌ¬ÂëÎª0£¬ÔòŒÌÐøœÓÊÕÏìÓŠ±šÎÄ ***/
    rv = HsmReceiveFromSocket(iSockfd, pucRsp, &iRetLen);
    if(rv)
    {
        LOG_ERROR("Receive from socket error, return code = [%#010X].", rv);
        rv = HAR_SOCK_RECV;
        goto end;
    }

    rv = ParseMsgHead_Print(iMsgHeadLen, "AZ", pucReBuffer, iRetLen);
    if(rv)
    {
        LOG_ERROR("Error: ParseMsgHead_Print return code = [%#010X].", rv);
    }

    goto end;

end:
    rv = DisconnectTcpServer(iSockfd);
    if(rv)
    {
        LOG_ERROR("Disconnect hsm server failed, return code = [%#010X].", rv);
    }

    return rv;
}

/***************************************************************************
* Subroutine: TCP_CommunicateHsm_Print
* Function:   ÓÃÓÚÐÅ·âŽòÓ¡ÖžÁîµÄÍšÑ¶œÓ¿Ú
* Input:
*    @pucCmd            ÃüÁî±šÎÄ
*    @iCmdLen           ÃüÁî±šÎÄ³€¶È
*    @pucRsp            ÏìÓŠ±šÎÄ
*    @piRspLen          ÏìÓŠ±šÎÄ³€¶È
* Output:
*    ÎÞ
*
* Return:       0 for success, other is error
* Description:  ÓÃÓÚŽòÓ¡ÐÅ·âÓÃµÄÍšÑ¶,Öž¶šÄ³ÌšŒÓÃÜ»úžºÔðŽòÓ¡¹€×÷£¬
*               ŽËÍšÑ¶µÄIPÓë·ÇŽòÓ¡ÖžÁîÊ¹ÓÃµÄÃüÁîµÄÍšÑ¶œÓ¿ÚIP¿É²»Í¬¡£
*
* Author:       Luo Cangjian
* Date:         2015.05.29
* ModifyRecord:
* *************************************************************************/
int TCP_CommunicateHsm_Print(unsigned char *pucCmd, int iCmdLen, unsigned char *pucRsp, int *piRspLen)
{
    int rv = HAR_OK;
    int iSockfd = 0;
    int iMsgHeadLen = 9999;

    if(pucRsp == NULL)
    {
        LOG_ERROR("pucRsp = [%s] is invalid.", "NULL");
        return HAR_MEM_LENLESS;
    }

    rv = ConnectTcpServer(g_szHost2, g_iPort2, &iSockfd);
    if(rv)
    {
        LOG_ERROR("Connection to server failed, return code = [%#010X].", rv);
        return HAR_SOCK_CONNECT;
    }

    rv = HsmCmd_TCP(iMsgHeadLen, iSockfd, pucCmd, iCmdLen, pucRsp, piRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with the server return code = [%#010X].", rv);
        return rv;
    }

    rv = DisconnectTcpServer(iSockfd);
    if(rv)
    {
        LOG_ERROR("Disconnect hsm server failed, return code = [%#010X].", rv);
    }

    return rv;
}


/***************************************************************************
* Subroutine: TCP_CommunicateHsm_ex
* Function:   ÍšÓÃÍšÑ¶œÓ¿Ú(»á»°Ÿä±úÐÎÊœ)
* Input:
*    @hSessionHandle    »á»°Ÿä±ú
*    @pucCmd            ÃüÁî±šÎÄ
*    @iCmdLen           ÃüÁî±šÎÄ³€¶È
*    @pucRsp            ÏìÓŠ±šÎÄ
*    @piRspLen          ÏìÓŠ±šÎÄ³€¶È
* Output:
*    ÎÞ
*
* Return:       0 for success, other is error
* Description:  ¶ÔÏìÓŠ±šÎÄÖÐµÄ×ŽÌ¬ÂëœøÐÐÁËœâÎö£¬²¢Êä³öÓÐÐ§µÄÏìÓŠ±šÎÄ
*
* Author:       Luo Cangjian
* Date:         2015.7.16
* ModifyRecord:
* *************************************************************************/
/*int TCP_CommunicateHsm_ex(void *hSessionHandle, int nSock,unsigned char *pucCmd, int iCmdLen, unsigned char *pucRsp, int *piRspLen)
{
    int rv = HAR_OK;
    SESSION_STRUCT* pSessionStruct = (SESSION_STRUCT *) hSessionHandle;

    if(g_iInitFlg == 1)
    {
        return TCP_CommunicateHsm(pucCmd, iCmdLen, pucRsp, piRspLen);
    }

    if(pucRsp == NULL)
    {
        LOG_ERROR("pucRsp = [%s] is invalid.", "NULL");
        return HAR_MEM_LENLESS;
    }

    if(pSessionStruct == NULL || pSessionStruct->status == 0)
    {
        LOG_ERROR("%s", "Error: hSessionHandle is invalid.");
        return HAR_SESSIONHANDLE_INVALID;
    }

    rv = HsmCmd_TCP(pSessionStruct->msgHeadLen, pSessionStruct->sockfd, pucCmd, iCmdLen, pucRsp, piRspLen);
    if(rv)
    {
        LOG_ERROR("Communicate with the server return code = [%d], [%#010X].", rv, rv);
        return rv;
    }

    return rv;
}*/

/***************************************************************************
* Subroutine: SDF_OpenDevie
* Function:   Žò¿ªÉè±žŸä±ú
* Input:
*    @pphDeviceHandle    Éè±žŸä±ú
*    @pcIp               IPµØÖ·
*    @iPort              ¶Ë¿ÚºÅ
*    @iMsgHeadLen        ÏûÏ¢Í·³€¶È
* Output:
*    ÎÞ
*
* Return:       0 for success, other is error
* Description:
*
* Author:       Luo Cangjian
* Date:         2015.7.16
* ModifyRecord:
* *************************************************************************/
/*
int SDF_OpenDevice(void **pphDeviceHandle, char *pcIp, int iPort, int iMsgHeadLen)
{
    int rv = HAR_OK;
    DEVICE_STRUCT *pstDevice = NULL;

    if(pcIp == NULL)
    {
        LOG_ERROR("Error: ip = [%s] is invalid.", pcIp);
        return HAR_PARAM_ISNULL;
    }

    if(iPort < 0)
    {
        LOG_ERROR("Error: port = [%d] is invalid.", iPort);
        return HAR_PARAM_VALUE;
    }

    if(*pphDeviceHandle != NULL && ((DEVICE_STRUCT *) (*pphDeviceHandle))->status == 1)
    {
        return HAR_ALREADY_INITIALIZED;
    }

    pstDevice = (DEVICE_STRUCT*)malloc(sizeof(DEVICE_STRUCT));

    memset(pstDevice, 0, sizeof(DEVICE_STRUCT));
    strncpy(pstDevice->ip, pcIp, 16);
    pstDevice->port = iPort;

    rv = ConnectTcpServer(pstDevice->ip, pstDevice->port, &(pstDevice->sockfd));
    if(rv)
    {
        LOG_ERROR("Error: TCP_ConnectHsm failed, return code = [%d], [%#010X].", rv, rv);
        free(pstDevice);
        rv = HAR_OPENDEVICE;
    }
    else
    {
        pstDevice->status = 1;
        pstDevice->msgHeadLen = iMsgHeadLen;
        *pphDeviceHandle = pstDevice;
    }

    return rv;
}
*/

/***************************************************************************
* Subroutine: SDF_CloseDevice 
* Function:   ¹Ø±ÕÉè±žŸä±ú
* Input:
*    @phDeviceHandle    Éè±žŸä±ú
* Output:
*    ÎÞ
*
* Return:       0 for success, other is error
* Description:
*
* Author:       Luo Cangjian
* Date:         2015.7.16
* ModifyRecord:
* *************************************************************************/
/*
int SDF_CloseDevice(void *phDeviceHandle)
{
    DEVICE_STRUCT *pstDevice = (DEVICE_STRUCT *)phDeviceHandle;

    if(pstDevice != NULL && pstDevice->status == 1)
    {
        
        DisconnectTcpServer(pstDevice->sockfd);
        pstDevice->status = 0;
        pstDevice->msgHeadLen = 0;
        free(pstDevice);
    }

    return HAR_OK;
}
*/

/***************************************************************************
* Subroutine: SDF_OpenSession
* Function:   Žò¿ª»á»°Ÿä±ú
* Input:
*    @phDeviceHandle      Éè±žŸä±ú
*    @pphSessionHandle    »á»°Ÿä±ú
* Output:
*    ÎÞ
*
* Return:       0 for success, other is error
* Description:
*
* Author:       Luo Cangjian
* Date:         2015.7.16
* ModifyRecord:
* *************************************************************************/
/*
int SDF_OpenSession(void *phDeviceHandle, void **pphSessionHandle)
{
    int rv = HAR_OK;
    DEVICE_STRUCT   *pstDevice = (DEVICE_STRUCT *)phDeviceHandle;
    SESSION_STRUCT  *pstSession = NULL;

    if(pstDevice == NULL || pstDevice->status != 1)
    {
        LOG_ERROR("%s", "Error: DeviceHandle is invalid.");
        return HAR_DEVICEHANDLE_INVALID;
    }

    if(*pphSessionHandle == NULL || ((SESSION_STRUCT *) *pphSessionHandle)->status != 1)
    {
        pstSession = (SESSION_STRUCT *)malloc(sizeof(SESSION_STRUCT));

      
        rv = ConnectTcpServer(pstDevice->ip, pstDevice->port, &(pstSession->sockfd));
        if(rv)
        {
            LOG_ERROR("Error: TCP_ConnectHsm failed, return code = [%d], [%#010X].", rv, rv);
            free(pstSession);
            rv = HAR_OPENSESSION;
        }
        else
        {
            pstSession->msgHeadLen = pstDevice->msgHeadLen;
            pstSession->status = 1;
            *pphSessionHandle = (void *) pstSession;
        }
    }

    return rv;
}
*/

/***************************************************************************
* Subroutine: SDF_CloseSession
* Function:   ¹Ø±Õ»á»°Ÿä±ú
* Input:
*    @phSessionHandle    »á»°Ÿä±ú
* Output:
*    ÎÞ
*
* Return:       0 for success, other is error
* Description:  ¹Ø±Õ»á»°Ÿä±ú
*
* Author:       Luo Cangjian
* Date:         2015.7.16
* ModifyRecord:
* *************************************************************************/
/*
int SDF_CloseSession(void *phSessionHandle)
{
    SESSION_STRUCT* pstSession = (SESSION_STRUCT *) phSessionHandle;

    if(pstSession != NULL && pstSession->status == 1)
    {
        
        DisconnectTcpServer(pstSession->sockfd);

        pstSession->msgHeadLen = 0;
        pstSession->sockfd = 0;
        pstSession->status = 0;
        free(pstSession);
    }

    return HAR_OK;
}
*/
