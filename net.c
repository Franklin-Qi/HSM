#include <string.h>
#include <stdio.h>
#include <memory.h>
#include <time.h>
#include <stdlib.h>
#if defined(WIN32) || defined(WIN64)
#include <winsock2.h>
#include <winsock.h>
#include <windows.h>
#include <winioctl.h>
#include <process.h>
#include <winbase.h>
#else
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#endif

#ifdef __LINUX__
#include <stdlib.h>
#include <arpa/inet.h>
#endif

#include "unionlog.h"
#include "net.h"


extern UINT unTimeout_ABC;


UINT CheckServer(char *sServerAddr, UINT nPort, UINT unTimeout) 
{
	struct sockaddr_in addr;
	int socketfd, flags;
	fd_set fdevents;
	struct timeval tv;
	int rv;
	int on;
#if defined(WIN32) || defined(WIN64)
	WSADATA WsaData;
#endif

	LOG(LOG_TRACE,0, "CheckServer->begin...");
	if(unTimeout == 0)
		return 0;

#if defined(WIN32) || defined(WIN64)
	if ((rv = WSAStartup(MAKEWORD(1,1),&WsaData)) != 0)
	{
		LOG(LOG_ERROR,SDR_UNKNOWERR, "CheckServer->WSAStartup error");
		return SDR_UNKNOWERR;
	}
#endif

	if ((socketfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
	{
		LOG(LOG_ERROR,SWR_CONNECT_ERR, "CheckServer->socket error");
		return SWR_CONNECT_ERR;
	}

	if (setsockopt(socketfd,SOL_SOCKET,SO_REUSEADDR,(char *)&on,sizeof(on)))
	{
		LOG(LOG_ERROR,SWR_CONNECT_ERR, "ReceiveRequest->setsockopt");
		CloseSocket(socketfd);
		return SWR_CONNECT_ERR;
	}

#if defined(WIN32) || defined(WIN64)
	flags = 1;
	if (ioctlsocket(socketfd,FIONBIO,(unsigned long *)&flags))
	{
		rv = WSAGetLastError();
		LOG(LOG_ERROR,rv, "CheckServer->Set socket flags error");
		CloseSocket(socketfd);
		return SWR_CONNECT_ERR;
	}
#else
	if((flags = fcntl(socketfd,F_GETFL,0)) <0)
	{
		LOG(LOG_ERROR,SWR_CONNECT_ERR, "ConnectServer->Get socket flags error");
		CloseSocket(socketfd);
		return SWR_CONNECT_ERR;
	}	
	if(fcntl(socketfd,F_SETFL,flags|O_NONBLOCK)<0)
	{
		LOG(LOG_ERROR,SWR_CONNECT_ERR, "CheckServer->Set socket flags error");
		CloseSocket(socketfd);
		return SWR_CONNECT_ERR;
	}
#endif

	addr.sin_family = AF_INET;
	addr.sin_port = htons((short)nPort);
	addr.sin_addr.s_addr = inet_addr(sServerAddr); 

	if (connect(socketfd,(struct sockaddr *)&addr,sizeof(addr)) == 0) 
	{
		CloseSocket(socketfd);
		return SDR_OK;
	}

	/*设置超时时间*/
	tv.tv_sec = unTimeout;///1000;
	tv.tv_usec = 0;//(unTimeout%1000)*1000;

	FD_ZERO(&fdevents);
	FD_SET((unsigned int)socketfd,&fdevents);

	if ((rv = select(socketfd+1,NULL,&fdevents,NULL,&tv)) <= 0)
	{
		LOG(LOG_ERROR,SDR_TIMEOUT, "CheckServer->Timeout");
		CloseSocket(socketfd);
		return SDR_TIMEOUT;	
	}

	if (!FD_ISSET(socketfd,&fdevents))
	{
		LOG(LOG_ERROR,SDR_UNKNOWERR, "CheckServer->!FD_ISSET");
		CloseSocket(socketfd);
		return SDR_UNKNOWERR;	
	}

	CloseSocket(socketfd);
	LOG(LOG_TRACE,0, "CheckServer->return");
	return SDR_OK;
}

UINT SendRequest_Racal(UINT nSock, byte *pbReqParas, UINT unReqParasLength)
{
	int  rest, sent, rv;
	unsigned char *pbSendBuffer;
	unsigned int unTotalLen;

	LOG(LOG_TRACE,unReqParasLength, "SendRequest");
	LOG(LOG_INFO,nSock, "SendRequest->SockID");
	LOG(LOG_INFO,unReqParasLength, "SendRequest->ReqParasLength");

	if(unReqParasLength > MAX_BUFFER_SIZE_EX)
	{
		LOG(LOG_ERROR,unReqParasLength, "SendRequest->req data length error");
		return SDR_PARAMETERS;
	}

	unTotalLen = unReqParasLength + 2;//2字节长度
	if((pbSendBuffer = malloc(unTotalLen)) == NULL)
	{
		LOG(LOG_ERROR,unTotalLen, "SendRequest->malloc error");
		return SDR_UNKNOWERR;
	}
	pbSendBuffer[0] = (unReqParasLength>>8)&0xFF;
	pbSendBuffer[1] = unReqParasLength & 0xFF;

	if(unReqParasLength > 0)
		memcpy(pbSendBuffer + 2, pbReqParas, unReqParasLength);

	rest = unTotalLen;
	sent = 0;
	while((rv = send(nSock,(const char *)pbSendBuffer + sent, rest,0)) < rest) 
	{
		if(rv <=0)  
		{
			LOG(LOG_ERROR,SWR_SOCKET_SEND, "SendRequest->send ReqHeader error");
			free(pbSendBuffer);
			return SWR_SOCKET_SEND;
		}
		sent += rv;
		rest -= rv;
	}

	free(pbSendBuffer);

	LOG(LOG_TRACE,0, "SendRequest->return");
	return SDR_OK;
}

UINT ReceiveResponse_Racal(UINT nSock,byte *pbResParas, UINT *punResParasLength, UINT *punTimeout)
{
	int rv;
	unsigned int  rest, recved;
	unsigned char stFirst[4];
	fd_set fdevents;
	struct timeval tv;
	unsigned char *tmpBuf = NULL;
#if defined(WIN32) || defined(WIN64)
	clock_t clockStart, clockEnd;
#else
	struct timeval tvStart, tvEnd;
#endif
	LOG(LOG_TRACE,0, "ReceiveResponse");

	LOG(LOG_INFO,nSock, "ReceiveResponse->SockID");
	LOG(LOG_INFO,*punResParasLength, "ReceiveResponse->ResParasLength");
	LOG(LOG_INFO,*punTimeout, "ReceiveResponse->Timeout");

#if defined(WIN32) || defined(WIN64)
	clockStart = clock();
#else
	gettimeofday(&tvStart, NULL);
#endif

	tv.tv_sec = *punTimeout;
	tv.tv_usec = 0;
	FD_ZERO(&fdevents);
	FD_SET((unsigned int)nSock,&fdevents);

	if ((rv = select(nSock+1,&fdevents,NULL,NULL,&tv)) <= 0)
	{
		LOG(LOG_ERROR,SDR_TIMEOUT, "ReceiveResponse->receive timeout");
#if defined(WIN32) || defined(WIN64)
		LOG(LOG_ERROR,WSAGetLastError(), "ReceiveResponse->WSAGetLastError");
#else
		LOG(LOG_ERROR, errno, "ReceiveResponse->receive ResHeader error");
#endif	
		return SDR_TIMEOUT;	
	}

	//first: Receive first 2 bytes
	rest = 2;
	recved = 0;	
	while(rest > 0) 
	{
		rv = recv(nSock, (char *)stFirst + recved, rest, 0);
		LOG(LOG_INFO,rv, "ReceiveResponse->receive ResHeader");
		if (rv==0)
		{
#if defined(WIN32) || defined(WIN64)
			Sleep(5);
#else
			sleep(5);
#endif
			rv = recv(nSock, (char *)stFirst + recved, rest, 0);
			LOG(LOG_INFO,rv, "ReceiveResponse->receive ResHeader");
			if (rv==0)
			{
				LOG(LOG_ERROR,SWR_SOCKET_RECV, "ReceiveResponse->receive ResHeader return 0");
				return SWR_SOCKET_RECV;
			}
			LOG(LOG_ERROR,SWR_SOCKET_RECV, "ReceiveResponse->receive ResHeader return 0");
			return SWR_SOCKET_RECV;
		}
		if(rv <0)
		{
#if defined(WIN32) || defined(WIN64)
			LOG(LOG_ERROR, WSAGetLastError(), "ReceiveResponse->receive ResHeader error");
#else
			LOG(LOG_ERROR, errno, "ReceiveResponse->receive ResHeader error");
#endif			
			return SWR_SOCKET_RECV;
		}
		recved += rv;
		rest -= rv;
	}

	//check return parameters length
	rest = (stFirst[0] << 8) + stFirst[1];
	if(*punResParasLength < rest)
	{
		LOG(LOG_ERROR,rest, "ReceiveResponse->rest");
		if(MAX_BUFFER_SIZE_EX < rest)
		{
			LOG(LOG_ERROR,rest, "ReceiveResponse->receive data length error");
			return SDR_UNKNOWERR;
		}
		if(rest > 0)
		{
			//分配的缓冲区过小，将剩余数据读出抛弃
			if((tmpBuf = malloc(rest)) == NULL)
			{
				LOG(LOG_ERROR,rest, "ReceiveResponse->malloc error");
				return SDR_UNKNOWERR;
			}
			recved = 0;
			while(0 < rest) 
			{
				rv = recv(nSock, (char *)&tmpBuf[recved], rest, 0);
				if(rv <= 0)
				{
					LOG(LOG_ERROR,SDR_UNKNOWERR, "ReceiveResponse->receive unwanted data error");
					free(tmpBuf);
					return SDR_UNKNOWERR;
				}
				recved += rv;
				rest -= rv;
			}
		}
		if(tmpBuf != NULL)
			free(tmpBuf);
		LOG(LOG_ERROR,rest, "ReceiveResponse->rest");
		return SDR_UNKNOWERR;
	}

	*punResParasLength = rest;
	if(rest <= 0)
	{
		LOG(LOG_TRACE,0, "ReceiveResponse->return");
		return SDR_OK;
	}

	//second: Receive response parameters
	recved = 0;
	while(0 < rest) 
	{
		rv = recv(nSock, (char *)&pbResParas[recved], rest, 0);
		LOG(LOG_INFO,rv, "ReceiveResponse->receive ResParas");
		if (rv==0)
		{
			LOG(LOG_ERROR,SWR_SOCKET_RECV, "ReceiveResponse->receive ResParas return 0");
			return SWR_SOCKET_RECV;
		}
		if(rv <0)
		{
			LOG(LOG_ERROR,rest, "ReceiveResponse->receive ResParas error");
#if defined(WIN32) || defined(WIN64)
			LOG(LOG_ERROR,WSAGetLastError(), "ReceiveResponse->receive ResParas error");
#else
			LOG(LOG_ERROR, errno, "ReceiveResponse->receive ResParas error");
#endif
			return SWR_SOCKET_RECV;
		}
		recved += rv;
		rest -= rv;
	}

#if defined(WIN32) || defined(WIN64)
	clockEnd = clock();  
	*punTimeout -= (clockEnd - clockStart) * 1000 / CLOCKS_PER_SEC;
#else
	gettimeofday(&tvEnd, NULL);
	*punTimeout -= (tvEnd.tv_sec - tvStart.tv_sec) * 1000 + tvEnd.tv_usec/1000 - tvStart.tv_usec/1000;
#endif

	LOG(LOG_TRACE,0, "ReceiveResponse->return");
	return SDR_OK;
}


UINT SocketCommunication_Racal(UINT nSock,byte *pbReqParas,UINT unReqParasLen,byte *pbResParas,UINT *punResParasLen,UINT unTimeout)
{
	int rv = SDR_OK;
	unsigned int unInteralTimeout;

	LOG(LOG_TRACE,0, "SocketCommunication");

	unInteralTimeout = unTimeout ; //step1 1/3 timeout for 1st socket comm
	rv = SendRequest_Racal(nSock, pbReqParas, unReqParasLen);
	if(rv == SDR_OK)
	{
		rv = ReceiveResponse_Racal(nSock, pbResParas, punResParasLen, &unInteralTimeout);
		if(rv != SDR_OK)
		{		
			LOG(LOG_ERROR,unReqParasLen, "SocketCommunication->ReceiveResponse");

			return rv;
		}
	}
	else
	{
		LOG(LOG_ERROR,rv, "SocketCommunication->SendRequest");
		return rv;
	}
	//重连后期增加，暂不支持

	LOG(LOG_TRACE,0, "SocketCommunication->return");
	return SDR_OK;
}
