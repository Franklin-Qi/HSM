/*********************************************************************/
/* 文 件 名：  unionsck.c                                            */
/* 版 本 号：  v1.1                                                  */
/* 所 有 者：  Flyger Zhuang                                         */
/* 版    权：  Union Beijing                                         */
/* 功    能：  农行ICCM_密钥安全系统_第05号_加密机接口（国密）api      */
/* 维护记录： 1. 2008-6-11 by  Liwb                                  */
/*           2. 2009-4-21 by Chendy	                            */
/*********************************************************************/

#include "unionsck.h"

#if 0
jmp_buf gConnFlg;

void connHsmTmOut(int arg)
{
#ifdef _LINUX_
    siglongjmp(gConnFlg, 10);
#else
    longjmp(gConnFlg, 10);
#endif
}
#endif
int SetSysTemBuf(int m_Socket,int length)
{
	//
	int rcvbuf; 
	int rcvbufsize=sizeof(int); 

	//	if(getsockopt(m_Socket,SOL_SOCKET,SO_RCVBUF,(char*)&rcvbuf,&rcvbufsize)==0) 
	//	{ 
		//	if(rcvbuf<length) 
			rcvbuf=length; 
			setsockopt(m_Socket,SOL_SOCKET,SO_RCVBUF,(char*) &rcvbuf,rcvbufsize); 
			#ifdef _DEBUG
			union_err_log("In UnionConnect::set recve buf ok HSM");
			#endif
	//	} else
	//	{
		//		return -1;
		//}

		//if(getsockopt(m_Socket,SOL_SOCKET,SO_SNDBUF,(char*) &rcvbuf,&rcvbufsize)==0) 
		//{ 
			//	if(rcvbuf<length) 
				rcvbuf=length; 
				setsockopt(m_Socket,SOL_SOCKET,SO_SNDBUF,(char*)&rcvbuf,rcvbufsize); 
			#ifdef _DEBUG
			union_err_log("In UnionConnect::set send  buf ok HSM");
			#endif
	//	} else
	//	{
		//	return -1;
		//}  
		return 0;
		
}

int UnionCkTm(int sk, UINT tm)
{

    int ret, err;
    fd_set wset;
    struct timeval tv, stTm, stNow;
    socklen_t errlen;
    struct sigaction sa;

    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, 0);

    gettimeofday(&stTm, NULL);
    stTm.tv_sec += tm;
    tv.tv_sec = tm; 	
    while(1)
    {
	gettimeofday(&stNow, NULL);	
	if(stNow.tv_sec >= stTm.tv_sec)
	{
#ifdef _DEBUG
	    union_err_log("In UnionCkTm::Connect to HSM TimeOut");
#endif
	    return -1;		
	}
	else
	{
	    tv.tv_sec = (stTm.tv_sec - stNow.tv_sec);	
	    tv.tv_usec = 0;	
	}

	FD_ZERO(&wset);
	FD_SET(sk, &wset);
	ret = select(sk+1, NULL, &wset, NULL, &tv);
	if(ret <= 0)
	{
#ifdef _DEBUG
	    union_err_log("In UnionCkTm::Failed to Select");
#endif
	    return -1;
	}
	
	if(FD_ISSET(sk, &wset))
	{
#ifdef _DEBUG
	    union_log("In UnionCkTm::Select Successfuly");
#endif
	    return 0;
	}

	if(!FD_ISSET(sk, &wset))
	{
#ifdef _DEBUG
	    union_err_log("In UnionCkTm::Failed to Exit");
#endif
	    return -1;
	}

	err = 0;
	errlen = sizeof(err);
	if(getsockopt(sk, SOL_SOCKET, SO_ERROR, &err, &errlen)==-1)
	{
#ifdef _DEBUG
	    union_err_log("In UnionCkTm::Failed to getsockopt");
#endif
	    return -1;
	}
	if(err)
	{
#ifdef _DEBUG
	    union_err_log("In UnionCkTm::Failed to err[%d]", err);
#endif
	    return -1;
	}     
    }

}


int UnionConnect(int nAdderss, int nPort, int *nSockfd, UINT tm)
{

    struct sockaddr_in dest_addr;
    int iFlag = 0, ret;
    int sockfd = -1;
    int rcvbuf=32*1024; 
		int rcvbufsize=sizeof(int); 

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
#ifdef _DEBUG
        printf("In UnionConnect::Failed to socket");
#endif
	return -1;
    }
  
  //  iFlag = fcntl(sockfd, F_GETFL, 0);    
 //   ÐÞžÄ·Ç×èÈûÄ£ÊœÎª×èÈûÄ£Êœ
   // fcntl(sockfd, F_SETFL, iFlag | O_NONBLOCK);
     fcntl(sockfd, F_GETFL, 0);

    memset((char *)&dest_addr, 0, sizeof(struct sockaddr_in));

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(nPort);
    dest_addr.sin_addr.s_addr = nAdderss;

    ret = connect(sockfd, (struct sockaddr *)&dest_addr, sizeof(struct sockaddr));
    if(setsockopt(sockfd,SOL_SOCKET,SO_RCVBUF,(char*)&rcvbuf,rcvbufsize)!=0)
    	{
    		#ifdef _DEBUG
        printf("In UnionConnect::set socket recive buf fail----------");
				#endif
    		}; 
    	if(setsockopt(sockfd,SOL_SOCKET,SO_SNDBUF,(char*)&rcvbuf,rcvbufsize)!=0)
    	{
    		#ifdef _DEBUG
        printf("In UnionConnect::set socket fail send buf fail----------");
				#endif
    		};
    if(ret == 0)
    {
			*nSockfd = sockfd;
			return 0;
    }

    if((ret < 0) && (errno != EINPROGRESS))
    {
			#ifdef _DEBUG
			union_err_log("In UnionConnect::Failed to Connect HSM");
			#endif
			return -1;	
    }
    else
    {
			ret = UnionCkTm(sockfd, tm);
			if(!ret)
			{
	   	 *nSockfd = sockfd;
	   	 			#ifdef _DEBUG
			union_err_log("In UnionConnect::Useing ckTm!-------");
			#endif
	    	return 0;
			}
			else
			{
	    	return -1;
			}
    }

}

/***************************************************/
/*      Function:       UnionCreatSocketClient()   */
/*      Input   :       ip                         */
/*                      port                       */
/*      Output  :       None                       */
/*      return  :                                  */
/***************************************************/
int UnionCreateSocketClient(char *ip,int port, UINT nTimeout)
{

    struct sockaddr_in psckadd;
    int	sckcli=-1;
    struct linger Linger;
    int	on = 1;
    int	ret;
    int nAdderss;
 
    nAdderss = inet_addr(ip);
    ret = UnionConnect(nAdderss, port, &sckcli, nTimeout);
    if(ret != 0)
    {
#ifdef	DEBUG
         union_err_log("In UnionCreatSocketClient::Could not " \
		"connect socket in nonblock mode");
#endif
         UnionCloseSocket(sckcli);
         return -1;
    }

    Linger.l_onoff = 1;
    Linger.l_linger = 0;
    if (setsockopt(sckcli,SOL_SOCKET,SO_LINGER,(char *)&Linger,sizeof(Linger)) != 0)
    {
#ifdef	DEBUG
        union_err_log("In UnionCreatSocketClient::setsockopt linger!");
#endif
	UnionCloseSocket(sckcli);
	return -1;
    }
    if (setsockopt(sckcli, SOL_SOCKET, SO_OOBINLINE, (char *)&on, sizeof(on)))
    {
#ifdef	DEBUG
	union_err_log("In UnionCreatSocketClient::setsockopt SO_OOBINLINE!\n");
#endif
	UnionCloseSocket(sckcli);
	return -1;
    }

    on = 1;
    if (setsockopt(sckcli, IPPROTO_TCP, TCP_NODELAY, (char *)&on, sizeof(on)))
    {
#ifdef	DEBUG
	union_err_log("In UnionCreatSocketClient::setsockopt: TCP_NODELAY");
#endif
	UnionCloseSocket(sckcli);
	return -1;
    }

#ifdef	DEBUG
    union_log("In UnionCreatSocketClient::HSM ip=[%s]",ip);
#endif

    return(sckcli);

}

/***************************************************/
/*      Function:       UnionCloseSocket()         */
/*      Input   :       sockfd                     */
/*      Output  :       None                       */
/*      return  :                                  */
/***************************************************/

int UnionCloseSocket(int sockfd)
{
#ifdef _WIN32
    if (closesocket(sockfd) != 0)
	    printf("close client connection error!\n");
    else
	    printf("close client connection successfully!\n");

    if (WSACleanup()!=0)
    {
#ifdef _DEBUG
	union_err_log("WSACleanup fail");
#endif
	return (-1);
    }
#else   
    shutdown(sockfd, 2);

    if (close(sockfd) != 0)
    {
#ifdef _DEBUG
	union_err_log("In UnionCloseSocket::Close Client Conn Error");
#endif
	return (-1);
    }
#endif
    return(0);
}

/***************************************************/
/*      Function:       UnionSendToSocket()        */
/*      Input   :       sockfd                     */
/*                      buf                        */
/*                      len                        */
/*                      timeout                    */
/*      Output  :       None                       */
/*      return  :                                  */
/***************************************************/
int UnionSendToSocket(int sckid, char *buf, int len)
{
    	  
#ifdef _DEBUG
    unsigned char out[8192]; 
    memset(out, 0, sizeof(out));
    if(NULL != buf)
    {
	UnpackBCD(buf+2, (char *)out, (len-2)*2);
	union_log("In SendToSocket::buf=[%s],len=[%d]", out, len);
    }
#endif
    if(send(sckid, buf, len, 0) != len)
    {
	UnionCloseSocket(sckid);
#ifdef _DEBUG
	union_err_log("In SendToSocket::Send data to HSM wrong!" );
#endif
	return(-1);
    }
    return len;
}

/***************************************************/
/*      Function:       UnionReceiveFromSocket()   */
/*      Input   :       sockfd                     */
/*                      len                        */
/*                      timeout                    */
/*      Output  :       buf                        */
/*      return  :                                  */
/***************************************************/

int UnionReceiveFromSocket(int sckid, char *buf,int len)
{

    int ret;

    if((ret = recv(sckid, buf, len, 0)) < 0)
    {
	UnionCloseSocket(sckid);
#ifdef _DEBUG	
	union_err_log("In ReceiveFromSocket:: Receive data from HSM wrong!");
#endif
	return(-1);
    }

#ifdef _DEBUG	
    union_log("In ReceiveFromSocket::buf=[%x]",buf+2);
#endif
    return (ret);

}
/***************************************************/
/*      Function:       UnionIsSocket()            */
/*      Input   :       sckid                      */
/*      return  :       1:yes 0:no  -1:error       */
/***************************************************/
int UnionIsSocket(int sckid)
{
    struct stat fdstat; 
    if(fstat(sckid, &fdstat) != 0) 
        return 0; 
    return S_ISSOCK(fdstat.st_mode);
    //return isfdtype(sckid, S_IFSOCK);
}

