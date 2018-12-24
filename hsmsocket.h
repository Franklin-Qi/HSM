#ifndef __HSM_API_SOCKET_H__
#define __HSM_API_SOCKET_H__

int TCP_ConnectHsm( char *hostip, int hostport );
int TCP_DisconnectHsm( int sockfd );
int TCP_CommunicateHsm( int sockfd,
    unsigned char *pucInput, int iInputLen,
    unsigned char *pucOutput, int *piOutputLen );
    
int TCP_CommunicateHsm_ex( void *hSessionHandle,int nSock,
        unsigned char *pucCmd, int iCmdLen,
        unsigned char *pucRsp, int *piRspLen);


#endif    /***  __HSM_API_SOCKET_H__ ***/
