/*********************************************************************/
/* 文 件 名：  unionsck.h                                            */
/* 版 本 号：  v1.1                                                  */
/* 所 有 者：  Flyger Zhuang                                         */
/* 版    权：  Union Beijing                                         */
/* 功    能：  农行ICCM_密钥安全系统_第05号_加密机接口（国密）api      */
/* 维护记录： 1. 2008-6-11 by  Liwb                                  */
/*           2. 2009-4-21 by Chendy	                            */
/*********************************************************************/

#ifndef _UNIONSCK_H_
#define _UNIONSCK_H_

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <setjmp.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/select.h>


typedef unsigned int UINT;

typedef	void Sigfunc(int);/* for signal handlers */
static void connect_alarm(int sigo);

/* modify by xusj 20081211 */
int UnionCkTm(int sk, UINT tm);
//int UnionConnect(int sk, int nAdderss, int nPort, UINT tm);
int UnionConnect(int nAdderss, int nPort, int *sk, UINT tm);
int UnionCreateSocketClient(char *ip,int port, UINT tm);
int UnionCloseSocket(int sockfd);
int UnionSendToSocket(int sckid, char *buf, int len);
int UnionReceiveFromSocket(int sckid, char *buf,int len);
int UnionIsSocket(int sckid);//add by zhangx 20120711
/* modify end */

/* add by lisq 2012012 */
/* add by lisq 20120112 end */

#endif
