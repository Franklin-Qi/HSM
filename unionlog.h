/*********************************************************************/
/* 文 件 名：  unionlog.h                                            */
/* 版 本 号：  v1.1                                                  */
/* 所 有 者：  Flyger Zhuang                                         */
/* 版    权：  Union Beijing                                         */
/* 功    能：  农行ICCM_密钥安全系统_第05号_加密机接口（国密）api      */
/* 维护记录： 1. 2008-6-11 by  Liwb                                  */
/*           2. 2009-4-21 by Chendy	                            */
/*********************************************************************/

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
// modify by lisq 2011-12-14
//#include <varargs.h>
#include <errno.h>
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>

#include "type.h"

#define UNIONMAXLOGFILESIZE 100000000

#ifndef __UNIONLOG_H
#define __UNIONLOG_H

/*本日志级别分为6层，实施部署时（生产环境）建议为2或3*/
#define LOG_NONE      0  //不记录日志
#define LOG_CRIT      1  //致命错误，会导致返回错误或引起程序异常
#define LOG_ERROR     2  //一般错误，内部错误不向上层返回错误，建议解决
#define LOG_WARNING   3  //警告信息，不是期望的结果，不会引起错误，但要用户引起重视
#define LOG_INFO      4  //重要变量，有助于解决问题
#define LOG_DEBUG     5  //调试信息，可打印二进制数据
#define LOG_TRACE     6  //跟踪执行，用于跟踪逻辑判断

/*########################################################*/
/*########################################################*/
/*###  重要说明：其他模块使用该日志时，建议修改  ###*/
/*###  宏定义的模块名称和全局变量名              ###*/
/*########################################################*/
/*########################################################*/

#define DEFAULT_LOG_PATH   "log"
#define DEFAULT_LOG_MODULE "HsmSanWei"
#define LOG_FILE_NAME "HsmWeiShiTong.log"

extern char         G_swsds_log_file[512]; //Global
extern unsigned int G_swsds_log_level;     //Global
extern unsigned int G_swsds_log_max_size;  //Global

extern void begin_dump_comm(u8 *);
extern void data_dump(u8 *, u8 *, int);
extern void end_dump_comm(u8 *);
extern void str_dump(u8 *);
extern void int_dump(u8 *str, int);

#define LOG(lvl, rv, msg) \
	do { \
	if ((lvl) <= G_swsds_log_level) {\
	LogMessage(DEFAULT_LOG_PATH, G_swsds_log_file, DEFAULT_LOG_MODULE, lvl, __FILE__, __LINE__, rv, msg);} \
	} while (0)
#define LOGDATA(msg, buf, len) \
	do { \
	if (LOG_DEBUG <= G_swsds_log_level) {\
	LogData(DEFAULT_LOG_PATH, G_swsds_log_file, DEFAULT_LOG_MODULE, LOG_DEBUG, __FILE__, __LINE__, msg, buf, len);} \
	} while (0)

#define LOGDATAEX(msg, buf, len) \
	do { \
{\
	LogData(DEFAULT_LOG_PATH, G_swsds_log_file, DEFAULT_LOG_MODULE, LOG_DEBUG, __FILE__, __LINE__, msg, buf, len);} \
	} while (0)


extern int errlog(char *fmt, ...);

/*########################################################*/
/*########################################################*/
/*###  重要说明：其他模块使用该日志时，建议修改  ###*/
/*###  宏定义的模块名称和全局变量名              ###*/
/*########################################################*/
/*########################################################*/
char *GetTime( char *, int, const char *);
FILE *union_open_logfile();
void union_err_log(char *sfmt,...);
void union_success_log(char *sfmt,...);
void union_log(char *sfmt,...);
int union_close_logfile(FILE *);

long union_PID;


void LogMessage(char *sPath, char *sLogFile, char* sModule, int nLogLevel, char *sFile,int nLine,unsigned int unErrCode, char *sMessage);
void LogData(char *sPath, char *sLogFile, char* sModule, int nLogLevel, char *sFile, int nLine, char *sMessage, unsigned char *pBuffer, unsigned int nLength);


#endif
