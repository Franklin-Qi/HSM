/*----------------------------------------------------------------------|
|    hsmapi_log.h -   The header file of hsmapi_log.c                   |
|    Version :     1.0                                                  |
|    Author:       by lcj.                                              |
|    Description:                                                       |
|    Copyright :   Beijing JN TASS Technology Co., Ltd.                 |
|    data:         2015-05-25. Create                                   |
|-----------------------------------------------------------------------|
|    Modify History:                                                    |
|----------------------------------------------------------------------*/
#ifndef __HSMAPI_LOG_H__
#define __HSMAPI_LOG_H__
#include <stdio.h>

#define LOG_ERROR_LEVEL 0
#define LOG_TRACE_LEVEL 1


#define LINE_LEN 16

#ifdef __cplusplus
extern "C" {
#endif
/***************************************************************************
* Subroutine: Log_GetFileLength
* Function:   获取日志文件大小
* Input:
*   @pcFileName   文件名称
* Output:
*   无
*
* Return:       返回文件字节数
* Description:
* Date:         2015.05.25
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
unsigned long Log_GetFileLength(char *pcFileName);


/***************************************************************************
* Subroutine: Log_GetTime
* Function:   获取系统当前时间
* Input:
*    @pcBuffer        存储时间字符串缓存区
*    @iBufferLen      存储时间字符串的长度
*    @pcFormat        时间格式
* Output:
*   无
*
* Return:       系统当前时间
* Description:
* Date:         2015.05.22
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
char *Log_GetTime(char *pcBuffer, int iBufferLen, const char *pcFormat);

/***************************************************************************
* Subroutine: Log_HexDumpBuffer
* Function:   将日志信息以十六进制写入文件
* Input:
*    @fp            文件描述符
*    @buffer        日志信息
*    @len           日志信息数据
* Output:
*   无
*
* Return:       成功返回0 ，失败返回其他
* Description:
* Date:         2015.05.22
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
int Log_HexDumpBuffer(FILE *fp, unsigned char *buffer, int length);

/***************************************************************************
* Subroutine: Log_HexDumpOneLine
* Function:   将日志信息以十六进制写入文件(写入一行)
* Input:
*    @fp            文件描述符
*    @buffer        日志信息
*    @len           日志信息数据
*    @line          本条日志信息打印的行数
* Output:
*   无
*
* Return:       成功返回0 ，失败返回其他
* Description:
* Date:         2015.05.22
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
int Log_HexDumpOneLine(FILE *fp, unsigned char *buffer, int *len, int *line);

/***************************************************************************
* Subroutine: Log_ErrorMessage
* Function:   打印错误日志
* Input:
*   @iLine          日志信息所在代码的行数
*   @pcFuncName     日志信息所在的函数名
*   @pcFormat       要打印的日志信息
* Output:
*   无
*
* Return:       无
* Description:
* Date:         2015.05.25
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
void Log_ErrorMessage(int iLine, const char *pcFuncName, const char *pcFormat, ...);

/***************************************************************************
* Subroutine: Log_TraceMessage
* Function:   打印报文
* Input:
*   @pcTitle          标题
*   @pucBuffer        输出的信息
*   @iBufferLen       输出的信息的字节数
* Output:
*   无
*
* Return:       无
* Description:
* Date:         2015.05.25
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
void Log_TraceMessage(char *pcTitle, unsigned char *pucBuffer, int iBufferLen);

#ifdef DEBUG
#define LOG_ERROR printf
#else
#define LOG_ERROR(format, ...) Log_ErrorMessage(__LINE__, __FUNCTION__, format, __VA_ARGS__)
#endif

#define LOG_TRACE(title, buffer, len) Log_TraceMessage(title, buffer, len)



#ifdef __cplusplus
}
#endif

#endif /*__HSMAPI_LOG_H__*/

