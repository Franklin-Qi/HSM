/*********************************************************************/
/* 文 件 名：  unionlog.c                                            */
/* 版 本 号：  v1.1                                                  */
/* 所 有 者：  Flyger Zhuang                                         */
/* 版    权：  Union Beijing                                         */
/* 功    能：  农行ICCM_密钥安全系统_第05号_加密机接口（国密）api      */
/* 维护记录： 1. 2008-6-11 by  Liwb                                  */
/*           2. 2009-4-21 by Chendy	                            */
/*********************************************************************/

#include "type.h"
#include "unionlog.h"

/*########################################################*/
/*########################################################*/
/*###  重要说明：其他模块使用该日志时，建议修改          ###*/
/*###  宏定义的模块名称和全局变量名                      ###*/
/*########################################################*/
/*########################################################*/

char         G_swsds_log_file[512] = "Hsm.log";//Global
unsigned int G_swsds_log_level     = LOG_ERROR;//Global
unsigned int G_swsds_log_max_size  = 2;        //Global


#define MAX_LOG_FILE_LEN  (50 * 1024 * 1024)

int lock_reg(int fd, int cmd, int type, off_t offset, int whence, off_t len)
{
    struct flock lock;

    lock.l_type = type;
    lock.l_start = offset;
    lock.l_whence = whence;
    lock.l_len = len;

    return ( fcntl(fd, cmd, &lock) );
}

#define read_lock(fd, offset, whence, len) lock_reg(fd, F_SETLK, F_RDLCK, offset, whence, len)
#define readw_lock(fd, offset, whence, len)   lock_reg(fd, F_SETLKW, F_RDLCK, offset, whence, len)
#define write_lock(fd, offset, whence, len)  lock_reg(fd, F_SETLK, F_WRLCK, offset, whence, len)
#define writew_lock(fd, offset, whence, len)  lock_reg(fd, F_SETLKW, F_WRLCK, offset, whence, len)
#define un_lock(fd, offset, whence, len)     lock_reg(fd, F_SETLK, F_UNLCK, offset, whence, len)

static char *DbgStr = "****************************";

void getLogFile(char *pLogFile)
{
    char *pPath = NULL;
    pPath = getenv("HSM_LOG_PATH");
    if (pPath != NULL)
    {
        strcpy(pLogFile, pPath);
        if (pPath[strlen(pPath) - 1] != '/')
        {
            strcat(pLogFile, "/");
        }
        strcat(pLogFile, LOG_FILE_NAME);
    }
    else
    {
        strcpy(pLogFile, "./HsmWeiShiTong.log");
    }
}


void WriteLog(char *pszFormat, ...)
{

    FILE *g_fp = NULL;
    long g_lFileLen = 0;
    char g_szLogFile[512] = {'\0'};
    va_list pArg;
    char szTime[50] = {'\0'};
    char cEnd = '\n';
    time_t tmNow;
    struct tm *pTm = NULL;
    int nWriteLen = -1;
    char g_szLogFile_new[256] = {'\0'};

    memset(g_szLogFile_new, 0x00, sizeof(g_szLogFile_new));

    if (strlen(g_szLogFile) == 0)
    {
        getLogFile(g_szLogFile);
    }

    g_fp = fopen(g_szLogFile, "a+");
    if (g_fp == NULL)
    {
        printf("can not open file. please make sure that you have set the environment variable \"HSM_LOG_PATH\" correctly, and try it again.\n");
        return;
    }


   /* 计算文件大小: filelen > maxfilelen */
    fseek(g_fp, 0, SEEK_END);
    g_lFileLen = ftell(g_fp);
    if (g_lFileLen >= MAX_LOG_FILE_LEN)
    {
        fclose(g_fp);
        g_fp = NULL;
        sprintf(g_szLogFile_new, "%s.bak", g_szLogFile);
        rename(g_szLogFile, g_szLogFile_new);
        g_fp = fopen(g_szLogFile, "a+");
        if (g_fp == NULL)
        {
            return;
        }
    }
    else
    {
        fseek(g_fp, -1, SEEK_CUR);
    }

    time(&tmNow);
    pTm = localtime(&tmNow);
    strftime(szTime, sizeof(szTime), "%Y-%m-%d %H:%M:%S\n", pTm);

    nWriteLen = fputs(szTime, g_fp);
    if (nWriteLen < 0)
    {
        fclose(g_fp);
        g_fp = NULL;
        goto END;
    }

    va_start(pArg, pszFormat);
    nWriteLen = fwrite(pszFormat, 1, strlen(pszFormat), g_fp);
    va_end(pArg);
    if (nWriteLen < 0)
    {
        fclose(g_fp);
        g_fp = NULL;
        goto END;
    }

    nWriteLen = fprintf(g_fp, "\n");
    if (nWriteLen < 0)
    {
        fclose(g_fp);
        g_fp = NULL;
        goto END;
    }

    nWriteLen = (int)fwrite(&cEnd, 1, 1, g_fp);
    if (nWriteLen != 1)
    {

        fclose(g_fp);
        g_fp = NULL;
        goto END;
    }

    fflush(g_fp);
    fclose(g_fp);
    g_fp = NULL;

END:

#ifdef DEBUG
    va_start(pArg, pszFormat);
    vprintf(pszFormat, pArg);
    va_end(pArg);
#endif /* DEBUG */
    return;
}

void data_log(char *str, void *inData, int len)
{
    int i, num, prev, curr;
    unsigned char *data = (unsigned char *)inData;
    char *g_szOutBuf = NULL;

    if (len > 10240)
        len = 10240;

    if (str == NULL)
    {
        WriteLog("parameter 1 pointer is NULL");
        return;
    }
    if (inData == NULL)
    {
        WriteLog("parameter 2 pointer is NULL");
        return;
    }


    num = len/16 + 2;

    g_szOutBuf = (char *)malloc(strlen(str) + 80 * num);


    sprintf(g_szOutBuf, "[%s] [length = %d]\n", str, len);
    prev = curr = 0;
    for (i = 0; i < len; i++)
    {
        if (i == (prev + 16))
        {
            i = prev;
            curr = prev + 16;
            sprintf(g_szOutBuf + strlen(g_szOutBuf), "    |    ");
            for (; i < curr; i++)
                if (isprint(data[i]))
                    sprintf(g_szOutBuf + strlen(g_szOutBuf), "%c", data[i]);
                else
                    sprintf(g_szOutBuf + strlen(g_szOutBuf), " ");
            sprintf(g_szOutBuf + strlen(g_szOutBuf), "\n");
            prev = curr;
        }
        sprintf(g_szOutBuf + strlen(g_szOutBuf), "%02x ", (data[i] & 0xff));
    }

    if (i != curr)
    {
        curr = i;
        for (; i < (prev + 16); i++)
            sprintf(g_szOutBuf + strlen(g_szOutBuf), "   ");
        sprintf(g_szOutBuf + strlen(g_szOutBuf), "    |    ");
        for (i = prev ; i < curr; i++)
        {
            if (isprint(data[i]))
                sprintf(g_szOutBuf + strlen(g_szOutBuf), "%c", data[i]);
            else
                sprintf(g_szOutBuf + strlen(g_szOutBuf), " ");
        }
    }
    sprintf(g_szOutBuf + strlen(g_szOutBuf), "\n");

    WriteLog(g_szOutBuf);
    free(g_szOutBuf);
    g_szOutBuf = NULL;
}


void str_log(char *str)
{
    char *g_szOutBuf = NULL;

    if (str == NULL)
    {
        WriteLog("parameter 1 pointer is NULL");
        return;
    }

    g_szOutBuf = (char *)malloc(strlen(str) + 80);

    sprintf(g_szOutBuf, "%s\n", str);

    WriteLog(g_szOutBuf);

    free(g_szOutBuf);
    g_szOutBuf = NULL;
}


void int_log(char *str, int data)
{
    char *g_szOutBuf = NULL;

    if (str == NULL)
    {
        WriteLog("parameter 1 pointer is NULL");
        return;
    }

    g_szOutBuf = (char *)malloc(strlen(str) + 80 * 2);
    sprintf(g_szOutBuf, "[%s]\n", str);
    sprintf(g_szOutBuf + strlen(g_szOutBuf), "Hex = %x Dec = %d\n", data, data);

    WriteLog(g_szOutBuf);
    free(g_szOutBuf);
    g_szOutBuf = NULL;
}


int errlog(char *fmt, ...)
{
    va_list ap;
    int d, n = 0;
    char *s = NULL;
    char str[512] = {'\0'};

    memset((char *)str, 0x00, sizeof(str));

    va_start(ap, fmt);
    while (*fmt)
    {
        if (*fmt == '%')
        {
            fmt++;
            switch (*fmt++)
            {
            case 's':                       /*   string   */
                s = va_arg(ap, char *);
                d = strlen(s);
                data_log(str, s, d);
                va_end(ap);
                return 0;
            case 'x':
                s = va_arg(ap, char *);
                d = va_arg(ap, int);
                data_log(str, s, d);
                va_end(ap);
                return 0;
            case 'd':                       /*   int   */
                d = va_arg(ap, int);
                int_log(str, d);
                va_end(ap);
                return 0;
            case 'c':
            default:
                str_log(str);
                va_end(ap);
                return 0;
            }
        }
        else
        {
            if (n < sizeof(str))
            {
                str[n++] = *fmt;
                fmt++;
            }
        }
    }

    str_log(str);
    va_end(ap);

    return 0;
}


/*Windows: 在系统安装盘符根目录*/
/*Linux/Unix: 在TMP目录*/
static FILE * OpenLogFile(char *sPath, char *sLogFile, char* sModule)
{
	FILE *fp;
	struct tm *newtime;
	time_t aclock;
	char sRealLogFile[300];
	char sLogPath[256];

	/*Get current time*/
	time( &aclock );                 
	newtime = localtime( &aclock ); 

	/*Get log file name*/
	if(strlen(sLogFile) == 0)
	{
#if defined(WIN32) || defined(WIN64)
		GetWindowsDirectoryA(sLogPath, sizeof(sLogPath)-1);
		sLogPath[2] = '\0'; /*只取系统盘符*/
		strcat(sLogPath, "\\");
		strcat(sLogPath, sPath);
		strcat(sLogPath, "\\");
#else
		sprintf(sLogPath, "/tmp/%s/", sPath);
#endif
		sprintf(sRealLogFile,"%s%s_%4d%02d%02d.log",sLogPath, sModule, newtime->tm_year+1900,newtime->tm_mon+1,newtime->tm_mday);
		/*Open log file*/
		fp = fopen(sRealLogFile,"a+");   
	}
	else
	{
		/*Open log file*/
		fp = fopen(sLogFile,"a+");   
	}

	return fp;
}

void LogMessage(char *sPath, char *sLogFile, char* sModule, int nLogLevel, char *sFile,int nLine,unsigned int unErrCode, char *sMessage)
{
#if defined(WIN32) || defined(WIN64)
	DWORD pid;
	DWORD nThreadID;
#else
	unsigned int pid;
	unsigned int nThreadID;
#endif
	struct tm *newtime;
	time_t aclock;

	/*Open log file*/
	FILE *fp = OpenLogFile(sPath, sLogFile, sModule);
#ifndef PRINT_LOG
	if(NULL == fp)
		return;
#endif
	/*Get current time*/
	time( &aclock );                 
	newtime = localtime( &aclock ); 

	/*Get current threadid*/
#if defined(WIN32) || defined(WIN64)
	pid = GetCurrentProcessId();
	nThreadID = GetCurrentThreadId();
#else
	pid = getpid();
	nThreadID = 0;//pthread_self();
#endif

	/*Write log message*/
	switch(nLogLevel)
	{
	case LOG_CRIT:
		if(NULL != fp)
			fprintf(fp,"\n<%4d-%02d-%02d %02d:%02d:%02d><%s><%d><%d><Erit>[0x%08x]%s(%s:%d)",newtime->tm_year+1900,newtime->tm_mon+1,newtime->tm_mday,newtime->tm_hour,newtime->tm_min,newtime->tm_sec,sModule,pid,nThreadID, unErrCode, sMessage, sFile,nLine);
#ifdef PRINT_LOG
		printf("\n<%4d-%02d-%02d %02d:%02d:%02d><%s><%d><%d><Error>[0x%08x]%s(%s:%d)",newtime->tm_year+1900,newtime->tm_mon+1,newtime->tm_mday,newtime->tm_hour,newtime->tm_min,newtime->tm_sec,sModule,pid,nThreadID,unErrCode, sMessage, sFile,nLine);
#endif
		break;
	case LOG_ERROR:
		if(NULL != fp)
			fprintf(fp,"\n<%4d-%02d-%02d %02d:%02d:%02d><%s><%d><%d><Error>[0x%08x]%s(%s:%d)",newtime->tm_year+1900,newtime->tm_mon+1,newtime->tm_mday,newtime->tm_hour,newtime->tm_min,newtime->tm_sec,sModule,pid,nThreadID, unErrCode, sMessage, sFile,nLine);
#ifdef PRINT_LOG
		printf("\n<%4d-%02d-%02d %02d:%02d:%02d><%s><%d><%d><Error>[0x%08x]%s(%s:%d)",newtime->tm_year+1900,newtime->tm_mon+1,newtime->tm_mday,newtime->tm_hour,newtime->tm_min,newtime->tm_sec,sModule,pid,nThreadID,unErrCode, sMessage, sFile,nLine);
#endif
		break;
	case LOG_WARNING:
		if(NULL != fp)
			fprintf(fp,"\n<%4d-%02d-%02d %02d:%02d:%02d><%s><%d><%d><Warning>%s<%d>(%s:%d)",newtime->tm_year+1900,newtime->tm_mon+1,newtime->tm_mday,newtime->tm_hour,newtime->tm_min,newtime->tm_sec,sModule, pid,nThreadID, sMessage, unErrCode, sFile,nLine);
#ifdef PRINT_LOG
		printf("\n<%4d-%02d-%02d %02d:%02d:%02d><%s><%d><%d><Warning>%s<%d>(%s:%d)",newtime->tm_year+1900,newtime->tm_mon+1,newtime->tm_mday,newtime->tm_hour,newtime->tm_min,newtime->tm_sec,sModule,pid,nThreadID, sMessage, unErrCode, sFile,nLine);
#endif
		break;
	case LOG_INFO:
		if(NULL != fp)
			fprintf(fp,"\n<%4d-%02d-%02d %02d:%02d:%02d><%s><%d><%d><Info>%s(%d)(%s:%d)",newtime->tm_year+1900,newtime->tm_mon+1,newtime->tm_mday,newtime->tm_hour,newtime->tm_min,newtime->tm_sec,sModule, pid,nThreadID, sMessage,  unErrCode, sFile,nLine);
#ifdef PRINT_LOG
		printf("\n<%4d-%02d-%02d %02d:%02d:%02d><%s><%d><%d><Info>%s(%d)(%s:%d)",newtime->tm_year+1900,newtime->tm_mon+1,newtime->tm_mday,newtime->tm_hour,newtime->tm_min,newtime->tm_sec,sModule,pid,nThreadID, sMessage,  unErrCode, sFile,nLine);
#endif
		break;
	case LOG_DEBUG:
		if(NULL != fp)
			fprintf(fp,"\n<%4d-%02d-%02d %02d:%02d:%02d><%s><%d><%d><Debug>%s(%d)(%s:%d)",newtime->tm_year+1900,newtime->tm_mon+1,newtime->tm_mday,newtime->tm_hour,newtime->tm_min,newtime->tm_sec,sModule, pid,nThreadID, sMessage,  unErrCode, sFile,nLine);
#ifdef PRINT_LOG
		printf("\n<%4d-%02d-%02d %02d:%02d:%02d><%s><%d><%d><Info>%s(%d)(%s:%d)",newtime->tm_year+1900,newtime->tm_mon+1,newtime->tm_mday,newtime->tm_hour,newtime->tm_min,newtime->tm_sec,sModule,pid,nThreadID, sMessage,  unErrCode, sFile,nLine);
#endif
		break;
	case LOG_TRACE:
		if(NULL != fp)
			fprintf(fp,"\n<%4d-%02d-%02d %02d:%02d:%02d><%s><%d><%d><Trace>%s(%s:%d)",newtime->tm_year+1900,newtime->tm_mon+1,newtime->tm_mday,newtime->tm_hour,newtime->tm_min,newtime->tm_sec,sModule, pid,nThreadID, sMessage, sFile,nLine);
#ifdef PRINT_LOG
		printf("\n<%4d-%02d-%02d %02d:%02d:%02d><%s><%d><%d><Trace>%s(%s:%d)",newtime->tm_year+1900,newtime->tm_mon+1,newtime->tm_mday,newtime->tm_hour,newtime->tm_min,newtime->tm_sec,sModule,pid,nThreadID, sMessage, sFile,nLine);
#endif
		break;
	default:
		break;
	}

	/*Close file handle*/
	if(NULL != fp)
		fclose(fp);
}

void LogData(char *sPath, char *sLogFile, char* sModule, int nLogLevel, char *sFile, int nLine, char *sMessage, unsigned char *pBuffer, unsigned int nLength)
{
	int i,j;
	char sLine[128];
	int rowCount = 16;
	char *ch;
	unsigned char low, high;

#if defined(WIN32) || defined(WIN64)
	DWORD pid;
	DWORD nThreadID;
#else
	unsigned int pid;
	unsigned int nThreadID;
#endif
	struct tm *newtime;
	time_t aclock;

	/*Open log file*/
	FILE *fp = OpenLogFile(sPath, sLogFile, sModule);
#ifndef PRINT_LOG
	if(NULL == fp)
		return;
#endif

	time( &aclock );
	newtime = localtime( &aclock ); 

#if defined(WIN32) || defined(WIN64)
	pid = GetCurrentProcessId();
	nThreadID = GetCurrentThreadId();
#else
	pid = getpid();
	nThreadID = 0;//pthread_self();
#endif

	/*Write log message*/
	if(NULL != fp)
		fprintf(fp,"\n<%4d-%02d-%02d %02d:%02d:%02d><%s><%d><%d><Debug>%s(%d)(%s:%d)",newtime->tm_year+1900,newtime->tm_mon+1,newtime->tm_mday,newtime->tm_hour,newtime->tm_min,newtime->tm_sec,sModule,  pid,nThreadID, sMessage,  nLength, sFile,nLine);
#ifdef PRINT_LOG
	printf("\n<%4d-%02d-%02d %02d:%02d:%02d><%s><%d><%d><Info>%s(%d)(%s:%d)",newtime->tm_year+1900,newtime->tm_mon+1,newtime->tm_mday,newtime->tm_hour,newtime->tm_min,newtime->tm_sec,sModule, pid,nThreadID, sMessage,  nLength, sFile,nLine);
#endif
	fprintf(fp, "\r\n");//数据另起一行
	if(nLength > 0)
	{
		i = 0;
		for(i=0;i<(int)nLength/rowCount;i++)
		{
			sprintf(sLine, "0x%08x  ",i*rowCount);
			ch = &sLine[12];
			for(j=0;j<rowCount;j++)
			{
				low = pBuffer[i * rowCount + j] & 0x0f;
				high = pBuffer[i * rowCount + j]>>4;

				if(high <= 9)
					*(ch++) = high + '0';
				else
					*(ch++) = high - 10 + 'A';

				if(low <= 9)
					*(ch++) = low + '0';
				else
					*(ch++) = low - 10 + 'A';

				*(ch++) = ' ';
			}
			*(ch++) = ' ';
			for(j=0;j<rowCount;j++)
			{
				if((pBuffer[i * rowCount + j] >= 33) && (pBuffer[i * rowCount + j] <= 126)) //Visible character
					*(ch++) = pBuffer[i * rowCount + j];
				else
					*(ch++) = '.';
			}
#if defined(WIN32) || defined(WIN64)
			*(ch++) = '\r';
#endif
			*(ch++) = '\n';
			*(ch++) = '\0';
			if(NULL != fp)
				fputs(sLine, fp);
#ifdef PRINT_LOG
			fputs(sLine, stdout);
#endif
		}

		if (nLength%rowCount)
		{
			sprintf(sLine, "0x%08x  ",i*rowCount);
			ch = &sLine[12];
			for(j=0;j<(int)nLength%rowCount;j++)
			{
				low = pBuffer[i * rowCount + j] & 0x0f;
				high = pBuffer[i * rowCount + j]>>4;

				if(high <= 9)
					*(ch++) = high + '0';
				else
					*(ch++) = high - 10 + 'A';

				if(low <= 9)
					*(ch++) = low + '0';
				else
					*(ch++) = low - 10 + 'A';

				*(ch++) = ' ';
			}
			for(j=0;j<rowCount - (int)nLength%rowCount;j++)
			{
				*(ch++) = ' ';
				*(ch++) = ' ';
				*(ch++) = ' ';
			}
			*(ch++) = ' ';
			for(j=0;j<(int)nLength%rowCount;j++)
			{
				if((pBuffer[i * rowCount + j] >= 33) && (pBuffer[i * rowCount + j] <= 126)) //Visible character
					*(ch++) = pBuffer[i * rowCount + j];
				else
					*(ch++) = '.';
			}
#if defined(WIN32) || defined(WIN64)
			*(ch++) = '\r';
#endif
			*(ch++) = '\n';
			*(ch++) = '\0';
			if(NULL != fp)
				fputs(sLine, fp);
#ifdef PRINT_LOG
			fputs(sLine, stdout);
#endif
		}//end if (nLength%rowCount)
	}//end if(nLength > 0)

	/*Close file handle*/
	if(NULL != fp)
		fclose(fp);
}

char *GetTime( char *Buffer, int Len, const char *format )
{
    time_t        clock;

    clock = time((time_t *)0);
    strftime(Buffer,Len,format,localtime(&clock));

    return(Buffer);
}

FILE *union_open_logfile()
{
    int        	i;
    char       	buf[512];
    FILE 		*union_logfile;
    char 		UNIONLOGFILENAME[512];

    memset(UNIONLOGFILENAME,0,512);

    //sprintf(UNIONLOGFILENAME,"%s/log/unionhsm.log",getenv("HOME"));	
    sprintf(UNIONLOGFILENAME,"HSMKeYou.log");	
    if ((union_logfile = fopen(UNIONLOGFILENAME,"a")) == NULL)
	return(stderr);
		
    if (ftell(union_logfile) >= UNIONMAXLOGFILESIZE)
    {
	union_close_logfile(union_logfile);
	if ((union_logfile = fopen(UNIONLOGFILENAME,"w")) == NULL)
	    return(stderr);
    }

    return(union_logfile);
}

int union_close_logfile(FILE *union_logfile)
{
    if ((union_logfile == stderr) || (union_logfile == stdout))
	return(0);
    return(fclose(union_logfile));
}


void union_err_log(char *sfmt,...)
{
    va_list args;
    char	*fmt;
    char	buf[150];
    FILE	*union_logfile;

    union_PID = getpid();
    union_logfile = union_open_logfile();
	
    memset(buf,0,sizeof(buf));
    GetTime(buf,sizeof(buf),"%Y%m%d%H%M%S");
	
    fprintf(union_logfile,"%s PID[%08ld] Error::",buf,union_PID);
	
    /*va_start(args);
    va_start(args, sfmt);
    fmt = va_arg(args,char *);
    vfprintf(union_logfile,fmt,args);*/
    va_start(args, sfmt);
    vfprintf(union_logfile,sfmt,args);
    va_end(args);

    //fprintf(union_logfile," [ERROR CODE = *%d*]",errno);	
    fprintf(union_logfile,"\n");
    fflush(union_logfile);	
	
    //errno = 0;
	
    union_close_logfile(union_logfile);
}


void union_success_log(char *sfmt,...)
{
    va_list args;
    char	*fmt;
    char	buf[150];
    FILE	*union_logfile;

    union_PID = getpid();
    union_logfile = union_open_logfile();

    memset(buf,0,sizeof(buf));
    GetTime(buf,sizeof(buf),"%Y%m%d%H%M%S");
	
    fprintf(union_logfile,"%s PID[%08ld] Success::",buf,union_PID);
	
    /*va_start(args);
    fmt = va_arg(args,char *);
    vfprintf(union_logfile,fmt,args);*/
    va_start(args, sfmt);
    vfprintf(union_logfile,sfmt,args);
    va_end(args);
	
    fprintf(union_logfile,"\n");
    fflush(union_logfile);
	
    union_close_logfile(union_logfile);
}


void union_log(char *sfmt,...)
{
    va_list args;
    char	*fmt;
    char	buf[150];
    FILE	*union_logfile;

    union_PID = getpid();
    union_logfile = union_open_logfile();

    memset(buf,0,sizeof(buf));
    GetTime(buf,sizeof(buf),"%Y%m%d%H%M%S");
	
    fprintf(union_logfile,"%s PID[%08ld][RECORD]",buf,union_PID);
	
    /*va_start(args);
    fmt = va_arg(args,char *);
    vfprintf(union_logfile,fmt,args);*/
    va_start(args, sfmt);
    vfprintf(union_logfile,sfmt,args);
    va_end(args);
	
    fprintf(union_logfile,"\n");
    fflush(union_logfile);
	
    union_close_logfile(union_logfile);
}


/******************************************************************/
/* Public Routine for debug                                       */
/******************************************************************/
void time_dump(void)
{
    time_t tm;
    u8 tmp[80];

    /* get current time */
    time(&tm);

    /* convert current time from seconds to ascii */
    sprintf((char *)tmp, "%s", ctime(&tm));

    /* omit the char of carriage return */
    tmp[strlen((char *)tmp) - 1] = 0x00;

    fprintf(stderr, "%s\n", tmp);
    fflush(stderr);
}

void begin_dump_comm(u8 *str)
{
    if (!str)
        return;

    time_dump();
    fprintf(stderr, "%s Begin of Command %s %s\n", DbgStr, str, DbgStr);
    fflush(stderr);
}

void end_dump_comm(u8 *str)
{
    if (!str)
        return;

    fprintf(stderr, "%s  End of Command  %s %s\n", DbgStr, str, DbgStr);
    fflush(stderr);
}

void data_dump(u8 *prompt, u8 *data, int len)
{
    int i;
    int prev;
    int curr;

    fprintf(stderr, "[%s] [length = %d]\n", prompt, len);
    prev = curr = 0;
    for (i = 0; i < len; i++)
    {
        if (i == (prev + 16))
        {
            i = prev;
            curr = prev + 16;
            fprintf(stderr, "    |    ");
            for (; i < curr; i++)
                if (isprint(data[i]))
                    fprintf(stderr, "%c", data[i]);
                else
                    fprintf(stderr, " ");
            fprintf(stderr, "\n");
            prev = curr;
        }
        fprintf(stderr, "%02X", data[i]);
    }
/*
    if (i != curr)
    {
        curr = i;
        for (; i < (prev + 16); i++)
            fprintf(stderr, "   ");
        fprintf(stderr, "    |    ");
        for (i = prev ; i < curr; i++)
        {
            if (isprint(data[i]))
                fprintf(stderr, "%c", data[i]);
            else
                fprintf(stderr, " ");
        }
    }
*/    
    fprintf(stderr, "\n");

    fflush(stderr);
}

void str_dump(u8 *str)
{
    if (!str)
        return;

    fprintf(stderr, "%s\n", str);
    fflush(stderr);
}

void int_dump(u8 *str, int data)
{
    if (!str)
        return;

    fprintf(stderr, "[%s]\n", str);
    fprintf(stderr, "Hex = %x Dec = %d\n", data, data);
    fflush(stderr);
}

