#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <fcntl.h>

#include "logpub.h"


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


