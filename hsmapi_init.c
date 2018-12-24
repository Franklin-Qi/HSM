/*----------------------------------------------------------------------|
|    hsmapi_init.c                                                      |
|    Version :     1.0                                                  |
|    Author:       Luo Cangjian.                                        |
|    Description:  SJJ1310密码机接口初始化模块                          |
|    Copyright :   Beijing JN TASS Technology Co., Ltd.                 |
|    data:         2015-05-29. Create                                   |
|-----------------------------------------------------------------------|
|    Modify History:                                                    |
|----------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>

#ifdef _MSC_VER
#pragma warning(disable:4996)
#include <WS2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include<arpa/inet.h>
#endif

#include "hsmapi_define.h"
//#include "hsmapi_tcpcom.h"
#include "hsmapi_init.h"
#include "hsmapi_log.h"

#define LEN_MAX_FNAME           FILENAME_MAX

int  g_iInitFlg = 0;        /*** 0:未初始化  1：已初始化 **/
int  g_iTimeout = 30;       /*** 默认超时时间30s ***/
int  g_iMsgHeadLen = 0;
int  g_iLogLevel = 1;       /*** 0 - 只输出错误日志  1 - 输出报文 ***/
int  g_iPort1;
int  g_iPort2;              /*** 该端口为用于信函打印相关接口 ***/
char g_szHost1[16 + 1];
char g_szHost2[16 + 1];     /*** 该IP用于信函打印相关接口 ***/
char g_szLogPath[LEN_MAX_FNAME];

/***************************************************************************
* Subroutine: IsIpv4Address
* Function:   判断IP合法性
* Input:
*    @pcIp    IP地址
* Output:
*    无
*
* Return:       返回0 IP地址合法，返回其他非法
* Description:
*
* Author:       Luo Cangjian
* Date:         2015.05.29
* ModifyRecord:
* *************************************************************************/
int IsIpv4Address(const char *pcIp)
{
    int rv = HAR_OK;
    struct in_addr stAddr;
    memset(&stAddr, 0x00, sizeof(struct in_addr));

    rv = inet_pton(AF_INET, pcIp, &stAddr);
    if(rv <= 0)
    {
        return HAR_CFGFILE_VALUE_INVALID;
    }

    return HAR_OK;
}

/***************************************************************************
* Subroutine: GetKeyValue
* Function:   根据指定的键名获取配置文件中的键值
* Input:
*    @pcFileName       配置文件路径
*    @pcKeyName        键名
* Output:
*    @pcKeyValue       键值
*
* Return:       0 for success, other is error
* Description:
*
* Author:       Luo Cangjian
* Date:         2015.05.29
* ModifyRecord:
* *************************************************************************/
int GetKeyValue(char *pcFileName, char *pcKeyName, char *pcKeyValue)
{
    int i;
    int iLen;
    FILE *pstIniFile;
    char *pcValueHead, szLine[128];

    if ((pstIniFile = fopen(pcFileName, "r")) == NULL)
    {
        return HAR_CFGFILE_OPEN;
    }

    while (!feof(pstIniFile))
    {
        fgets(szLine, 127, pstIniFile);
        if (strstr(szLine, pcKeyName) == szLine)
        {
            break;
        }
    }

    if (feof(pstIniFile))
    {
        fclose(pstIniFile);
        return HAR_CFGFILE_KEY_NOEXIST;
    }

    pcValueHead = strstr(szLine, "=");

    if (pcValueHead == NULL)
    {
        fclose(pstIniFile);
        return HAR_CFGFILE_VALUE_NOEXIST;
    }

    pcValueHead++;
    iLen = strlen(pcValueHead);

    for(i = 0; i < iLen; i++, pcValueHead++)
    {
        if(*pcValueHead != '\n' && *pcValueHead != '\r')
        {
            *pcKeyValue = *pcValueHead;
            pcKeyValue++;
        }
    }
    *pcKeyValue = 0x00;

    fclose(pstIniFile);
    return HAR_OK;
}

/***************************************************************************
* Subroutine: SDF_HsmApiInit
* Function:   通过接口指定配置信息的方式初始化接口
* Input:
*    @pcConfigFilePath      配置文件路径
* Output:
*    无
*
* Return:       0 for success, other is error
* Description:
*
* Author:       Luo Cangjian
* Date:         2015.05.29
* ModifyRecord:
* *************************************************************************/
int SDF_HsmApiInit(char *pcConfigFilePath)
{
    int  rv = HAR_OK;
    char szValue[128] = {0};
    char szConfigFile[LEN_MAX_FNAME] = {0};

    if(g_iInitFlg)
    {
        return HAR_OK;
    }

    if(pcConfigFilePath == NULL)
    {
        return HAR_CFGFILE_NOEXIST;
    }

    strcpy(szConfigFile, pcConfigFilePath);

    rv = GetKeyValue(szConfigFile, "logpath", szValue);
    if (rv)
    {
        printf("============> [tass hsm api] logpath not defined!\n");
        return rv;
    }
    strcpy(g_szLogPath, szValue);

    rv = GetKeyValue(szConfigFile, "logsw", szValue);
    if (rv)
    {
        printf("============> [tass hsm api] logsw not defined!\n");
        return rv;
    }

    if(!strcmp(szValue, "trace"))
    {
        g_iLogLevel = 1;
    }
    else
    {
        g_iLogLevel = 0;
    }

    rv = GetKeyValue(szConfigFile, "timeout", szValue);
    if (rv)
    {
        printf("============> [tass hsm api] timeout not defined!\r\n\r\n");
        return rv;
    }
    g_iTimeout = atoi(szValue);

    rv = GetKeyValue(szConfigFile, "msgheadlen", szValue);
    if (rv)
    {
        printf("============> [tass hsm api] msgheadlen not defined!\r\n\r\n");
        return rv;
    }
    g_iMsgHeadLen = atoi(szValue);

    rv = GetKeyValue(szConfigFile, "host1", szValue);
    if (rv)
    {
        printf("============> [tass hsm api] host1 not defined!\r\n\r\n");
        return rv;
    }

    rv = IsIpv4Address(szValue);
    if(rv)
    {
        printf("============> [tass hsm api] host1 is invalid! return code = [%d]\r\n\r\n", rv);
        return rv;
    }
    strcpy(g_szHost1, szValue);

    rv = GetKeyValue(szConfigFile, "port1", szValue);
    if (rv)
    {
        printf("============> [tass hsm api] port1 not defined!\r\n\r\n");
        return rv;
    }
    g_iPort1 = atoi(szValue);

    rv = GetKeyValue(szConfigFile, "host2", szValue);
    if (rv)
    {
        g_iInitFlg = 1;
        printf("============> [tass hsm api] init success!\r\n\r\n");
        return 0;
    }

    rv = IsIpv4Address(szValue);
    if(rv)
    {
        printf("============> [tass hsm api] host2 is invalid!\r\n\r\n");
        return rv;
    }
    strcpy(g_szHost2, szValue);

    rv = GetKeyValue(szConfigFile, "port2", szValue);
    if (rv)
    {
        printf("============> [tass hsm api] port2 not defined!\r\n\r\n");
        return rv;
    }
    g_iPort2 = atoi(szValue);

    g_iInitFlg = 1;
    printf("============> [tass hsm api] init success!\r\n\r\n");

    return rv;
}

/***************************************************************************
* Subroutine: Tass_HsmApiInitByContent
* Function:   通过接口指定配置信息的方式初始化接口
* Input:
*    @pcIp            密码机IP
*    @uiPort          密码机端口
*    @uiTimeOut       socket读取超时时间，单位秒
*    @pcLogPath       日志输出路径
* Output:
*    无
*
* Return:       0 for success, other is error
* Description:
*
* Author:       Luo Cangjian
* Date:         2015.05.29
* ModifyRecord:
* *************************************************************************/
int Tass_HsmApiInitByContent(char *pcIp, unsigned int uiPort, unsigned int uiTimeOut, char *pcLogPath)
{
    int rv = HAR_OK;
    if(pcIp == NULL)
    {
        LOG_ERROR("pcIp = [%s] is invalid.", "NULL");
        return HAR_PARAM_ISNULL;
    }

    if(pcLogPath == NULL)
    {
        return HAR_PARAM_ISNULL;
    }

    /*** error ***/
    g_iLogLevel = 0;

    /*** log path ***/
    strcpy(g_szLogPath, pcLogPath);

    /*** 加密机IP ***/
    rv = IsIpv4Address(pcIp);
    if(rv)
    {
        printf("============> [tass hsm api] pcIp is invalid!\r\n\r\n");
        return rv;
    }
    strcpy(g_szHost1, pcIp);

    /*** 加密机端口 ***/
    g_iPort1 = (int)uiPort;

    /*** 超时时间 ***/
    g_iTimeout = (int)uiTimeOut;

    g_iInitFlg = 1;

    return rv;
}


