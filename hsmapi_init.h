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
#ifndef __HSM_API_INIT_H_
#define __HSM_API_INIT_H_

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
int IsIpv4Address(const char *pcIp);

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
int GetKeyValue(char *pcFileName, char *pcKeyName, char *pcKeyValue);

/***************************************************************************
* Subroutine: Tass_HsmApiInit
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
//int Tass_HsmApiInit(char *pcConfigFilePath);

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
int Tass_HsmApiInitByContent(char *pcIp, unsigned int uiPort, unsigned int uiTimeOut, char *pcLogPath);

#endif /*** __HSM_API_INIT_H_ ***/


