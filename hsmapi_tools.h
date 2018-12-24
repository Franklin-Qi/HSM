/*----------------------------------------------------------------------|
|    hsmapi_tools.h -   The header file of hsmapi_tools.c               |
|    Version :     1.0                                                  |
|    Author:       by lcj.                                              |
|    Description:                                                       |
|    Copyright :   Beijing JN TASS Technology Co., Ltd.                 |
|    data:         2015-05-21. Create                                   |
|-----------------------------------------------------------------------|
|    Modify History:                                                    |
|----------------------------------------------------------------------*/
#ifndef __HSMAPI_TOOLS_H__
#define __HSMAPI_TOOLS_H__

#ifdef __cplusplus
extern "C" {
#endif

/***************************************************************************
* Subroutine: Tools_CheckNum
* Function:   判断一个字符串是不是纯数字的字符串
* Input:
*   @pcInData   pcInData
*
* Output:
*   无
*
* Return:       0:纯数字字符串   -1:不是纯数字字符串
* Description:
* Date:         2015.05.21
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
int Tools_CheckNum(char *pcInData);

/***************************************************************************
* Subroutine: Tools_CheckHex
* Function:   判断一个字符串是不是纯数字的字符串
* Input:
*   @pcInData   待处理的字符串
*
* Output:
*   无
*
* Return:       0:十六进制字符串   -1:不是十六进制字符串
* Description:
* Date:         2015.05.21
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
int Tools_CheckHex(char *pcInData);

/***************************************************************************
* Subroutine: Toos_CheckKeyType
* Function:   判断对称密钥类型是否合法
* Input:
*   @pcKeyType   密钥类型
*
* Output:
*   无
*
* Return:       0:密钥类型合法     返回其他标识类型非法
* Description:
* Date:         2015.05.21
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
int Toos_CheckKeyType(char *pcKeyType);

/***************************************************************************
* Subroutine: Tools_ConvertHexBuf2Int
* Function:   将指定长度的十六进制字符缓存区转为int类型
* Input:
*   @pucBuffer   待处理的数据
*   @iLen        指定的长度
* Output:
*   无
*
* Return:       转换后的整型数据
* Description:
* Date:         2015.05.21
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
int Tools_ConvertHexBuf2Int(unsigned char *pucBuffer, int iBufferLen);

/***************************************************************************
* Subroutine: Tools_ConvertDecBuf2Int
* Function:   将指定长度的十进制字符缓存区转换为整型
* Input:
*   @pucBuffer   待处理的数据
*   @iLen        指定的长度
* Output:
*   无
*
* Return:       转换后的整型数据
* Description:
* Date:         2015.05.21
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
int Tools_ConvertDecBuf2Int(unsigned char *pucBuffer, int iBufferLen);

/***************************************************************************
* Subroutine: Tools_ConvertUint2Ucbuf
* Function:   将4字节的int转换为unsigned char 类型的数据
* Input:
*   @uiInData   待处理的数据
* Output:
*   @pucOutBuf  转换后的数据
*
* Return:
* Description:
* Date:         2015.05.21
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
int Tools_ConvertUint2Ucbuf(unsigned int uiInData, unsigned char *pucOutBuf);

/***************************************************************************
* Subroutine: Tools_AddFieldPan
* Function:   根据检测账号是否十进制数据，根据PIN格式添加到命令报文中
* Input:
*   @iPinFmt  PIN块格式
*   @pcPan    PAN号
* Output:
*   @pucDst   命令报文
*
* Return:       成功则返回有效的PAN长度，否则返回 HAR_PARAM_PAN
* Description:  pinfmt=4, pan为18N；pinfmt=0，pan为作为分散因子的域，16N；其他，pan为12N
* Date:         2015.05.21
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
int Tools_AddFieldPan(int iPinFmt, char *pcPan, unsigned char *pucDst);

/***************************************************************************
* Subroutine: Tools_AddFieldKey
* Function:    将密钥索引或密钥密文添加到命令报文域中
* Input:
*   @iKeyIdx       密钥索引
*   @pcKeyCipher   密钥密文
* Output:
*   @pucDst        命令报文
*
* Return:       成功返回添加的数据长度，否则返回 HSMAPIERR_PARAM_VALUE
* Description:
* Date:         2015.05.22
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
int Tools_AddFieldKey(int iKeyIdx, char *pcKeyCipher, unsigned char *pucDst);

/***************************************************************************
* Subroutine: Tools_AddFieldSavedKey
* Function:    将要存到内部的密钥索引和密钥标识添加到命令报文域中
* Input:
*   @iKeyIdx       密钥索引
*   @pcKeyLabel    密钥标签
* Output:
*   @pucDst        命令报文
*
* Return:       成功返回添加的数据长度，否则返回 HSMAPIERR_PARAM_VALUE
* Description:
* Date:         2015.05.22
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
int Tools_AddFieldSavedKey(int iKeyIdx, char *pcKeyLabel, unsigned char *pucDst);

/***************************************************************************
* Subroutine: Tools_AddFieldDiversifyData
* Function:    添加密钥分散级数及分散因子域到命令报文中
* Input:
*   @iMode          0-每级分散因子8字节，1-每级分散因子16字节
*   @iDiversifyNum     分散级数
*   @pcDiversifyData   分散因子
* Output:
*   @pucDst        命令报文
*
* Return:       成功返回添加的数据长度，否则返回 HSMAPIERR_PARAM_Diversify_DATA
* Description:
* Date:         2015.05.22
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
int Tools_AddFieldDiversifyData(int iMode, int iDiversifyNum, char *pcDiversifyData, unsigned char *pucDst);

/***************************************************************************
* Subroutine: Tools_AddFieldSessionData
* Function:    添加会话密钥模式和会话密钥因子域到命令报文中
* Input:
*   @iMode          会话密钥生成模式
*   @pcSessData     会话密钥因子
* Output:
*   @pucDst        命令报文
*
* Return:       成功则返回有效的添加数据长度
*               失败返回 HSMAPIERR_PARAM_SESSION_KEY_DATA
*                       或HSMAPIERR_PARAM_SESSION_KEY_MODE
* Description:
* Date:         2015.05.22
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
int Tools_AddFieldSessionData(int iMode, char *pcSessData, unsigned char *pucDst);

/***************************************************************************
* Subroutine: Tools_GetFieldKeyLength
* Function:   获取密钥长度
* Input:
*   @pcKeyCipher   密钥密文
* Output:
*   无
*
* Return:       密钥密文长度（包含算法标识）
* Description:
* Date:         2015.05.21
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
int Tools_GetFieldKeyLength(char *pcKeyCipher);

/***************************************************************************
* Subroutine: Tools_GetFieldDerBufLength
* Function:   获取DER编码的数据长度
* Input:
*   @pucDst          报文数据
* Output:
*   无
*
* Return:       成功则返回有效数据长度
*               失败返回 HSMAPIERR_DER_DECODE
* Description:
* Date:         2015.05.22
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
int Tools_GetFieldDerBufLength(unsigned char *pucDst);

/***************************************************************************
* Subroutine: Tools_PrintBuf
* Function:   按十六进制打印缓存区
* Input:
*   @pucDst   待打印的数据
* Output:
*   无
*
* Return:
* Description:
* Date:         2015.05.22
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
void Tools_PrintBuf(char *pcTitle, unsigned char *pucBuf, int iBufLen);

/***************************************************************************
* Subroutine: Tools_ConvertToupper
* Function:   将小写的字符转换为大写
* Input:
*   @pcInData   待处理的字符串
* Output:
*   无
*
* Return:
* Description:
* Date:         2015.05.22
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
void Tools_ConvertToupper(char *pcInData);

/***************************************************************************
* Subroutine: Tools_ConvertByte2HexStr
* Function:   将字节数组转换为十六进制字符串
* Input:
*   @pucInBuf    待处理字节数组
*   @iInBufLen   待处理的数据的字节数
* Output:
*   @pcOutBuf    转换后的十六进制字符串
*
* Return:       成功返回十六进制字符串长度， 失败返回-1
* Description:
* Date:         2015.05.22
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
int Tools_ConvertByte2HexStr(unsigned char *pucInBuf, int iInBufLen, char *pcOutBuf);

/***************************************************************************
* Subroutine: Tools_ConvertHexStr2Byte
* Function:   将十六进制字符串转换为字节数组
* Input:
*   @pcInBuf    待处理的字符串
*   @iInBufLen  待处理的字符串长度
* Output:
*   @pucOutBuf  输出的字节数组
*
* Return:
* Description: 成功返回转换后的字节数， 失败返回-1
* Date:         2015.05.22
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
int Tools_ConvertHexStr2Byte(char *pcInBuf, int iInBufLen, unsigned char *pucOutBuf);

/***************************************************************************
* Subroutine: Tools_Padding_0
* Function:   非强制填充0x80
* Input:
*   @pcInData    待处理的字符串（十六进制）
* Output:
*   @pcOutData   填充后的数据
*
* Return:       成功返回0， 失败返回-1
* Description:  将数据填充为16的倍数（十六进制）
* Date:         2015.05.22
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
int Tools_Padding_0(char *pcInData, char *pcOutData/*out*/);

/***************************************************************************
* Subroutine: Tools_Padding_00
* Function:   非强制填充0x00
* Input:
*   @pcInData    待处理的字符串（十六进制）
* Output:
*   @pcOutData   填充后的数据
*
* Return:       成功返回0， 失败返回-1
* Description:  将数据填充为16的倍数（十六进制）
* Date:         2015.05.22
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_Padding_00(char *pcInData, char *pcOutData/*out*/);

/***************************************************************************
* Subroutine: Tools_CycleXorHexStr
* Function:   对十六进制字符串按指定分组长度循环异或
* Input:
*   @iMode       分组模式： 0-按8字节异或   1-按16字节异或
*   @pcInData    待处理的字符串
* Output:
*   @pcOutData   异或后的数据
*
* Return:       成功返回0， 失败返回-1
* Description:
* Date:         2015.05.22
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
int Tools_CycleXorHexStr(int iMode, char *pcInData, char *pcOutData/*out*/);

/***************************************************************************
* Subroutine: Tools_CycleXorHexStr
* Function:   对二进制数据按指定分组长度循环异或
* Input:
*   @iMode       分组模式： 0-按8字节异或   1-按16字节异或
*   @pucInData   待处理的字节数组
*   @iInDataLen  待处理的字节数组长度
* Output:
*   @pucOutData   异或后的数据
*
* Return:       成功返回0， 失败返回-1
* Description:
* Date:         2015.05.22
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
int Tools_CycleXorByteArray(int iMode, unsigned char *pucInData, int iInDataLen, unsigned char *pucOutData/*out*/);

/***************************************************************************
* Subroutine: Tools_GenDiversifyData
* Function:   计算分散因子
* Input:
*   @pcInData    待处理的数据，要求长度为16H
* Output:
*   @pcOutData   处理后的分散因子 32H
*
* Return:       成功返回0， 失败返回-1
* Description:  用于计算将十六进制的数据进行取反，然后将原数据与取反后的数据进行拼接，
*               形成一个分散因子。
* Date:         2015.05.22
* Author:       lcj
* ModifyRecord:
* *************************************************************************/
int Tools_GenDiversifyData(char *pcInData, char *pcOutData/*out*/);

/***************************************************************************
* Subroutine: Tools_CheckSchemeValidity
* Function:   检查算法标识有效性
* Input:
*   @cScheme  算法标识
* Output:
*   无
*
* Return:       成功返回0， 失败返回其他
* Description:  暂时不支持AES算法
*
* Date:         2015.06.08
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_CheckSchemeValidity(char cScheme);

/***************************************************************************
* Subroutine: Tools_CheckKeyValidity
* Function:   检查密钥信息有效性
* Input:
*   @iKeyIdx            密钥索引
*   @pcKeyCipherByLmk   密钥密文
* Output:
*   @pcOutData          完整的密钥密文（待算法标识）
*
* Return:       成功返回0， 失败返回其他
* Description:  暂时不支持AES算法
*
* Date:         2015.06.08
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_CheckKeyValidity(int iKeyIdx, char *pcKeyCipherByLmk, char *pcOutData);

/***************************************************************************
* Subroutine: Tools_CheckKeyValidity_1
* Function:   检查密钥信息有效性
* Input:
*   @iKeyIdx            密钥索引
*   @pcKeyCipherByLmk   密钥密文
* Output:
*   无
*
* Return:       成功返回0， 失败返回其他
* Description:  当密钥索引值为0时，密钥密文长度是否为16,33，49,如果不是则报错
*
* Date:         2015.06.08
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_CheckKeyValidity_1(int iKeyIdx, char *pcKeyCipherByLmk);

/***************************************************************************
* Subroutine: Tools_CheckKeyValidity_2
* Function:   检查密钥信息有效性
* Input:
*   @iKeyIdx            密钥索引
*   @pcKeyCipherByLmk   密钥密文
* Output:
*   无
*
* Return:       成功返回0， 失败返回其他
* Description:  当密钥索引值为0时，密钥密文长度是否为17,33，49,如果不是则报错
*
* Date:         2015.06.08
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_CheckKeyValidity_2(int iKeyIdx, char *pcKeyCipherByLmk);

/***************************************************************************
* Subroutine: Tools_CheckKeyValidity_3
* Function:   检查密钥信息有效性
* Input:
*   @iKeyIdx            密钥索引
*   @pcKeyCipherByLmk   密钥密文
* Output:
*   @pcOutData          完整的密钥密文（待算法标识）
*
* Return:       成功返回0， 失败返回其他
* Description:  密钥密文长度只支持32或33H，当长度为32H时，则填充算法标识X
*
* Date:         2015.06.08
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_CheckKeyValidity_3(int iKeyIdx, char *pcKeyCipherByLmk, char *pcOutData);

/***************************************************************************
* Subroutine: Tools_CheckSessionKeyDataValidity
* Function:   检查会话密钥生成模式及数据的有效性
* Input:
*   @iSessionKeyMode           会话密钥生成模式
*   @pcSessionKeyData          会话密钥因子
* Output:
*   无
*
* Return:       成功返回0， 失败返回其他
* Description:
*
* Date:         2015.06.08
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_CheckSessionKeyDataValidity(int iSessionKeyMode, char *pcSessionKeyData);

/***************************************************************************
* Subroutine: Tools_CheckPaddingModeValidity
* Function:   检查数据填充模式的有效性
* Input:
*   @iPaddingMode           数据填充模式
* Output:
*   无
*
* Return:       成功返回0， 失败返回其他
* Description:
*
* Date:         2015.06.08
* Author:       Luo Cangjian
* ModifyRecord:
* *************************************************************************/
int Tools_CheckPaddingModeValidity(int iPaddingMode);

/***************************************************************************
 * * Subroutine: Tools_Der
 * * Function:   对RSA公钥的模、指数序列做DER编码
 * * Input:
 * *   @N           模
 * *   @E           指数（十六进制）
 * * Output:
 * *   @pubkeyDer   公钥
 * *   @pubkeyDerLen公钥长度
 * *
 * * Return:       成功返回0， 失败返回其他
 * * Description:
 * *
 * * Date:         2015.06.08
 * * Author:       Luo Cangjian
 * * ModifyRecord:
 * * *************************************************************************/
int Tools_Der(char *N, char *E, char *pubkeyDer,int *pubkeyDerLen);
/***************************************************************************
 * Subroutine: Tools_DDer
 * Function:   对Der编码的公钥解码，生成模和指数
 * Input:
 *   @pubkeyDer      Der编码
 *   @pubkeyDerLen   Der长
 * Output
 *   @ppmodulus      模
 *   @modulusLen     模长
 *   @pppubExp       指数
 *   @pubExpLen      指数长度
 * Output:
 *   @pubkeyDer   公钥
 *
 * Return:       成功返回0， 失败返回其他
 * Description:
 *
 * Date:         2015.06.08
 * Author:       Luo Cangjian
 * ModifyRecord:
 *************************************************************************/
int Tools_DDer(unsigned char *pubkeyDer, unsigned char *ppmodulus,
               int *modulusLen, unsigned char *pppubExp, int *pubExpLen);

#ifdef __cplusplus
}
#endif

#endif /*__HSMAPI_TOOLS_H__*/


