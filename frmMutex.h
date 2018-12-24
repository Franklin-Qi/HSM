/**
 * @file frmMutex.h
 * @brief  互斥锁操作
 * @author IDleGG
 * @version 1.0
 * @date 2015-09-22
 * @Copyright (C) Beijing JN TASS Technology Co.,Ltd.
 */

#ifndef TASSAPIFRAME_INCLUDE_FRMMUTEX_H
#define TASSAPIFRAME_INCLUDE_FRMMUTEX_H


#ifdef  __cplusplus
extern "C" {
#endif

#include "frmTypes.h"

#if _MSC_VER
#define STDCALL_ __stdcall
#else
#define STDCALL_
#endif

typedef void *      FRMHANDLE_Mutex;

#define FRMERR_MUTEX_OK             0
#define FRMERR_MUTEX_ARG_NULL       -1001

FRM_INT32 STDCALL_ tafrm_CreateMutex(FRMHANDLE_Mutex * phMutex);

FRM_INT32 STDCALL_ tafrm_DestroyMutex(FRMHANDLE_Mutex hMutex);

FRM_INT32 STDCALL_ tafrm_LockMutex(FRMHANDLE_Mutex hMutex);

FRM_INT32 STDCALL_ tafrm_UnlockMutex(FRMHANDLE_Mutex hMutex);

#ifdef  __cplusplus
}
#endif

#endif // end TASSAPIFRAME_INCLUDE_FRMMUTEX_H

