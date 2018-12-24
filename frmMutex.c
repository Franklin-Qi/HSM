/**
 * @file frame_mutex.c
 * @brief  互斥锁实现
 * @author IDleGG
 * @version 1.0
 * @date 2015-09-22
 * @Copyright (C) Beijing JN TASS Technology Co.,Ltd.
 */

//#if _MSC_VER
//#include <WINDOWS.H>
//#else
#include <pthread.h>
//#endif
#include <stdlib.h>
#include <malloc.h>
#include "frmTypes.h"
#include "frmDefines.h"
#include "frmMutex.h"

#ifndef FALSE
#define FALSE
#endif

FRM_INT32 STDCALL_ tafrm_CreateMutex(FRMHANDLE_Mutex * phMutex  /* location to receive ptr to mutex */)
{
#if _MSC_VER
    FRMHANDLE_Mutex p_Mutex;
#else
    pthread_mutex_t *p_Mutex = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
    pthread_mutexattr_t mutexattr;
#endif

#if _MSC_VER
    p_Mutex = CreateMutex(NULL, FALSE, NULL);
    *phMutex = (void *)p_Mutex;
#else
    /*使锁支持多进程共享*/
    pthread_mutexattr_init(&mutexattr);
    pthread_mutexattr_setpshared(&mutexattr,PTHREAD_PROCESS_SHARED);    //设置为进程共享

    pthread_mutex_init(p_Mutex, &mutexattr);
    *phMutex = p_Mutex;
#endif

    return FRMERR_MUTEX_OK;
}

FRM_INT32 STDCALL_ tafrm_DestroyMutex(FRMHANDLE_Mutex hMutex  /* ptr to mutex */)
{
#if _MSC_VER
    FRMHANDLE_Mutex p_Mutex;
#else
    pthread_mutex_t *p_Mutex;
#endif

    if (hMutex == NULL)
    {
        return FRMERR_MUTEX_OK;
    }

#if _MSC_VER
    p_Mutex = (FRMHANDLE_Mutex)hMutex;
    CloseHandle(p_Mutex);
#else
    p_Mutex = (pthread_mutex_t *)hMutex;
    pthread_mutex_destroy(p_Mutex);
    free(p_Mutex);
#endif

    hMutex = NULL;

    return FRMERR_MUTEX_OK;
}

FRM_INT32 STDCALL_ tafrm_LockMutex(FRMHANDLE_Mutex hMutex  /* ptr to mutex */)
{
#if _MSC_VER
    FRMHANDLE_Mutex p_Mutex;
#else
    pthread_mutex_t *p_Mutex;
#endif

    if (hMutex == NULL)
    {
        return FRMERR_MUTEX_ARG_NULL;
    }

#if _MSC_VER
    p_Mutex = (FRMHANDLE_Mutex)hMutex;
    WaitForSingleObject(p_Mutex, INFINITE);
#else
    p_Mutex = (pthread_mutex_t *)hMutex;
    pthread_mutex_lock(p_Mutex);
#endif

    return FRMERR_MUTEX_OK;
}

FRM_INT32 STDCALL_ tafrm_UnlockMutex(FRMHANDLE_Mutex hMutex  /* ptr to mutex */)
{
#if _MSC_VER
    FRMHANDLE_Mutex p_Mutex;
#else
    pthread_mutex_t *p_Mutex;
#endif

    if (hMutex == NULL)
    {
        return FRMERR_MUTEX_ARG_NULL;
    }

#if _MSC_VER
    p_Mutex = (FRMHANDLE_Mutex)hMutex;
    ReleaseMutex(p_Mutex);
#else
    p_Mutex = (pthread_mutex_t *)hMutex;
    pthread_mutex_unlock(p_Mutex);
#endif

    return FRMERR_MUTEX_OK;
}

