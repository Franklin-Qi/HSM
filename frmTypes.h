/**
 * @file frmTypes.h
 * @brief Using this head file for data-type defining, Firstly make sure the type is defined
 * @author IDleGG
 * @version 1.0
 * @date 2016-04-05
 * @Copyright (C) Beijing JN TASS Technology Co.,Ltd.
 */
#ifndef TASSAPIFRAME_INCLUDE_FRMETYPES_H
#define TASSAPIFRAME_INCLUDE_FRMETYPES_H

/////////////////////////////////////////////////////////////////////////////////
//C Standards
/////////////////////////////////////////////////////////////////////////////////
#if defined(__STDC__)
#define FRMDEF_STANDARD_C_1989
#if defined(__STDC_VERSION__)
#define FRMDEF_STANDARD_C_1990
#if (__STDC_VERSION__ >= 199409L)
#define FRMDEF_STANDARD_C_1994
#endif
#if (__STDC_VERSION__ >= 199901L)
#define FRMDEF_STANDARD_C_1999
#endif
#endif
#endif

/////////////////////////////////////////////////////////////////////////////////
// Pre-C89 compilers do not recognize certain keywords. 
// Let the preprocessor remove those keywords for those compilers.
/////////////////////////////////////////////////////////////////////////////////
#if !defined(FRMDEF_STANDARD_C_1989) && !defined(__cplusplus)
#define const
#define volatile
#endif

/////////////////////////////////////////////////////////////////////////////////
// Define 8-bits Integer, 16-bits Integer,32-bits Integer
// All compliant compilers that support Standard C/C++
// VC++， Borland C++, Turb C++  those who support C89,but undefined __STDC__) 
/////////////////////////////////////////////////////////////////////////////////
#if defined(__STDC__) || defined(__cplusplus) || defined(_MSC_VER) || defined(__BORLANDC__) || defined(__TURBOC__)
#include <limits.h>
// Defined 8 - bit Integer
#if defined(UCHAR_MAX) && (UCHAR_MAX == 0xFF)
#ifndef FRMDEFINED_INT8
typedef  char  FRM_INT8, * FRM_INT8_PTR;
typedef  unsigned char FRM_UINT8, * FRM_UINT8_PTR;
#define FRMDEFINED_INT8
#endif
#endif
// Defined 16-bits Integer
#if defined(USHRT_MAX) && (USHRT_MAX == 0xFFFF)
#ifndef FRMDEFINED_INT16
typedef  short int  FRM_INT16, * FRM_INT16_PTR;
typedef  unsigned short int FRM_UINT16, * FRM_UINT16_PTR;
#define FRMDEFINED_INT16
#endif
#elif defined(UINT_MAX) && (UINT_MAX == 0xFFFF)
#ifndef FRMDEFINED_INT16
typedef  int  FRM_INT16, * FRM_INT16_PTR;
typedef  unsigned int FRM_UINT16, * FRM_UINT16_PTR;
#define FRMDEFINED_INT16
#endif 
#endif
// Defined 32-bits Integer
#if defined(UINT_MAX) && (UINT_MAX == 0xFFFFFFFFUL)
#ifndef FRMDEFINED_INT32
typedef int  FRM_INT32, * FRM_INT32_PTR;
typedef unsigned int FRM_UINT32, *FRM_UINT32_PTR;
#define FRMDEFINED_INT32
#endif
#elif defined(ULONG_MAX) && (ULONG_MAX == 0xFFFFFFFFUL)
#ifndef FRMDEFINED_INT32
typedef long int  FRM_INT32, * FRM_INT32_PTR;
typedef unsigned long int FRM_UINT32, * FRM_UINT32_PTR;
#define FRMDEFINED_INT32
#endif
#endif
#endif

/////////////////////////////////////////////////////////////////////////////////
// Define 64-bits Integer
// Here Only support typical systems 
// such as GNU/Linux Windows UNIX Vxworks  BSD Solaris 
/////////////////////////////////////////////////////////////////////////////////

// GNU/Linux System 64-bits Integer
#if defined(__GNUC__) || defined(linux) ||defined(__linux)
#if defined (__GLIBC_HAVE_LONG_LONG) || (defined(ULLONG_MAX) && (ULLONG_MAX == 0xFFFFFFFFFFFFFFFFUL))
#ifndef FRMDEFINE_INT64
typedef  long long FRM_INT64, * FRM_INT64_PTR;
typedef  unsigned long long FRM_UINT64, * FRM_UINT64_PTR;
#define FRMDEFINE_INT64
#endif  //FRMDEFINE_INT64
#endif
#endif

// Windows System 64-bits Integer
#if defined (WIN32) || defined (_WIN32)
#if defined(_MSC_VER) || defined(__BORLANDC__)
#ifndef FRMDEFINE_INT64
typedef __int64 FRM_INT64, * FRM_INT64_PTR;
typedef unsigned __int64 FRM_UINT64, * FRM_UINT64_PTR;
#define FRMDEFINE_INT64
#endif  //FRMDEFINE_INT64
#else
typedef signed long long FRM_INT64, * FRM_INT64_PTR;
typedef unsigned long long FRM_UINT64, * FRM_UINT64_PTR;
#ifndef FRMDEFINE_INT64
#define FRMDEFINE_INT64
#endif
#endif
#endif

// UNIX 
#if defined(unix) || defined(__unix__) || defined(__unix)
# define FRMDEF_PLATFORM_UNIX
#endif
#if defined(FRMDEF_PLATFORM_UNIX)
#include <unistd.h>
#if defined(_XOPEN_VERSION)
#if (_XOPEN_VERSION >= 3)
#define FRMDEF_STANDARD_XOPEN_1989
#endif
#if (_XOPEN_VERSION >= 4)
#define FRMDEF_STANDARD_XOPEN_1992
#endif
#if (_XOPEN_VERSION >= 4) && defined(_XOPEN_UNIX)
#define FRMDEF_STANDARD_XOPEN_1995
#endif
#if (_XOPEN_VERSION >= 500)
#define FRMDEF_STANDARD_XOPEN_1998
#endif
#if (_XOPEN_VERSION >= 600)
#define FRMDEF_STANDARD_XOPEN_2003
#ifndef FRMDEFINE_INT64
typedef signed long long FRM_INT64, * FRM_INT64_PTR;
typedef unsigned long long FRM_UINT64, * FRM_UINT64_PTR;
#define FRMDEFINE_INT64
#endif
#endif
#endif
#endif

/////////////////////////////////////////////////////////////////////////////////
// Define BOOL
/////////////////////////////////////////////////////////////////////////////////
#ifndef FRMDEFINE_BOOL
typedef FRM_UINT8 FRM_BOOL;
#define FRMDEFINE_BOOL
#endif
#ifndef FRMBOOL_TRUE
#define FRMBOOL_TRUE (FRM_BOOL)1
#endif
#ifndef FRMBOOL_FALSE
#define FRMBOOL_FALSE (FRM_BOOL)0
#endif

/////////////////////////////////////////////////////////////////////////////////
// Define VOID
/////////////////////////////////////////////////////////////////////////////////
#ifndef FRMDEFINE_VOID
typedef void FRM_VOID, * FRM_VOID_PTR;
#define FRMDEFINE_VOID
#endif

#endif //TASSAPIFRAME_INCLUDE_FRMETYPES_H

