#ifndef _HSM_TYPE_H_
#define _HSM_TYPE_H_

/* 是否包含报文头(2字节或4字节) 0--表示不包含 */
#define PKGHEAD_SIZE  2

#ifndef  SUCC
#define  SUCC 0x41
#endif
#ifndef  FAIL
#define  FAIL 0x45
#endif

#ifndef u8
typedef unsigned char u8;
#endif

#ifndef u16
typedef unsigned short u16;
#endif

#ifndef u32
typedef unsigned long u32;
#endif

#ifndef u64
typedef unsigned long long  u64;
#endif

#ifndef s8
typedef signed char s8;
#endif

#ifndef s16
typedef signed short s16;
#endif

#ifndef s32
typedef signed long s32;
#endif

#ifndef s64
typedef signed long long  s64;
#endif


#endif /* end _HSM_TYPE_H_ */

