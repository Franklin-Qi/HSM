#ifndef __DUMP_H__
#define __DUMP_H__

#include "type.h"

extern void begin_dump_comm(u8 *);
extern void data_dump(u8 *, u8 *, int);
extern void end_dump_comm(u8 *);
extern void str_dump(u8 *);
extern void int_dump(u8 *str, int);

#endif
