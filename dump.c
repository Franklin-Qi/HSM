#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>

#include "type.h"

static char *DbgStr = "****************************";

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
