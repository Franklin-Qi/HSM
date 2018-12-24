/*********************************************************************/
/* 文 件 名：  utilpack.c                                            */
/* 版 本 号：  v1.1                                                  */
/* 所 有 者：  Flyger Zhuang                                         */
/* 版    权：  Union Beijing                                         */
/* 功    能：  农行ICCM_密钥安全系统_第05号_加密机接口（国密）api      */
/* 维护记录： 1. 2008-6-11 by  Liwb                                  */
/*           2. 2009-4-21 by Chendy	                            */
/*********************************************************************/

#include <stdio.h>

#include "util.h"

int Hex2Int(char *string, int size)
{
	int length = 0;
	int i = 0;

	while(size > 0)
	{
		if ((string[size - 1] >= '0') && (string[size - 1] <= '9'))
			length += ((string[size - 1] - '0') << (i << 2));
		else if ((string[size - 1] >= 'A') && (string[size - 1] <= 'F'))
			length += ((string[size - 1] - 'A' + 0xA) << (i << 2));
		else if ((string[size - 1] >= 'a') && (string[size - 1] <= 'f'))
			length += ((string[size - 1] - 'a' + 0xA) << (i << 2));
		else
			return 0;
		i ++;
		size --;		
	}
	return length;
}

int Num2Int(char *string, int size)
{
	int length = 0;
	int i = 1;

	while(size > 0)
	{
		if ((string[size - 1] >= '0') && (string[size - 1] <= '9'))
			length += (string[size - 1] - '0') * i;
		else
			return 0;
		i *= 10;
		size --;
	}
	return length;
}

int Int2Num(unsigned int integer, char *string, int size)
{
	char tmpstr[5];

	if ((size > 4) || (integer > 9999))
		return 0;

	sprintf(tmpstr, "%04d", integer);
	memcpy(string, &tmpstr[4 - size], size);
	string[size] = '\0';

	return size;
}

int Int2Hex(unsigned int integer, char *string, int size)
{
	char tmpstr[9];

	if ((size > 4) || (integer > 0xFFFF))
		return 0;

	sprintf(tmpstr, "%04X", integer);
	memcpy(string, &tmpstr[4 - size], size);
	string[size] = '\0';

	return size;
}

int Int2Bin(unsigned int integer, unsigned char *string, int size)
{
	int i;

	if (size > 4)
		return 0;

	for (i=0; i<size; i++)
	{
		string[size-i-1] = integer >> (i*8);
	}

	return size;
}

unsigned int Bin2Int(unsigned char *string, int size)
{
	int i;
	unsigned int ret = 0;

	if (size > 4)
		return 0;

	for (i=0; i<size; i++)
	{
		ret = ret << 8;
		ret += string[i];		
	}

	return ret;
}


int Hex2Bin(char *string, unsigned char* bytes, unsigned int *length)
{
	int len = 0;

	while ((*string != '\0') && (*(string + 1) != '\0') && (len < (int)*length))
	{
		if ((*string >= '0') && (*string <= '9'))
			*bytes = ((*string - '0') << 4);
		else if ((*string >= 'A') && (*string <= 'F'))
			*bytes = ((*string - 'A' + 0xA) << 4);
		else if ((*string >= 'a') && (*string <= 'f'))
			*bytes = ((*string - 'a' + 0xA) << 4);
		else
			break;

		string ++;

		if ((*string >= '0') && (*string <= '9'))
			*bytes |= *string - '0';
		else if ((*string >= 'A') && (*string <= 'F'))
			*bytes |= *string - 'A' + 0xA;
		else if ((*string >= 'a') && (*string <= 'f'))
			*bytes |= *string - 'a' + 0xA;
		else
			break;

		string++;
		bytes++;
		len++;
	}

	if(length)
		*length = len;

	return len;
}

int Bin2Hex(unsigned char *bytes, unsigned int length, char *string)
{
	*(string + (length << 1) ) = '\0';

	while (length--)
	{
		if ((bytes[length] & 0xF0) > 0x90)
			*(string + (length << 1)) = 'A' + ((bytes[length] >> 4) - 10);
		else
			*(string + (length << 1)) = '0' + (bytes[length] >> 4);

		if ((bytes[length] & 0xF) > 0x9)
			*(string + (length << 1) + 1) = 'A' + ((bytes[length] & 0xF) - 10);
		else
			*(string + (length << 1) + 1) = '0' + (bytes[length] & 0xF);
	}

	return (int)strlen(string);
}

int CheakNum(char *string,unsigned int length)
{
	int i;
	for (i =0;i<(int)length;i++)
	{
		if (string[i]>'9' ||string[i]<'0')
		{
			break;
		}
	}
	if (i!=length)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

int GetNumCnt(char *string,unsigned int *length)
{
	int i;
	int len = *length;
	for (i =0;i<(int)len;i++)
	{
		if (string[i]>'9' ||string[i]<'0')
		{
			break;
		}
	}
	
	if (i!=*length)
	{
		*length = i;
		return 1;
	}
	else
	{
		*length = i;
		return 0;
	}
}
/********************** functions *************************/

int int2bcd(int iNum, unsigned char to[])
{
    if (iNum > 256*256)
    {
	iNum = iNum - (256*256);
    }

    to[0] = (unsigned char)(iNum/256);
    to[1] = (unsigned char)(iNum%256);

    return(0);
}

char dec2hex(int n)
{
    if(n>=10 && n<=15)
	return 'A'+n-10;
    else
	return '0'+n;
}


void dec_hex(int n, char *to)
{

    int i = 0, j = 0, k = 0;
    int mod;
    char tmp;

    while(n)
    {
	mod = (n % 16);
	to[i++] = dec2hex(mod);
	n = (n / 16);
    }
    for(j=0,k=i-1; j<i/2; j++,k--)
    {
	tmp = to[j];
	to[j] = to[k];
	to[k] = tmp;
    }

    to[i] = '\0';

}



int UnpackBCD( unsigned char *InBuf,  char *OutBuf, int Len )
{

	int rc = 0;

	unsigned char ch;

	//register int i, active = 0;
	int i, active = 0;
	for ( i = 0; i < Len; i++ )
	{

		ch = *InBuf;

		if ( active )
		{
			(*OutBuf=(ch&0xF))<10 ? (*OutBuf+='0') : (*OutBuf+=('A'-10));
			InBuf++;
		}
		else
		{
			(*OutBuf=(ch&0xF0)>>4)<10 ? (*OutBuf+='0') : (*OutBuf+=('A'-10));
		}

		active ^= 1;

		if ( !isxdigit ( *OutBuf ) )	/* validate character */
		{
			rc = -1;
			break;
		}

		OutBuf++;

	}

	*OutBuf = 0;

	return ( rc );

}

int PackBCD( char *InBuf, unsigned char *OutBuf, int Len )
{
	int	    rc;		/* Return Value */

	register int     ActiveNibble;	/* Active Nibble Flag */

	char     CharIn;	/* Character from source buffer */
	unsigned char   CharOut;	/* Character from target buffer */

	rc = 0;		/* Assume everything OK. */

	ActiveNibble = 0;	/* Set Most Sign Nibble (MSN) */
				/* to Active Nibble. */

	for ( ; (Len > 0); Len--, InBuf++ )
	{
		CharIn = *InBuf;
		
		if ( !isxdigit ( CharIn ) )	/* validate character */
		{
			rc = -1;
		}
		else
		{
			if ( CharIn > '9')
			{
				CharIn += 9;	/* Adjust Nibble for A-F */
			}
		}

		if ( rc == 0 )
		{

			CharOut = *OutBuf;
			if ( ActiveNibble )		
			{
				*OutBuf++ = (unsigned char)( ( CharOut & 0xF0) |
					     ( CharIn  & 0x0F)   );
			}
			else
			{
				*OutBuf = (unsigned char)( ( CharOut & 0x0F)   |
					   ( (CharIn & 0x0F) << 4)   );
			}
			ActiveNibble ^= 1;	/* Change Active Nibble */
		}
	}

	return rc;

}

// add by lisq 2011-12-14
char hexlowtoasc(int xxc)
{
    xxc&=0x0f;
    if (xxc<0x0a) xxc+='0';
    else xxc+=0x37;
    return (char)xxc;
}

char hexhightoasc(int xxc)
{
    xxc&=0xf0;
    xxc = xxc>>4;
    if (xxc<0x0a) xxc+='0';
    else xxc+=0x37;
    return (char)xxc;
}

char asctohex(char ch1,char ch2)
{
    char ch;
    if (ch1>='A') ch=(char )((ch1-0x37)<<4);
    else ch=(char)((ch1-'0')<<4);
    if (ch2>='A') ch|=ch2-0x37;
    else ch|=ch2-'0';
    return ch;
}

int aschex_to_bcdhex(char aschex[],int len,char bcdhex[])
{
    int i,j;

        if (len % 2 == 0)
                j = len / 2;
        else
                j = len / 2 + 1;

    for (i = 0; i < j; i++)
        bcdhex[i] = asctohex(aschex[2*i],aschex[2*i+1]);

    return(j);
}

int bcdhex_to_aschex(char bcdhex[],int len,char aschex[])
{
    int i;

    for (i=0;i<len;i++)
    {
        aschex[2*i]   = hexhightoasc(bcdhex[i]);
        aschex[2*i+1] = hexlowtoasc(bcdhex[i]);
    }

    return(len*2);
}

// add by lisq 2011-12-14 end
