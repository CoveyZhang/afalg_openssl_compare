#include <stdio.h>
#include <stdlib.h>
#include "common.h"

int array_equal(char *buf1, char *buf2, int n)
{
	for (int i = 0; i < n; ++i)
	{
		if ((unsigned char)buf1[i] != (unsigned char)buf2[i])
			{printf("%02x;%02x;%d\n",buf1[i],buf2[i],i);
			return -1;}
	}
	return 0;
}

int rand_array(char *buf, int n)
{
	for (int i = 0; i < n; ++i)
	{
		buf[i] = (unsigned char) rand() % 256;
#ifdef PRINT_DETAIL
		printf("%02x ", (unsigned char)buf[i]);
#endif
	}
#ifdef PRINT_DETAIL
	printf("\n");
#endif
}
