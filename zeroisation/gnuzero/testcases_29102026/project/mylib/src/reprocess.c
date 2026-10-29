#include<string.h>
#include "reprocess.h"
#include <stdlib.h>
#include <stdio.h>

void reprocess_secret(unsigned char *data, int len)
{
    for (int i = 0; i < len; i++)
        data[i] ^= 0x55;
}