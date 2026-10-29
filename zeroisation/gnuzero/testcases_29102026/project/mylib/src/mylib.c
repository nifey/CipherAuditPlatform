#include <string.h>
#include "mylib.h"
#include "reprocess.h"
#include <stdlib.h>
#include <stdio.h>

void process_secret(unsigned char *data, int len)
{
   
    char *ptr = (char *)malloc (sizeof (char)*len);
    if (ptr)
    {
        memcpy (ptr, data, sizeof (char)*len);
        //memset(ptr, 0, sizeof (char)*len);
        free(ptr);
        
    }


}