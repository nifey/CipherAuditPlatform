#include <stdio.h>
#include "mylib.h"
#include<stdlib.h>
#include "scrub.h"

int main()
{
    unsigned char SCRUB_ATTR secret[] = "SensitiveData";
    int len = sizeof(secret);

    process_secret(secret, len);
    

    // for(int i = 0; i < 10; i++)
    //     printf("%02x ", secret[0]);
    // printf("\n");

    return 0;
}
