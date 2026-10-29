#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "../../scrub.h"

// What is the leak here?
// What can be done to fix it?
__attribute__((noinline))

void foo(int *a6)
{
	
	
    int value = *a6;
    printf("Value: %d\n", value);	
}


int main()
{
	
    int SCRUB_ATTR a6 = 8;
	int *a2 = &a6;
	
	
	
	foo(a2);
		
	
    *a2 = 0;
	return 0;
}



