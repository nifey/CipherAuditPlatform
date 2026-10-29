#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../scrub.h"


void function_spill(int *a1, int *a2, int *a3, int *a4, char *a5, int a6, int a7, int a8)
{
	int value = a8;
	for(int i=0;i<sizeof(a5);i++)
	{
		printf("%c\n",a5[i]);
	}
	
}

int main()
{
	int SCRUB_ATTR *a1 = malloc(sizeof(int));
    int a6;
	int *a2 = &a6;
	int *a3 = a2;
	int *a4 = a3;
	char a5[10] ;
	a5[0] = 'A';
	a6 = 8;
	int a7 = 9;
	int a8 = 6;
	if(a1)
	{
		function_spill(a1,a2,a3,a4,a5,a6,a7,a8);
		free(a1);
	}
	return 0;
}
