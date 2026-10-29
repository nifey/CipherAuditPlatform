#include <stdio.h>

__attribute__((noinline)) 
void write_secret_to_mem()
{
	char secret[] = "AAAAAAAAAAAAA"; // This is a secret string

}



__attribute__((noinline))
void read_secret_from_mem()
{
	char secret[12];
	for (int i = 0; i < 12; i++)
	{
		printf("%c", secret[i]);
	}
}

int main()
{
	write_secret_to_mem();
	read_secret_from_mem();

 	return 0;
}

