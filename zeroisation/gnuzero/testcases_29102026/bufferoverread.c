#include <stdio.h>

__attribute__((noinline)) 
void write_secret_to_mem()
{   
    
	char secret[] = "AAAAAAAAAAAAA"; // This is a secret string
    char filler[] = "BBBBBBBBBBBBB"; // This is a filler array to occupy space in memory
    char new_filler[12];
    new_filler[12] = filler[12] + secret[12]; // This is another filler array to occupy space in memory
    
    for (int i = 0; i < 12; i++)
	{
		printf("%c", filler[i]);
	}
    printf("\n");
}



__attribute__((noinline))
void read_secret_from_mem()
{   
    // C rule : if you initialize an array with lesser elements than it's size, rest of the elements are filled with 0
    // char secret[24] = "CCCC";
	char secret[24];
    secret[0] = 'C';
    secret[1] = 'C';
    secret[2] = 'C';
    secret[3] = 'C';
    //char secret[24];
	for (int i = 0; i < 24; i++)
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

