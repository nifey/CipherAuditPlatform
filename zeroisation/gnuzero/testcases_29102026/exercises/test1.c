#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "../../scrub.h"





__attribute__((noinline)) 
void use_key_operation(volatile uint8_t* key) {

    int SCRUB_ATTR a = 1;
    int SCRUB_ATTR b = 7; 
    // int *g = &a; 
    // int *h = &b;
    
    // *g = 0;
    // *h = 0;
}