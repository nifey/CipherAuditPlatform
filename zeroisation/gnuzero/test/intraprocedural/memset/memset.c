#include <stdlib.h>
#include <string.h>
#include "scrub.h"

// unable to detect that only first 4 bytes getting zeroised
// GNUZero is probably not looking into what memset is actually doing, 
// need to understand why GNUZero is able to detect case C but not case A problem

// CASE A:
// void
// foo ()
// {
//   int * SCRUB_ATTR ptr = (int *)malloc (sizeof (int)*4);
//   if (ptr)
//     memset (ptr, 0, sizeof (int)); //only zeroising first few 4 bits but this GNUZero is unable to detect
//   free (ptr);
// }


// CASE B:
//The below implementation is safe
// void
// foo ()
// {
//   int * SCRUB_ATTR ptr = (int *)malloc (sizeof (int)*4);
//   if (ptr)
//     memset (ptr, 0, sizeof (ptr)); 
//   free (ptr);
// }


// CASE C:
// it is able to detect this problem correctly as sizeof(ptr) returns an 8 byte pointer, 
// zeroining 8 bytes whne allocated memory region was 4 bytes
// void
// foo ()
// {
//   int * SCRUB_ATTR ptr = (int *)malloc (sizeof (int));
//   if (ptr)
//     memset (ptr, 0, sizeof (ptr)); // causing a heap based buffer overflow warning , why?
//   free (ptr);
// }            


