#include <stdlib.h>
#include <string.h>
#include "scrub.h"

#define SIZE 32

void
foo (int * x)
{
  char * SCRUB_ATTR alloc_ptr = (int *)malloc (SIZE);
  if (alloc_ptr)
    {
      memcpy (alloc_ptr, x, sizeof (4));
      free (alloc_ptr);
    }
}