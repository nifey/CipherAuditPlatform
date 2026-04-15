#include <stdlib.h>
#include <string.h>
#include "../../scrub.h"


// They named the file as no leak, but this causes leak too 
// even when scrubber is called on the memory first before a realloc is called on it
extern SCRUBBER_ATTR void scrubber_fn (void *);

void
foo ()
{
  int *SCRUB_ATTR ptr = (int *)malloc (sizeof (int));
  if (ptr)
    {
      scrubber_fn (ptr);
      //free(ptr);
      realloc (ptr, 0);
    }
}
