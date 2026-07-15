#include <stdlib.h>
#include "scrub.h"

extern SCRUBBER_ATTR void scrub (void *);

void
foo (void)
{
  int *SCRUB_ATTR ptr = (int *)malloc (sizeof (int));
  if (ptr)
    {
      scrub (ptr);
      free (ptr);
    }
}