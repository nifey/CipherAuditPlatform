#include <stdlib.h>
#include "../../scrub.h"

SCRUBBER_ATTR void
scrubber_fn (void *ptr)
{
}

void
foo (void)
{
  int *SCRUB_ATTR ptr = (int *)malloc (sizeof (int));
  if (ptr)
    {
      scrubber_fn (ptr);
      free (ptr);
    }
}