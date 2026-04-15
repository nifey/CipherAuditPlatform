#include <stdlib.h>
#include "../../scrub.h"

SCRUBBER_ATTR void
scrubber_fn (void *ptr)
{
}

extern char some_cond;

void
foo (void)
{
  int *SCRUB_ATTR ptr = (int *)malloc (sizeof (int));
  if (ptr)
    {
      if (some_cond)
        scrubber_fn (ptr);
      free (ptr);
    }
}