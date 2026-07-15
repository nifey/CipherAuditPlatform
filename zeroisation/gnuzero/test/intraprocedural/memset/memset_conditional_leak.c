#include <stdlib.h>
#include <string.h>
#include "scrub.h"

extern char some_cond;

void
foo ()
{
  int *SCRUB_ATTR ptr = (int *)malloc (sizeof (int));
  if (ptr)
    {
      if (some_cond)
        memset (ptr, 0, sizeof (int));
      free (ptr);
    }
}