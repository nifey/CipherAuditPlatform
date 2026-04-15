#include <stdlib.h>
#include <string.h>
#include "../../scrub.h"

extern char some_cond;

void
bar (int *ptr, unsigned size)
{
  memset (ptr, 0, size);
}

void
foo ()
{
  int *SCRUB_ATTR ptr = (int *)malloc (sizeof (int));
  if (ptr)
    {
      if (some_cond)
      {
        bar (ptr, sizeof (int));
        
      }
      free (ptr);
    }
}