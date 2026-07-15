#include <stdlib.h>
#include <string.h>
#include "scrub.h"

void
bar (int *ptr, unsigned size)
{
  if (ptr)
    memset (ptr, 0, size);
}

void
foo ()
{
  int *SCRUB_ATTR ptr = (int *)malloc (sizeof (int));
  bar (ptr, sizeof (int));
  free (ptr);
}