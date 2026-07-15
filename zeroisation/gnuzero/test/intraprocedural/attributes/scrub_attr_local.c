#include <stdlib.h>
#include "scrub.h"

void
foo ()
{
  int *SCRUB_ATTR ptr = (int *)malloc (sizeof (int));
  free (ptr);
}

extern char some_cond;

void
bar ()
{
  int *SCRUB_ATTR ptr = NULL;
  if (some_cond)
    ptr = (int *)malloc (sizeof (int));
  free (ptr);
}