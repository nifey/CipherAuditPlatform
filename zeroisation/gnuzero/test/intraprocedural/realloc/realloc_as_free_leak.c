#include <stdlib.h>
#include <string.h>
#include "scrub.h"

void
foo ()
{
  int *SCRUB_ATTR ptr = (int *)malloc (sizeof (int));
  if (ptr)
    realloc (ptr, 0);
}
