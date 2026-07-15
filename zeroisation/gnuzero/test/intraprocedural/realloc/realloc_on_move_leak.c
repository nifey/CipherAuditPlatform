#include <stdlib.h>
#include <string.h>
#include "scrub.h"

void
foo ()
{
  int *SCRUB_ATTR ptr = (int *)malloc (sizeof (int));
  if (ptr)
    {
      int *guard = ptr;
      ptr = realloc (ptr, 2 * sizeof (int));
      if (!ptr)
        {
          // In case realloc fails
          memset (guard, 0, sizeof (int));
          free (guard);
        }
      else
        {
          memset (ptr, 0, 2 * sizeof (int));
          free (ptr);
        }
    }
}
