#include <stdlib.h>
#include "../../scrub.h"

extern SCRUBBER_ATTR void scrubber_fn (void *);

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
        scrubber_fn(guard);
        free (guard);
      }

      else
      { 
        scrubber_fn(ptr);
        free(ptr);
      }

    }
  //free (ptr);
}