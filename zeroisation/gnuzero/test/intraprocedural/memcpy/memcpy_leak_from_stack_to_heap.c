#include <stdlib.h>
#include <string.h>
#include "scrub.h"

#define SIZE 32

extern SCRUBBER_ATTR void scrubber_fn (void *);
extern void init (char *);

void
foo ()
{
  char SCRUB_ATTR buf[SIZE];
  init (buf);

  char unbuf[SIZE];

  memcpy (unbuf, buf, SIZE);

  unbuf[2] = unbuf[0]*2;
  char *alloc_ptr = malloc (SIZE);
  if (alloc_ptr)
    {
      memcpy (alloc_ptr, buf, SIZE);
    }
  free (alloc_ptr);
  scrubber_fn (buf);
}