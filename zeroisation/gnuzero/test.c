#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "scrub.h"

extern SCRUBBER_ATTR void scrubber_fn (void *);
extern void use (char *);
extern char some_cond;
extern void __attribute__ ((access (write_only, 1))) init (char *);

void
foo (char *ptr)
{
  char x = *ptr;
  char y = x;
  y += 1;
  y -= x;
  use (&y);
  x = 42;
}

void
stack_issue (void)
{
  char SCRUB_ATTR buf[256];
  init (buf);
  if (some_cond)
    foo (buf);
  scrubber_fn (buf);
}

void
heap_issue (void)
{
  unsigned size = 64;
  char *SCRUB_ATTR buf = (char *)malloc (size);
  if (buf)
    {
      char *_guard = buf;
      buf = realloc (buf, 256);
      // in case realloc fails
      if (!buf)
        buf = _guard;
      else
        size = 256;
      memset (buf, 0, size);
    }
  free (buf);
}

// void
// f (int z)
// {
//   int a = z;
// }

// int
// main (void)
// {
//   int SCRUB_ATTR buf[4] = { 0 };
//   int y;
//   if (some_cond)
//     y = buf[1];
//   else
//     y = 5;
//   int x = y;
//   y = 0;
//   scrubber_fn (buf);
//   return 0;
// }
