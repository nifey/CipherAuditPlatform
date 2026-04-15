#include "../../scrub.h"

extern SCRUBBER_ATTR void * scrubber_fn (void *);

void
bar (int *ptr)
{
  int x = 0;
  if (ptr)
    x = *ptr;
}

void
foo (void)
{
  int SCRUB_ATTR buf[4] = { 42 };
  bar (buf);
  scrubber_fn (buf);
}