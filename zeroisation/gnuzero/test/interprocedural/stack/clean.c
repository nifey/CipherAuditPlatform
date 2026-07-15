#include "scrub.h"

extern SCRUBBER_ATTR void clear (char *);

void
bar (char *buf)
{
  clear (buf);
}

void
foo (void)
{
  char SCRUB_ATTR buf[256] = { 0 };
  bar (buf);
}