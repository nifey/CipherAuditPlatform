#include "scrub.h"

extern SCRUBBER_ATTR void clear (char *);
extern char some_cond;

void
bar (char *buf)
{
  if (some_cond)
    clear (buf);
}

void
foo (void)
{
  char SCRUB_ATTR buf[256] = { 0 };
  bar (buf);
}