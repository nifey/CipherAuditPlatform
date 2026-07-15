#include "scrub.h"

extern SCRUBBER_ATTR void clear(char *);

void
foo (void)
{
  char SCRUB_ATTR buf[256] = {0};
  clear (buf);
}