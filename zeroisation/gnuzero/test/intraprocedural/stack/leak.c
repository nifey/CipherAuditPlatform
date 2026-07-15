#include "scrub.h"

extern SCRUBBER_ATTR void gen(char *);

void
foo (void)
{
  char SCRUB_ATTR buf[256] = {0};
  gen (buf);
  
  
}
