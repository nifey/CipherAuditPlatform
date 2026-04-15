#include "../../scrub.h"

extern void gen (char *);

void
bar (char *ptr)
{
  gen (ptr);
}

void
foo (void)
{
  char SCRUB_ATTR buf[256] = { 0 };
  bar (buf);
}