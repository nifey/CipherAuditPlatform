#include <string.h>
#include "scrub.h"

void
bar (int *ptr, unsigned int size)
{
  memset (ptr, 1, size);
}

void
foo ()
{
  int SCRUB_ATTR buf[256] = { 0 };
  bar (buf, 256);
}