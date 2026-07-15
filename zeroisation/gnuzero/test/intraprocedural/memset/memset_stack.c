#include <stdlib.h>
#include <string.h>
#include "scrub.h"

void
foo ()
{
  int SCRUB_ATTR buf[256] = { 0 };
  memset (buf, 0, 256);
}