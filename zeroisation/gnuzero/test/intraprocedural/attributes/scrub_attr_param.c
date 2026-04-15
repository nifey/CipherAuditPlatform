#include "../../scrub.h"

int
foo (int *SCRUB_ATTR ptr)
{
  if (ptr)
    return *ptr;
  else
    return 0;
}