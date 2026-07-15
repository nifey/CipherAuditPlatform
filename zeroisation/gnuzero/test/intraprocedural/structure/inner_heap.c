#include <stdlib.h>
#include <string.h>
#include "scrub.h"

struct foo
{
  char *ptr;
  unsigned size;
};

extern char some_cond;

void
foo (void)
{
  struct foo SCRUB_ATTR s = { (char *)malloc (64), 64 };
  if (s.ptr)
    {
      // if (some_cond)
      //   {
          memset (s.ptr, 0, s.size);
        //}
    }
  free (s.ptr);
}