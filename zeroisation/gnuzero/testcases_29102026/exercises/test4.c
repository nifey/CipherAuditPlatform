#include "../../scrub.h"

extern SCRUBBER_ATTR void * scrubber_fn (void *);
// what is the point of leak? what is the fix?
void
bar (int *ptr)
{
  int t[4] = {0};
  if (ptr)
    t[1] = *ptr;

}

void
foo (void)
{
  int SCRUB_ATTR buf[4] = { 42 };
  bar (buf);

  int p[5]={0};
  p[2] = buf[2]; 
  scrubber_fn (buf); 
}