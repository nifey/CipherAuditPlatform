#include "scrub.h"

extern SCRUBBER_ATTR void * scrubber_fn (void *);

void
bar (int *ptr)
{
  int t[4] = {0};
  if (ptr)
    t[1] = *ptr;
  //t[1] = 0; // sensitive data getting copied and cleared
  t[1] = 0; // even t[1] = 1 is being considered as a leak, which is unnecessary

  // interesting fact however is that it tracked that ptr is sensitive and was getting stored somewhere else
}

void
foo (void)
{
  int SCRUB_ATTR buf[4] = { 42 };
  bar (buf);

  int p[5]={0};
  //p[2] = buf[2]; // rightly leaks
  scrubber_fn (buf); // only buf getting cleared
  p[2] = buf[2]; // rightly doesnot leak
}