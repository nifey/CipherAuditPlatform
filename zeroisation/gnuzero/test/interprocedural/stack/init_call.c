#include "../../scrub.h"

extern SCRUBBER_ATTR void clear (char *);
extern char some_cond;

static void
init (char *buf, unsigned size)
{
  for (int i = 0; i < size; i++)
    *buf = (char) 0;
    
}

static void
bar (char *buf)
{
  if (some_cond)
    clear (buf);
}

void
foo (void)
{
  char SCRUB_ATTR buf[256];
  init (buf, sizeof(buf));
  bar (buf);
}