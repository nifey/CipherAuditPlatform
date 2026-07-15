#include <stdlib.h>
#include <string.h>
#include "scrub.h"

#define SIZE 32

extern SCRUBBER_ATTR void scrubber_fn (void *);
extern void init (char *);

void
foo ()
{
  char SCRUB_ATTR src_buf[SIZE];
  init (src_buf);
  char dst_buf[SIZE];
  //memcpy (dst_buf, src_buf, SIZE);
  scrubber_fn (src_buf);
}