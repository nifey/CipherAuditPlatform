#include "scrub.h"


extern SCRUBBER_ATTR void clear (struct foo *ctx);
struct foo
{
  unsigned int inner[2];
};

extern const unsigned int some_data;

void
init (struct foo *ctx, const unsigned int data)
{
  ctx->inner[1] = data;
}

// couldnot declare as erased after this function, not being able to check at the field level probably
// void clear (struct foo *ctx)
// {
//   ctx->inner[1] = 0;
//   ctx->inner[2] = 0;
// }

void
entry (void)
{
  struct foo SCRUB_ATTR s;
  init (&s, some_data);
  //when clear is a scrubber function and the structure object is passed, it is getting marked as clean 
  clear(&s);
}