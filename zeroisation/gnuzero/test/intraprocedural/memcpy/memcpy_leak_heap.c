#include <stdlib.h>
#include <string.h>
#include "../../scrub.h"

#define SIZE 32


extern SCRUBBER_ATTR void scrubber_fn (void *);
//extern void init (char *);
void init(char *p) { memset(p, 'A', SIZE); }

void
foo ()
{
  //char * SCRUB_ATTR alloc_src = malloc (SIZE);
  char * SCRUB_ATTR alloc_src = (char *)malloc (sizeof (char)*32);
  if (alloc_src)
    {
      init(alloc_src);
      char *alloc_dst = (char *)malloc (sizeof (char)*32);
      // if (alloc_dst)
      //   memcpy (alloc_dst, alloc_src, SIZE);
      //   //scrubber_fn(alloc_dst);
      //  free (alloc_dst);
 
      
    }
  //scrubber_fn(alloc_src);
  free (alloc_src);
}