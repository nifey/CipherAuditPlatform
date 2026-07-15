#include "scrub.h"

//extern SCRUBBER_ATTR void gen(char *);

void gen(char *val)
{
 *val = 0;
}

void
foo (void)
{
  char SCRUB_ATTR buf[256] = {0};
  //gen(&buf[0]); // GNUZero flagging it as a leak
  // gen(buf)  // GNUZero unable to detect a leak, although both the statements are the same, 

  // size info is important
  for(int i = 0; i<256;i++)
  {
  gen (&buf[i]);
  }
  
  //original code 
  // gen(buf) should also consider the size , otherwise how does it know how much to zeroize gen(buf, sizeof(buf)); // Correct: pointer AND size passed
  
  // passing a pointer to the starting location of the array gen(buf) (not gen(&buf[0]) is not showing a warning
  // whereas passing a pointer to a particular memory element is showing a warningg
  // it does check if scrubber function is called on all the memory locations
  // calling on gen(&buf[0]) causes a leak


  // Depends on the implementation of the gen function
  // buf(gen) should work fine(in zeroising) if inside it takes the first address and 
  // loops through to zeroise the entire array(only possible for gen to work without length is if it is a string), 
  // but it would also require the size argument in this case

  // The statements gen(buf) and gen(&buf[0]) mean the same thing, why does GNUZERO flag the second one as not secure zeroisation
  // and the first gen(buf) as safe?

  
}
