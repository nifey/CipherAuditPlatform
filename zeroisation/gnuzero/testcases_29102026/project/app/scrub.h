#ifndef SCRUBBER_ATTR
#define SCRUBBER_ATTR __attribute__((__scrubber__))
#endif
#ifndef SCRUB_ATTR
#define SCRUB_ATTR __attribute__((__scrub__))
#endif

// For Windows tests
#ifdef SecureZeroMemory
#undef SecureZeroMemory
extern void SCRUBBER_ATTR SecureZeroMemory(void *, size_t);
#endif