#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "scrub.h"
 

void sanfoundry_handler(int sig) {
    if (sig == SIGINT)
        printf("Sanfoundry: Caught SIGINT (Ctrl+C)\n");
    // else if (sig == SIGTERM)
    //     printf("Sanfoundry: Caught SIGTERM (kill)\n");
}
 
int main() {
    signal(SIGINT, sanfoundry_handler);
    // signal(SIGTERM, sanfoundry_handler);
    int *SCRUB_ATTR ptr;
    printf("Sanfoundry: Send SIGINT (Ctrl+C) or SIGTERM (kill)\n");
    while (1)
    {
        sleep(10);
        ptr = (int *)malloc (sizeof (int));
        if (ptr)
        {
          memset (ptr, 0, sizeof (int));
          free (ptr);
        }
    }
    return 0;
}



#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#define SCRUB_SIZE sizeof(int)

volatile sig_atomic_t got_sigint = 0;

/* Global sensitive buffer */
static int *sensitive_ptr = NULL;

/* Signal-safe zeroization */
static inline void
signal_safe_bzero(void *p, size_t n)
{
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (n--)
        *vp++ = 0;
}

void sanfoundry_handler(int sig)
{
    if (sig == SIGINT) {
        got_sigint = 1;

        /* Signal-safe wipe */
        if (sensitive_ptr)
            signal_safe_bzero(sensitive_ptr, SCRUB_SIZE);
    }
}

int main(void)
{
    struct sigaction sa = {0};
    sa.sa_handler = sanfoundry_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGINT, &sa, NULL);

    printf("Send SIGINT (Ctrl+C)\n");

    /* Pre-allocate once */
    sensitive_ptr = malloc(SCRUB_SIZE);
    if (!sensitive_ptr)
        return 1;

    while (1) {
        sleep(10);

        /* Normal program use */
        *sensitive_ptr = 0xdeadbeef;

        if (got_sigint) {
            write(STDOUT_FILENO,
                  "SIGINT received, memory scrubbed\n",
                  32);
            got_sigint = 0;
        }
    }

    /* Normal cleanup */
    signal_safe_bzero(sensitive_ptr, SCRUB_SIZE);
    free(sensitive_ptr);
    return 0;
}

