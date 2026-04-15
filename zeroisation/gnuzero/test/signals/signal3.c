#include <stdio.h>
#include <signal.h>
#include <unistd.h>

 
void pause_handler(int sig) {
    printf("Sanfoundry: Signal %d received during blocked state.\n", sig);
}
 
int main() {

    signal(SIGINT, sanfoundryHandler);
    struct sigaction block_action;
    sigset_t signal_set, old_set;
 
    block_action.sa_handler = pause_handler;
    sigemptyset(&block_action.sa_mask);
    block_action.sa_flags = 0;
    sigaction(SIGINT, &block_action, NULL);
 
    sigemptyset(&signal_set);
    sigaddset(&signal_set, SIGINT);
    sigprocmask(SIG_BLOCK, &signal_set, &old_set);  // Block SIGINT
 
    printf("Sanfoundry: SIGINT blocked for 5 seconds. Press Ctrl+C now.\n");
    sleep(5);
 
    printf("Sanfoundry: Unblocking SIGINT...\n");
    sigprocmask(SIG_SETMASK, &old_set, NULL);  // Unblock
 
    sleep(5);
    return 0;
}