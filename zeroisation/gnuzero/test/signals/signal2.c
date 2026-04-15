#include <stdio.h>
#include <signal.h>
 
void result_handler(int sig) {
    printf("Sanfoundry: raise() handled signal %d successfully!\n", sig);
}
 
int main() {
    signal(SIGUSR1, result_handler);
    raise(SIGUSR1);
    return 0;
}