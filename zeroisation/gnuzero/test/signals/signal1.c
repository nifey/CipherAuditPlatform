#include <stdio.h>
#include <signal.h>
#include <unistd.h>
 
void sanfoundryHandler(int signal) {
    printf("\nSignal received: %d\n", signal);
    printf("Sanfoundry: Handling Ctrl+C gracefully!\n");
}
 
int main() {
    signal(SIGINT, sanfoundryHandler);  // Handle Ctrl+C
 
    while (1) {
        printf("Running... Press Ctrl+C to test signal handling\n");
        sleep(2);
    }
 
    return 0;
}