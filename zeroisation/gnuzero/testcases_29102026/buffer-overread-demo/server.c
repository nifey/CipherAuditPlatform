#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void receive_and_reply(int sockfd) {
    char buffer[32] = {0}; //local variable
    ssize_t n, reply_size;
    struct sockaddr_in client;
    socklen_t client_len = sizeof(client);
    n = recvfrom(sockfd, buffer, sizeof(buffer) - 1, 0, (struct sockaddr*)&client, &client_len);
    if (n > 0) {
        printf("Received: %s\n", buffer);
        reply_size = atoi(buffer); // interpreting the first few bytes as reply size
        sendto(sockfd, buffer, reply_size, 0, (struct sockaddr *)&client, client_len);
    }
}

void use_and_zeroize(void *key, size_t key_size) {
    // Do some encryption somewhere
    //explicit_bzero(key, key_size);
    
}

int main(){

    printf(">> Starting server on port 7000\n");
    int sockfd = socket (AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        printf("Error creating socket. Exiting.\n");
        exit(1);
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(7000);

    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        printf("Error binding to port\n");
        exit(1);
    }

    uint32_t super_secret_key[8] = {0xA5A5A5A5,0xA5A5A5A5,0xA5A5A5A5,0xA5A5A5A5,
                                    0xA5A5A5A5,0xA5A5A5A5,0xA5A5A5A5,0xA5A5A5A5};
    // function that uses the key should zeroize it as well.
    use_and_zeroize(&super_secret_key, sizeof(super_secret_key));
    while (1) {
        receive_and_reply(sockfd);
    }
    close(sockfd);
}
