#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(int argc, char** argv){
    int len;
    if (argc < 2) {
        printf("Usage: ./a.out <stringmsg>\n");
        exit(1);
    }
    len = strlen(argv[1]);
    printf(">> Sending message of size %d to server on port 7000\n", len);
    int sockfd = socket (AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        printf("Error creating socket. Exiting.\n");
        exit(1);
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(7001);

    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        printf("Error binding to port\n");
        exit(1);
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(7000);

    if (sendto(sockfd, argv[1], strlen(argv[1]), 0, 
                (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
        printf("Failed sending a packet\n");

    unsigned char buffer[1024];
    ssize_t n = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
    if (n > 0) {
        buffer[n] = '\0';
        printf("Server reply length: %d\n", (int)n);
        for (int i = 0;  i < n; i++)
            printf("%02x", buffer[i]);
        printf("\n");
    }

    close(sockfd);
}
