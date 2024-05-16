#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>

#define PORT 12345
#define MAX_BUFFER_SIZE 1024
#define FORWARDING_PORT 12346

void *receiveMessages(void *sockfd_ptr) {
    int new_sockfd = *((int *)sockfd_ptr);
    char buffer[MAX_BUFFER_SIZE];
    int bytesReceived;

    int forward_sockfd;
    forward_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (forward_sockfd < 0) {
        perror("Error in socket creation for proxy");
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in forwardAddress;
    memset(&forwardAddress, 0, sizeof(forwardAddress));
    forwardAddress.sin_family = AF_INET;
    forwardAddress.sin_addr.s_addr = htonl(INADDR_ANY);
    forwardAddress.sin_port = htons(FORWARDING_PORT);

    if (connect(forward_sockfd, (struct sockaddr*)&forwardAddress, sizeof(forwardAddress)) < 0) {
        perror("Error in connecting to the forwarding server");
        exit(EXIT_FAILURE);
    }

    while (1) {
        bytesReceived = read(new_sockfd, buffer, sizeof(buffer) - 1);
        if (bytesReceived <= 0) {
            perror("Error in receiving message or client disconnected");
            break;
        }
        buffer[bytesReceived] = '\0';
        strcat(buffer, "test msg from 12345");
        printf("Received message: %s\n", buffer);

        // Send the message to the forwarding server
        if (write(forward_sockfd, buffer, strlen(buffer)) < 0) {
            perror("Failed to forward the message");
            break;
        }
    }

    close(forward_sockfd);
    close(new_sockfd);

    return NULL;
}

int main() {
    int sockfd;
    pthread_t receiveThread;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Error in socket creation");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in serverAddress;
    memset(&serverAddress, 0, sizeof(serverAddress));
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);
    serverAddress.sin_port = htons(PORT);

    if (bind(sockfd, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) {
        perror("Error in binding");
        exit(EXIT_FAILURE);
    }

    if (listen(sockfd, 1) < 0) {
        perror("Error in listening");
        exit(EXIT_FAILURE);
    }

    while (1) {
        struct sockaddr_in clientAddress;
        socklen_t clientAddrLen = sizeof(clientAddress);

        int new_sockfd = accept(sockfd, (struct sockaddr*)&clientAddress, &clientAddrLen);
        if (new_sockfd < 0) {
            perror("Error in accepting the client");
            exit(EXIT_FAILURE);
        }

        if (pthread_create(&receiveThread, NULL, &receiveMessages, &new_sockfd) != 0) {
            perror("Failed to create thread");
            exit(EXIT_FAILURE);
        }

        pthread_detach(receiveThread);
    }

    close(sockfd);

    return 0;
}
