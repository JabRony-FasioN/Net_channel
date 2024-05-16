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

void *receiveMessages(void *sockfd_ptr) {
    int sockfd = *((int *)sockfd_ptr);
    char buffer[MAX_BUFFER_SIZE];
    struct sockaddr_in clientAddress;
    socklen_t addrLen;
    int bytesReceived;

    while (1) {
        addrLen = sizeof(clientAddress);
        bytesReceived = recvfrom(sockfd, buffer, MAX_BUFFER_SIZE, 0, (struct sockaddr *)&clientAddress, &addrLen);
        if (bytesReceived == -1) {
            perror("Error in receiving message");
            exit(EXIT_FAILURE);
        }
        strncpy(buffer + bytesReceived, "test msg from 12345", sizeof(buffer)-bytesReceived - 1);
        printf("Received message: %s\n", buffer);
    }
}

void *sendTestMessage(void *sockfd_ptr) {
    int sockfd = *((int *)sockfd_ptr);
    struct sockaddr_in serverAddress;
    char *testMessage = "This is a test message.";
    int bytesSent;

    memset((char *)&serverAddress, 0, sizeof(serverAddress));
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);
    serverAddress.sin_port = htons(PORT);

    while (1) {
        bytesSent = sendto(sockfd, testMessage, strlen(testMessage), 0, (struct sockaddr *)&serverAddress, sizeof(serverAddress));
        if (bytesSent == -1) {
            perror("Error in sending test message");
            exit(EXIT_FAILURE);
        }
        sleep(60); // Пауза в 60 секунд
    }
}

int main() {
    int sockfd;
    pthread_t sendThread, receiveThread;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Error in socket creation");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in serverAddress;
    memset((char *)&serverAddress, 0, sizeof(serverAddress));
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);
    serverAddress.sin_port = htons(PORT);

    if (bind(sockfd, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) {
        perror("Error in binding");
        exit(EXIT_FAILURE);
    }

    pthread_create(&sendThread, NULL, &sendTestMessage, &sockfd);
    pthread_create(&receiveThread, NULL, &receiveMessages, &sockfd);

    pthread_join(sendThread, NULL);
    pthread_join(receiveThread, NULL);

    close(sockfd);

    return 0;
}
