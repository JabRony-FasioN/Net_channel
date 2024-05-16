#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include "common_mod.h"

#define BUFFER_SIZE 1024

void handle_error(const char* message) {
    perror(message);
    exit(1);
}

// Функция, которая будет выполняться в отдельном потоке для каждого подключения
void* handleConnection(void* socket) {
    char buffer[BUFFER_SIZE];
    int valread;
    int newSocket = *(int*)socket;
    pthread_mutex_t lock;
    if (pthread_mutex_lock(&lock) != 0) {
        handle_error("Mutex lock error");
    }
    valread = read(newSocket, buffer, BUFFER_SIZE - 1);
    if (valread < 0) {
        handle_error("Read error");
    }
    buffer[valread] = '\0';
    printf("Received message: %s\n", buffer);
    if (pthread_mutex_unlock(&lock) != 0) {
        handle_error("Mutex unlock error");
    }
    close(newSocket);
    pthread_exit(NULL);
}

void start_open_server(char *first_ip, int first_port){
        int serverSocket, newSocket;
        struct sockaddr_in serverAddress, clientAddress;
        socklen_t clientLength;
        char buffer[BUFFER_SIZE];
        serverSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (serverSocket < 0) {
            perror("Ошибка при создании сокета");
            exit(1);
        }
        serverAddress.sin_family = AF_INET;
        serverAddress.sin_addr.s_addr = inet_addr(first_ip);
        serverAddress.sin_port = htons(first_port);
        if (bind(serverSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) {
            perror("Ошибка при привязке сокета");
            exit(1);
        }
        if (listen(serverSocket, 5) < 0) {
            perror("Ошибка при ожидании подключений");
            exit(1);
        }
        printf("Сервер запущен и ожидает подключений...\n");
        while (1) {
            clientLength = sizeof(clientAddress);
            newSocket = accept(serverSocket, (struct sockaddr *)&clientAddress, &clientLength);
            int remotePort;
            monitorSocketStatus(newSocket, &remotePort);
            printf("Порт источника: %hu\n", remotePort);
            if (newSocket < 0) {
                perror("Ошибка при принятии подключения");
                exit(1);
            }
            printf("Подключение принято. Создан новый сокет: %d\n", newSocket);
            pthread_t thread;    // Создаем новый поток для обработки подключения
            if (pthread_create(&thread, NULL, handleConnection, (void *)&newSocket) != 0) {
                perror("Ошибка при создании потока");
                exit(1);
            }
//            char filename[20];
//            sprintf(filename, "data_%d.txt", remotePort);
//            FILE *file = fopen(filename, "w");
//            if (file == NULL) {
//                perror("Ошибка при создании файла");
//                exit(1);
//            }
//            ssize_t bytesRead;
//            while ((bytesRead = read(newSocket, buffer, BUFFER_SIZE)) > 0) {
//                fwrite(buffer, 1, bytesRead, file);
//            }
//            if (bytesRead < 0) {
//                perror("Ошибка при чтении данных из сокета");
//                exit(1);
//            }
//            printf("Данные сохранены в файл: %s\n", filename);
//            close(newSocket);
//            fclose(file);
        }
        close(serverSocket);
}




//#define BUFFER_SIZE 1024
//#define SOURCE_PORT 12345
//#define DESTINATION_PORT 54321
//
//int listen_server() {
//    int source_socket, destination_socket;
//    struct sockaddr_in source_address, destination_address;
//    char buffer[BUFFER_SIZE];
//    // Создаем сокет для исходного порта
//    source_socket = socket(AF_INET, SOCK_STREAM, 0);
//    if (source_socket < 0) {
//        perror("Не удалось создать сокет для исходного порта");
//        exit(EXIT_FAILURE);
//    }
//    // Настраиваем адрес для исходного порта
//    memset(&source_address, 0, sizeof(source_address));
//    source_address.sin_family = AF_INET;
//    source_address.sin_addr.s_addr = htonl(INADDR_ANY);
//    source_address.sin_port = htons(SOURCE_PORT);
//    // Привязываем сокет к адресу исходного порта
//    if (bind(source_socket, (struct sockaddr *)&source_address, sizeof(source_address)) < 0) {
//        perror("Не удалось привязать исходный сокет к адресу");
//        exit(EXIT_FAILURE);
//    }
//    // Начинаем прослушивать исходный порт
//    if (listen(source_socket, 5) < 0) {
//        perror("Не удалось начать прослушивать исходный порт");
//        exit(EXIT_FAILURE);
//    }
//    printf("Сервер запущен и прослушивает порт %d\n", SOURCE_PORT);
//    // Создаем сокет для порта назначения
//    destination_socket = socket(AF_INET, SOCK_STREAM, 0);
//    if (destination_socket < 0) {
//        perror("Не удалось создать сокет для порта назначения");
//        exit(EXIT_FAILURE);
//    }
//    // Настраиваем адрес для порта назначения
//    memset(&destination_address, 0, sizeof(destination_address));
//    destination_address.sin_family = AF_INET;
//    destination_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
//    destination_address.sin_port = htons(DESTINATION_PORT);
//    // Подключаемся к порту назначения
//    if (connect(destination_socket, (struct sockaddr *)&destination_address, sizeof(destination_address)) < 0) {
//        perror("Не удалось подключиться к порту назначения");
//        exit(EXIT_FAILURE);
//    }
//    printf("Успешно подключено к порту %d\n", DESTINATION_PORT);
//    // Бесконечный цикл для прослушивания и пересылки данных
//    while (1) {
//        int client_socket = accept(source_socket, NULL, NULL);
//        if (client_socket < 0) {
//            perror("Ошибка при принятии клиентского соединения");
//            exit(EXIT_FAILURE);
//        }
//        // Чтение данных из исходного порта
//        memset(buffer, 0, BUFFER_SIZE);
//        ssize_t bytesRead = read(client_socket, buffer, BUFFER_SIZE);
//        if (bytesRead < 0) {
//            perror("Ошибка при чтении данных из исходного порта");
//            exit(EXIT_FAILURE);
//        }
//        // Отправка данных на порт назначения
//        ssize_t bytesSent = write(destination_socket, buffer, bytesRead);
//        if (bytesSent < 0) {
//            perror("Ошибка при отправке данных на порт назначения");
//            exit(EXIT_FAILURE);
//        }
//        close(client_socket);
//    }
//    // Закрываем сокеты
//    close(source_socket);
//    close(destination_socket);
//    return 0;
//}
