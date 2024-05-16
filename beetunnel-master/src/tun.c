#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "first_adres.h"
#include "first_ssl_adres.h"
#include "second_adres.h"
#include "second_ssl_adres.h"
#include "openssl_mod.h"
#include "common_mod.h"


#include <sys/socket.h>
#include <netinet/in.h>

#define BUFFER_SIZE 1024


int main(int argc, char *argv[]){
    if (argc != 6){printf("Usage: %s <-s|-c> <Proxy IP> <Proxy Port> <Destination IP> <Destination Port>\n", argv[0]);exit(EXIT_FAILURE);}
    printIPAddress();
    char *mode = argv[1];  // mode from arguments
    char *first_ip = argv[2];  // Get listen ip from arguments
    char *first_port = argv[3];  // Get listen port from arguments
    char *second_ip = argv[4];  // Get destination IP from arguments
    char *second_port = argv[5];  // Get destination Port from arguments
    char password[] = "12345678";
    char *cert_file;
    char *key_file;
    char *ca_file;
    patch_cert(mode, &cert_file, &key_file, &ca_file);
    if (strcmp(argv[1], "-s") == 0) {printf("Mode: %s\n", mode);
        printf("Program completed.\n");
    } else if (strcmp(argv[1], "-c") == 0) {printf("Mode: %s\n", mode);
        int serverSocket, newSocket;
        struct sockaddr_in serverAddress, clientAddress;
        socklen_t clientLength;
        char buffer[BUFFER_SIZE];
        // Создание сокета
        serverSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (serverSocket < 0) {
            perror("Ошибка при создании сокета");
            exit(1);
        }
        // Настройка адреса сервера
        serverAddress.sin_family = AF_INET;
        serverAddress.sin_addr.s_addr = INADDR_ANY;
        serverAddress.sin_port = htons(first_port);
        // Привязка сокета к адресу сервера
        if (bind(serverSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) {
            perror("Ошибка при привязке сокета");
            exit(1);
        }
        // Ожидание подключений
        if (listen(serverSocket, 5) < 0) {
            perror("Ошибка при ожидании подключений");
            exit(1);
        }
        printf("Сервер запущен и ожидает подключений...\n");
        while (1) {
            // Принятие нового подключения
            clientLength = sizeof(clientAddress);
            newSocket = accept(serverSocket, (struct sockaddr *)&clientAddress, &clientLength);
            if (newSocket < 0) {
                perror("Ошибка при принятии подключения");
                exit(1);
            }
            printf("Подключение принято. Создан новый сокет: %d\n", newSocket);
            // Создание отдельного файла для сохранения данных
            char filename[20];
            sprintf(filename, "data_%d.txt", newSocket);
            FILE *file = fopen(filename, "w");
            if (file == NULL) {
                perror("Ошибка при создании файла");
                exit(1);
            }
            // Чтение данных из сокета и запись в файл
            ssize_t bytesRead;
            while ((bytesRead = read(newSocket, buffer, BUFFER_SIZE)) > 0) {
                fwrite(buffer, 1, bytesRead, file);
            }
            if (bytesRead < 0) {
                perror("Ошибка при чтении данных из сокета");
                exit(1);
            }
            printf("Данные сохранены в файл: %s\n", filename);
            // Закрытие сокета и файла
            close(newSocket);
            fclose(file);
        }
        // Закрытие серверного сокета
        close(serverSocket);

//        listen_server();
//        char* message = "Hello, server!";
//        if (sendInformation(second_ip, atoi(second_port), cert_file, key_file, ca_file, password, message) == 0) {
//            printf("Information sent successfully.\n");
//        } else {
//            printf("Failed to send information.\n");
//        }
        printf("Program completed.\n");
    }
    return 0;
}


