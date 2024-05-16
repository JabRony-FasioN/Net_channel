#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define BUFFER_SIZE 1024
#define SOURCE_PORT 12345
#define DESTINATION_PORT 54321

int listen_server() {
    int source_socket, destination_socket;
    struct sockaddr_in source_address, destination_address;
    char buffer[BUFFER_SIZE];
    // Создаем сокет для исходного порта
    source_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (source_socket < 0) {
        perror("Не удалось создать сокет для исходного порта");
        exit(EXIT_FAILURE);
    }
    // Настраиваем адрес для исходного порта
    memset(&source_address, 0, sizeof(source_address));
    source_address.sin_family = AF_INET;
    source_address.sin_addr.s_addr = htonl(INADDR_ANY);
    source_address.sin_port = htons(SOURCE_PORT);
    // Привязываем сокет к адресу исходного порта
    if (bind(source_socket, (struct sockaddr *)&source_address, sizeof(source_address)) < 0) {
        perror("Не удалось привязать исходный сокет к адресу");
        exit(EXIT_FAILURE);
    }
    // Начинаем прослушивать исходный порт
    if (listen(source_socket, 5) < 0) {
        perror("Не удалось начать прослушивать исходный порт");
        exit(EXIT_FAILURE);
    }
    printf("Сервер запущен и прослушивает порт %d\n", SOURCE_PORT);
    // Создаем сокет для порта назначения
    destination_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (destination_socket < 0) {
        perror("Не удалось создать сокет для порта назначения");
        exit(EXIT_FAILURE);
    }
    // Настраиваем адрес для порта назначения
    memset(&destination_address, 0, sizeof(destination_address));
    destination_address.sin_family = AF_INET;
    destination_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    destination_address.sin_port = htons(DESTINATION_PORT);
    // Подключаемся к порту назначения
    if (connect(destination_socket, (struct sockaddr *)&destination_address, sizeof(destination_address)) < 0) {
        perror("Не удалось подключиться к порту назначения");
        exit(EXIT_FAILURE);
    }
    printf("Успешно подключено к порту %d\n", DESTINATION_PORT);
    // Бесконечный цикл для прослушивания и пересылки данных
    while (1) {
        int client_socket = accept(source_socket, NULL, NULL);
        if (client_socket < 0) {
            perror("Ошибка при принятии клиентского соединения");
            exit(EXIT_FAILURE);
        }
        // Чтение данных из исходного порта
        memset(buffer, 0, BUFFER_SIZE);
        ssize_t bytesRead = read(client_socket, buffer, BUFFER_SIZE);
        if (bytesRead < 0) {
            perror("Ошибка при чтении данных из исходного порта");
            exit(EXIT_FAILURE);
        }
        // Отправка данных на порт назначения
        ssize_t bytesSent = write(destination_socket, buffer, bytesRead);
        if (bytesSent < 0) {
            perror("Ошибка при отправке данных на порт назначения");
            exit(EXIT_FAILURE);
        }
        close(client_socket);
    }
    // Закрываем сокеты
    close(source_socket);
    close(destination_socket);
    return 0;
}
