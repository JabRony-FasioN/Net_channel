#include <iostream>
#include "bee2/defs.h"
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <thread>
#include <fstream>

using namespace std;

void forwardData(int sourceSocket, int destinationSocket) {
    char buffer[1024];
    ssize_t bytesRead;
    
    while ((bytesRead = recv(sourceSocket, buffer, sizeof(buffer), 0)) > 0) {
        ssize_t bytesSent = send(destinationSocket, buffer, bytesRead, 0);
        if (bytesSent == -1) {
            std::cerr << "Ошибка при отправке данных" << std::endl;
            break;
        }
    }
    
    close(sourceSocket);
    close(destinationSocket);
}

int main() {
    // Создание сокета для прослушивания входящих подключений
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1) {
        std::cerr << "Ошибка при создании сокета" << std::endl;
        return 1;
    }
    
    // Настройка адреса сервера
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);
    serverAddress.sin_port = htons(12345);
    
    // Привязка сокета к адресу сервера
    if (bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) == -1) {
        std::cerr << "Ошибка при привязке сокета" << std::endl;
        close(serverSocket);
        return 1;
    }
    
    // Ожидание подключения первого клиента
    if (listen(serverSocket, 1) == -1) {
        std::cerr << "Ошибка при ожидании подключения первого клиента" << std::endl;
        close(serverSocket);
        return 1;
    }
    
    std::cout << "Ожидание подключения первого клиента..." << std::endl;
    
    // Принятие подключения первого клиента
    int clientSocket1 = accept(serverSocket, NULL, NULL);
    if (clientSocket1 == -1) {
        std::cerr << "Ошибка при принятии подключения первого клиента" << std::endl;
        close(serverSocket);
        return 1;
    }
    
    std::cout << "Первый клиент подключен!" << std::endl;
    
    // Ожидание подключения второго клиента
    std::cout << "Ожидание подключения второго клиента..." << std::endl;
    
    // Принятие подключения второго клиента
    int clientSocket2 = accept(serverSocket, NULL, NULL);
    if (clientSocket2 == -1) {
        std::cerr << "Ошибка при принятии подключения второго клиента" << std::endl;
        close(serverSocket);
        return 1;
    }
    
    std::cout << "Второй клиент подключен!" << std::endl;
    
    // Создание потоков для двунаправленного пересылки данных
    std::thread thread1(forwardData, clientSocket1, clientSocket2);
    std::thread thread2(forwardData, clientSocket2, clientSocket1);
    
    // Ожидание завершения потоков
    thread1.join();
    thread2.join();
    
    // Закрытие сокетов
    close(clientSocket1);
    close(clientSocket2);
    close(serverSocket);
    
    return 0;
}