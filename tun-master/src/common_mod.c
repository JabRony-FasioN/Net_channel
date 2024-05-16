#include <sys/types.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

// --------------------------------------- patch cert -----------------------------------------------------------------
char* get_username() {
    char* username = getlogin();
    if (username == NULL) {
        perror("getlogin failed");
        return NULL;
    }
    return username;
}

void prepare_file_path(const char* base_dir, const char* username, const char* file_path, char** output) {
    snprintf(*output, strlen(base_dir) + strlen(username) + strlen(file_path) + 1, "%s%s%s", base_dir, username, file_path);
}


int patch_cert(char* mode, char** cert_file, char** key_file, char** ca_file){
    char* username = get_username();
    if (username == NULL) {
        return EXIT_FAILURE;
    }
    const char* base_dir = "/home/";
    const char* ca_path = "/app/cert/root.crt";
    char cert_path[30];
    char key_path[30];
    if (strcmp(mode, "-s") == 0) {
        strcpy(cert_path, "/app/cert/server.pem");
        strcpy(key_path, "/app/cert/server.key");
    } else if (strcmp(mode, "-c") == 0) {
        strcpy(cert_path, "/app/cert/client.pem");
        strcpy(key_path, "/app/cert/client.key");
    } else {
        printf("Invalid mode. Please use -s for SERVER mode or -c for CLIENT mode.\n");
        return EXIT_FAILURE;
    }
    size_t cert_file_len = strlen(base_dir) + strlen(username) + strlen(cert_path) + 1;
    size_t key_file_len = strlen(base_dir) + strlen(username) + strlen(key_path) + 1;
    size_t ca_file_len = strlen(base_dir) + strlen(username) + strlen(ca_path) + 1;
    *cert_file = (char*)malloc(cert_file_len * sizeof(char));
    *key_file = (char*)malloc(key_file_len * sizeof(char));
    *ca_file = (char*)malloc(ca_file_len * sizeof(char));
    if (cert_file == NULL || key_file == NULL || ca_file == NULL) {
        perror("Failed to allocate memory");
        return EXIT_FAILURE;
    }
    prepare_file_path(base_dir, username, cert_path, cert_file);
    prepare_file_path(base_dir, username, key_path, key_file);
    prepare_file_path(base_dir, username, ca_path, ca_file);
//    printf("cert_file: %s\n", *cert_file);
//    printf("key_file: %s\n", *key_file);
//    printf("ca_file: %s\n", *ca_file);
}

// ----------------------------------------- end patch cert -----------------------------------------------------------

void printIPAddress() {
    struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char host[NI_MAXHOST];
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;
        family = ifa->ifa_addr->sa_family;
        if (family == AF_INET || family == AF_INET6) {
            s = getnameinfo(ifa->ifa_addr,
                            (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
                            host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                printf("getnameinfo() failed: %s\n", gai_strerror(s));
                exit(EXIT_FAILURE);
            }
            if (family == AF_INET) {
                if (strcmp(ifa->ifa_name, "lo") != 0) {
                    printf("IP address: %s\n", host);
                    break;
                }
            }
        }
    }
    freeifaddrs(ifaddr);
}


void monitorSocketStatus(int socket, int* remotePort) {
    int error;
    socklen_t errorLength = sizeof(error);
    if (getsockopt(socket, SOL_SOCKET, SO_ERROR, &error, &errorLength) < 0) {
        perror("Error getting socket option");
        return;
    }
    if (error != 0) {
        fprintf(stderr, "Socket error: %s\n", strerror(error));
    } else {
        pid_t pid = getpid();
        pid_t ppid = getppid();
        printf("Socket is connected and working fine with PID %d and PPID %d\n", pid, ppid);
        struct sockaddr_in socketAddress;
        socklen_t socketAddressLength = sizeof(socketAddress);
        if (getsockname(socket, (struct sockaddr *)&socketAddress, &socketAddressLength) == -1) {
            perror("Error getting socket information");
            return;
        }
        printf("Socket Information:\n");
        printf("Descriptor: %d\n", socket);
        printf("Family: %d\n", socketAddress.sin_family);
        printf("Port: %d\n", ntohs(socketAddress.sin_port));
        printf("Address: %s\n", inet_ntoa(socketAddress.sin_addr));
        if (getpeername(socket, (struct sockaddr *)&socketAddress, &socketAddressLength) == -1) {
            perror("Ошибка получения информации о соединении");
            exit(EXIT_FAILURE);
        }
        char remoteIP[INET_ADDRSTRLEN];         // Вывод адреса удаленного узла
        inet_ntop(AF_INET, &(socketAddress.sin_addr), remoteIP, INET_ADDRSTRLEN);
        unsigned short remotePortV = ntohs(socketAddress.sin_port);
        *remotePort = remotePortV;
        printf("Адрес удаленного узла: %s\n", remoteIP);
        printf("Порт удаленного узла: %hu\n", remotePort);
    }
}