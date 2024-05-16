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
        start_open_server(first_ip, atoi(first_port));

        printf("Program completed.\n");
    }
    return 0;
}

//        listen_server();
//        char* message = "Hello, server!";
//        if (sendInformation(second_ip, atoi(second_port), cert_file, key_file, ca_file, password, message) == 0) {
//            printf("Information sent successfully.\n");
//        } else {
//            printf("Failed to send information.\n");
//        }
