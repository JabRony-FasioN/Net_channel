#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "openssl_mod.h"
#include "second_ssl_adres.h"

int sendInformation(char* hostname, int port, char* CertFile, char* KeyFile, char* CAFile, char* password, char* message) {
    SSL_CTX* ctx = NULL;
    SSL* ssl = NULL;
    int sockfd = -1;
    int ret = -1;
    SSL_library_init();  // Initialize OpenSSL
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    ctx = SSL_CTX_new(TLS_client_method()); // Create a new SSL context
    LoadCertificates(ctx, CertFile, KeyFile, CAFile, password);
    ssl = SSL_new(ctx);      /* create new SSL connection state */
    if (ctx == NULL) {
        fprintf(stderr, "Failed to create SSL context.\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    sockfd = socket(AF_INET, SOCK_STREAM, 0); // Create a new socket
    if (sockfd == -1) {
        perror("Failed to create socket");
        goto cleanup;
    }
    struct sockaddr_in server_addr;  // Connect to the server
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, hostname, &(server_addr.sin_addr)) <= 0) {
        perror("Failed to convert IP address");
        goto cleanup;
    }
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("Failed to connect to server");
        goto cleanup;
    }
    ssl = SSL_new(ctx);  // Create a new SSL connection
    if (ssl == NULL) {
        fprintf(stderr, "Failed to create SSL connection.\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    if (SSL_set_fd(ssl, sockfd) == 0) {  // Attach the SSL connection to the socket
        fprintf(stderr, "Failed to attach SSL connection to socket.\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    if (SSL_connect(ssl) != 1) {  // Perform the SSL handshake
        fprintf(stderr, "Failed to perform SSL handshake.\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    } else {    ShowCerts(ssl);}
    if (SSL_write(ssl, message, strlen(message)) <= 0) {  // Send the message to the server
        fprintf(stderr, "Failed to send message to server.\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    ret = 0; // Successful connection and sending
cleanup:  // Clean up resources
    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (ctx != NULL) {
        SSL_CTX_free(ctx);
    }
    if (sockfd != -1) {
        close(sockfd);
    }
    return ret;
}

