//TLS-Server.c
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"

#include <stdio.h>  // for load ip server before connection
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <netdb.h>

#define FAIL    -1

int OpenListener(int port)
{   int sd;
    struct sockaddr_in addr;

    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if ( bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        perror("can't bind port");
        abort();
    }
    if ( listen(sd, 10) != 0 )
    {
        perror("Can't configure listening port");
        abort();
    }
    return sd;
}

/* идентично OpenListener только без шифрования */
int OpenUnencryptedListener(int port) /* same as OpenListener but without encryption */
{
	int sd;
    struct sockaddr_in addr;
    int yes = 1;

    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    // Use setsockopt to allow reusing of the port
    if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
    	perror("setsockopt");
    	abort();
    }

    if ( bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        perror("can't bind port");
        abort();
    }
    if ( listen(sd, 10) != 0 )
    {
        perror("Can't configure listening port");
        abort();
    }
    return sd;
}


void UnencryptedServlet(int client_socket, SSL_CTX * ctx, int port)
{
    int server_socket = OpenListener(port);
    char buffer[1024];
    int bytes;
    while(1){
        bytes = read(client_socket, buffer, sizeof(buffer));
        if(bytes < 0){
            perror("Error reading from unencrypted socket");
            exit(EXIT_FAILURE);
        }
        else if(bytes == 0){
            close(client_socket);
            break;
        }
        else {
            // print the message received
            buffer[bytes] = 0; // make sure the string is null-terminated
            printf("Message received: %s\n", buffer);

            struct sockaddr_in addr;
            socklen_t len = sizeof(addr);
            SSL *ssl;
            server_socket = accept(server_socket, (struct sockaddr*)&addr, &len);  /* accept connection as usual */
            printf("Connection from: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
            ssl = SSL_new(ctx);
            SSL_set_fd(ssl, server_socket);
            bytes = SSL_write(ssl, buffer, bytes);
            if ( bytes < 0 ) {
                ERR_print_errors_fp(stderr);
            }
            SSL_free(ssl);
            close(server_socket);
        }
    }
}

SSL_CTX* InitServerCTX(void)
{
	const SSL_METHOD *method;
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
    SSL_load_error_strings();   /* load all error messages */
	method = TLS_server_method();
    ctx = SSL_CTX_new(method);   /* create new context from method */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
	return ctx;
}


void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    //New lines
    if (SSL_CTX_load_verify_locations(ctx, CertFile, KeyFile) != 1)
        ERR_print_errors_fp(stderr);
    if (SSL_CTX_set_default_verify_paths(ctx) != 1)
        ERR_print_errors_fp(stderr);
    //End new lines
    /* set the local certificate from CertFile */
    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
	SSL_CTX_set_default_passwd_cb_userdata(ctx, "12345678");
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if (!SSL_CTX_check_private_key(ctx))
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
    //New lines - Force the client-side have a certificate
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_verify_depth(ctx, 4);
    //End new lines
}

void ShowCerts(SSL* ssl)
{
	X509 *cert;
	char *line;
	cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
	if ( cert != NULL )
	{
		printf("Server certificates:\n");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("Subject: %s\n", line);
		free(line);
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("Issuer: %s\n", line);
		free(line);
		X509_free(cert);
	}
	else
		printf("No certificates.\n");
}

void Servlet(SSL* ssl) /* Serve the connection -- threadable */
{
    char buf[1024];
    int sd, bytes;
    char enter[3] = { 0x0d, 0x0a, 0x00 };
    char output[1024];
    strcpy(output, "text from tls server malidi");
    strcat(output, enter);
    strcat(output, "msg from TLS server!");
    strcat(output, enter);
    if ( SSL_accept(ssl) == FAIL )     /* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);
    else{
        ShowCerts(ssl);        /* get any certificates */
        printf("Cipher being used: %s\n", SSL_get_cipher(ssl)); /* get the cipher */
	        bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
	        if ( bytes > 0 )
	        {
	            buf[bytes] = 0;
	            printf("Client msg: \"%s", buf);
	            SSL_write(ssl, output, strlen(output)); /* send reply */
	        }
	        else
	            ERR_print_errors_fp(stderr);
	 }
    sd = SSL_get_fd(ssl);       /* get socket connection */
    SSL_free(ssl);         /* release SSL state */
    close(sd);          /* close connection */
}

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
                if (strcmp(ifa->ifa_name, "lo") != 0) { // Исключаем адрес loopback-интерфейса
                    printf("IP address: %s\n", host);
                    break;
                }
            }
        }
    }
    freeifaddrs(ifaddr);
}

int main() {
    /* все как и раньше, до создания серверного сокета */
    printf("Getting IP address...\n");
    printIPAddress();
	SSL_CTX *ctx;
	int server;
	char portnum[]="5000";
	char unencrypted_portnum[]="5432";
	printf("Server started and listen port for encrypt and decryption: %s:\n",portnum);
	printf("Server started and listen port for broadcast: %s:\n",unencrypted_portnum);

	char CertFile[] = "key/certificate.crt";
    char KeyFile[] = "key/private_key.pem";
	SSL_library_init();
	ctx = InitServerCTX();        /* initialize SSL */
	LoadCertificates(ctx, CertFile, KeyFile); /* load certs */
	server = OpenListener(atoi(portnum));    /* create server socket */
    int unencrypted_socket = OpenUnencryptedListener(atoi(unencrypted_portnum));

    int pid = fork();
    if (pid == 0) { // child process
        while (1) {
            struct sockaddr_in addr;
            socklen_t len = sizeof(addr);
            int client = accept(unencrypted_socket, (struct sockaddr*)&addr, &len);
            printf("Unencrypted connection from: %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
            UnencryptedServlet(client, ctx, atoi(portnum));
        }
        close(unencrypted_socket);
        exit(EXIT_SUCCESS);
    }
    else if (pid > 0) { // parent process
        while (1)
        {
            struct sockaddr_in addr;
            socklen_t len = sizeof(addr);
            SSL *ssl;

            int client = accept(server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */
            printf("Connection from: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
            ssl = SSL_new(ctx);              /* get new SSL state with context */
            SSL_set_fd(ssl, client);      /* set connection socket to SSL state */
            Servlet(ssl);         /* service connection */
        }
        close(server);
        SSL_CTX_free(ctx);
    }
    else {
        perror("Error creating process");
        exit(EXIT_FAILURE);
    }
}
