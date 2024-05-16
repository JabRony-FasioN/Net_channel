//TLS-Client.c
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>  // for load ip client before connection
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ifaddrs.h>

#define FAIL    -1

    //Added the LoadCertificates how in the server-side makes.
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile, char* password)
{
	/* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
	/* set the private key from KeyFile (may be the same as CertFile) */
	SSL_CTX_set_default_passwd_cb_userdata(ctx, password);
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    if ( !SSL_CTX_check_private_key(ctx) )  /* verify private key */
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

int OpenConnection(const char *hostname, int port)
{
    int sd;
    struct hostent *host;
    struct sockaddr_in addr;
    struct sockaddr_in local_addr;
    socklen_t addr_size = sizeof(struct sockaddr_in);
    if ( (host = gethostbyname(hostname)) == NULL )
    {
        perror(hostname);
        abort();
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        close(sd);
        perror(hostname);
        abort();
    }
    getsockname(sd, (struct sockaddr *)&local_addr, &addr_size);
    printf("Local IP address is: %s\n", inet_ntoa(local_addr.sin_addr));
    printf("Local port is: %d\n", (int)ntohs(local_addr.sin_port));
    return sd;
}


int SetCipherList(SSL_CTX* ctx, const char *cipher_list)
{
    if (SSL_CTX_set_cipher_list(ctx, cipher_list) != 1) {
        ERR_print_errors_fp(stderr);
        return 0;  // fail
    }
    return 1;  // success
}


SSL_CTX* InitCTX(void)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    int ret;
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    method = TLS_client_method();  // replaced with TLS_client_method
    ctx = SSL_CTX_new(method);   /* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    // Sets minimum and maximum supported protocol to TLS1.2
    ret = SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    ret &= SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
    if (ret != 1)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
        printf("No certificates.\n");
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

void ReadFromServer(SSL* ssl) {
    char buf[1024];
    int bytes;

    bzero(buf, sizeof(buf)); // очищаем буферы
    bytes = SSL_read(ssl, buf, sizeof(buf) - 1); // Записываем данные из сокета
    if(bytes > 0) // если данные получены
    {
        buf[bytes] = 0;
        printf("Received: \n%s\n", buf); // Выводим данные на консоль
    }
    memset(buf, 0, sizeof(buf)); // clear the buffer
}


void UserToServerInteraction(SSL* ssl) {
    char buf[1024];
    while (1) {
        printf("\nEnter psql command (type QUIT to exit): ");
        fgets(buf, sizeof(buf), stdin);
        buf[strcspn(buf, "\n")] = 0;  // remove newline character at the end
        if (strncmp(buf, "QUIT", 4) == 0) {
            break;
        }
        SSL_write(ssl, buf, strlen(buf));   /* encrypt & send message */
        // read from server after each command
        ReadFromServer(ssl);
    }
    memset(buf, 0, sizeof(buf)); // clear the buffer
}

int main(int count, char *strings[])
{

    char *hostname, *portnum;
    SSL_CTX *ctx;
    int server;
    SSL *ssl;
    printf("Getting IP address...\n");
    printIPAddress();
    if ( count != 2 )
    {
        printf("Usage: %s <portnum>\n", strings[0]);
        exit(0);
    }
    SSL_library_init();
    hostname="127.0.0.1";
    portnum=strings[1];
    ctx = InitCTX();
    char CertFile[] = "key/certificate.crt";
    char KeyFile[] = "key/private_key.pem";
    LoadCertificates(ctx, CertFile, KeyFile, "12345678");
    server = OpenConnection(hostname, atoi(portnum));
    ssl = SSL_new(ctx);      /* create new SSL connection state */
    SSL_set_fd(ssl, server);    /* attach the socket descriptor */
    if ( SSL_connect(ssl) == FAIL )    /* perform the connection */
        ERR_print_errors_fp(stderr);
    else
    {
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);       /* get and print the server's certificates */
        UserToServerInteraction(ssl); /* interact with server with psql commands */
        SSL_free(ssl);        /* release SSL connection state */
    }
    close(server);         /* close socket */
    SSL_CTX_free(ctx);        /* release SSL context */
}