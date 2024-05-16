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

    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
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

void PrintAvailableCiphers(SSL_CTX* ctx)
{
    SSL *ssl;
    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        printf("Could not create new SSL object\n");
        return;
    }

    STACK_OF(SSL_CIPHER) *ciphers = SSL_get_ciphers(ssl);
    int num_ciphers = sk_SSL_CIPHER_num(ciphers);
    printf("Available ciphers:\n");
    for (int i = 0; i < num_ciphers; i++) {
        const SSL_CIPHER* cipher = sk_SSL_CIPHER_value(ciphers, i);
        printf(" - %s\n", SSL_CIPHER_get_name(cipher));
    }

    SSL_free(ssl);
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




int main()
{
    printf("Getting IP address...\n");
    printIPAddress();
    SSL_CTX *ctx;
    int server;
    SSL *ssl;
    char buf[1024];
    int bytes;
    char hostname[]="127.0.0.1";
    char portnum[]="5000";
    char CertFile[] = "key/certificate.crt";
    char KeyFile[] = "key/private_key.pem";
    SSL_library_init();
    ctx = InitCTX();
//    PrintAvailableCiphers(ctx);  //Output the Available Ciphers. work!!!
    LoadCertificates(ctx, CertFile, KeyFile, "12345678");
    server = OpenConnection(hostname, atoi(portnum));
    ssl = SSL_new(ctx);      /* create new SSL connection state */
    SSL_set_fd(ssl, server);    /* attach the socket descriptor */
    if ( SSL_connect(ssl) == FAIL )   /* perform the connection */
        ERR_print_errors_fp(stderr);
    else
    {   char *msg = "test_page_malise";

        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);        /* get any certs */
        SSL_write(ssl, msg, strlen(msg));   /* encrypt & send message */
        bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
        buf[bytes] = 0;
        printf("Received: \"%s\"\n", buf);
        SSL_free(ssl);        /* release connection state */
    }
    close(server);         /* close socket */
    SSL_CTX_free(ctx);        /* release context */
    return 0;
}

