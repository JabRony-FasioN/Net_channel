//TLS-Client.c
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#define FAIL    -1

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile, char* CAFile, char* password)
{
    if (SSL_CTX_load_verify_locations(ctx, CAFile, NULL) != 1)
        ERR_print_errors_fp(stderr);
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
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

char* ReadFromServer(SSL* ssl, size_t buf_size) {
    char *buf = (char*) malloc(buf_size);
    int bytes;
    bzero(buf, buf_size); // очищаем буфер
    bytes = SSL_read(ssl, buf, buf_size - 1); // Записываем данные из сокета
    if(bytes > 0) // если данные получены
    {
        buf[bytes] = 0;
        printf("Received: \n%s\n", buf); // Выводим данные на консоль
    }
    else
    {
        free(buf);
        buf = NULL;
    }
    return buf;
}

void SendMessage(SSL* ssl) {
    const char msg[] = "Hello, World!";
    SSL_write(ssl, msg, sizeof(msg));   /* encrypt & send message */
}

int main(int count, char *strings[]) {
    char *hostname, *portnum;
    SSL_CTX *ctx;
    int server;
    SSL *ssl;

    if ( count != 3 ) {
        printf("Usage: %s <hostname> <portnum>\n", strings[0]);
        exit(0);
    }

    SSL_library_init();

    hostname = strings[1];
    portnum = strings[2];

    ctx = InitCTX();
    char CertFile[] = "/home/pi/app/cert/client.pem";
    char KeyFile[] = "/home/pi/app/cert/client.key";
    char CAFile[] = "/home/pi/app/cert/root.crt";
    char password[] = "12345678";
    LoadCertificates(ctx, CertFile, KeyFile, CAFile, password);

    server = OpenConnection(hostname, atoi(portnum));

    ssl = SSL_new(ctx);      /* create new SSL connection state */
    SSL_set_fd(ssl, server); /* attach the socket descriptor */

    if ( SSL_connect(ssl) == FAIL ) /* perform the connection */
        ERR_print_errors_fp(stderr);
    else {
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);       /* get and print the server's certificates */
        SendMessage(ssl); /* send hello world message */
        SSL_free(ssl);        /* release SSL connection state */
    }

    close(server);         /* close socket */
    SSL_CTX_free(ctx);        /* release SSL context */

    return 0;
}