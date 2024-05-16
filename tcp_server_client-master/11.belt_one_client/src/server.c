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
#include <postgresql/libpq-fe.h>  // psql parsing
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

int OpenConnection(const char *hostname, int port)
{
    int sd;
    struct hostent *host;
    struct sockaddr_in addr;
    if ( (host = gethostbyname(hostname)) == NULL )
    {
        perror(hostname);
        abort();
    }
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    sd = socket(PF_INET, SOCK_STREAM, 0);
    if ( sd < 0 )
    {
        perror("Socket");
        abort();
    }
    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        close(sd);
        perror(hostname);
        abort();
    }
    return sd;
}


void ProxyServlet(int client, SSL_CTX * ctx, SSL *ssl)
{
    char buffer[1024];
    int bytes;
    int server_socket;
    PGconn *conn;
    PGresult *res;
    char conninfo[512];
    char sqlResult[8096] = {0}; // Держите результат SQL здесь

    while(1){
        // Clear sqlResult at the start of each loop iteration
        memset(sqlResult, 0, sizeof(sqlResult));
        bytes = SSL_read(ssl, buffer, sizeof(buffer));
        if(bytes <= 0){
            close(server_socket);
            close(client);
            break;
        }
        else {
            buffer[bytes] = 0;
            printf("\nReceived from client: %s\n", buffer);
            char *command = strtok(buffer, " ");
            char *hostname = strtok(NULL, " ");
            char *port = strtok(NULL, " ");
            char *username = strtok(NULL, " ");
            char *database = strtok(NULL, " ");
            char *query = strtok(NULL, "\"");
            printf("Command: %s\n", command);
            printf("Query: %s\n", query);
            sprintf(conninfo, "host=%s port=%s user=%s dbname=%s", hostname, port, username, database);
            conn = PQconnectdb(conninfo);
            if (PQstatus(conn) != CONNECTION_OK) {
                printf("Connection to database failed: %s\n", PQerrorMessage(conn));
                PQfinish(conn);
                break;
            }
            res = PQexec(conn, query);
            if (PQresultStatus(res) != PGRES_TUPLES_OK &&
                PQresultStatus(res) != PGRES_COMMAND_OK) {
                printf("Query failed: %s", PQerrorMessage(conn));
                PQclear(res);
                PQfinish(conn);
                break;
            }
            int nrows = PQntuples(res);
            int nfields = PQnfields(res);

            for (int i = 0; i < nfields; i++)
                printf("%s ", PQfname(res, i));
            printf("\n");

            for (int i = 0; i < nrows; i++)
            {
                for(int j = 0; j < nfields; j++)
                    printf("%s ", PQgetvalue(res,i,j));
                printf("\n");
            }
            // Запись результатов в sqlResult
            for (int i = 0; i < nrows; i++)
            {
                for(int j = 0; j < nfields; j++)
                {
                    strcat(sqlResult,PQgetvalue(res,i,j));
                    strcat(sqlResult," ");
                }
                strcat(sqlResult,"\n");
            }

            // Отправка ответа обратно клиенту
            SSL_write(ssl,sqlResult,strlen(sqlResult));
            PQclear(res);
            PQfinish(conn);
        }
    }
}


void Servlet(SSL* ssl, SSL_CTX * ctx) /* Serve the connection -- threadable */
{
    if ( SSL_accept(ssl) == FAIL )     /* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);
    else{
        ShowCerts(ssl);        /* get any certificates */
        int client = SSL_get_fd(ssl);
        ProxyServlet(client, ctx, ssl); /* service connection */
    }
}

int main()
{
    // Инициализация, сертификаты, ключи и т.п.
    SSL_CTX *ctx;
	int server;
	char portnum[]="5000";
	char unencrypted_portnum[]="5432";
	printf("Server started and listen port for encrypt and decryption: %s:\n",portnum);
	printf("Server started and listen port for broadcast: %s:\n",unencrypted_portnum);
	char CertFile[] = "key/certificate.crt";
    char KeyFile[] = "key/private_key.pem";
	SSL_library_init();
	ctx = InitServerCTX();
	LoadCertificates(ctx, CertFile, KeyFile);
	server = OpenListener(atoi(portnum));
    while (1)
    {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;
        int client = accept(server, (struct sockaddr*)&addr, &len);
        printf("Connection from: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);
        Servlet(ssl, ctx);
    }
    close(server);
    SSL_CTX_free(ctx);
    return 0;
}
