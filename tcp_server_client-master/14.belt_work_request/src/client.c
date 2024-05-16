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
#include <postgresql/libpq-fe.h>
#define FAIL    -1

//Added the LoadCertificates how in the server-side makes.
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile, char* CAFile, char* password)
{
    if (SSL_CTX_load_verify_locations(ctx, CAFile, NULL) != 1)
        ERR_print_errors_fp(stderr);
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


// initialize PostgreSQL connection
PGconn *init_postgresql(const char *conninfo) {
    PGconn *conn = PQconnectdb(conninfo);
    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "Connection to database failed: %s", PQerrorMessage(conn));
        PQfinish(conn);
        exit(1);
    }
    return conn;
}

char *exec_postgresql_query(PGconn *conn, const char *query) {
    PGresult *res = PQexec(conn, query);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Query failed: %s", PQerrorMessage(conn));
    } else {
        int num_fields = PQnfields(res);
        int num_rows = PQntuples(res);
        char *result = malloc(num_fields * 1024 * num_rows);  // estimate element size
        result[0] = '\0';  // initialize empty
        for (int i = 0; i < num_rows; i++) {
            for (int j = 0; j < num_fields; j++) {
                strcat(result, PQgetvalue(res, i, j));
                if (j < num_fields - 1)
                    strcat(result, ",");
            }
            if (i < num_rows - 1)
                strcat(result, "\n");
        }
        PQclear(res);
        return result;
    }
}


// Trim unwanted ending characters from a string (whitespace, newline, return carriage)
void rtrim(char *str) {
    int n = strlen(str) - 1;
    while(n >= 0 && (str[n] == ' ' || str[n] == '\n' || str[n] == '\r')) {
        str[n--] = '\0';
    }
}

char* add_quotes_and_group_values(char* raw_string) {
    char* savePtr;
    char* token = strtok_r(raw_string, "\n", &savePtr);
    char* result = (char*)calloc(strlen(raw_string)*3, sizeof(char));
    result[0] = 0;

    while (token != NULL) {
        char* savePtr2;
        char* subtoken = strtok_r(token, ",", &savePtr2);
        strcat(result, "("); // начало строки вставки

        while(subtoken != NULL) {
            char* quoted = (char*)malloc(strlen(subtoken)+3);
            sprintf(quoted, "\'%s\'", subtoken);
            strcat(result, quoted);
            free(quoted);

            subtoken = strtok_r(NULL, ",", &savePtr2);
            if(subtoken != NULL) strcat(result, ",");
        }

        strcat(result, ")"); // конец строки вставки
        token = strtok_r(NULL, "\n", &savePtr);
        if(token != NULL) strcat(result, ",");
    }

    return result;
}

void UserToServerInteraction(SSL* ssl, const char* hostname, const char* port, const char* username, const char* dbname) {
    char buf[2048];
    snprintf(buf, sizeof(buf), "psql 127.0.0.1 5432 postgres mydatabase \"SELECT max(id) FROM temp_name\"");
    SSL_write(ssl, buf, strlen(buf));   /* encrypt & send message */
    char *remote_max_id = ReadFromServer(ssl, 20);   // assume id won't be more than 19 digits

    char conninfo[] = "dbname=mydb host=localhost user=postgres password=1234";
    PGconn *local_conn = init_postgresql(conninfo);
    char *missing_rows_query = malloc(2048);

    snprintf(missing_rows_query, 2048, "SELECT * FROM temp_name WHERE id > %s ORDER BY id ASC", remote_max_id);
    char *missing_rows = exec_postgresql_query(local_conn, missing_rows_query);
    printf(missing_rows);
    char *quoted_and_grouped_missing_rows = add_quotes_and_group_values(strdup(missing_rows));

    snprintf(buf, sizeof(buf), "psql 127.0.0.1 5432 postgres mydatabase \"INSERT INTO temp_name (Date, ID, FIO, Test) VALUES %s\"", quoted_and_grouped_missing_rows);
    printf(quoted_and_grouped_missing_rows);
//    SSL_write(ssl, buf, strlen(buf));   /* encrypt & send message */
    int bytes = SSL_write(ssl, buf, strlen(buf));   /* encrypt & send message */
    if(bytes < 0){
        int error = SSL_get_error(ssl, bytes);
        fprintf(stderr, "SSL write error: %d\n", error);
    }

    free(remote_max_id);
    free(missing_rows_query);
    free(missing_rows);
    free(quoted_and_grouped_missing_rows);
    PQfinish(local_conn);
}


int main(int count, char *strings[])
{
    char *hostname, *portnum;
    SSL_CTX *ctx;
    int server;
    SSL *ssl;

    printf("Getting IP address...\n");
    printIPAddress();
    if ( count != 3 )
    {
        printf("Usage: %s <hostname> <portnum>\n", strings[0]);
        exit(0);
    }

    SSL_library_init();
    hostname = strings[1];
    portnum = strings[2];
    char username[] = "postgres";
    char dbname[] = "mydatabase";
    char portnum_sql[]="5432";
    ctx = InitCTX();
    char CertFile[] = "/home/pi/app/cert/client.pem";
    char KeyFile[] = "/home/pi/app/cert/client.key";
    char CAFile[] = "/home/pi/app/cert/root.crt";
    char password[] = "12345678";
    LoadCertificates(ctx, CertFile, KeyFile, CAFile, password);

    server = OpenConnection(hostname, atoi(portnum));

    ssl = SSL_new(ctx);      /* create new SSL connection state */
    SSL_set_fd(ssl, server);    /* attach the socket descriptor */

    if ( SSL_connect(ssl) == FAIL )    /* perform the connection */
        ERR_print_errors_fp(stderr);
    else
    {
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);       /* get and print the server's certificates */
        UserToServerInteraction(ssl, hostname, portnum_sql, username, dbname); /* interact with server with SQL commands
         */
        SSL_free(ssl);        /* release SSL connection state */
    }
    close(server);         /* close socket */
    SSL_CTX_free(ctx);        /* release SSL context */
}