// openssl_mod.c
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
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <postgresql/libpq-fe.h>
#include <pthread.h>
//--------------------------------------- common -----------------------------------------------------------------------
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile, char* CAFile, char* password)
{
    if (SSL_CTX_load_verify_locations(ctx, CAFile, NULL) != 1)
        ERR_print_errors_fp(stderr);
    if (SSL_CTX_load_verify_locations(ctx, CertFile, KeyFile) != 1)
        ERR_print_errors_fp(stderr);
    if (SSL_CTX_set_default_verify_paths(ctx) != 1)
        ERR_print_errors_fp(stderr);
    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
	SSL_CTX_set_default_passwd_cb_userdata(ctx, password);
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    if (!SSL_CTX_check_private_key(ctx))
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_verify_depth(ctx, 4);
}

void ShowCerts(SSL* ssl)
{
	X509 *cert;
	char *line;
	cert = SSL_get_peer_certificate(ssl);
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

//----------------------------------------- end common -----------------------------------------------------------------
SSL_CTX* InitServerCTX(void)
{
	const SSL_METHOD *method;
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
    SSL_load_error_strings();   /* load all error messages */
	method = TLS_server_method();
    ctx = SSL_CTX_new(method);   /* create new context from method */
    const char *const PREFERRED_CIPHER = "DHT-BIGN-WITH-BELT-DWP-HBELT";
    if(SSL_CTX_set_cipher_list(ctx, PREFERRED_CIPHER) != 1) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
	return ctx;
}
