// openssl_mod.h
/*заголовочный файл программы модуля openssl*/
#ifndef OPENSSL_MOD_H
#define OPENSSL_MOD_H
#include <openssl/ssl.h>

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile, char* CAFile, char* password);
void ShowCerts(SSL* ssl);

#endif
