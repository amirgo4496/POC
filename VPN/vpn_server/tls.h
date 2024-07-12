#ifndef __TLS_H_CR4__ 
#define __TLS_H_CR4__

#include <openssl/ssl.h>
#include <netdb.h>

struct connection
{
	struct sockaddr_in server_addr ,client_addr;
	SSL *ssl;
	int tun_fd;
	int id;
};

enum ConnectionState {FREE ,WORKING ,DONE}; 

void InitSslContext(SSL_CTX **ctx);
void SslWriteHandle(SSL *ssl ,char *tun_buf ,int tun_fd);
void SslReadHandle(SSL *ssl ,char *ssl_buf ,int tun_fd);
void *ConnectionHandle(void *connection);

int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len);
int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len);
int dtls_verify_callback (int ok, X509_STORE_CTX *ctx);

#endif
