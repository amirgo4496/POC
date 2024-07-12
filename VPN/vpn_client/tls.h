#ifndef __TLS_H_CR4__ 
#define __TLS_H_CR4__

void InitSslContext(SSL_CTX **ctx);
void SslReadHandle(SSL *ssl ,char *ssl_buf ,int tun_fd);
void SslWriteHandle(SSL *ssl ,char *tun_buf ,int tun_fd);
void PrintConnection(struct sockaddr_in remote_addr ,SSL *ssl);

#endif
