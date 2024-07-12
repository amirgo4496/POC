#define _POSIX_C_SOURCE 200112L

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <fcntl.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>

#include "vpn.h"
#include "utils.h"
#include "tls.h"

#define MTU (1400)
#define PORT (44444)

int verbose = 1;
int veryverbose = 1;


void InitSslContext(SSL_CTX **ctx)
{
	OpenSSL_add_ssl_algorithms();
	SSL_load_error_strings();
	*ctx = SSL_CTX_new(DTLS_client_method());

	if(!SSL_CTX_use_certificate_file(*ctx, "certs/cert.pem", SSL_FILETYPE_PEM))
	{
		printf("\nERROR: no certificate found!");
		exit(1);
	}
	
	if(!SSL_CTX_use_PrivateKey_file(*ctx, "certs/key.pem", SSL_FILETYPE_PEM))
	{
		printf("\nERROR: no private key found!");
		exit(2);
	}
	if(!SSL_CTX_check_private_key(*ctx))
	{
		printf("\nERROR: invalid private key!");
		exit(3);
	}

	SSL_CTX_set_verify_depth (*ctx, 2);
	SSL_CTX_set_read_ahead(*ctx, 1);
}


void SslWriteHandle(SSL *ssl ,char *tun_buf ,int tun_fd)
{
	int bytes_count = 0;
	printf("ready to write ssl\n");
	bytes_count = read(tun_fd, tun_buf, MTU);
	if(bytes_count >= 0)
	{
		printf("tun read %d bytes\n" ,bytes_count);
		bytes_count = SSL_write(ssl ,tun_buf, bytes_count);
		switch (SSL_get_error(ssl, bytes_count))
		{
			case SSL_ERROR_NONE:
				printf("ssl wrote %d bytes\n" ,bytes_count);
				break;
			case SSL_ERROR_WANT_WRITE:
				printf("SSL_ERROR_WANT_WRITE\n");
				break;
			case SSL_ERROR_WANT_READ:
				printf("SSL_ERROR_WANT_READ\n");
				break;
			case SSL_ERROR_WANT_CONNECT:
				printf("SSL_ERROR_WANT_CONNECT\n");
				break;
			case SSL_ERROR_WANT_ACCEPT:
				printf("SSL_ERROR_WANT_ACCEPT\n");
				break;
			case SSL_ERROR_WANT_X509_LOOKUP:
				printf("SSL_ERROR_WANT_X509_LOOKUP\n");
				break;
			case SSL_ERROR_WANT_ASYNC:
				printf("SSL_ERROR_WANT_ASYNC\n");
				break;
			case SSL_ERROR_WANT_ASYNC_JOB:
				printf("SSL_ERROR_WANT_ASYNC_JOB\n");
				break;
			case SSL_ERROR_WANT_CLIENT_HELLO_CB:
				printf("SSL_ERROR_WANT_CLIENT_HELLO_CB\n");
				break;
			case SSL_ERROR_SYSCALL:
				printf("SSL_ERROR_SYSCALL\n");
				break;
			case SSL_ERROR_SSL:
				printf("SSL_ERROR_SSL\n");
				break;
			default:
				printf("Unexpected error while writing!\n");
				break;
		}
	}
}

void SslReadHandle(SSL *ssl ,char *ssl_buf ,int tun_fd)
{
	int bytes_count = 0;
	printf("ready to read ssl\n");
	bytes_count = SSL_read(ssl, ssl_buf, MTU);
	switch (SSL_get_error(ssl, bytes_count))
	{
		case SSL_ERROR_NONE:
			printf("ssl read %d bytes\n" ,bytes_count);
			bytes_count = write(tun_fd, ssl_buf, bytes_count);
			printf("tun wrote %d bytes\n" ,bytes_count);
			break;
		case SSL_ERROR_WANT_WRITE:
			printf("SSL_ERROR_WANT_WRITE\n");
			break;
		case SSL_ERROR_WANT_READ:
			printf("SSL_ERROR_WANT_READ\n");
			break;
		case SSL_ERROR_WANT_CONNECT:
			printf("SSL_ERROR_WANT_CONNECT\n");
			break;
		case SSL_ERROR_WANT_ACCEPT:
			printf("SSL_ERROR_WANT_ACCEPT\n");
			break;
		case SSL_ERROR_WANT_X509_LOOKUP:
			printf("SSL_ERROR_WANT_X509_LOOKUP\n");
			break;
		case SSL_ERROR_WANT_ASYNC:
			printf("SSL_ERROR_WANT_ASYNC\n");
			break;
		case SSL_ERROR_WANT_ASYNC_JOB:
			printf("SSL_ERROR_WANT_ASYNC_JOB\n");
			break;
		case SSL_ERROR_WANT_CLIENT_HELLO_CB:
			printf("SSL_ERROR_WANT_CLIENT_HELLO_CB\n");
			break;
		case SSL_ERROR_SYSCALL:
			printf("SSL_ERROR_SYSCALL\n");
			break;
		case SSL_ERROR_SSL:
			printf("SSL_ERROR_SSL\n");
			break;
		default:
			printf("Unexpected error while writing!\n");
			break;
	}
}


void PrintConnection(struct sockaddr_in remote_addr ,SSL *ssl)
{
	char addrbuf[INET_ADDRSTRLEN] = {0};
	printf ("\nConnected to %s\n",
			inet_ntop(AF_INET, &remote_addr.sin_addr, addrbuf, INET_ADDRSTRLEN));
	printf ("------------------------------------------------------------\n");
	X509_NAME_print_ex_fp(stdout, X509_get_subject_name(SSL_get_peer_certificate(ssl)),
						  1, XN_FLAG_MULTILINE);
	printf("\n\n Cipher: %s", SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));
	printf ("\n------------------------------------------------------------\n\n");
}
