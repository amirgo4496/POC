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
#include <netdb.h>
#include <fcntl.h>
#include <pthread.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>

#include "vpn.h"
#include "utils.h"
#include "tls.h"
#include "dhcp.h"
#include "flags.h"


unsigned char cookie_secret[COOKIE_SECRET_LENGTH];
int cookie_initialized=0;

extern int threads_flags[10];

static void PrintConnection(struct sockaddr_in client_addr ,SSL *ssl);

void *ConnectionHandle(void *connection)
{
	struct sockaddr_in server_addr = ((struct connection *)connection)->server_addr;
	struct sockaddr_in client_addr = ((struct connection *)connection)->client_addr;
	SSL *ssl = ((struct connection *)connection)->ssl;
	int tun_fd = ((struct connection *)connection)->tun_fd;
	int thread_id = ((struct connection *)connection)->id;


	char ssl_buf[MTU] = {0} ,tun_buf[MTU] = {0};
	int client_fd, reading = 0, ret;
	const int on = 1, off = 0;
	struct timeval timeout;

	int ready_fds = 1;
	int select_by = 0;
	fd_set read_set ,write_set;

	struct timeval test_timeout;
	struct timeval select_timeout;

	char addr_buf[INET_ADDRSTRLEN + 1] = {0};

	pthread_detach(pthread_self());

	if(0 > (client_fd = SetUdp(PORT ,&server_addr ,"0.0.0.0")))/*"0.0.0.0"*/
	{
		threads_flags[thread_id] = DONE;
		return NULL;
	}

	/* Set new client_fd and set BIO to connected */
	BIO_set_fd(SSL_get_rbio(ssl), client_fd, BIO_NOCLOSE);

	if (connect(client_fd, (struct sockaddr *) &client_addr, sizeof(struct sockaddr_in))) {
		perror("connect");
		close(client_fd);
		threads_flags[thread_id] = DONE;
		return NULL;
	}
	BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_CONNECTED, 0, &client_addr);

	/* Finish handshake */
	do { ret = SSL_accept(ssl); }
	while (ret == 0);

	if (ret < 0) {
		perror("Error in SSL_accept\n");
		close(client_fd);
		threads_flags[thread_id] = DONE;
		return NULL;
	}

	/* Set and activate timeouts */
	timeout.tv_sec = 2;
	timeout.tv_usec = 0;
	BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

	PrintConnection(client_addr ,ssl);

	if(GetFreeIpAddress(addr_buf))
	{
		printf("No valid IP address available\n");
		close(client_fd);
		threads_flags[thread_id] = DONE;
		SSL_shutdown(ssl);
		return NULL;
	}

	printf("IP: %s\n" ,addr_buf);
	SSL_write(ssl, addr_buf, sizeof(addr_buf));

	fcntl(tun_fd, F_SETFL, O_NONBLOCK);
	fcntl(client_fd, F_SETFL, O_NONBLOCK);

	select_timeout.tv_sec = 30;
	select_timeout.tv_usec = 0;

	while(!(SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN))
	{		

		FD_ZERO(&read_set);
		FD_SET(tun_fd, &read_set);
		FD_SET(client_fd, &read_set);
		FD_SET(tun_fd, &write_set);
		FD_SET(client_fd, &write_set);
		select_by = GetMax(2, tun_fd ,client_fd) + 1;
		ready_fds = select(select_by, &read_set, &write_set, NULL, NULL);

		if(FD_ISSET(client_fd, &read_set) && FD_ISSET(tun_fd, &write_set))
		{
			SslReadHandle(ssl ,ssl_buf ,tun_fd);
		}

		if(FD_ISSET(client_fd, &write_set) && FD_ISSET(tun_fd, &read_set))
		{
			SslWriteHandle(ssl ,tun_buf ,tun_fd);
		}
	}

	/*FreeIpAddress(addr_buf);*//*returns ip back to dhcp*/
	close(client_fd);
	threads_flags[thread_id] = DONE;
	return NULL;
}


int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
	unsigned char *buffer, result[EVP_MAX_MD_SIZE];
	unsigned int length = 0, resultlength;
	struct sockaddr_in peer;

	/* Initialize a random secret */
	if (!cookie_initialized)
		{
		if (!RAND_bytes(cookie_secret, COOKIE_SECRET_LENGTH))
			{
			printf("error setting random cookie secret\n");
			return 0;
			}
		cookie_initialized = 1;
		}

	/* Read peer information */
	(void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

	/* Create buffer with peer's address and port */
	length = 0;
	length += sizeof(struct in_addr);

	length += sizeof(in_port_t);
	buffer = (unsigned char*) OPENSSL_malloc(length);

	if (buffer == NULL)
		{
		printf("out of memory\n");
		return 0;
		}

			memcpy(buffer,
				   &peer.sin_port,
				   sizeof(in_port_t));
			memcpy(buffer + sizeof(peer.sin_port),
				   &peer.sin_addr,
				   sizeof(struct in_addr));

	/* Calculate HMAC of buffer using the secret */
	HMAC(EVP_sha1(), (const void*) cookie_secret, COOKIE_SECRET_LENGTH,
		 (const unsigned char*) buffer, length, result, &resultlength);
	OPENSSL_free(buffer);

	memcpy(cookie, result, resultlength);
	*cookie_len = resultlength;

	return 1;
}

int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len)
{
	unsigned char *buffer, result[EVP_MAX_MD_SIZE];
	unsigned int length = 0, resultlength;
	struct sockaddr_in peer;
	/*********************/
	return 1;
	/* If secret isn't initialized yet, the cookie can't be valid */
	if (!cookie_initialized)
		return 0;

	/* Read peer information */
	(void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

	/* Create buffer with peer's address and port */
	length = 0;
	length += sizeof(struct in_addr);

	length += sizeof(in_port_t);
	buffer = (unsigned char*) OPENSSL_malloc(length);

	if (buffer == NULL)
		{
		printf("out of memory\n");
		return 0;
		}

			memcpy(buffer,
				   &peer.sin_port,
				   sizeof(in_port_t));
			memcpy(buffer + sizeof(in_port_t),
				   &peer.sin_addr,
				   sizeof(struct in_addr));

	/* Calculate HMAC of buffer using the secret */
	HMAC(EVP_sha1(), (const void*) cookie_secret, COOKIE_SECRET_LENGTH,
		 (const unsigned char*) buffer, length, result, &resultlength);
	OPENSSL_free(buffer);

	if (cookie_len == resultlength && memcmp(result, cookie, resultlength) == 0)
		return 1;

	return 0;
}

int dtls_verify_callback(int ok, X509_STORE_CTX *ctx)
{
	/* This function should ask the user
	 * if he trusts the received certificate.
	 * Here we always trust.
	 */
	return 1;
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

void InitSslContext(SSL_CTX **ctx)
{
	OpenSSL_add_ssl_algorithms();
	SSL_load_error_strings();

	*ctx = SSL_CTX_new(DTLS_server_method());
	if(NULL == (*ctx))
	{
		printf("\nERROR: SSL_CTX_new");
		exit(1);
	}

	if (!SSL_CTX_use_certificate_file(*ctx, "certs/example.crt", SSL_FILETYPE_PEM))
	{
		printf("\nERROR: no certificate found!");
		exit(2);
	}
	if (!SSL_CTX_use_PrivateKey_file(*ctx, "certs/example.key", SSL_FILETYPE_PEM))
	{	
		printf("\nERROR: no private key found!");
		exit(3);
	}
	if (!SSL_CTX_check_private_key (*ctx))
	{	
		printf("\nERROR: invalid private key!");
		exit(4);
	}

	SSL_CTX_set_verify(*ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, dtls_verify_callback);

	SSL_CTX_set_read_ahead(*ctx, 1);
	SSL_CTX_set_cookie_generate_cb(*ctx, generate_cookie);
	SSL_CTX_set_cookie_verify_cb(*ctx, &verify_cookie);
}

static void PrintConnection(struct sockaddr_in client_addr ,SSL *ssl)
{
	char addrbuf[INET_ADDRSTRLEN] = {0};
	printf ("Accepted connection from %s:%d\n",
			inet_ntop(AF_INET, &client_addr.sin_addr, addrbuf, INET_ADDRSTRLEN)
			,ntohs(client_addr.sin_port));
	printf ("------------------------------------------------------------\n");
	X509_NAME_print_ex_fp(stdout, X509_get_subject_name(SSL_get_peer_certificate(ssl)),
						  1, XN_FLAG_MULTILINE);\
	printf("\n\n Cipher: %s", SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));
	printf ("\n------------------------------------------------------------\n\n");	
}



