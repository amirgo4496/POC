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
#define SERVER_IP ("192.168.57.10")
#define CLIENT_IP ("192.168.56.10")


static void StartClient(char *remote_address, char *local_address, int port);
static int IsValidIpAddress(char *ip);

int main(void)
{
	StartClient(SERVER_IP, CLIENT_IP, PORT);
	return 0;
}


static void StartClient(char *remote_address, char *local_address, int port)
{
	int udp_fd = 0;
	int tun_fd = 0;
	int retval = 0;
	const int on = 1;
	struct sockaddr_in remote_addr, local_addr;
	char tun_buf[MTU] = {0} ,ssl_buf[MTU] = {0};
	int bytes_count = 0;

	SSL_CTX *ctx;
	SSL *ssl;
	BIO *bio;

	struct timeval timeout;
	struct timeval select_timeout;

	char addr_buf[INET_ADDRSTRLEN + 1] = {0};

	int ready_fds = 0;
	int select_by = 0;
	fd_set read_set ,write_set;

	memset((void *) &remote_addr, 0, sizeof(struct sockaddr_in));
	memset((void *) &local_addr, 0, sizeof(struct sockaddr_in));

	remote_addr.sin_family = AF_INET;
	remote_addr.sin_port = htons(port);
	remote_addr.sin_addr.s_addr = inet_addr(remote_address);/*server ip "192.168.57.10"*/

	if(0 > (udp_fd = SetUdp(0 ,&local_addr ,local_address)))/*client ip "192.168.56.10"*/
	{
		return;
	}

	InitSslContext(&ctx);

	ssl = SSL_new(ctx);

	/* Create BIO, connect and set to already connected */
	bio = BIO_new_dgram(udp_fd, BIO_CLOSE);
	if(connect(udp_fd, (struct sockaddr *) &remote_addr, sizeof(struct sockaddr_in)))
	{
			printf("Error in connect\n");
			return;
	}
	BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &remote_addr);

	SSL_set_bio(ssl, bio, bio);


	retval = SSL_connect(ssl);
	if (retval <= 0)
	{
		printf("SSL_connect failed\n");
		exit(EXIT_FAILURE);
	}

	/* Set and activate timeouts */
	timeout.tv_sec = 5;
	timeout.tv_usec = 0;
	BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

	PrintConnection(remote_addr ,ssl);
	bytes_count = SSL_read(ssl, addr_buf, sizeof(addr_buf));
	printf("IP: %s\n" ,addr_buf);

	tun_fd = InitVirtualInterface();
	if(tun_fd < 0)
	{
		printf("Error in InitVirtualInterface\n");
		return;
	}
	Configure(addr_buf);

	fcntl(tun_fd, F_SETFL, O_NONBLOCK);
	fcntl(udp_fd, F_SETFL, O_NONBLOCK);

	select_timeout.tv_sec = 5;
	select_timeout.tv_usec = 0;

	while(1)
	{

		FD_ZERO(&read_set);
		FD_SET(udp_fd, &read_set);
		FD_SET(tun_fd, &read_set);
		FD_SET(udp_fd, &write_set);
		FD_SET(tun_fd, &write_set);

		select_by = GetMax(2, tun_fd ,udp_fd) + 1;
		ready_fds = select(select_by, &read_set, &write_set, NULL, NULL);

		if(FD_ISSET(udp_fd, &read_set) && FD_ISSET(tun_fd, &write_set))
		{
			SslReadHandle(ssl ,ssl_buf ,tun_fd);
		}

		if(FD_ISSET(udp_fd, &write_set) && FD_ISSET(tun_fd, &read_set))
		{
			SslWriteHandle(ssl ,tun_buf ,tun_fd);
		}
	}

	SSL_shutdown(ssl);
	close(udp_fd);
	close(tun_fd);
	printf("Connection closed.\n");
}

static int IsValidIpAddress(char *ip)
{
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip, &(sa.sin_addr)) == 1;
}

