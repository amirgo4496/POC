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
#include <netdb.h>
#include <fcntl.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>

#include "vpn.h"
#include "utils.h"
#include "tls.h"
#include "flags.h"

int threads_flags[MAX_CLIENTS_AMOUNT] = {0};

static void StartServer(int port);
static int FindFreeThreadId();


int main()
{
	StartServer(PORT); /*"192.168.57.10"*/
	return 0;
}

static void StartServer(int port)
{
	int server_udp_fd = 0;
	int tun_fd = 0;
	struct sockaddr_in server_addr, client_addr;
	socklen_t server_addrlen = 0;

	SSL_CTX *ctx;
	SSL *ssl;
	BIO *bio;
	struct timeval timeout;
	const int on = 1, off = 0;
	int dtls_listen_ret = 0;

	int ready_fds = 0;
	int select_by = 0;
	fd_set read_set;

	struct connection *con = NULL;
	pthread_t clients_threads[MAX_CLIENTS_AMOUNT];
	int clients_amount = 0;
	int i = 0;

	tun_fd = InitVirtualInterface();
	if(tun_fd < 0)
	{
		printf("Error in InitVirtualInterface\n");
		return;
	}

	Configure();

	memset(&server_addr, 0, sizeof(struct sockaddr_in));
	
	InitSslContext(&ctx);

	if(0 > (server_udp_fd = SetUdp(PORT ,&server_addr ,"0.0.0.0")))
	{
		return;
	}
	
	fcntl(server_udp_fd, F_SETFL, O_NONBLOCK);

	/* Create BIO */
	bio = BIO_new_dgram(server_udp_fd, BIO_NOCLOSE);
	/* Set and activate timeouts */
	timeout.tv_sec = 5;
	timeout.tv_usec = 0;
	BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

	ssl = SSL_new(ctx);

	SSL_set_bio(ssl, bio, bio);
	SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);

	while(1)
	{
		FD_ZERO(&read_set);
		FD_SET(server_udp_fd, &read_set);
		select_by = server_udp_fd + 1;
		ready_fds = select(select_by, &read_set, NULL, NULL, NULL);
	
		memset(&client_addr, 0, sizeof(struct sockaddr_in));

		if(FD_ISSET(server_udp_fd, &read_set) && clients_amount < MAX_CLIENTS_AMOUNT)
		{
			while (0 >= (dtls_listen_ret = DTLSv1_listen(ssl, (BIO_ADDR *)&client_addr)));
			
			con = (struct connection*)malloc(sizeof(struct connection));
			if(!con)
			{	
				printf("malloc failed\n");
				continue;
			}
			con->server_addr = server_addr;
			con->client_addr = client_addr;
			con->ssl = ssl;
			con->tun_fd = tun_fd;
			con->id = FindFreeThreadId();

			++clients_amount;
			threads_flags[con->id] = WORKING;

			pthread_create(&clients_threads[con->id], NULL, ConnectionHandle, con);
		}
		else
		{
			/*check if thread has finished working*/
			for(i = 0; i < MAX_CLIENTS_AMOUNT; ++i)
			{
				if(DONE == threads_flags[i])
				{
					--clients_amount;
				}	
			}
		}
		
	}
	SSL_shutdown(ssl);
}

static int FindFreeThreadId()
{
	int i = 0;
	for(; i < MAX_CLIENTS_AMOUNT; ++i)
	{
		if(FREE == threads_flags[i])
		{
			return i;
		}
	}
	return -1;
}

