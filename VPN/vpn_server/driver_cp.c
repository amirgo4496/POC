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


#define PORT (44444)
#define MAX_CLIENTS_AMOUNT (10)

int threads_flags[10] = {0};

static void StartServer(int port, char *local_address);

struct clients_manager
{
	pthread_t clients_threads[MAX_CLIENTS_AMOUNT];
	int clients_amount;
	struct connection connections[MAX_CLIENTS_AMOUNT];
};


int main()
{
	StartServer(PORT, "192.168.57.10"); /*"192.168.57.10"*/
	return 0;
}

static void StartServer(int port, char *local_address)
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

	struct clients_manager cm;
	/*pthread_attr_t pt_attr;*/

	int i = 0;

	tun_fd = InitVirtualInterface();
	Configure();

	memset(&server_addr, 0, sizeof(struct sockaddr_in));
	memset(&cm, 0, sizeof(struct clients_manager));
	
	InitSslContext(&ctx);

	if(0 > (server_udp_fd = SetUdp(PORT ,&server_addr ,"0.0.0.0")))
	{
		return;
	}
	
	/*pthread_attr_init(&pt_attr);
	pthread_attr_setdetachstate(&pt_attr ,PTHREAD_CREATE_DETACHED);*/
	
	fcntl(server_udp_fd, F_SETFL, O_NONBLOCK);

	while(1)
	{
		FD_ZERO(&read_set);
		FD_SET(server_udp_fd, &read_set);
		select_by = server_udp_fd + 1;
		ready_fds = select(select_by, &read_set, NULL, NULL, NULL);
	
		memset(&client_addr, 0, sizeof(struct sockaddr_in));

		/* Create BIO */
		bio = BIO_new_dgram(server_udp_fd, BIO_NOCLOSE);

		/* Set and activate timeouts */
		timeout.tv_sec = 5;
		timeout.tv_usec = 0;
		BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

		ssl = SSL_new(ctx);

		SSL_set_bio(ssl, bio, bio);
		SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);

		if(FD_ISSET(server_udp_fd, &read_set) && cm.clients_amount < MAX_CLIENTS_AMOUNT)
		{
			while (0 >= (dtls_listen_ret = DTLSv1_listen(ssl, (BIO_ADDR *)&client_addr)));
			
			cm.connections[cm.clients_amount].server_addr = server_addr;
			cm.connections[cm.clients_amount].client_addr = client_addr;
			cm.connections[cm.clients_amount].ssl = ssl;
			cm.connections[cm.clients_amount].tun_fd = tun_fd;
			cm.connections[cm.clients_amount].id = cm.clients_amount;

			++cm.clients_amount;

			/*pthread_create(&cm.clients_threads[cm.clients_amount], NULL, ConnectionHandle
					, &cm.connections[cm.clients_amount]);*/
			ConnectionHandle(&cm.connections[cm.clients_amount]);
		}

		/*for(i = 0; i < MAX_CLIENTS_AMOUNT; ++i)
		{
			if(threads_flags[i])
			{
				--cm.clients_amount;
				threads_flags[i] = 0;
			}	
		}*/
		
	}
	SSL_shutdown(ssl);
}

