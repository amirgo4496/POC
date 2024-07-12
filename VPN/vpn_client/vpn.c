#define _POSIX_C_SOURCE 200112L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h> /* ? */
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <signal.h> /* ? */
#include <linux/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <arpa/inet.h>


#include "vpn.h"
#include "utils.h"

int Encrypt(char *plain_text ,char *encrypt_buff)
{
	(void)plain_text;
	(void)encrypt_buff;
	return 0;
}

int Decrypt(char *encrypted ,char *plain_text_buff)
{
	(void)encrypted;
	(void)plain_text_buff;
	return 0;
}

int InitVirtualInterface(void)
{
	struct ifreq v_ifr;
	int v_ifr_fd = -1;
	char *dev_path = "/dev/net/tun";

	if(0 > (v_ifr_fd = open(dev_path ,O_RDWR)))
	{
		perror("Failed in open\n");
		return v_ifr_fd;
	}
	memset(&v_ifr ,0 ,sizeof(v_ifr_fd));

	v_ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	strncpy(v_ifr.ifr_name, VIRTUAL_INTERFACE_NAME, IFNAMSIZ);

	if(0 > ioctl(v_ifr_fd, TUNSETIFF, &v_ifr))
	{
		perror("Failed in ioctl\n");
		close(v_ifr_fd);
		return -1;
	}

	return v_ifr_fd;
}

int SetUdp(unsigned short port ,struct sockaddr_in *addr ,char *connection_ip)
{
	int udp_fd = 0;
	int err_code = 0;
	int yes = 1;
	addr->sin_family = AF_INET; // IPv4
    	addr->sin_port = htons(port);
	addr->sin_addr.s_addr = inet_addr(connection_ip);

	if(0 > (udp_fd = socket(AF_INET, SOCK_DGRAM, 0)))
	{
		perror("Failed in udp setup at socket()\n");
		return udp_fd;
	}
	setsockopt(udp_fd, SOL_SOCKET, SO_REUSEADDR, (const void*) &yes, (socklen_t) sizeof(yes));
	if(0 != (err_code = bind(udp_fd, (const struct sockaddr *)addr, sizeof(struct sockaddr_in))))
	{
		perror("Failed in udp setup at bind()\n");
		close(udp_fd);
		return err_code;
	}
	return udp_fd;
}

