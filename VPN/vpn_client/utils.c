#define _XOPEN_SOURCE 500 /*FOR SPRINTF BECAUSE OF C89*/

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "utils.h"


static int ConfigureRoutes(void);
static int ConfigureInterfaceIp(char *ip);
static int ConfigureNat(void);

int GetMax(int count, ...)
{
	int max_fd = -1 ,curr_fd = -1;
	int i = 0;
	va_list fds;

	va_start(fds, count); 
	for(i = 0; i < count; ++i)
	{
		curr_fd = va_arg(fds, int);
		if(curr_fd > max_fd)
		{
			max_fd = curr_fd;
		}
	}
	va_end(fds);
	return max_fd;
}

int Configure(char *ip)
{
	system("sysctl -w net.ipv4.ip_forward=1");
	ConfigureInterfaceIp(ip);
	ConfigureRoutes();
	ConfigureNat();
	return 0;
}

static int ConfigureRoutes(void)
{
	system("ip route add 192.168.57.10 via 192.168.56.254 dev enp0s3 onlink");
	/*more specific way of adding default gateway*/
	system("ip route add 0/1 dev a555");
	system("ip route add 128/1 dev a555");
	return 0;
}

static int ConfigureInterfaceIp(char *ip)
{
	char command[256] = {0};
	snprintf(command, sizeof(command), "ifconfig a555 %s/24 mtu 1400 up", ip);
	system(command);
	return 0;
}

static int ConfigureNat(void)
{
	system("iptables -t nat -A POSTROUTING -o a555 -j MASQUERADE");
	system("iptables -I FORWARD 1 -i a555 -m state --state RELATED,ESTABLISHED -j ACCEPT");
	system("iptables -I FORWARD 1 -o a555 -j ACCEPT");
	return 0;
}
