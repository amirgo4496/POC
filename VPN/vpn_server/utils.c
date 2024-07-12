#define _XOPEN_SOURCE 500 /*FOR SPRINTF BECAUSE OF C89*/

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "utils.h"

static int ConfigureInterfaceIp(void);
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


int Configure(void)
{
	system("sysctl -w net.ipv4.ip_forward=1");
	ConfigureInterfaceIp();
	ConfigureNat();
	return 0;
}

static int ConfigureInterfaceIp(void)
{
	return system("ifconfig a555 10.1.99.254/24 mtu 1400 up");
}

static int ConfigureNat(void)
{
  	system("iptables -t nat -A POSTROUTING -s 10.1.99.0/24 ! -d 10.1.99.0/24 -j MASQUERADE");
  	system("iptables -A FORWARD -s 10.1.99.0/24 -m state --state RELATED,ESTABLISHED -j ACCEPT");
  	system("iptables -A FORWARD -d 10.1.99.0/24 -j ACCEPT");
	return 0;
}
