#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <signal.h>

#include "flags.h"

sig_atomic_t stupid_lock = 0;

static int IsValidIpAddress(char *ip);

static char ip_adresses[MAX_CLIENTS_AMOUNT][INET_ADDRSTRLEN + 1] = 
{
"10.1.99.99",
"10.1.99.100",
"10.1.99.101",
"10.1.99.102",
"10.1.99.103",
"10.1.99.104",
"10.1.99.105",
"10.1.99.106",
"10.1.99.107",
"10.1.99.108",
};

int GetFreeIpAddress(char *ip_add)
{
	int i = 0;
	for(; i < MAX_CLIENTS_AMOUNT; ++i)
	{
		if(strcmp(ip_adresses[i] ,"occupied"))
		{
			strcpy(ip_add ,ip_adresses[i]);
			strncpy(ip_adresses[i] ,"occupied" ,(INET_ADDRSTRLEN + 1));
			return 0;
		}
	}
	return -1;
}

void FreeIpAddress(char *ip_add)
{
	int i = 0;
	for(; i < MAX_CLIENTS_AMOUNT; ++i)
	{
		if(0 == strcmp(ip_adresses[i] ,"occupied"))
		{
			strncpy(ip_adresses[i] ,ip_add ,(INET_ADDRSTRLEN + 1));
		}
	}
}
