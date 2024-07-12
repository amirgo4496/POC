#ifndef __VPN_H_CR4__ 
#define __VPN_H_CR4__

int InitVirtualInterface(void);
int Encrypt(char *plain_text ,char *encrypt_buff);
int Decrypt(char *encrypted ,char *plain_text_buff);
int SetUdp(unsigned short port ,struct sockaddr_in *addr ,char *connection_ip);


#endif
