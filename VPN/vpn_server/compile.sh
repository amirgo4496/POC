#!/bin/bash

gcc vpn_server_driver.c tls.c vpn.c utils.c dhcp.c -lssl -lcrypto -pthread -o vpn_server.out
