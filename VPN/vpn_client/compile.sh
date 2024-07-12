#!/bin/bash

gcc vpn_client_driver.c utils.c vpn.c tls.c -lssl -lcrypto -o vpn_clien.out
