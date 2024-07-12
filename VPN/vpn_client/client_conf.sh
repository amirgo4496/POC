#!/bin/bash

sysctl -w net.ipv4.ip_forward=1
ifconfig test0 10.1.99.99/24 mtu 1500 up
iptables -t nat -D POSTROUTING -o tun0 -j MASQUERADE
iptables -I FORWARD 1 -i tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -I FORWARD 1 -o tun0 -j ACCEPT

ip route add 192.168.57.10 via 192.168.56.254 dev enp0s3 onlink
ip route add 0/1 dev test0
ip route add 128/1 dev test0
