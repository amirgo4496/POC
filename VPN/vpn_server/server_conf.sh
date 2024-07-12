sysctl -w net.ipv4.ip_forward=1

ifconfig test0 10.1.99.254/24 mtu 1500 up

iptables -t nat -A POSTROUTING -s 10.99.0.0/24 ! -d 10.99.0.0/24 -j MASQUERADE
iptables -A FORWARD -s 10.99.0.0/24 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -d 10.99.0.0/24 -j ACCEPT
