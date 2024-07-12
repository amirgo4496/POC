from scapy.all import *

MAC_IP_TABLE = {\
    "MY_IP" : get_if_addr(conf.iface),
    "MY_MAC" : get_if_hwaddr(conf.iface),
    "VICTIM_IP" : "",
    "VICTIM_MAC" : "",
    "DEFAULT_GATEWAY_IP" : "",
    "DEFAULT_GATEWAY_MAC" : ""
}

def GetMacAddr(ip):
    eth = Ether(dst = "ff:ff:ff:ff:ff:ff")
    arp = ARP(op="who-has", pdst=ip)
    res = srp1(eth/arp ,timeout = 5)    
    return res.hwsrc if res else None

def InitInfo(victim_ip ,default_gateway_ip):
    MAC_IP_TABLE["VICTIM_IP"] = victim_ip
    MAC_IP_TABLE["VICTIM_MAC"] = GetMacAddr(victim_ip)
    MAC_IP_TABLE["DEFAULT_GATEWAY_MAC"] = GetMacAddr(default_gateway_ip)
    MAC_IP_TABLE["DEFAULT_GATEWAY_IP"] = default_gateway_ip
    return MAC_IP_TABLE if MAC_IP_TABLE["VICTIM_MAC"] and  MAC_IP_TABLE["DEFAULT_GATEWAY_MAC"] else None
