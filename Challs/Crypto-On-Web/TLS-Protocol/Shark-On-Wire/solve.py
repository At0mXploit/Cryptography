from scapy.all import rdpcap, IP

# wireshark is a tool for capturing and analysing network packets
# a packet is a unit of data sent over a network, containing headers and payload
# pcapng is the file format wireshark uses to save captured packets
# each packet has a source IP and destination IP in its IP header

# the cryptohack server IP is 178.62.74.206
# we want to count packets WHERE DESTINATION = cryptohack server
# i.e. packets sent TO cryptohack (received by cryptohack)

CRYPTOHACK_IP = "178.62.74.206"
PCAP_FILE = "cryptohack.org.pcapng"

# rdpcap reads the entire pcap/pcapng file into a list of packets
packets = rdpcap(PCAP_FILE)

# filter packets that have an IP layer and whose destination is the cryptohack server
# IP layer contains src and dst fields - not all packets have this (e.g. pure ethernet frames)
received_by_cryptohack = [
    pkt for pkt in packets
    if IP in pkt and pkt[IP].dst == CRYPTOHACK_IP
]

print(f"Total packets in capture: {len(packets)}")
print(f"Packets received by CryptoHack.org ({CRYPTOHACK_IP}): {len(received_by_cryptohack)}")

# the answer / flag is this count
# in wireshark you can get the same result by:
# 1. applying filter: ip.dst == 178.62.74.206
# 2. checking the status bar at the bottom which shows "Displayed: X"
