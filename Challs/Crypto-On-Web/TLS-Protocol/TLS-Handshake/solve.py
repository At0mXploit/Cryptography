from scapy.all import rdpcap
from scapy.layers.tls.record import TLS
from scapy.layers.tls.handshake import TLSServerHello

# ── packet capture overview ────────────────────────────────────────────────────
# packets 1-2:  DNS request to resolve cryptohack.org → 178.62.74.206
# packets 3-4:  Firefox Safe Browsing check to Google (is this site malicious?)
# packets 5-6:  DNS responses confirming cryptohack.org = 178.62.74.206
# packets 7-9:  TCP three-way handshake (SYN → SYN-ACK → ACK) on port 443
#               this establishes a reliable connection before TLS can start
# packets 10-11: TLS ClientHello sent from laptop to server
#               contains: TLS versions supported, list of cipher suites, client random
#               packet 11 is just a TCP ACK from server confirming receipt
# packets 12-17: server responds with ServerHello, Change Cipher Spec, Application Data
#               ServerHello picks the TLS version and cipher suite to use
#               Change Cipher Spec signals: everything from here is encrypted
#               Application Data = the server's TLS certificate (now encrypted)
# packets 18-21: OCSP (Online Certificate Status Protocol) check
#               laptop contacts an OCSP server to verify the cert hasn't been revoked
# packets 22-27: laptop sends Change Cipher Spec (switching to encrypted)
#               then sends the actual HTTP GET request for the homepage (encrypted)
# packets 28-39: server streams the CryptoHack homepage back (encrypted HTTP/TLS)
# packets 40-50: DNS requests for CDN resources (cdnjs.cloudflare.com etc.)
#               note: DNS is unencrypted by default - a known privacy leak
#               DNS-over-HTTPS (DoH) fixes this but isn't universal yet

# ── why randomness matters ─────────────────────────────────────────────────────
# both client and server contribute 32 bytes of random data during the handshake
# these randoms feed into HKDF (key derivation) to produce unique session keys
# replay attack: attacker records a full handshake and replays the same messages
# fresh randomness defeats this - replayed messages produce different keys = useless
# server random is sent in the ServerHello (packet 12 in this capture)

# ── scapy note ────────────────────────────────────────────────────────────────
# TLS layers are NOT in scapy.all by default - must import from scapy.layers.tls
# scapy splits the 32-byte ServerHello random into two fields:
#   gmt_unix_time  = first 4 bytes (legacy unix timestamp from older TLS specs)
#   random_bytes   = remaining 28 bytes of actual randomness
# we must combine both to get the full 32-byte / 64 hex char random the challenge wants

PCAP_FILE = "cryptohack.org.pcapng"

packets = rdpcap(PCAP_FILE)

for i, pkt in enumerate(packets):
    # check for TLS layer presence
    if pkt.haslayer(TLS):
        tls = pkt[TLS]

        # tls.msg can be a single message or a list, normalise to list
        msgs = tls.msg if hasattr(tls, 'msg') else []
        if not isinstance(msgs, list):
            msgs = [msgs]

        for msg in msgs:
            # TLSServerHello is handshake type 2
            # it lives in packet 12 in this capture (first packet from server after ClientHello)
            if isinstance(msg, TLSServerHello):
                print(f"Found ServerHello in packet {i+1}")

                # reconstruct full 32-byte random by joining both scapy fields
                time_bytes = msg.gmt_unix_time.to_bytes(4, 'big')  # 4 bytes timestamp
                rand_bytes  = msg.random_bytes                       # 28 bytes random

                full_random = (time_bytes + rand_bytes).hex()

                print(f"Server Random : {full_random}")
                print(f"Length check  : {len(full_random)} hex chars = {len(full_random)//2} bytes")
                # submit this 64-char hex string as the flag
