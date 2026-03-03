"""
TLS 1.3 Client Challenge 
Computes the verify_data for the Client Finished message from a PCAP + keylog file.
"""

import struct
import hmac
import hashlib
from math import ceil
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ─── TLS 1.3 key derivation helpers ──────────────────────────────────────────

HASH_ALG = hashlib.sha384
HASH_LEN = HASH_ALG().digest_size


def tls_HMAC(k, b, algorithm):
    return bytearray(hmac.new(k, b, algorithm).digest())


def HKDF_expand(prk, info, length, algorithm):
    hash_len = algorithm().digest_size
    t = bytearray()
    okm = bytearray()
    for i in range(1, ceil(length / hash_len) + 2):
        t = tls_HMAC(prk, t + info + bytearray([i]), algorithm)
        okm += t
    return okm[:length]


def HKDF_expand_label(secret, label, hashValue, length, algorithm):
    hkdfLabel = bytearray()
    hkdfLabel += struct.pack('>H', length)
    seq = bytearray(b"tls13 ") + label
    hkdfLabel += bytearray([len(seq)]) + seq
    seq = hashValue
    hkdfLabel += bytearray([len(seq)]) + seq
    return HKDF_expand(secret, hkdfLabel, length, algorithm)


def verify_data(finished_key, transcript, hash_alg):
    transcript_hash = hash_alg(transcript).digest()
    return tls_HMAC(finished_key, transcript_hash, hash_alg)


# ─── PCAP parsing (link type 113 = Linux cooked / SLL) ───────────────────────

def load_pcapng_packets(path):
    with open(path, 'rb') as f:
        data = f.read()
    packets = []
    offset = 0
    while offset < len(data):
        if offset + 8 > len(data):
            break
        block_type = struct.unpack_from('<I', data, offset)[0]
        block_len  = struct.unpack_from('<I', data, offset + 4)[0]
        if block_len == 0 or block_len > len(data):
            break
        if block_type == 6:  # Enhanced Packet Block
            cap_len = struct.unpack_from('<I', data, offset + 20)[0]
            packets.append(data[offset + 28: offset + 28 + cap_len])
        offset += block_len
    return packets


def tcp_payload(pkt):
    """Extract TCP payload + ports from an SLL-framed IPv4/TCP packet."""
    proto = struct.unpack_from('>H', pkt, 14)[0]
    if proto != 0x0800:
        return None
    ip_start   = 16
    ip_hdr_len = (pkt[ip_start] & 0x0F) * 4
    if pkt[ip_start + 9] != 6:          # not TCP
        return None
    tcp_start       = ip_start + ip_hdr_len
    tcp_data_offset = (pkt[tcp_start + 12] >> 4) * 4
    src_port = struct.unpack_from('>H', pkt, tcp_start)[0]
    dst_port = struct.unpack_from('>H', pkt, tcp_start + 2)[0]
    payload  = pkt[tcp_start + tcp_data_offset:]
    return payload, src_port, dst_port


def split_tls_records(payload):
    """Yield (content_type, record_bytes) for every TLS record in payload."""
    off = 0
    while off + 5 <= len(payload):
        ct     = payload[off]
        length = struct.unpack_from('>H', payload, off + 3)[0]
        yield ct, payload[off + 5: off + 5 + length]
        off += 5 + length


# ─── Decrypt one TLS 1.3 AEAD record ─────────────────────────────────────────

def make_nonce(iv: bytes, seq: int) -> bytes:
    seq_b = seq.to_bytes(12, 'big')
    return bytes(a ^ b for a, b in zip(iv, seq_b))


def decrypt_record(aesgcm, iv, seq, enc_data):
    nonce = make_nonce(iv, seq)
    aad   = bytes([23, 3, 3]) + struct.pack('>H', len(enc_data))
    return aesgcm.decrypt(nonce, enc_data, aad)


def extract_handshake_messages(plaintext):
    """Parse TLS handshake messages from decrypted record content."""
    messages = {}
    off = 0
    while off < len(plaintext):
        ht  = plaintext[off]
        hl  = struct.unpack_from('>I', b'\x00' + plaintext[off+1:off+4])[0]
        messages[ht] = bytes(plaintext[off: off + 4 + hl])
        off += 4 + hl
    return messages


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    pcap_path   = "no-finished-tls3_cryptohack_org.pcapng"
    keylog_path = "keylogfile.txt"

    # Keys from keylogfile (TLS_AES_256_GCM_SHA384, so SHA-384 + AES-256)
    client_handshake_traffic_secret = bytes.fromhex(
        "ca8fb94500b13314d4c47158b1e9c7e5d3374cf9c5703b6d8ab879e99af1529d"
        "0e013b84ae1e7b15233ff64a1ed6e06c"
    )
    server_handshake_traffic_secret = bytes.fromhex(
        "c64856c95f298b1caae60b3d8146960e700b1dc3354a3f46f05ca77362df599a"
        "0729701a92716573360dcdd50aa28fe4"
    )

    # Derive server write key/IV (AES-256-GCM)
    KEY_LEN, IV_LEN = 32, 12
    server_key = bytes(HKDF_expand_label(server_handshake_traffic_secret, b"key", b"", KEY_LEN, HASH_ALG))
    server_iv  = bytes(HKDF_expand_label(server_handshake_traffic_secret, b"iv",  b"", IV_LEN,  HASH_ALG))
    aesgcm = AESGCM(server_key)

    # Load and classify TLS records
    packets = load_pcapng_packets(pcap_path)

    client_hello_msg = server_hello_msg = None
    server_encrypted = []   # encrypted AppData records from server, in order

    for pkt in packets:
        result = tcp_payload(pkt)
        if not result:
            continue
        payload, src_port, dst_port = result
        if not payload:
            continue
        direction = "client" if dst_port == 443 else "server"

        for ct, rec_data in split_tls_records(payload):
            if direction == "client" and ct == 22 and rec_data and rec_data[0] == 1:
                client_hello_msg = bytes(rec_data)   # ClientHello handshake bytes
            if direction == "server" and ct == 22 and rec_data and rec_data[0] == 2:
                server_hello_msg = bytes(rec_data)   # ServerHello handshake bytes
            if direction == "server" and ct == 23:
                server_encrypted.append(bytes(rec_data))

    # Decrypt server handshake records and collect handshake messages
    hs = {}
    for seq, enc_data in enumerate(server_encrypted):
        plaintext   = decrypt_record(aesgcm, server_iv, seq, enc_data)
        inner_ct    = plaintext[-1]
        content     = plaintext[:-1]
        if inner_ct == 22:
            hs.update(extract_handshake_messages(content))

    # Handshake type codes
    # 8=EncryptedExtensions, 11=Certificate, 15=CertificateVerify, 20=Finished
    server_enc_ext      = hs[8]
    server_cert         = hs[11]
    server_cert_verify  = hs[15]
    server_finished     = hs[20]

    # Transcript = concatenation of handshake message bodies (no TLS record headers)
    transcript = (
        client_hello_msg
        + server_hello_msg
        + server_enc_ext
        + server_cert
        + server_cert_verify
        + server_finished
    )

    # Finished key derived from CLIENT_HANDSHAKE_TRAFFIC_SECRET
    finished_key = bytes(HKDF_expand_label(
        client_handshake_traffic_secret, b"finished", b"", HASH_LEN, HASH_ALG
    ))

    result = verify_data(finished_key, transcript, HASH_ALG).hex()
    print("Client Finished verify_data:")
    print(result)
    return result


if __name__ == "__main__":
    main()
