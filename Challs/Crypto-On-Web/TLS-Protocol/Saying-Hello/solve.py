import ssl
import socket

# TLS handshake overview:
# client sends ClientHello containing:
#   - list of cipher suites it supports
#   - highest TLS version it supports
#   - extensions and compression methods
#   - random number (entropy for key exchange)
#   - session ID

# a cipher suite name like ECDHE-RSA-AES128-GCM-SHA256 means:
#   ECDHE     = elliptic curve diffie-hellman ephemeral (key exchange algorithm)
#   RSA       = algorithm used to sign the certificate (authenticity)
#   AES-128   = symmetric cipher used to encrypt application data (confidentiality)
#   GCM       = mode of operation for AES (how blocks are chained)
#   SHA256    = hash used for handshake authentication (integrity)

# the server tls1.cryptohack.org supports only ONE TLS 1.2 cipher suite
# to find it we force a TLS 1.2 connection so the server can't fall back to TLS 1.3
# then we read which cipher suite was actually negotiated

hostname = "tls1.cryptohack.org"
port = 443

# create SSL context and force maximum version to TLS 1.2
# this means our ClientHello will advertise TLS 1.2 as the highest supported version
# the server must therefore negotiate using TLS 1.2 and its single supported suite
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.maximum_version = ssl.TLSVersion.TLSv1_2

# load system CA certs so the server certificate is verified properly
ctx.load_default_certs()

with socket.create_connection((hostname, port)) as sock:
    with ctx.wrap_socket(sock, server_hostname=hostname) as tls:

        # cipher() returns a tuple: (cipher_name, tls_version, secret_bits)
        # cipher_name is in OpenSSL format e.g. ECDHE-RSA-AES128-GCM-SHA256
        cipher_name, tls_version, bits = tls.cipher()

        print(f"TLS version negotiated : {tls_version}")
        print(f"Cipher suite (OpenSSL) : {cipher_name}")
        print(f"Key size               : {bits} bits")
        # submit cipher_name as the flag

# equivalent shell commands that do the same thing:
# curl --tls-max 1.2 https://tls1.cryptohack.org -v 2>&1 | grep "SSL connection"
# openssl s_client -connect tls1.cryptohack.org:443 -tls1_2 2>&1 | grep "Cipher is"
