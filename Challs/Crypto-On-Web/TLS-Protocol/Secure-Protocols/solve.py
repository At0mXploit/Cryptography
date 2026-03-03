import ssl
import socket

# TLS is the cryptographic protocol that secures HTTP traffic (HTTPS)
# it provides confidentiality, authenticity, and integrity (CIA triad)
# when you connect to a site over HTTPS, a TLS handshake happens first
# during the handshake the server presents a certificate signed by a CA

# a Certificate Authority (CA) is a trusted third party that vouches for
# the identity of a server by signing its TLS certificate
# browsers and OS ship with a list of trusted root CAs
# if the cert is signed by one of them, the connection is trusted

# we connect to tls1.cryptohack.org and inspect the certificate
# specifically we want the issuer organisation (the CA that signed it)

hostname = "tls1.cryptohack.org"

# create a default SSL context which loads the system's trusted CA store
ctx = ssl.create_default_context()

# open a raw TCP connection on port 443 (standard HTTPS port)
# then wrap it with TLS - this performs the TLS handshake automatically
with socket.create_connection((hostname, 443)) as sock:
    with ctx.wrap_socket(sock, server_hostname=hostname) as tls:

        # get_peercert() returns the server's certificate as a dict
        # this is the certificate the server presented during the handshake
        cert = tls.getpeercert()

        # the issuer field is a tuple of tuples like ((key, value), ...)
        # it contains info about the CA that signed this cert
        # we extract the Organisation (O) field which is the CA name
        issuer = dict(x[0] for x in cert["issuer"])

        print("Full issuer info:", cert["issuer"])
        print("Certificate Authority (O):", issuer.get("organizationName"))

        # the flag is the CA organisation name found here
        # submit it on the CryptoHack challenge page
