from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long
from cryptography import x509
from cryptography.hazmat.backends import default_backend

with open("2048b-rsa-example-cert_3220bd92e30015fe4fbeb84a755e7ca5.der", "rb") as f:
    cert_data = f.read()

cert = x509.load_der_x509_certificate(cert_data, default_backend())
public_key = cert.public_key()

print(public_key.public_numbers().n)
