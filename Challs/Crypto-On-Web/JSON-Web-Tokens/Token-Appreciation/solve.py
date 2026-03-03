import base64
import json

token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmbGFnIjoiY3J5cHRve2p3dF9jb250ZW50c19jYW5fYmVfZWFzaWx5X3ZpZXdlZH0iLCJ1c2VyIjoiQ3J5cHRvIE1jSGFjayIsImV4cCI6MjAwNTAzMzQ5M30.shKSmZfgGVvd2OSB2CGezzJ3N6WAULo3w9zCl_T47KQ"

header_b64, payload_b64, signature_b64 = token.split(".")

def b64url_decode(data):
    # Add padding if needed
    padding = '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)

# Decode header
header = json.loads(b64url_decode(header_b64))
print("Header:", header)

# Decode payload
payload = json.loads(b64url_decode(payload_b64))
print("Payload:", payload)

# Print flag
print("\nFlag:", payload["flag"])
