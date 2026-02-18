import requests

# Get encrypted flag
encrypt_response = requests.get('http://aes.cryptohack.org/block_cipher_starter/encrypt_flag/')
ciphertext = encrypt_response.json()['ciphertext']
print(f"Ciphertext: {ciphertext}")

# Decrypt it
decrypt_response = requests.get(f'http://aes.cryptohack.org/block_cipher_starter/decrypt/{ciphertext}/')
plaintext_hex = decrypt_response.json()['plaintext']
print(f"Plaintext hex: {plaintext_hex}")

# Convert hex to ASCII
plaintext = bytes.fromhex(plaintext_hex).decode('utf-8')
print(f"Flag: {plaintext}")
