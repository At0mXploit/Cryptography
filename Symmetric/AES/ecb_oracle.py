import requests
BASE = "http://aes.cryptohack.org/ecb_oracle/encrypt/"
def encrypt(text):
    r = requests.get(BASE + text.encode().hex())
    return r.json()['ciphertext']
def pad_input(s):
    pad = 'A' * (16 - len(s) % 16)
    return pad + s + pad
def decrypt_flag():
    chars = "abcdefghijklmnopqrstuvwxyz1234567890_{}"
    flag = ""
    while True:
        for c in chars:
            guess = flag + c
            padded = pad_input(guess)
            ct = encrypt(padded)
            size = 2 * ((16 - len(guess) % 16) + len(guess))
            part1, part2 = ct[:size], ct[size:size*2]
            if part1 == part2:
                flag += c
                print(flag)
                break
        if flag.endswith('}'):
            break
if __name__ == '__main__':
    decrypt_flag()
