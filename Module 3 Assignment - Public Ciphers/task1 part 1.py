from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import binascii

def pad(message):
    paddinglen = 16 - (len(message) % 16)
    padding = bytes([paddinglen] * paddinglen)
    return message + padding


def encrypt_cbc(key, iv,  data):
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pad(data)
    block_size = 16
    enc = bytearray()
    block_enc = iv
    for i in range(0, len(padded), block_size):
        block = padded[i:i+block_size]
        block_xored = bytearray(block_size)
        for byte_i in range(block_size):
            block_xored[byte_i] = block[byte_i] ^ block_enc[byte_i]
        block_enc = cipher.encrypt(block_xored)
        enc = enc + block_enc
    return bytes(enc)

def decrypt_cbc(key, iv, encryptedParams):
    cipher = AES.new(key, AES.MODE_ECB)
    block_size = 16
    block_enc = iv
    dec = b''
    for i in range(0, len(encryptedParams), 16):
        block = encryptedParams[i:i+16]
        decrypted = cipher.decrypt(block)
        block_xored = bytearray(block_size)
        for byte_i in range(block_size):
            block_xored[byte_i] = decrypted[byte_i] ^ block_enc[byte_i]
        block_enc = block
        dec = dec + block_xored
    return dec


q = 37
g = 5

print("Diffle-Hellman Protocol (q=" + str(q) + ", g=" + str(g) + ")")
print("----------------------------------------------")
aliceprivate = int(input("Alice's private key (XA): "))
alicepublic = pow(g, aliceprivate, q)
print("Alice's public key (YA): " + str(alicepublic))
bobprivate = int(input("Bob's private key (XB): "))
bobpublic = pow(g, bobprivate, q)
print("Bob's public key (XY): " + str(bobpublic))
alicesecret = pow(bobpublic, aliceprivate, q)
bobsecret = pow(alicepublic, bobprivate, q)
print("Alice's computed shared secret: " + str(alicesecret))
print("Bob's computed shared secret: " + str(bobsecret))
alicekey = SHA256.new((str(alicesecret).encode())).digest()[:16]
bobkey = SHA256.new((str(bobsecret).encode())).digest()[:16]
print("Alice's derived key: " + str(alicekey.hex()))
print("Bob's derived key: " + str(bobkey.hex()))
if alicekey != bobkey:
    samekey = False
else:
    samekey = True

print("Alice and Bob have the same key: " + str(samekey))
print()

alicemessage = b"Hi Bob!"
print("Alice's message: " + str(alicemessage))
aliceiv = get_random_bytes(16)
print("Alice's IV: " + str(aliceiv))
alicecybertext = encrypt_cbc(alicekey, aliceiv, alicemessage)
print("Alice's ciphertext: " + str(alicecybertext))

bobmessage = b"Hi Alice!"
bobiv = get_random_bytes(16)
bobcybertext = encrypt_cbc(bobkey, bobiv, bobmessage)

bobdecrypted = decrypt_cbc(alicekey, bobiv, bobcybertext)
print("Bob's decrypted message: " + str(bobdecrypted))
print()

print("Bob's message: " + str(bobmessage))
print("Bob's IV: " + str(bobcybertext))
print("Bob's ciphertext: " + str(bobcybertext))
alicedecrypted = decrypt_cbc(bobkey, aliceiv, alicecybertext)
print("Alice's decrypted message: " + str(alicedecrypted))