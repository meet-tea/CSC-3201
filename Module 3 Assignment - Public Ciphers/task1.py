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


#q = 37
#g = 5

# qstr = (
#     "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6"
#     "9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0"
#     "13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
#     "98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
#     "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708"
#     "DF1FB2BC2E4A4371"
# )
qstr = (
    "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6"
    "9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0"
    "13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
    "98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
    "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708"
    "DF1FB2BC2E4A4371"
)

gstr = (
    "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F"
    "D6406CFF14266D31266FEA1E5C41564B777E690F5504F213"
    "160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1"
    "909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
    "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24"
    "855E6EEB22B3B2E5"
)


q = int(qstr, 16)
g = int(gstr, 16)

print("Diffle-Hellman Protocol (q=" + qstr + ", g=" + gstr + ")")

print("----------------------------------------------")
aliceprivate = int(input("Alice's private key (XA): "))
alicepublic = pow(g, aliceprivate, q)
print("Alice's public key (YA): " + str(alicepublic))
bobprivate = int(input("Bob's private key (XB): "))
bobpublic = pow(g, bobprivate, q)
print("Bob's public key (ZA): " + str(bobpublic))
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