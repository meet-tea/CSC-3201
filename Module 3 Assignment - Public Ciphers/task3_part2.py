from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.number import getPrime
import math


def pad(message):
    paddinglen = 16 - (len(message) % 16)
    padding = bytes([paddinglen] * paddinglen)
    return message + padding


def unpad(message):
    paddinglen = message[-1]
    return message[:-paddinglen]


def encrypt_cbc(key, iv, data):
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
    for i in range(0, len(encryptedParams), block_size):
        block = encryptedParams[i:i+block_size]
        decrypted = cipher.decrypt(block)
        block_xored = bytearray(block_size)
        for byte_i in range(block_size):
            block_xored[byte_i] = decrypted[byte_i] ^ block_enc[byte_i]
        block_enc = block
        dec = dec + block_xored
    return dec


def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y


def mod_inverse(value, modulus):
    gcd, x, y = extended_gcd(value, modulus)
    if gcd != 1:
        raise ValueError("The modular inverse does not exist")
    return x % modulus


def generate_keypair(primebits):
    e = 65537

    while True:
        p = getPrime(primebits)
        q = getPrime(primebits)

        if p == q:
            continue

        phi = (p - 1) * (q - 1)

        if math.gcd(e, phi) == 1:
            break

    n = p * q
    d = mod_inverse(e, phi)
    return p, q, n, e, d


def random_secret(n):
    bytecount = (n.bit_length() + 7) // 8

    while True:
        secret = int.from_bytes(get_random_bytes(bytecount), "big") % n
        if secret > 1 and math.gcd(secret, n) == 1:
            return secret


print("RSA MITM Key-Fixing Attack")
print("----------------------------------------------")

primebits = int(input("Prime bit length (64-2048): "))

if primebits < 64 or primebits > 2048:
    raise ValueError("Prime bit length must be between 64 and 2048")

print("Generating Alice's RSA keys...")
p, q, n, e, d = generate_keypair(primebits)

print("Alice's public key (n, e): (" + str(n) + ", " + str(e) + ")")
print("Alice keeps d private")
print()

bobsecret = random_secret(n)
bobciphertext = pow(bobsecret, e, n)

print("Bob's original secret (s): " + str(bobsecret))
print("Bob's ciphertext (c): " + str(bobciphertext))
print()

mallorysecret = 2
modifiedciphertext = pow(mallorysecret, e, n)

print("Mallory replaces c with c'")
print("Mallory's known secret: " + str(mallorysecret))
print("Modified ciphertext (c'): " + str(modifiedciphertext))
print()

alicesecret = pow(modifiedciphertext, d, n)
alicekey = SHA256.new(str(alicesecret).encode()).digest()[:16]
mallorykey = SHA256.new(str(mallorysecret).encode()).digest()[:16]

print("Alice decrypts c' and gets: " + str(alicesecret))
print("Alice's derived key: " + str(alicekey.hex()))
print("Mallory's derived key: " + str(mallorykey.hex()))
print("Alice and Mallory have the same key: " + str(alicekey == mallorykey))
print()

iv = get_random_bytes(16)
alicemessage = b"Hi Bob!"
aliceciphertext = encrypt_cbc(alicekey, iv, alicemessage)
mallorydecrypted = decrypt_cbc(mallorykey, iv, aliceciphertext)
mallorydecrypted = unpad(mallorydecrypted)

print("Alice's message: " + str(alicemessage))
print("Alice's IV: " + str(iv))
print("Alice's ciphertext (c0): " + str(aliceciphertext))
print("Mallory decrypts c0: " + str(mallorydecrypted))
print("Mallory recovered the message: " + str(mallorydecrypted == alicemessage))
print()

multiplier = 3
multiplierciphertext = pow(multiplier, e, n)
malleatedciphertext = (bobciphertext * multiplierciphertext) % n
malleatedmessage = pow(malleatedciphertext, d, n)
expectedmessage = (bobsecret * multiplier) % n

print("RSA Multiplicative Malleability")
print("Mallory multiplies c by 3^e mod n")
print("Alice decrypts the modified ciphertext to: " + str(malleatedmessage))
print("Expected value s * 3 mod n: " + str(expectedmessage))
print("The values match: " + str(malleatedmessage == expectedmessage))
print()

print("RSA Signature Malleability")
print("----------------------------------------------")

m1 = 12
m2 = 13
m3 = m1 * m2

signature1 = pow(m1, d, n)
signature2 = pow(m2, d, n)
forgedsignature = (signature1 * signature2) % n
verifiedmessage = pow(forgedsignature, e, n)

print("Message m1: " + str(m1))
print("Message m2: " + str(m2))
print("Message m3 = m1 * m2: " + str(m3))
print("Signature for m1: " + str(signature1))
print("Signature for m2: " + str(signature2))
print("Forged signature for m3: " + str(forgedsignature))
print("Message recovered from forged signature: " + str(verifiedmessage))
print("The forged signature is valid: " + str(verifiedmessage == m3))
