from Crypto.Util.number import getPrime
import math


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


def message_to_int(message):
    messagehex = message.encode().hex()
    return int(messagehex, 16)


def int_to_message(messageint):
    messagehex = hex(messageint)[2:]
    if len(messagehex) % 2 != 0:
        messagehex = "0" + messagehex
    return bytes.fromhex(messagehex).decode()


def encrypt_rsa(messageint, e, n):
    return pow(messageint, e, n)


def decrypt_rsa(ciphertext, d, n):
    return pow(ciphertext, d, n)


print("Textbook RSA")
print("----------------------------------------------")

primebits = int(input("Prime bit length (64-2048): "))

if primebits < 64 or primebits > 2048:
    raise ValueError("Prime bit length must be between 64 and 2048")

print("Generating RSA keys...")
p, q, n, e, d = generate_keypair(primebits)

print("Prime p bit length: " + str(p.bit_length()))
print("Prime q bit length: " + str(q.bit_length()))
print("Modulus n bit length: " + str(n.bit_length()))
print("Public exponent e: " + str(e))
print("Public key (n, e): (" + str(n) + ", " + str(e) + ")")
print()

messages = ["Hi Bob!", "Hi Alice!", "RSA works!"]

for message in messages:
    messageint = message_to_int(message)

    if messageint >= n:
        raise ValueError("The message integer must be less than n")

    ciphertext = encrypt_rsa(messageint, e, n)
    decryptedint = decrypt_rsa(ciphertext, d, n)
    decryptedmessage = int_to_message(decryptedint)

    print("Original message: " + message)
    print("Message as an integer: " + str(messageint))
    print("Ciphertext: " + str(ciphertext))
    print("Decrypted integer: " + str(decryptedint))
    print("Decrypted message: " + decryptedmessage)
    print("Message recovered correctly: " + str(message == decryptedmessage))
    print()
