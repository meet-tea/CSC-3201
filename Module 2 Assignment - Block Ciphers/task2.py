from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from binascii import unhexlify
import re
import binascii

def pad(message):
    paddinglen = 16 - (len(message) % 16)
    padding = bytes([paddinglen] * paddinglen)
    return message + padding



key = get_random_bytes(16)
iv = get_random_bytes(16)



def encrypt_cbc(data):
    #padded = pad(data.encode(), 16, style="pkcs7")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(data)
    enc = cipher.encrypt(padded)
    return enc

def decrypt_cbc(encryptedParams):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    paddedParams = cipher.decrypt(bytes(encryptedParams))
    #print(f"\nPlaintext after byte-flip: userid=456;userdata=admin/true;session-id=31337")
    print("Decrypted data:", paddedParams)

def submit(pstring):

    pstring = pstring.replace(";", "%3B").replace("=", "%3D")

    pstring = "userid=456;userdata=" + pstring + ";session-id=31337"
    pstring = pstring.encode("utf-8")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(pstring)
    enc = cipher.encrypt(padded)
    return enc

def verify(encryptedParams):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    paddedParams = cipher.decrypt(bytes(encryptedParams))
    print(paddedParams)
    if b';admin=true;' in paddedParams:
        return True
    else:
        return False

string = input("Enter String: ")

ciphertext = submit(string)
ciphertext_hex = ''.join([hex(x)[2:].zfill(2) for x in ciphertext])
print("Encrypted String:", ciphertext_hex)
print("is verified: ", verify(ciphertext))
print("\n\n")

admintxt = bytearray(b"admin=true;")
beginning = bytearray(b"session-id=")
modified_ciphertext = bytearray(ciphertext)


block_num = (21 // 16)
pos_in_prev_block = 21 % 16
prev_block_start = (block_num-1) * 16
for i in range(11):
    modified_ciphertext[prev_block_start + pos_in_prev_block + i] ^= (ord(chr(beginning[i])) ^ ord(chr(admintxt[i])))

modified_hex = ''.join([hex(x)[2:].zfill(2) for x in modified_ciphertext])
print(modified_hex)
print("modified is verified: ", verify(modified_ciphertext))

print("\nKey:", binascii.hexlify(key).decode('utf-8'))
print("IV: ", binascii.hexlify(iv).decode('utf-8'))


