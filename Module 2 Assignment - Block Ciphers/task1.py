from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import binascii

def pad(message):
    paddinglen = 16 - (len(message) % 16)
    padding = bytes([paddinglen] * paddinglen)
    return message + padding

key = get_random_bytes(16)
iv = get_random_bytes(16)

def encrypt_cbc(data):
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

def encrypt_ecb(data):
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pad(data)
    block_size = 16
    enc = bytearray()
    for i in range(0, len(padded), block_size):
        block = padded[i:i+block_size]
        enc = enc + cipher.encrypt(block)
    return bytes(enc)

# for testing only
# def decrypt_cbc(encryptedParams):
#     cipher = AES.new(key, AES.MODE_CBC, iv)
#     paddedParams = cipher.decrypt(bytes(encryptedParams))
#     #print(f"\nPlaintext after byte-flip: userid=456;userdata=admin/true;session-id=31337")
#     print("Decrypted data:", paddedParams)
#
# def decrypt_ecb(encryptedParams):
#     cipher = AES.new(key, AES.MODE_ECB)
#     padded = cipher.decrypt(bytes(encryptedParams))
#     print("Decrypted data:", padded)


try:
    fileName = input("Enter file name: ")
    with open(fileName, "r+b") as f:
        header = f.read(54)
        data = f.read()
    encryptedcbc = encrypt_cbc(data)
    encryptedecb = encrypt_ecb(data)

    with open(fileName + "CBC_encryption.bmp", "wb") as f:
        f.write(header)
        f.write(encryptedcbc)

    with open(fileName + "ECB_encryption.bmp", "wb") as f:
        f.write(header)
        f.write(encryptedecb)

    print("\nKey:", binascii.hexlify(key).decode('utf-8'))
    print("\nIV: ", binascii.hexlify(iv).decode('utf-8'))

except Exception as e:
    print(f"An error occurred: {e}")

