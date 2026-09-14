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

def encrypt_ecb(data):
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pad(data)
    enc = cipher.encrypt(padded)
    return enc

def decrypt_ecb(encryptedParams):
    cipher = AES.new(key, AES.MODE_ECB)
    padded = cipher.decrypt(bytes(encryptedParams))
    print("Decrypted data:", padded)



try:
    # message = b'userid=456;userdata=admin/true;session-id=31337'
    # print(f"Plaintext before byte-flip: {message.decode('ascii')}")
    # slash_pos = message.index(b'/')
    #
    # ciphertext = encrypt_ecb(message)
    #
    # print("\nBefore admin/true - Ciphertext (hex):")
    # ciphertext_hex = ''.join([hex(x)[2:].zfill(2) for x in ciphertext])
    # print(ciphertext_hex)
    #
    # block_num = (slash_pos // 16)
    # pos_in_prev_block = slash_pos % 16
    # prev_block_start = (block_num - 1) * 16
    #
    # modified_ciphertext = bytearray(ciphertext)
    # modified_ciphertext[prev_block_start + pos_in_prev_block] ^= (ord('/') ^ ord('='))
    #
    # print("\nAfter admin/true - Ciphertext (hex):")
    # modified_hex = ''.join([hex(x)[2:].zfill(2) for x in modified_ciphertext])
    # print(modified_hex)
    #
    # print(f"\nChanged byte position: {prev_block_start + pos_in_prev_block}")
    # print(f"Original byte: {hex(ciphertext[prev_block_start + pos_in_prev_block])[2:].zfill(2)}")
    # print(f"Modified byte: {hex(modified_ciphertext[prev_block_start + pos_in_prev_block])[2:].zfill(2)}")
    #
    # # The bit flipping modification:
    # # cipher[:16] - Keep first block unchanged
    # # cipher[16:18] - These hex chars represent the byte we want to modify
    # # cipher[18:] - Keep the rest unchanged
    # # The modification works because:
    # # 1. In CBC, each plaintext block is XORed with previous ciphertext block
    # # 2. By modifying the ciphertext block before where 'r' appears,
    # # we affect the XOR operation during decryption of the next block
    # # 3. This causes 'r' to become 's' after decryption
    #
    # decrypt_ecb(modified_ciphertext)
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

