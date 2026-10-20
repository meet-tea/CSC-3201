from Crypto.Hash import SHA256

def seed_from_password(password):
    h = SHA256.new(password.encode('utf-8')).digest()
    return int.from_bytes(h[:8], 'big')

def capacity_bytes(height, width, channels=3):
    return (height * width * channels) // 8

def bytes_to_bits(data):
    bits = []
    for b in data:
        for i in range(7, -1, -1):
            bits.append((b >> i) & 1)
    return bits

def bits_to_bytes(bits):
    paddinglen = 8 - (len(bits) % 8)
    padding = [paddinglen] * paddinglen
    print(padding)
    out = []
print(bits_to_bytes(bytes_to_bits(b'ab')))