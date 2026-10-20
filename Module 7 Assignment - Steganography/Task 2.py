from Crypto.Hash import SHA256
from PIL import Image
import numpy as np
import io

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
    paddinglen = (8 - (len(bits) % 8)) % 8
    padding = [0] * paddinglen
    bits = bits + padding
    out = []
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i:i+8]:
            byte = (byte << 1) | bit
        out.append(byte)
    return bytes(out)

def frame_payload(type, payload_bytes):
    magic = b'STEG'
    if type == 'text':
        tbyte = bytes([0x00])
    else:
        tbyte = bytes([0x01])
    length = len(payload_bytes).to_bytes(4, 'big')
    return magic + tbyte + length + payload_bytes


def extract(stego_path, password):
    image = Image.open(stego_path).convert('RGB')
    arr = np.array(image)
    H, W, _ = arr.shape
    total_channels = H * W * 3

    rng = np.random.default_rng(seed_from_password(password))
    perm = rng.permutation(total_channels)

    bits = []
    header_seen = False
    for i in range(total_channels):
        channel_pos = perm[i]

        pixel = channel_pos // 3
        ch = channel_pos % 3

        y = pixel // W
        x = pixel % W

        bits.append(arr[y, x, ch] & 1)

        if len(bits) == 72:
            header = bits_to_bytes(bits)

            if header[:4] != b'STEG':
                return (None, None)

            if header[4] == 0:
                type = "text"
            else:
                type = "image"

            length = int.from_bytes(header[5:9], 'big')
            total_bits_needed = (9 + length) * 8
            header_seen = True

        if header_seen and len(bits) >= total_bits_needed:
            break

    payload_bytes = bits_to_bytes(bits[72:(72 + (length * 8))])
    if type == "text":
        return ("text", payload_bytes.decode("UTF-8"))
    else:
        img = Image.open(io.BytesIO(payload_bytes))
        img.show()
        return ("image", payload_bytes)
if __name__ == '__main__':
    print(extract('stego_text.png', 'secret'))
    extract('stego_laptop.png', 'secret')
    print(extract('stego_text.png', 'password'))