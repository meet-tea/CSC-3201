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

def embed(cover_path, out_path, type, payload_bytes, password):
    image = Image.open(cover_path).convert('RGB')
    arr = np.array(image)
    H, W, _ = arr.shape
    total_channels = H * W * 3

    framed = frame_payload(type, payload_bytes)
    bits = bytes_to_bits(framed)

    if len(bits) > total_channels:
        raise ValueError('payload too large')

    rng = np.random.default_rng(seed_from_password(password))
    perm = rng.permutation(total_channels)

    out = arr.copy()
    for i in range(len(bits)):
        channel_pos = perm[i]
        pixel = channel_pos // 3
        ch = channel_pos % 3
        y = pixel // W
        x = pixel % W
        out[y, x, ch] = (out[y, x, ch] & 0xFE) | bits[i]

    Image.fromarray(out).save(out_path, 'PNG')

def image_to_png_bytes(path):
    buf = io.BytesIO()
    Image.open(path).save(buf, 'PNG')
    return buf.getvalue()

if __name__ == '__main__':
    print(bits_to_bytes(bytes_to_bits(b'ab')))

    embed('apple_logo_cover.png', 'stego_text.png', 'text', 'This is a secret'.encode('utf-8'), 'secret')
    print('created stego_text.png')

    embed('apple_logo_cover.png', 'stego_laptop.png', 'image', image_to_png_bytes('laptop_secret.png'), 'secret')
    print('created stego_laptop.png')

    try:
        embed('apple_logo_cover.png', 'too_big.png', 'text', b'A' * 20000, 'secret')
    except ValueError as e:
        print('error:', e)
