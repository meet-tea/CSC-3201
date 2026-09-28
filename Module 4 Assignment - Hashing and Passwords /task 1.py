import random
import string
import time
from Crypto.Hash import SHA256


def sha256_hash(input_string):
    return SHA256.new(input_string.encode()).hexdigest()

def truncate_hash(hash_string, bits):
    substring = int(hash_string[:bits//4], 16)
    mask = (1 << bits) - 1
    return substring & mask

def hamming_distance(s1, s2):
    count = 0
    for c1, c2 in zip(s1, s2):
        if c1 != c2:
            count += 1
    return count

def find_hamming_distance_1():
    base = str(''.join(random.choices(string.ascii_letters, k=10)))

    for i in range(len(base)):
        modified = ''
        for k in range(len(base)):
            binary = format(ord(base[k]), '08b')
            modifiedbit = ''
            if k == i :
                for j in range(8):
                    if i == (7-j):
                        modifiedbit += str(int(binary[j]) ^ 1)
                    else:
                        modifiedbit += str(binary[j])
            else:
                modifiedbit =str(binary)
            modified += chr(int(modifiedbit, 2))
        if hamming_distance(base, modified) == 1:
            return base, modified
    return None, None


def find_collision(bits, max_attempts):
    seen = {}
    start_time = time.perf_counter()
    for i in range(max_attempts):
        s = str(''.join(random.choices(string.ascii_letters, k=10)))
        h = sha256_hash(s)[:int(bits//4)]
        if h in seen:
            end_time = time.perf_counter()
            elapsed_time = end_time - start_time
            return bits, seen[h], s, h,i + 1, f"{elapsed_time:.4f}"
        else:
            seen[h] = s
    end_time = time.perf_counter()
    elapsed_time = end_time - start_time
    return bits, None, None, None, max_attempts, f"{elapsed_time:.4f}"

def task_1a():
    print("Task 1a: SHA256 hashes of arbitrary inputs")
    for i in ["Hello, World!", "Python", "Cryptography"]:
        print("Input: ", i)
        print("SHA256: ", sha256_hash(i))
        print()

def task_1b():
    print("Task 1b: Strings with Hamming distance of 1")
    for i in range(3):
        base, modified = find_hamming_distance_1()
        print("String 1:", base)
        print("String 2:", modified)
        print("SHA256 (1):", sha256_hash(base))
        print("SHA256 (2):", sha256_hash(modified))
        print()

def task_1c():
    print("+-------+-----------+-----------+---------------+-------------------+---------------+")
    print("| Bits\t| Input 1\t| Input 2\t| Hash\t\t\t| Inputs Tried\t\t| Times (s)\t\t|")
    print("+-------+-----------+-----------+---------------+-------------------+---------------+")
    for i in range(8, 50, 2):
        bits, input1, input2, hashes, tries, t = find_collision(i, 200000000)
        tries = str(tries).ljust(10)
        hashes = str(hashes).ljust(14)
        t = str(t).ljust(8)
        print("|" + str(bits) + "\t\t|" + str(input1) + "\t|" + str(input2) + "\t|"  + str(hashes) + "\t|" + str(tries) + "\t\t\t|" + str(t) + "\t\t|" )
    print("+-------+-----------+-----------+---------------+-------------------+---------------+")

def task_1_main():
    task_1a()
    task_1b()
    task_1c()

if __name__ == "__main__":
    task_1_main()