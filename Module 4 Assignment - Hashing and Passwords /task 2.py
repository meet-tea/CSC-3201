import bcrypt
import multiprocessing as mp
from nltk.corpus import words

def chunk(arg):
    word_chunk, hashs = arg
    for word in word_chunk:
        if bcrypt.checkpw(word.encode("utf-8"), hashs):
            return word
    return None

if __name__ == "__main__":
    possible_words = []
    for i in words.words():
        if i.isalpha():
            if 6 <= len(i) <= 10:
                possible_words.append(i)

    with open("shadow.txt", "r") as file:
        contents = file.readlines()

    for i in range(15):
        user, hashs = contents[i].strip().split(":")
        hashs = hashs.encode("utf-8")
        chunk_size = 1000

        chunks = [
            possible_words[i:i + chunk_size]
            for i in range(0, len(possible_words), chunk_size)
        ]
        jobs = [(chunk, hashs) for chunk in chunks]

        with mp.Pool() as pool:
            for password in pool.imap_unordered(chunk, jobs):
                if password is not None:
                    print(f"{user}: {password}")
                    pool.terminate()
                    break