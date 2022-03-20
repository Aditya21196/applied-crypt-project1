import os
import sys
import inspect

currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
dictionary_path = os.path.join(parentdir,'dictionaries')

import sys
sys.path.insert(0, "../encryption")
sys.path.insert(0, "../dictionaries")

import encrypt, alphabet, random, accuracy, frequency
from decrypt import get_space_key_value

with open(os.path.join(dictionary_path,'official_dictionary_1_cleaned.txt'), "r") as f:
    PLAIN_TEXTS = [line.rstrip() for line in f]

ALPHABET = alphabet.get_alphabet()
KEY = encrypt.generate_key_mapping()
TEST_PROB = 0.4
# The constant that stores the probability of a random character

ciphers = [encrypt.encrypt(t, KEY, TEST_PROB) for t in PLAIN_TEXTS]
cipher_h = {c: 0 for c in ALPHABET}

def decrypt_test_1(cipher, all_plain):
    """
    Given a ciphertext and a number of plaintexts, returns the 
    plaintext that best matches the ciphertext.
    """

    space_val = get_space_key_value(cipher)
    words = cipher.split(space_val)
    lengths = [len(w) for w in words]
    diffs = []

    for j, p in enumerate(PLAIN_TEXTS):
        p_words = p.split(" ")
        p_lengths = [len(w) for w in p_words]
        c_lengths = lengths[::]
        diff = []
        a = b = 0
        
        while a < len(p_lengths) and b < len(c_lengths):
            if a >= len(lengths):
                continue
            if c_lengths[b] < p_lengths[a] and b < len(c_lengths) - 1:
                c_lengths[b + 1] += c_lengths[b]
                b += 1
                continue

            d = abs(c_lengths[b] - p_lengths[a]) / p_lengths[a]
            diff.append(d)
            a += 1
            b += 1
        
        diffs.append((j, sum(diff) / len(diff)))
    
    diffs.sort(key=lambda x: x[1])
    res = diffs[0][0]
    
    return all_plain[res]

####print(decrypt_test_1(ciphers[0], PLAIN_TEXTS))
