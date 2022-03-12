import sys
sys.path.insert(0, "../encryption")
sys.path.insert(0, "../dictionaries")

import encrypt, alphabet, random, accuracy, frequency

with open("../dictionaries/official_dictionary_1_cleaned.txt", "r") as f:
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
    
    def get_space_key_value(ciphertext):
        """
        returns the space key value for the ciphertext
        works for values of p up to atleast .95
        theoretically should work to ~p(.96)
        """
        word_stats = []

        for char in (alphabet.get_alphabet()):
            try:
                word_stats.append(frequency.get_word_frequency_statistics(ciphertext, delimiter = char))
            except KeyError:
                pass

        word_stats.sort(key = lambda x: x['stdev'])
        return word_stats[0]['delimiter']
    
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

print(decrypt_test_1(ciphers[0], PLAIN_TEXTS))