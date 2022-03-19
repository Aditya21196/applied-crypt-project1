import sys
sys.path.insert(0, "../encryption")
sys.path.insert(0, "../dictionaries")

from test2_generate_plaintext import get_plaintext
import encrypt, alphabet, random, accuracy, frequency, decrypt
from collections import Counter
from test_2_first_steps import split_t2_ciphertext, find_matches_for_duplicates
from find_similar_words import get_longest_common_subsequence
#from test_1_decryption import decrypt_test_1

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
    print(diffs)
    res = diffs[0][0]
    
    return all_plain[res]

with open("../dictionaries/official_dictionary_1_cleaned.txt", "r") as f:
    PLAIN_TEXTS = [line.rstrip() for line in f]
    

ALPHABET = alphabet.get_alphabet()
KEY = encrypt.generate_key_mapping()
TEST_PROB = 0.7
# The constant that stores the probability of a random character

t2 = get_plaintext()
t2_cipher = encrypt.encrypt(t2, KEY, TEST_PROB)
#PLAIN_TEXTS.append(t2)

ciphers = [encrypt.encrypt(t, KEY, TEST_PROB) for t in PLAIN_TEXTS]
#cipher_h = {c: 0 for c in ALPHABET}

#for c in ciphers:
#    decrypt_test_1(c, PLAIN_TEXTS)

#for p in PLAIN_TEXTS:
#    words = p.split(" ")
#    print(Counter(words))
#    print("\n\n\n")

common_subseq = 'jynt tyj'
# actual longest subsequence: "yanp tyj"
w1 = 'jyalentp tkyjmj'
w2 = ' pyanp jtdyj'

def draft(w1, w2):
    dp = [[0 for _ in range(len(w1) + 1)] for _ in range(len(w2) + 1)]
    
    for i in range(1, len(w2) + 1):
        for j in range(1, len(w1) + 1):
            c1, c2 = w2[i - 1], w1[j - 1]
            x = int(c1 == c2)
            dp[i][j] = max(dp[i][j - 1], dp[i - 1][j - 1] + x, dp[i - 1][j])
            
    res = []
    k = len(dp[-1]) - 1
    for i in reversed(range(len(dp) - 1)):
        j = i + 1
        if dp[i][k] == dp[j][k]:
            continue
        while k >= 0 and dp[i][k] < dp[j][k]:
            k -= 1
        if k >= 0:
            res.append(w1[k])
            
    return "".join(reversed(res))
    

#print(get_longest_common_subsequence(w1, w2))
#print(draft(w1, w2))

for c in ciphers:
    space_key = decrypt.get_space_key_value(c)
    words = sorted(c.split(space_key), key=lambda w: len(w), reverse=True)
    all_seqs = []
    
    for i in range(len(words)):
        for j in range(i + 1, len(words)):
            seq = draft(words[i], words[j])
            #all_seqs.append((seq, words[i], words[j]))
            all_seqs.append(seq)
            
    #all_seqs.sort(key=lambda x: len(x[0]), reverse=True)
    all_seqs.sort(key=lambda x: len(x), reverse=True)
    print(max([len(s) for s in all_seqs]))
    print("\n\n\n")
    
space_key = decrypt.get_space_key_value(t2_cipher)
words = sorted(t2_cipher.split(space_key), key=lambda w: len(w), reverse=True)
all_seqs = []

for i in range(len(words)):
    for j in range(i + 1, len(words)):
        seq = draft(words[i], words[j])
        #all_seqs.append((seq, words[i], words[j]))
        all_seqs.append(seq)

#all_seqs.sort(key=lambda x: len(x[0]), reverse=True)
all_seqs.sort(key=lambda x: len(x), reverse=True)
#print(all_seqs)
print(max([len(s) for s in all_seqs]))
print("\n\n\n")