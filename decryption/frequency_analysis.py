import sys
sys.path.insert(0, "../encryption")
sys.path.insert(0, "../dictionaries")

import encrypt, alphabet, random, accuracy, frequency
from collections import Counter
#from decrypt import get_space_key_value

with open("../dictionaries/plaintext_dictionary_1.txt", "r") as f:
    PLAIN_TEXTS = [line.rstrip() for line in f]

ALPHABET = alphabet.get_alphabet()
KEY = encrypt.generate_key_mapping()
#TEST_PROB = 0.05
TEST_PROB = 0.4

ciphers = [encrypt.encrypt(t, KEY, TEST_PROB) for t in PLAIN_TEXTS]
cipher_h = {c: 0 for c in ALPHABET}

for c in ciphers[0]:
    cipher_h[c] += 1

cipher_res = [(c, cipher_h[c]) for c in cipher_h]
cipher_res.sort(key=lambda x: x[1], reverse=True)

acc_lst = []

for i in range(len(PLAIN_TEXTS)):
    plain_h = {c: 0 for c in ALPHABET}
    for c in PLAIN_TEXTS[i]:
        plain_h[c] += 1

    plain_res = [(c, plain_h[c]) for c in plain_h]
    plain_res.sort(key=lambda x: x[1], reverse=True)

    decpt_key = {}
    for j in range(27):
        x, y = cipher_res[j][0], plain_res[j][0]
        decpt_key[x] = y

    decpt_txt = []
    for c in ciphers[0]:
        decpt_txt.append(decpt_key[c])

    decpt_txt = "".join(decpt_txt)
    acc_lst.append(accuracy.calc_accuracy(PLAIN_TEXTS[i], ciphers[0]))


def rank_letters_by_freq(text):
    c = Counter(text)
    return sorted([(x, c[x]) for x in c], key=lambda x: x[1], reverse=True)

#for i, txt in enumerate(PLAIN_TEXTS):
#    print(rank_letters_by_freq(txt))

def match_letters_by_freq(plain, cipher, t):
    # t = the number of next-most-common letters
    # to try to map the current letter to

    r1 = rank_letters_by_freq(plain)
    r2 = rank_letters_by_freq(cipher)
    print(r1, r2)
    print(len(r1), len(r2))
    cipher_to_plain = {}
    original_cipher = cipher[::]

    for i, x in enumerate(r2):
        acc_lst = []

        #for j in range(i, min(len(r1), i + t)):
        #    decrpt = cipher.replace(x[0], r1[j][0])
        #    acc = accuracy.calc_accuracy(plain, decrpt)
        #    acc_lst.append((r1[j][0], acc))

        #acc_lst.sort(key=lambda x: x[1], reverse=True)
        #y = acc_lst[0][0] if acc_lst else "!"

        y = r1[i][0] if i < len(r1) else "!"
        cipher_to_plain[x[0]] = y

        r3 = []
        for z in r1:
            if z[0] != y:
                r3.append(z)

        r1 = r3

    decrpt = []
    for x in original_cipher:
        if x not in cipher_to_plain:
            decrpt.append("!")
        else:
            decrpt.append(cipher_to_plain[x])

    print(cipher_to_plain)

    return "".join(decrpt)


#for i, plain in enumerate(PLAIN_TEXTS):
#    print("Plaintext: #" + str(i))
#    t = 3
#    decrpt = match_letters_by_freq(plain, ciphers[0], t)
#    acc = accuracy.calc_accuracy(plain, decrpt)
#
#    print("Decrypted text:")
#    print(decrpt)
#    print("\n\nAccuracy: " + str(acc))

"""
for i, plain in enumerate(PLAIN_TEXTS):
        print("Plaintext: #" + str(i))
        print(plain)
        #print(Counter(plain))
        words = plain.split(" ")
        #print(words)
        l0 = [len(w) for w in words]
        print(l0)

        print("Ciphertext: #" + str(i))
        print(ciphers[i])
        c = Counter(ciphers[i])
        print(c)

        freq = [(x, c[x]) for x in c]
        freq.sort(key=lambda x: x[1], reverse=True)
        print(freq[:2])
        a, b = freq[0][0], freq[1][0]

        r1 = ciphers[i].replace(a, " ")
        r2 = ciphers[i].replace(b, " ")

        w1 = r1.split(" ")
        w2 = r2.split(" ")

        l1 = [len(w) for w in w1]
        l2 = [len(w) for w in w2]

        print(l1)
        print(l2)

        d1, d2 = [], []
        for i in range(len(l0)):
            if i >= len(l1):
                continue
            diff = abs(l0[i] - l1[i]) / l0[i]
            d1.append(diff)

        for i in range(len(l0)):
            if i >= len(l2):
                continue
            diff = abs(l0[i] - l2[i]) / l0[i]
            d2.append(diff)

        print(sum(d1))
        print(sum(d2))
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

def main():
    for i, cipher in enumerate(ciphers):
        space_val = get_space_key_value(cipher)
        words = cipher.split(space_val)
        lengths = [len(w) for w in words]
        print("In ciphertext: ")
        print(lengths)
        diffs = []

        for j, p in enumerate(PLAIN_TEXTS):
            #print("In Plaintext #" + str(j) + ": ")
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
            #print(p_lengths)
            #print(sum(diff))

        diffs.sort(key=lambda x: x[1])
        res = diffs[0][0]
        print("Matched plaintext: #" + str(res))

        if res == i:
            print("Match is correct.")
        else:
            print("Match is incorrect.")

        print(diffs)
        print("\n\n")


if __name__ == "__main__":
    main()
