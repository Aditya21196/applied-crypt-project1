import sys
sys.path.insert(0, "../encryption")
sys.path.insert(0, "../dictionaries")

import encrypt, alphabet, random, accuracy

with open("../dictionaries/plaintext_dictionary_1.txt", "r") as f:
    PLAIN_TEXTS = [line.rstrip() for line in f]

ALPHABET = alphabet.get_alphabet()
KEY = encrypt.generate_key_mapping()
TEST_PROB = 0.05

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

print(acc_lst)
