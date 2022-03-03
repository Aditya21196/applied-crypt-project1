import sys
sys.path.insert(0, "../encryption")
sys.path.insert(0, "../dictionaries")

import encrypt, alphabet, random, accuracy
from collections import Counter

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


for i, plain in enumerate(PLAIN_TEXTS):
    print("Plaintext: #" + str(i))
    t = 3
    decrpt = match_letters_by_freq(plain, ciphers[0], t)
    acc = accuracy.calc_accuracy(plain, decrpt)
    
    print("Decrypted text:")
    print(decrpt)
    print("\n\nAccuracy: " + str(acc))