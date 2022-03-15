import sys
sys.path.insert(0, "../encryption")
sys.path.insert(0, "../dictionaries")

import encrypt, alphabet, random, accuracy, frequency, decrypt
from test2_generate_plaintext import get_plaintext
from find_similar_words import get_longest_common_subsequence
from datetime import datetime

with open("../dictionaries/official_dictionary_1_cleaned.txt", "r") as f:
    PLAIN_TEXTS = [line.rstrip() for line in f]
    
with open("../dictionaries/official_dictionary_2_cleaned.txt", "r") as f:
    dictionary = [line.rstrip() for line in f]
    
#min_len = min(len(w) for w in dictionary)
#len_sum = sum(len(w) for w in dictionary)
#print("The minimum length of a word in the dictionary is: " + 
#      str(min_len) + " characters")
#print("The total number of characters in the dictionary is: " + str(len_sum))

#ALPHABET = alphabet.get_alphabet()
#KEY = encrypt.generate_key_mapping()
# The first element in KEY is the substitution for the space character

TEST_PROB = 0.1
# The constant that stores the probability of a random character

#t2_plain = get_plaintext()
#t2 = encrypt.encrypt(t2_plain, KEY, TEST_PROB)
#print("The length of the Test 2 plaintext is: " + str(len(t2)) + " characters")

#space_c = decrypt.get_space_key_value(t2)
#print("The space key returned by the algorithm is: " + space_c)
#print("The correct space key is: " + ALPHABET[KEY[0]])

#words = sorted(t2.split(space_c), key=lambda x: len(x), reverse=True)

#print(words)
#print(len(words))


def split_t2_ciphertext(cipher, dictionary):
    space_c = decrypt.get_space_key_value(cipher)
    #print("The space key returned by the algorithm is: " + space_c)
    #print("The correct space key is: " + ALPHABET[KEY[0]])
    
    words = []
    i = j = 0
    lengths = sorted(list(len(w) for w in dictionary), reverse=True)
    min_len = lengths[-1]
    # The minimum length of a word in the dictionary
    
    while i < len(cipher):
        if cipher[i] == space_c and i - j + 1 < min_len:
            i += 1
            continue
            
        if cipher[i] == space_c:
            w = cipher[j : i]
            words.append(w)
            j = i + 1
        
        i += 1
        
    if i > j:
        words.append(cipher[j:i])
        
    return sorted(words, key=lambda w: len(w), reverse=True)

#words_2 = split_t2_ciphertext(t2, dictionary)
#print(words_2)
#print(len(words_2))

def find_matches_for_duplicates(words, dictionary):
    res = set()
    h = {w: True for w in dictionary}
    
    for i in range(len(words)):
        for j in range(i + 1, len(words)):
            seq = get_longest_common_subsequence(words[i], words[j])
            for w in h:
                if len(w) == len(seq):
                    res.add((w, seq))
                    
    return sorted(list(res), key=lambda x: len(x[0]), reverse=True)

#dup = find_matches_for_duplicates(words_2, dictionary)
#print(dup)
#print(len(dup))

def map_char_in_duplicates(matches, ciphertext):
    cnt = [0] * len(matches)
    for i, (p, c) in enumerate(matches):
        mapping = {x: y for x in c for y in p}
        for j, (p2, c2) in enumerate(matches):
            if j == i:
                continue
            
            dec = []
            for x in c2:
                if x in mapping:
                    dec.append(mapping[x])
                else:
                    dec.append(x)
            
            dec = "".join(dec)
            seq = get_longest_common_subsequence(p2, dec)
            cnt[i] += len(seq)
            
    for i in range(len(cnt)):
        cnt[i] = [i, cnt[i]]
           
    cnt.sort(key=lambda x: x[1], reverse=True)
    #print(cnt)
    
    space_c = decrypt.get_space_key_value(ciphertext)
    
    m = {space_c: " "}
    i = 0
    while len(m) < 27 and i < len(cnt):
        j = cnt[i][0]
        p, c = matches[i]
        for k, x in enumerate(c):
            if x in m:
                continue
            m[x] = p[k]
        
        i += 1
        
    all_decrypted = []
    for p, c in matches:
        d = "".join([m[x] for x in c])
        all_decrypted.append([p, c, d])
        
    #print(all_decrypted)
    
    return m
        
#m = map_char_in_duplicates(dup, t2)

def find_test2_accuracy(mapping, plaintext, ciphertext, dictionary):
    t2_dec = []
    for x in ciphertext:
        if x not in mapping:
            continue
        t2_dec.append(mapping[x])

    t2_dec = "".join(t2_dec)
    #print(t2_dec)

    dec_words = t2_dec.split(" ")
    dec_2 = []

    for w in dec_words:
        all_len = []
        for w2 in dictionary:
            seq = get_longest_common_subsequence(w, w2)
            all_len.append((w2, len(seq)))

        all_len.sort(key=lambda x: x[1], reverse=True)
        dec_2.append(all_len[0][0])

    final_dec = " ".join(dec_2)
    #print("\n\nFinal decrypted text: ")
    #print(final_dec)
    #print("\n\nOriginal plaintext: ")
    #print(t2_plain)

    seq = get_longest_common_subsequence(final_dec, plaintext)
    acc = len(seq) / len(plaintext)
    #print("\n\nAccuracy: " + str(acc))
    
    return acc
    
def stress_test(rand_p, dictionary, round_cnt):
    all_acc = []
    for i in range(round_cnt):
        start_t = datetime.now().strftime("%H:%M:%S")
        print("Round #" + str(i + 1) + 
                " is starting. Current time: " + start_t)
        keys = encrypt.generate_key_mapping()
        t2_plain = get_plaintext()
        t2_cipher = encrypt.encrypt(t2_plain, keys, rand_p)

        words = split_t2_ciphertext(t2_cipher, dictionary)
        matches = find_matches_for_duplicates(words, dictionary)
        m = map_char_in_duplicates(matches, t2_cipher)
        acc = find_test2_accuracy(m, t2_plain, t2_cipher, dictionary)
        all_acc.append(acc)
        
        completion = (i + 1) / round_cnt * 100
        end_t = datetime.now().strftime("%H:%M:%S")
        print(str(completion) + "% completed. Current time: " + end_t)
        
    res = []
    res.append("Random character probability: " + str(rand_p))
    res.append("Rounds completed: " + str(round_cnt))
    res.append("Lowest accuracy: " + str(min(all_acc)))
    res.append("Highest accuracy: " + str(max(all_acc)))
    avg_acc = sum(all_acc) / len(all_acc)
    res.append("Average accuracy: " + str(avg_acc))
    
    return res

if __name__ == "__main__":
    p = 0.5
    out = []
    while p < 1:
        #t1 = datetime.now().strftime("%H:%M:%S")
        #print("Test is starting. Current time: " + t1)
        res = stress_test(p, dictionary, 10)
        print(res)

        #t2 = datetime.now().strftime("%H:%M:%S")
        #print("Test ended. Current time: " + t2)
        for s in res:
            out.append(s + "\n")
        p += 0.1

    with open("t2_scheme_stress_test_result.txt", "w") as f:
        for s in out:
            f.write(s)
