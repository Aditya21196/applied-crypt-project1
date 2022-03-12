import sys
sys.path.insert(0, "../encryption")
sys.path.insert(0, "../dictionaries")

import encrypt, alphabet, random, accuracy, frequency, decrypt
from test2_generate_plaintext import get_plaintext

with open("../dictionaries/official_dictionary_1_cleaned.txt", "r") as f:
    PLAIN_TEXTS = [line.rstrip() for line in f]
    
with open("../dictionaries/official_dictionary_2_cleaned.txt", "r") as f:
    dictionary = [line.rstrip() for line in f]
    
min_len = min(len(w) for w in dictionary)
len_sum = sum(len(w) for w in dictionary)
print("The minimum length of a word in the dictionary is: " + 
      str(min_len) + " characters")
print("The total number of characters in the dictionary is: " + str(len_sum))

ALPHABET = alphabet.get_alphabet()
KEY = encrypt.generate_key_mapping()
# The first element in KEY is the substitution for the space character

TEST_PROB = 0.1
# The constant that stores the probability of a random character

t2 = encrypt.encrypt(get_plaintext(), KEY, TEST_PROB)
print("The length of the Test 2 plaintext is: " + str(len(t2)) + " characters")

space_c = decrypt.get_space_key_value(t2)
print("The space key returned by the algorithm is: " + space_c)
print("The correct space key is: " + ALPHABET[KEY[0]])

words = sorted(t2.split(space_c), key=lambda x: len(x), reverse=True)

print(words)
print(len(words))


def split_t2_ciphertext(cipher, dictionary):
    space_c = decrypt.get_space_key_value(t2)
    print("The space key returned by the algorithm is: " + space_c)
    print("The correct space key is: " + ALPHABET[KEY[0]])
    
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

words_2 = split_t2_ciphertext(t2, dictionary)
print(words_2)
print(len(words_2))