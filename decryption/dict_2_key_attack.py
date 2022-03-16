"""
Dict 2 key attack
"""
DEBUG = False

import alphabet
import dictionary
import frequency
import permutation
import preprocess
import encrypt
import decrypt
import random


_dict_2_char_frequency_mapping_million = [' ', 'e', 'r', 'a', 's', 'l', 'i', 't', 'o', 'n', 'c', 'u', 'g', 'f', 'd', 'p', 'b', 'k', 'h', 'y', 'v', 'z', 'w', 'm', 'j', 'q', 'x']

_dict_2_missing = ['x', 'q', 'j']


def preprocess_dictionary_2():
    """
    prepprocess dict 2 for the attack
    returns a dict (k:v) where the key is word length
                value is a list of (words, unique_chars) tuple
    """
    words = dictionary.get_dictionary_2()
    words.sort(key = lambda x: len(x))
    by_length = []
    current_length = len(words[0])
    current = []
    for i, w in enumerate(words):
        if len(w) == current_length:
            current.append((w, num_unique_chars(w)))
        else:
            by_length.append(current)
            current = []
            current_length = len(w)
            current.append((w, num_unique_chars(w)))

    length_dict = {len(w[0][0]):w for w in by_length}


    print(by_length)
    return length_dict


def num_unique_chars(a_word):
    """
    returns how many unique chars are in a word
    """
    return len(set(a_word))


def make_key_mapping(space, sample_freq, population_freq):
    """
    Makes best initial key mapping
    """
    chars_to_pick = set(alphabet.get_alphabet())
    candidate_key = [0 for i in range(alphabet.get_size())]

    #set space val
    candidate_key[alphabet.get_int_from_char(" ")] = alphabet.get_int_from_char(space)
    chars_to_pick.remove(space)

    # remove space from sample and population_freq
    sample_freq.remove(space)
    population_freq = population_freq[1:]

    for s, p in zip(sample_freq, population_freq):
        candidate_key[alphabet.get_int_from_char(p)] = alphabet.get_int_from_char(s)
        chars_to_pick.remove(s)

    for s,p in zip(list(chars_to_pick), _dict_2_missing):
        candidate_key[alphabet.get_int_from_char(p)] = alphabet.get_int_from_char(s)
        chars_to_pick.remove(s)

    return candidate_key


def swap_random_pair(key):
    """
    Swaps a random pair in the key -> never the space key
    note: randint is inclusive so only go to 26
    """
    pos1 = random.randint(1, 26)
    pos2 = random.randint(1, 26)
    while pos2 == pos1:
        pos2 = random.randint(1, 26)
    key[pos1], key[pos2] = key[pos2], key[pos1]
    return key


def dict_2_attack_v1(ciphertext):
    cleaned_ciphertext = preprocess.remove_duplicate_char_triplets(ciphertext)
    space = decrypt.get_space_key_value(cleaned_ciphertext)
    cleaned_ciphertext = preprocess.remove_double_duplicate(space, cleaned_ciphertext)

    if DEBUG:
        print(f"space is '{space}'")
    chars = frequency.get_ordered_list_of_char_frequencies(cleaned_ciphertext)
    if DEBUG:
        print(f"Char Text Frequency {chars}")

    key_guess = make_key_mapping(space, chars, _dict_2_char_frequency_mapping_million)
    if DEBUG:
        print(f"key_guess {key_guess}")

    count = 0
    while True and count < 10000:
        key_guess = swap_random_pair(key_guess)
        print(key_guess)
        print(decrypt.decrypt(cleaned_ciphertext, key_guess))
        print()
        count+= 1


    return decrypt.decrypt(cleaned_ciphertext, key_guess)


def build_mapping_from_cipher_words(a_list):
    unknown_chars = set(alphabet.get_alphabet())
    unknown_chars.remove(" ")
    for entry in _dict_2_missing:
        unknown_chars.remove(entry)

    print(f"unknown chars {unknown_chars}")

    a_list.sort(key = lambda x: len(x))

    for entry in a_list:
        print(entry)

    dict_words = preprocess_dictionary_2()

    for k, v in dict_words.items():
        print(f"{k} : {v}")







def dict_2_attack_v2(ciphertext):
    cleaned_ciphertext = preprocess.remove_duplicate_char_triplets(ciphertext)
    space = decrypt.get_space_key_value(cleaned_ciphertext)
    print(f"space {space}")
    cleaned_ciphertext = preprocess.remove_double_duplicate(space, cleaned_ciphertext)
    print(f"cleaned_ciphertext {len(cleaned_ciphertext)}\n'{cleaned_ciphertext}'")

    cipher_words = frequency.get_words(cleaned_ciphertext, delimiter = space)
    key_guess = build_mapping_from_cipher_words(cipher_words)

    print(cipher_words)


    #return decrypt.decrypt(cleaned_ciphertext, key_guess)


def main():
    #print(preprocess_dictionary_2())


    plaintext = dictionary.make_random_dictionary_2_plaintext()
    print(f"plaintext {len(plaintext)} chars \n'{plaintext}'\n")

    key = encrypt.generate_key_mapping()
    print(f"key: {key}")

    ciphertext = encrypt.encrypt(plaintext, key, probability=0)
    print(f"ciphertext: \n'{ciphertext}'\n")

    print(dict_2_attack_v2(ciphertext))


if __name__ == "__main__":
    main()
