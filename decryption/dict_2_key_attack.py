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
    if len(current) > 0:
        by_length.append(current)
    length_dict = {len(w[0][0]):w for w in by_length}

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


def build_mapping_from_cipher_words(cipher_words, space):
    """
    builds a key mapping by compairing dict letter frequencies
    """
    key = [-1 for i in range(alphabet.get_size())]
    key[0] = alphabet.get_int_from_char(space)

    unknown_chars = set(alphabet.get_alphabet())
    unknown_chars.remove(" ")

    for entry in _dict_2_missing:
        unknown_chars.remove(entry)

    dict_words = preprocess_dictionary_2()

    for word in cipher_words:
        possible_plaintext_words = get_dict_2_word_options(word, dict_words)
        print(f"{word} -> {possible_plaintext_words}")



    #print(f"cipher_words {cipher_words}\n")
    #print(f"dict_words {dict_words}\n")
    #print(f"key {key}\n")
    #print(f"unknown chars {unknown_chars}")


def get_dict_2_word_options(a_word, dict_words):
    """
    returns all the possible options the word could be
    """
    word_len = len(a_word)
    num_unique = num_unique_chars(a_word)
    possible_words = []
    if word_len in dict_words:
        for entry in dict_words[word_len]:
            if entry[1] == num_unique:
                possible_words.append(entry[0])
    return possible_words




'''
def partial_decrypt(ciphertext, key):
    """
    Map the ciphertext to plaintext using the key
    """
    inverted_key = build_partial_inverted_key(key)
    print(f"inverted_key {inverted_key}")
    plaintext = ""
    for char in ciphertext:
        print(f"char: {char}")
        plaintext += inverted_key[char]
    return plaintext


def build_partial_inverted_key(key):
    """
    k, v    k is ciphercharacter
            v is plaintext character
            if [] is -1, return *
    """
    key_map = {}
    for i, entry in enumerate(key):
        if entry == -1:
            char = "*"
        else:
            char = alphabet.get_char_from_int(entry)
        key_map[alphabet.get_char_from_int(i)] = char
    return key_map
'''



def dict_2_attack_v2(ciphertext):
    cleaned_ciphertext = preprocess.remove_duplicate_char_triplets(ciphertext)
    space = decrypt.get_space_key_value(cleaned_ciphertext)
    print(f"space {space}")
    cleaned_ciphertext = preprocess.remove_double_duplicate(space, cleaned_ciphertext)
    print(f"cleaned_ciphertext {len(cleaned_ciphertext)}\n'{cleaned_ciphertext}'")

    cipher_words = frequency.get_words(cleaned_ciphertext, delimiter = space)
    text_guess = build_mapping_from_cipher_words(cipher_words, space)

    #print(cipher_words)


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
