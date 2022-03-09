"""
Module to test dictionary 2 attacks

"""
DEBUG = True

from pydoc import plain
import random
import math
from tracemalloc import start
import preprocess
import encrypt
import decrypt


#setup
def load_dictionary():
    return preprocess.read_all_lines("../dictionaries/official_dictionary_2_cleaned.txt")


def make_a_dict_2_plaintext(words, seed = None):
    """
    takes a list of dictionary words
    returns a randomly generated 500 character plaintext
    """
    random.seed(seed)
    word_count = len(words)
    message = ""

    while len(message) < 500:
        if len(message) != 0:
            message += " "
        choice = random.randint(0, word_count-1)
        message += words[choice]

    return message[:500]


def find_word(words, cipherword):
    """
    takes a possible cipherword
    returns a list of possible values or [] if none found
    """
    candidates = []
    for word in words:
        if is_word_in_ciphertext(word, cipherword):
            candidates.append(word)
    return candidates


def is_word_in_ciphertext(word, text):
    """
    Returns a boolean if the word can be found in the text
    """
    w_pointer = 0

    for char in text:
        if w_pointer == len(word):
            break
        if word[w_pointer] == char:
            w_pointer += 1

    return w_pointer == len(word)


def get_possible_word_list(words_list, cipher_words):
    """"
    input:  words_list, a list of words from the dictionary we are comparing agains
            cipher_words, the list of cipher words we want to check

    output: a list of possible dictionary words that are in the cipherwords
            returns an empyt list if none found
    """
    plaintext = []
    cipher_word_idx = 0

    while cipher_word_idx != len(cipher_words):
        i = cipher_word_idx + 1
        while i != len(cipher_words) + 1:
            current_cipher_word = "".join(cipher_words[cipher_word_idx:i])

            if DEBUG:
                #print(f"cipher_word_idx {cipher_word_idx}")
                #print(f"i {i}")
                #print(f"current_cipher_word {current_cipher_word}")
                #print(f"plaintext {plaintext}")
                #print()
                pass

            current_word = find_word(words_list, current_cipher_word)
            if len(current_word) != 0:
                plaintext.append(current_word)
                cipher_word_idx = i - 1
                break
            i += 1
        cipher_word_idx += 1
    return plaintext


def combine_words(word_list, delimiter = " "):
    """
    input a list of words and a desired delimiter
    output a string with delimiter added between each word
    """
    combined = ""
    for i, entry in enumerate(word_list):
            if i > 0:
                combined += delimiter
            combined += "".join(entry)
    return combined


def get_candidate_components(plaintext_options):
    """
    returns all 500 char candidates
    """
    candidates = []
    current_string = ""
    first_word_in_string = True
    for entry in plaintext_options:
        if DEBUG:
            #print(f"candidates {candidates}")
            #print(f"current_string {current_string}")
            pass
        if len(entry) == 1:
            if not first_word_in_string:
                current_string += " "
            current_string += entry[0]
            if first_word_in_string == True:
                first_word_in_string = False
        else:
            if len(current_string) > 0:
                candidates.append([current_string])
                current_string = ""
            candidates.append(entry)
            first_word_in_string = True

    if len(candidates) == 0:
        candidates = [[current_string]]
    return candidates



def process_candidate_components(dictionary, component_list, ciphertext_words):
    #note modify to return only one text of 500 chars
    num_candidate_options = [len(entry) for entry in component_list]
    num_of_potential_candidates = math.prod(num_candidate_options)
    if DEBUG:
        print(f"num_candidate_options {num_candidate_options}")
        print(f"num_of_potential_candidates {num_of_potential_candidates}")

    current_key = [0 for i in enumerate(num_candidate_options)]
    for i in range(num_of_potential_candidates):
        current_candidate = ""

        if DEBUG:
            print(f"line 157 - current_key {current_key}")

        for i, (key, entry) in enumerate(zip(current_key, component_list)):
            if i > 0:
                current_candidate += " "
            current_candidate += entry[key]
        if len(current_candidate) > 500:
            current_key = get_next_key(current_key, num_candidate_options)
            continue
        elif len(current_candidate) == 500:
            return current_candidate
        else:   # text < 500
            chars_to_add = 500 - len(current_candidate)
            padding = pad_ending(chars_to_add, dictionary, ciphertext_words)
            current_candidate += padding
            if len(current_candidate) == 500:
                return current_candidate
            else:
                current_key = get_next_key(current_key, num_candidate_options)


def get_next_key(current_key, key_options):
    """
    input:  Takes in the current key
            a list of key options
    returns: the next permutation
    """
    if DEBUG:
        print(f"ln 185 - current_key {current_key}")
        print(f"ln 186 - key_options: {key_options}")

    # do some processing
    return current_key



def pad_ending(num_chars, dictionary, cipher_words):
    last_char = cipher_words[-1][-1]
    padded = " " #keep as an empty space
    dict_word_len = num_chars - 1

    truncated_dict = [word[:dict_word_len] for word in dictionary if len(word) >= dict_word_len and word[dict_word_len-1] == last_char]
    if DEBUG:
        print(f"truncated_dict {truncated_dict}")
        print(f"last_char {last_char}")
        print(f"num_chars {num_chars}")

    j = len(cipher_words) - 1
    last_word = get_possible_word_list(truncated_dict, cipher_words[j])

    if len(last_word) == 0:
        return padded

    while len(last_word[0]) == 0:
        j -= 1
        last_word = get_possible_word_list(truncated_dict, cipher_words[j])

    if DEBUG:
        print(f"last_words {last_word}")
        print(f"truncated dict: {truncated_dict}")
        print(f"j word: {cipher_words[j:]}")

    padded += last_word[0][random.randint(0,len(last_word[0])-1)]

    return padded



def find_plaintext(words, ciphertext):
    """
    Input:  words, the dictionary of words
            ciphertext, must have the correct key applied to it and only contain extra nulls

    Output: a 500 char plaintext of words from dict
    """
    space = decrypt.get_space_key_value(ciphertext)

    duplicate_spaces_removed = preprocess.remove_double_duplicate(space, ciphertext)
    cipher_words = duplicate_spaces_removed.split(space)
    plaintext_pieces = get_possible_word_list(words, cipher_words)
    candidate_text_components = get_candidate_components(plaintext_pieces)
    return process_candidate_components(words, candidate_text_components, cipher_words)




def main():
    dict2 = load_dictionary()
    seed = 150

    t_array = [[]]

    print(len(t_array[0]))

    # Generate Test Data
    plaintext = make_a_dict_2_plaintext(dict2, seed)
    print(f"dict plaintext with seed({seed}):\n{plaintext}\n")

    # Encrypt Test Data
    ciphertext = encrypt.encrypt(plaintext, encrypt.BLANK_KEY, .7, seed)
    #print(f"ciphertext with seed({seed}) of length {len(ciphertext)}:\n{ciphertext}\n")

    # Try to Generate Plaintext
    cleaned_ciphertext = preprocess.remove_duplicate_char_triplets(ciphertext)
    print(f"cleaned ciphertext length {len(cleaned_ciphertext)}:\n{cleaned_ciphertext}\n")

    plaintext_guess = find_plaintext(dict2, cleaned_ciphertext)
    print(f"plaintext guess length {len(plaintext_guess)}: \n{plaintext_guess}")

    #for entry in plaintext_guess:
        #print(entry)
        #print()


    #print(is_word_in_ciphertext("moponwsetk","moponwsetk"))

if __name__ == "__main__":
    main()
