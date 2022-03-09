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
    returns a list of possible values or -1 if none found
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



def process_candidate_components(dictionary, component_list):

    num_candidate_options = [len(entry) for entry in component_list]
    num_of_potential_candidates = math.prod(num_candidate_options)
    if DEBUG:
        print(f"num_candidate_options {num_candidate_options}")
        print(f"num_of_potential_candidates {num_of_potential_candidates}")
    candidates = []

    for i in range(num_of_potential_candidates):
        current_candidate = ""
        current_key = get_permutation_mapping(0, num_candidate_options)
        print(f"current_key {current_key}")
        for i, (key, entry) in enumerate(zip(current_key, component_list)):
            if i > 0:
                current_candidate += " "
            current_candidate += entry[key]
        if len(current_candidate) > 500:
            continue
        elif len(current_candidate) == 500:
            candidates.append(current_candidate)
        else:   # text < 500
            chars_to_add = 500 - len(current_candidate)
            current_candidate += pad_ending(chars_to_add, dictionary, component_list)
            if current_candidate == 500:
                candidates.append(current_candidate)

    return candidates



def pad_ending(num_chars, dictionary, component_list):
    padded = " "

    truncated_dict = [el[:num_chars] for el in dictionary if el[num_chars - 1] == ciphertext[-1]]
            j = len(cipher_words) - 1
            last_word = get_possible_word_list(truncated_dict, cipher_words[j])
            while len(last_word[0]) == 0:
                j -= 1
                last_word = get_possible_word_list(truncated_dict, cipher_words[j])

            if DEBUG:
                print(f"last_words {last_word}")
                print(f"truncated dict: {truncated_dict}")
                print(f"j word: {cipher_words[j:]}")

            return_string += last_word[0][random.randint(0,len(last_word[0])-1)]







def get_permutation_mapping(perm_num, key_array):
    """
    input:  perm_num, what permutation to return
            key_array, the key space
            num_of_permutations, the total number of permutations possible
    """
    current_key = [0 * len(key_array)]
    if DEBUG:
        print(f"perm number {perm_num}")
        print(f"key_array: {key_array}")

    # do some processing
    return current_key




def find_plaintext(words, ciphertext):
    """
    The main dict 2 searching algorithm to find the best 500 character plaintext
    Input:  words, the dictionary of words
            ciphertext, must have the correct key applied to it and only contain extra nulls

    Output: a 500 char string of only words from <words>
    """
    space = decrypt.get_space_key_value(ciphertext)

    duplicate_spaces_removed = preprocess.remove_double_duplicate(space, ciphertext)
    cipher_words = duplicate_spaces_removed.split(space)
    plaintext_pieces = get_possible_word_list(words, cipher_words)
    candidate_text_components = get_candidate_components(plaintext_pieces)
    candidate_texts = process_candidate_components(words, candidate_text_components)

    return candidate_texts

    if DEBUG:
        print(f"DEBUG - space: '{space}'")
        print(f"Length of cipherwords {len(cipher_words)}")
        print(f"cipher_words{cipher_words}")


    plaintext_word_option_counts = [len(el) for el in plaintext]

    if DEBUG:
        print(f"plaintext {plaintext}")
        print(f"plaintext word option counts {plaintext_word_option_counts}")

    return_string = ""


    if max(plaintext_word_option_counts) == 1:
        if DEBUG:
            print("here - all one")

        return_string = combine_words(plaintext[0:20])

    else:  #multiple possibilities
        if DEBUG:
            print("here - some multiples")
        # find the best fit up to 500 chars
        single_option_char_count = 0

        for i, (option_cnt, words) in enumerate(zip(plaintext_word_option_counts, plaintext)):
            if DEBUG:
                print(f"i: {i} opt_cnt {option_cnt}, words {words}")
            if option_cnt == 1:
                pass

        if DEBUG:
            print(f"single_option_char_count {single_option_char_count}")


    # make sure text is 500 chars long
    """
    return_string_length = len(return_string)
    if return_string_length < 500:
            return_string += " "
            chars_to_fill = 500 - return_string_length - 1 # the plus one is the added space

            truncated_dict = [el[:chars_to_fill] for el in words if el[chars_to_fill - 1] == ciphertext[-1]]
            j = len(cipher_words) - 1
            last_word = get_possible_word_list(truncated_dict, cipher_words[j])
            while len(last_word[0]) == 0:
                j -= 1
                last_word = get_possible_word_list(truncated_dict, cipher_words[j])

            if DEBUG:
                print(f"last_words {last_word}")
                print(f"truncated dict: {truncated_dict}")
                print(f"j word: {cipher_words[j:]}")

            return_string += last_word[0][random.randint(0,len(last_word[0])-1)]
    """
    return candidate_texts




def main():
    dict2 = load_dictionary()
    seed = 150

    t_array = [[]]

    print(len(t_array[0]))

    # Generate Test Data
    plaintext = make_a_dict_2_plaintext(dict2, seed)
    print(f"dict plaintext with seed({seed}):\n{plaintext}\n")

    # Encrypt Test Data
    ciphertext = encrypt.encrypt(plaintext, encrypt.BLANK_KEY, .2, seed)
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
