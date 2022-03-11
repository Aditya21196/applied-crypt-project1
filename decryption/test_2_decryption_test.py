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
import frequency_analysis
import collections


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
    if DEBUG:
        print(f"in get_possible_word_list")
        print(f"words_list\n{words_list}")
        print(f"cipher_words len: {len(cipher_words)}\n{cipher_words}")
    plaintext = []
    cipher_word_idx = 0

    while cipher_word_idx != len(cipher_words):
        i = cipher_word_idx + 1
        while i != len(cipher_words) + 1:
            current_cipher_word = "".join(cipher_words[cipher_word_idx:i])

            if DEBUG:
                print(f"cipher_word_idx {cipher_word_idx}")
                print(f"i {i}")
                print(f"current_cipher_word {current_cipher_word}")
                #print(f"plaintext {plaintext}")
                #print()
                pass

            current_word = find_word(words_list, current_cipher_word)
            if len(current_word) != 0:
                if DEBUG:
                    print(f"Current_word_found -> {current_word}\n")
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
            print(f"candidates {candidates}")
            print(f"current_string {current_string}")
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
    elif len(current_string) > 0:
        candidates.append([current_string])
    return candidates

def gen_all_permutation_keys(key_space):
    """
    Input, an array of integers representing how many options for each position
    Output, all possible combinations of integers
    """
    candidates = []
    if len(key_space) == 1:  # base case
        for i in range(key_space[0]):
            candidates.append([i])
    else:
        suffix = gen_all_permutation_keys(key_space[1:])
        for i in range(key_space[0]):
            for entry in suffix:
                permutation = [i] + entry
                candidates.append(permutation)
    return candidates



def process_candidate_components(dictionary, component_list, ciphertext_words):

    num_candidate_options = [len(entry) for entry in component_list]
    candidate_lengths = []
    for entry in component_list:
        if isinstance(entry, str):
            candidate_lengths.append(len(entry))
        else:
            min = len(entry[0])
            for sub_entry in entry:
                if len(sub_entry) < min:
                    min = len(sub_entry)
            candidate_lengths.append(min)

    shortest_possible = sum(candidate_lengths) + len(candidate_lengths) - 1


    if DEBUG:
        print(f"num_candidate_options {num_candidate_options}")
        print(f"min_candidate_lengths {candidate_lengths}")
        print(f"Total key space = {math.prod(num_candidate_options)}")
        print(f"shortest_possible {shortest_possible}")

    #print("key gen_all_permutations started")
    all_keys = gen_all_permutation_keys(num_candidate_options)  # fix to be a generator
    #print("key gen_all_permutations finished")

    if DEBUG:
        print(f"num_candidate_options {num_candidate_options}")
        print(f"all keys \n{all_keys}")

    for i, current_key in enumerate(all_keys):
        current_candidate = ""

        if DEBUG:
            print(f"line 157 - current_key {current_key}")

        for i, (key, entry) in enumerate(zip(current_key, component_list)):
            if i > 0:
                current_candidate += " "
            current_candidate += entry[key]
        if len(current_candidate) > 500:
            continue
        elif len(current_candidate) == 500:
            return current_candidate
        else:   # text < 500
            chars_to_add = 500 - len(current_candidate)
            if DEBUG:
                print(f" -- Before pad_ending")
            padding = pad_ending(chars_to_add, dictionary, ciphertext_words)
            if DEBUG:
                print(f" -- After pad ending- padding {padding}")
            current_candidate += padding
            if len(current_candidate) == 500:
                return current_candidate




def key_saturated(n, current_vals, max_vals):
    for i, (cur, max) in enumerate(zip(current_vals, max_vals)):
        if cur + 1 != max:
            return False
    return True


def pad_ending(num_chars, dictionary, cipher_words):
    """
    input   num_chars -> number needed for padding
            dictionary -> words to find
            cipher_words -> words to match

    Output  a valid padding string if one is found
    """
    last_char = cipher_words[-1][-1]
    padded = " " #keep as an empty space
    dict_word_len = num_chars - 1

    if DEBUG:
        print(f"pad_ending cipher words\n{cipher_words}")
        print(f"dictionary\n{dictionary}")
        print(f"last_char {last_char}")
        print(f"num_chars {num_chars}")
        print(f"truncated dict_word_len {dict_word_len}")

    truncated_dict = [word[:dict_word_len] for word in dictionary if len(word) >= dict_word_len and word[dict_word_len-1] == last_char]
    if len(truncated_dict) == 0:
        return padded

    if DEBUG:
        print(f"truncated_dict {truncated_dict}")
        print(f"last_char {last_char}")
        print(f"num_chars {num_chars}")

    j = len(cipher_words) - 1
    last_word = get_possible_word_list(truncated_dict, cipher_words[j])

    if DEBUG:
        print(f" 225last_words {last_word}")


    while len(last_word) == 0: #and j > len(cipher_words) - 10:
        # TODO -> What is the best value for the second conditional
        #  It says that only look at the last 1/8 of the ciphertext for the padding

        j -= 1
        last_word = get_possible_word_list(truncated_dict, cipher_words[j:])

    if DEBUG:
        print(f"last_words {last_word}")
        print(f"truncated dict: {truncated_dict}")
        print(f"j word: {cipher_words[j:]}")

    if len(last_word) == 0:
        return padded

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
    if DEBUG:
        print(f"Space char is '{space}'")
        print(f"Duplicate spaces removed \n{duplicate_spaces_removed}")
    cipher_words = duplicate_spaces_removed.split(space)
    cipher_words = [entry for entry in cipher_words if len(entry) > 0]
    plaintext_pieces = get_possible_word_list(words, cipher_words)
    candidate_text_components = get_candidate_components(plaintext_pieces)
    if DEBUG:
        print(f"\ncandidate_text_components \n{candidate_text_components}\n")
    solution = process_candidate_components(words, candidate_text_components, cipher_words)

    print(f"\nspace char '{space}'")

    #todo
        # if solution totally fails it returns none
        # make a do while loop
        # if solution fails, move on to next possible space value and recompute

    return solution


def stress_test(low_p, high_p, step, num_repeats, dict):
    seed = 0
    for p in range(low_p, high_p, step):
        prob = p / 100
        for j in range(num_repeats):
            print(f"\n\nCurrent Iteration p {p} j {j} seed {seed}")
            plaintext = make_a_dict_2_plaintext(dict, seed)
            ciphertext = encrypt.encrypt(plaintext, encrypt.BLANK_KEY, prob, seed)
            cleaned_ciphertext = preprocess.remove_duplicate_char_triplets(ciphertext)
            plaintext_guess = find_plaintext(dict, cleaned_ciphertext)
            print(f"Plaintext\n{plaintext}\n")
            print(f"plaintext_guess\n{plaintext_guess}\n")

            try:
                assert len(plaintext_guess) == 500
            except AssertionError as e:
                print(f" *** AssertionError - error caused with p {p} j {j} seed {seed}")
                raise e
            except TypeError as e:
                print(f" *** Type error wile at caused with p {p} j{j} seed {seed}")
            seed += 1


def generate_test_char_frequencies(dict, test_size, hash_length):
    """
    returns  frequencies -> a list of (key, frequency) pairs
            letter_count -> char counts
    """
    seed = 0
    frequency_counts = {}
    letter_count = collections.Counter()
    for i in range(test_size):
        text = make_a_dict_2_plaintext(dict, seed)
        fq = frequency_analysis.rank_letters_by_freq(text)
        fq_full_hash = generate_hash_key(fq)
        fq_hash = fq_full_hash[:hash_length]
        letter_count.update(fq_hash)
        if fq_hash not in frequency_counts:
            frequency_counts[fq_hash] = 1
        else:
            frequency_counts[fq_hash] += 1
        seed += 1

    frequencies = [(k, v) for k,v in frequency_counts.items()]
    frequencies.sort(key = lambda x: x[1], reverse=True)
    return frequencies, letter_count


def generate_hash_key(a_frequency):
    """
    input -> a frequency from rank_letters_by_frequency
    output -> a string that can be used as a hash map key
    """
    key = ""
    for (char, _) in a_frequency:
        key += char
    return key



def frequency_test(test_size, hash_length_in):
    dict2 = load_dictionary()
    test, counts = generate_test_char_frequencies(dict = dict2, test_size = test_size, hash_length = hash_length_in)


    #report Statistics
    print(f"Test Size {test_size}")
    print(f"First {hash_length_in} most significant chars")

    print(f"Total unique keys: {len(test)}")
    print(f"Char Counts: {counts}\n")

    print("All test Keys:")
    for entry in test:
        print(entry)



def main():

    #stress_test(low_p = 70,high_p = 76, step = 1, num_repeats = 10, dict = dict2)

    frequency_test(test_size=250000, hash_length_in=6)



    #for entry in test:
     #   if test[entry] > 1:
      #      print(f"{entry} : count {test[entry]}")

    """


    # Generate Test Data
    plaintext = make_a_dict_2_plaintext(dict2, seed)
    print(f"dict plaintext with seed({seed}):\n{plaintext}\n")

    # Encrypt Test Data
    ciphertext = encrypt.encrypt(plaintext, encrypt.BLANK_KEY, .73, seed)
    print(f"ciphertext with seed({seed}) of length {len(ciphertext)}:\n{ciphertext}\n")

    # Try to Generate Plaintext
    cleaned_ciphertext = preprocess.remove_duplicate_char_triplets(ciphertext)
    #print(f"cleaned ciphertext length {len(cleaned_ciphertext)}:\n{cleaned_ciphertext}\n")

    plaintext_guess = find_plaintext(dict2, cleaned_ciphertext)
    print(f"plaintext guess length {len(plaintext_guess)}: \n{plaintext_guess}")

    #for entry in plaintext_guess:
        #print(entry)
        #print()


    #print(is_word_in_ciphertext("moponwsetk","moponwsetk"))

    """

if __name__ == "__main__":
    main()
