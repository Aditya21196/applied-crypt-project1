"""
Module to test dictionary 2 attacks

"""
DEBUG = False

from pydoc import plain
import random
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
    returns a 500 character plaintext
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


def find_plaintext(words, ciphertext):
    space = decrypt.get_space_key_value(ciphertext)

    duplicate_spaces_removed = preprocess.remove_double_duplicate(space, ciphertext)
    cipher_words = duplicate_spaces_removed.split(space)

    if DEBUG:
        print(f"DEBUG - space: '{space}'")
        print(f"Length of cipherwords {len(cipher_words)}")
        print(f"cipher_words{cipher_words}")

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
                print()
            current_word = find_word(words, current_cipher_word)
            if len(current_word) != 0:
                plaintext.append(current_word)
                cipher_word_idx = i - 1
                break
            i += 1
        cipher_word_idx += 1

    return plaintext



def main():
    dict2 = load_dictionary()
    seed = 500

    # Generate Test Data
    plaintext = make_a_dict_2_plaintext(dict2, seed)
    print(f"dict plaintext with seed({seed}):\n{plaintext}\n")

    # Encrypt Test Data
    ciphertext = encrypt.encrypt(plaintext, encrypt.BLANK_KEY, .30, seed)
    #print(f"ciphertext with seed({seed}) of length {len(ciphertext)}:\n{ciphertext}\n")

    # Try to Generate Plaintext
    cleaned_ciphertext = preprocess.remove_duplicate_char_triplets(ciphertext)
    print(f"cleaned ciphertext length {len(cleaned_ciphertext)}:\n{cleaned_ciphertext}\n")

    plaintext_guess = find_plaintext(dict2, cleaned_ciphertext)
    print(f"plaintext guess length {len(plaintext_guess)}: \n{plaintext_guess}")


    #print(is_word_in_ciphertext("moponwsetk","moponwsetk"))

if __name__ == "__main__":
    main()
