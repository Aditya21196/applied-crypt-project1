"""
Module to test dictionary 2 attacks

"""
import random
import preprocess
import encrypt
import alphabet

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


def examine_word(cipherword):
    """
    takes a possible cipherword
    returns a list of possible values or -1 if none found
    """


def main():
    dict2 = load_dictionary()
    seed = 500

    # Generate Test Data
    plaintext = make_a_dict_2_plaintext(dict2, seed)
    print(plaintext)

    # Encrypt Test Data
    ciphertext = encrypt.encrypt(plaintext, encrypt.BLANK_KEY, .2, seed)
    print(ciphertext)

    # Try to Generate Plaintext


if __name__ == "__main__":
    main()
