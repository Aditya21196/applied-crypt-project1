'''
A module to encrypt messages
'''
import random
import numpy as np

# GLOBALS
ALPHABET = " abcdefghijklmnopqrstuvwxyz"
ALPHABET_SIZE = len(ALPHABET)
LETTER_POS_DICT = {char: i for i, char in enumerate(ALPHABET)}
PROBABILITY_REPLACEMENT = 0
BLANK_KEY = [i for i in range(ALPHABET_SIZE) ]

TEST_M = "tumble cooked twirled absinths ceca cheatery raters redeploy niacinamide offeree preventively tangibleness beamy oligarchical microbus intends galvanize indelible tubings overcools rollover maladroit logways frilling skinks affirmatively flatfoots oversleeps consignors completes espadrille booms repaved ofays keens dinosaurs rerouted consignments victimless psychophysical chuckle admissibility muleteer deescalating ovary bowwow assisi fore tubbiest vocatively filially preestablish lacquerers spr"

TEST_BLANKS = "w" * 500

def generate_key_mapping(seed = None):
    """
    Generates Key Mappings
    Input: an optional argument for a random generator seed
    Output: a purmuted list of integers in the range 0 to ALPHABET_SIZE (inclusive)
    """
    np.random.seed(seed)
    k_mapping = [i for i, _ in enumerate(ALPHABET)]
    np.random.shuffle(k_mapping)
    return k_mapping

def char_key_mapping_from_key_mapping(key_mapping):
    char_key_mapping = dict()

    for i,k_val in enumerate(key_mapping):
        char_key_mapping[ALPHABET[i]] = ALPHABET[k_val]

    return char_key_mapping


def encrypt(user_message, user_key, probability = PROBABILITY_REPLACEMENT, seed = None):
    """
    Takes in a user message, user key, and optionaly a probability value (0, 1]
    Outputs Ciphertext based on the encryption algorithm for Project 1
    """
    random.seed(seed)
    c_text = []
    message_ptr = 0
    num_rand_chars = 0

    while message_ptr < len(user_message):
        coin_value = random.random() # always less than 1
        if probability < coin_value:
            char = user_message[message_ptr]
            encrypted_char = ALPHABET[ user_key [ LETTER_POS_DICT[char]]]
            c_text.append(encrypted_char)
            message_ptr += 1
        else:  # add a random char
            rand_char = ALPHABET[random.randint(0, ALPHABET_SIZE - 1)] # randint is inclusive (a, b)
            c_text.append(rand_char)
            num_rand_chars += 1

    return "".join(c_text)


def main():
    """
    Main - runs if executed from cli
    """
    # get message
    message = TEST_M
    #message = TEST_BLANKS

    # generate keys
    key = generate_key_mapping()

    # encrypt message using keys, num_rand_chars, prop_random_ciphertext
    ciphertext = encrypt(message, key)

    # return message
    print("Ciphertext:\n")
    print(f"'{ciphertext}'")
    print("\nDone Encrypting")
    print(f"Key: {key}")

    # print stats
    print("\nStats:")
    print(f"lenght of ciphertext: {len(ciphertext)} chars")
    print(f"Probability of replacement: {PROBABILITY_REPLACEMENT}")
    print("\nkey \n(plain -> cipher)")
    for i, char in enumerate(ALPHABET):
        print(f"{char} : {ALPHABET[key[i]]}")

    print("\n\nFinished\n")



if __name__ == "__main__":
    main()
