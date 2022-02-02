'''
A module to encrypt messages
'''
import numpy as np

ALPHABET = " abcdefghijklmnopqrstuvwxyz"
ALPHABET_SIZE = len(ALPHABET)
LETTER_POS_DICT = {char: i for i, char in enumerate(ALPHABET)}


def generate_key_mapping(seed = 0):
    """
    Generates a list of integers
    """
    np.random.seed(seed)
    k_mapping = [i for i, _ in enumerate(ALPHABET)]
    np.random.shuffle(k_mapping)

    return k_mapping



def main():
    key = generate_key_mapping()
    print(f"key {key}")
    print(f"Letter Pos Dict {LETTER_POS_DICT}")

if __name__ == "__main__":
    main()
