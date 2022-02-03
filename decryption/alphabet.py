"""
The module for storing the alphabet
"""

# *** Define any change to the alphabet here ***
_ALPHABET = " abcdefghijklmnopqrstuvwxyz"  # the leading space should be there
_ALPHABET_SIZE = len(_ALPHABET)
_LETTER_POS_DICT = {char: i for i, char in enumerate(_ALPHABET)}

def get_alphabet():
    """
    returns a string of all alphabet chars
    """
    return _ALPHABET


def get_alphabet_size():
    """
    get the size of the alphabet
    returns an int
    """
    return _ALPHABET_SIZE


def get_alphabet_char_to_int_dict():
    """
    Returns a dictionary
    Keys : a char from the alphabet
    Values : the index position of the char in the alphabet
    """
    return _LETTER_POS_DICT


def main():
    """
    Default main when called from CLI
    """
    # Prints out some info if called from the command line
    print(f"The alphabet is: \'{get_alphabet()}\'")
    print(f"\nIt contains {get_alphabet_size()} characters.")
    letter_map = get_alphabet_char_to_int_dict()
    print("\nThe char to index position mappings are:")
    for entry in letter_map:
        print(f"{entry} : {letter_map[entry]}")

if __name__ == "__main__":
    main()
