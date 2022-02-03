"""
The module for storing the alphabet
"""

# *** Define any change to the alphabet here ***
_ALPHABET = " abcdefghijklmnopqrstuvwxyz"  # the leading space should be there
_ALPHABET_SIZE = len(_ALPHABET)


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


def main():
    """
    Default main when called from CLI
    """
    print(f"The alphabet is {get_alphabet()}")
    print(f"The size of the alphabet is: {get_alphabet_size()}")

if __name__ == "__main__":
    main()
