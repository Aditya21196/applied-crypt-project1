"""
The module for storing the alphabet
"""

# *** Define any change to the alphabet here ***
_ALPHABET = " abcdefghijklmnopqrstuvwxyz"  # the leading space should be there
_ALPHABET_SIZE = len(_ALPHABET)
_LETTER_TO_POS_DICT = {char: i for i, char in enumerate(_ALPHABET)}


def get_alphabet():
    """
    returns a string of all alphabet chars
    """
    return _ALPHABET


def get_size():
    """
    get the size of the alphabet
    returns an int
    """
    return _ALPHABET_SIZE


def get_int_from_char(a_char):
    """
    input: a single char
    output: an int between 0 and the size of the alphabet
    """
    if not isinstance(a_char, str):
        raise TypeError(f"Please pass a lower case char, you passed a {type(a_char)}")
    if len(a_char) != 1:
        raise ValueError(f"Please pass a single character, you passed {len(a_char)} chars")
    return _LETTER_TO_POS_DICT[a_char]


def get_char_from_int(a_int):
    """
    input: an int in the range (0, _ALPHABET_SIZE - 1)
    output: the character from the alphabet at position <a_int>

    """
    if not isinstance(a_int, int):
        raise TypeError(f"Please pass an int, you passed a {type(a_int)}")
    if a_int < 0 or a_int >= _ALPHABET_SIZE:
        raise ValueError(f"Int out of range. It should be in the range \
                            (0, {_ALPHABET_SIZE - 1})  You passed: {a_int}")
    return _ALPHABET[a_int]


def main():
    """
    Default main when called from CLI
    """
    # Prints out some info if called from the command line
    print(f"The alphabet is: \'{get_alphabet()}\'")
    print(f"It contains {get_size()} characters.")

    # test for errors
    assert get_int_from_char("a") == 1
    assert get_char_from_int(22) == "v"
    assert get_size() == 27
    assert get_alphabet() == " abcdefghijklmnopqrstuvwxyz"


if __name__ == "__main__":
    main()
