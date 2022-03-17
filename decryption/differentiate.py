"""
A module to differentiate between dict_1 and dict_2
"""
import dictionary
import preprocess
import encrypt


def differentiate(ciphertext):
    """
    returns 1 or 2 depending on dict attack
    """
    plaintexts = dictionary.get_dictionary_1()
    last_char_and_first_idx = [(text[-1], text.find(text[-1])) for text in plaintexts]
    plaintext_front_chars = [ plaintexts[i][:idx] for i, (_, idx) in enumerate(last_char_and_first_idx)]

    p_hat = preprocess.p_estimate(ciphertext)
    print(last_char_and_first_idx)
    print(plaintext_front_chars)


def main():
    print(f"In main")

    test_text = dictionary.get_dictionary_1()

    differentiate(test_text[0])


if __name__ == "__main__":
    main()
