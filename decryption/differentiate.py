"""
A module to differentiate between dict_1 and dict_2
"""
DEBUG = True

import dictionary
import preprocess
import encrypt


def differentiate(ciphertext):
    """
    returns 1 or 2 depending on dict attack
    ciphertext -> assume remove triple chars has already happened
    """
    p_hat = preprocess.p_estimate(ciphertext)

    if DEBUG:
        print(f"p_hat = {p_hat}")

    plaintexts = dictionary.get_dictionary_1()
    last_char_and_first_idx = [(text[-1], text.find(text[-1])) for text in plaintexts]
    plaintext_front_chars = [ plaintexts[i][:idx] for i, (_, idx) in enumerate(last_char_and_first_idx)]

    p_hat = preprocess.p_estimate(ciphertext)
    print(last_char_and_first_idx)
    print(plaintext_front_chars)


def test_differentiate():
    test_text = dictionary.get_dictionary_1()
    text = test_text[0]
    key = encrypt.generate_key_mapping()
    ciphertext = encrypt.encrypt(text, key, probability = .10)
    ciphertext_cleaned = preprocess.remove_duplicate_char_triplets(ciphertext)
    differentiate(ciphertext_cleaned)



def main():
    test_differentiate()





if __name__ == "__main__":
    main()
