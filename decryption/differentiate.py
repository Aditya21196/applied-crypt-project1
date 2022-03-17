"""
A module to differentiate between dict_1 and dict_2
"""
DEBUG = True

import dictionary
import preprocess
import encrypt
import decrypt


def differentiate(ciphertext):
    """
    returns 1 or 2 depending on dict attack
    ciphertext -> assume remove triple chars has already happened
    """
    p_hat = preprocess.p_estimate(ciphertext)
    alpha = len(ciphertext) / 500

    if DEBUG:
        print(f"p_hat = {p_hat}")
        print(f"alpha {alpha}")

    plaintexts = dictionary.get_dictionary_1()
    last_char_and_first_idx = [(text[-1], text.find(text[-1])) for text in plaintexts]
    plaintext_front_chars_and_unique_num = [(plaintexts[i][:idx], preprocess.num_unique_chars(plaintexts[i][:idx])) for i, (_, idx) in enumerate(last_char_and_first_idx)]
    plaintext_char_idx_positions = [preprocess.get_all_char_idx(text) for text in plaintexts]
    if DEBUG:
        print(last_char_and_first_idx)
        print(plaintext_front_chars_and_unique_num)

    ciphertext_last_char = ciphertext[-1]
    ciphertext_space_char = decrypt.get_space_key_value(ciphertext)
    ciphertext_front_chars = ciphertext[:ciphertext.find(ciphertext_last_char)] # will need to be fancified to accept p val
    c_front_chars_num_unique = preprocess.num_unique_chars(ciphertext_front_chars)
    ciphertext_char_position_idxs = preprocess.get_all_char_idx(ciphertext)

    if DEBUG:
        print(f"ciphertext_last_char: '{ciphertext_last_char}'")
        print(f"ciphertext space char: '{ciphertext_space_char}'")
        print(f"ciphertext_front_chars: '{ciphertext_front_chars}'")
        print(f"Number of unique chars in ciphertext_front_chars {c_front_chars_num_unique}")
        print(f"ciphertext char positions")
        for entry in ciphertext_char_position_idxs.items():
            print(entry)
        print()
        print(f"\nciphertext\n{ciphertext}\n")


    candidates = [i for i,_ in enumerate(plaintexts)]

    # remove plaintext candidates that have more unique chars than the ciphetext
    cand_itr = candidates[:]
    for idx in cand_itr:
        if plaintext_char_idx_positions[idx]["num_unique"] > ciphertext_char_position_idxs["num_unique"]:
            candidates.remove(idx)
            continue
        if len(plaintext_char_idx_positions[idx][" "]) > len(ciphertext_char_position_idxs[ciphertext_space_char]):
            candidates.remove(idx)
            continue
        if len(plaintext_char_idx_positions[idx][last_char_and_first_idx[idx][0]]) > len(ciphertext_char_position_idxs[ciphertext_last_char]):
            candidates.remove(idx)
            continue


    # remove plaintext candidates based on space, and last char positioning


    # remove plaintext candidates based on front chars



    # remove plaintext candidates that have more space characters than ciphertext



    # iterate through last_char, space_char, and front_chars to remove candidates


    # first space
    '''
    print(ciphertext_char_position_idxs[ciphertext_space_char])

    cand_itr = candidates[:]
    score = []
    for idx in cand_itr:
        candidate_space_pos = preprocess.scale_nums(plaintext_char_idx_positions[idx][" "], alpha)
        print(f"\nidx {idx} space_pos {candidate_space_pos}")
        print()
    '''



    if DEBUG:
        print(candidates)


def score(reference_list, candidate_list):
    """
    input: two lists of integers
    returns a score of how close the candidate matches the reference
    """


def test_score():
    pass



def test_differentiate():
    p = .10
    print(f"Differentiate Test using p = {p}")


    # test dict 1
    dict_1_texts = dictionary.get_dictionary_1()

    """
    for i,_ in enumerate(dict_1_texts):
        print(f"\n *** Dictionary 1 -> Text {i+1} *** \n")
        text = dict_1_texts[i]
        print(f"Dict 1 Plaintext\n'{text}'\n")
        key = encrypt.generate_key_mapping()
        ciphertext = encrypt.encrypt(text, key, probability = p)
        ciphertext_cleaned = preprocess.remove_duplicate_char_triplets(ciphertext)
        differentiate(ciphertext_cleaned)
        print()
    """

    # text dict 2
    for i in range(5):
        print(f"\n *** Dictionary 2 -> Randomly Generated Text {i+1} *** \n")
        generated_text = dictionary.make_random_dictionary_2_plaintext(i)
        print(f"Generated Plaintext\n'{generated_text}'\n")
        key = encrypt.generate_key_mapping()
        ciphertext = encrypt.encrypt(generated_text, key, probability = p)
        ciphertext_cleaned = preprocess.remove_duplicate_char_triplets(ciphertext)
        differentiate(ciphertext_cleaned)
        print()



def test_differentiate_single(p = 0, text_1_id = 0):
    print(f"Differentiate Test using p = {p}")

    dict_1_texts = dictionary.get_dictionary_1()
    dict_1_char_positions = [preprocess.get_all_char_idx(text) for text in dict_1_texts]

    text = dict_1_texts[text_1_id]

    print(f"Dict 1 Plaintext\n'{text}'\n")
    key = encrypt.generate_key_mapping()
    ciphertext = encrypt.encrypt(text, key, probability = p)
    ciphertext_cleaned = preprocess.remove_duplicate_char_triplets(ciphertext)
    differentiate(ciphertext_cleaned)
    print()





def test_get_all_char_idx():
    print("\nTest get_all_char_idx for Dict 1 Texts\n")
    dict_1_texts = dictionary.get_dictionary_1()
    dict_1_char_positions = [preprocess.get_all_char_idx(text) for text in dict_1_texts]

    for text, idxs in zip(dict_1_texts, dict_1_char_positions):
        print(f"\ttext\n'{text}'\n")
        for entry in idxs.items():
            print(f"\t{entry}")


def main():
    test_differentiate()
    #test_differentiate_single(p = .1, text_1_id=4)
    #test_get_all_char_idx()





if __name__ == "__main__":
    main()
