"""
Dict 2 key attack
"""
DEBUG = False  # all helper function output
DEBUG_2 = False  # steps in decrypt function

import alphabet
import dictionary
import frequency
import permutation
import preprocess
import encrypt
import decrypt
import random
import find_similar_words

#constants
UNKNOWN_CHAR = "#"
SPACE = " "

_dict_2_plain_chars_missing = ['x', 'q', 'j']


def preprocess_dictionary_2():
    """
    prepprocess dict 2 for the attack
    returns a dict (k:v) where the key is word length
                value is a list of (words, unique_chars) tuple
    """
    words = dictionary.get_dictionary_2()
    return build_word_len_dict_data_structure(words)


def build_word_len_dict_data_structure(words):
    """
    Takes in a list of words
    returns a dict, keyed on word length
        k (int) : v [(word, # unique chars in word)]

    """
    words.sort(key = lambda x: len(x))
    by_length = []
    current_length = len(words[0])
    current = []
    for i, w in enumerate(words):
        if len(w) == current_length:
            current.append((w, preprocess.num_unique_chars(w)))
        else:
            by_length.append(current)
            current = []
            current_length = len(w)
            current.append((w, preprocess.num_unique_chars(w)))
    if len(current) > 0:
        by_length.append(current)
    length_dict = {len(w[0][0]):w for w in by_length}

    return length_dict



def get_truncated_dict(word_length):
    """
    returns all the words in the dict as long as word_length truncated to word_length
    """
    words = dictionary.get_dictionary_2()
    truncated = [word[:word_length] for word in words if len(word) >= word_length]
    return truncated



def key_mapping(key_map, cipher_word, plaintext_word):
    """
    Input key_map -> a dictionary of {p_char : c_char}
    cipherword (str) -> an encrypted word
    candidate (str) -> the plaintext word
    """
    for p_char, c_char in zip(plaintext_word, cipher_word):
        if DEBUG:
            print(f"in key mapping")
            print(f"p_char {p_char} c_char {c_char}")
        if p_char not in key_map.values():
            if DEBUG:
                print(f"saving  c_char '{c_char}' : p_char '{p_char}'")
            if c_char in key_map.keys():
                if DEBUG:
                    print(f"ERROR!!!! c_char in map already current val {key_map[c_char]}")
                continue
            key_map[c_char] = p_char
    return key_map



def build_mapping_from_cipher_words(cipher_words, space, key):
    """
    builds a key mapping by compairing dict letter frequencies
    INPUT: cipherwords is a list of words
    SPACE: space char
    KEY: dict to map c_text to p_text
    OUTPUTS: a key
    """

    dict_words = preprocess_dictionary_2()
    possible_plaintext_words = []

    for word in cipher_words:
        possible_plaintext_words.append(get_dict_2_word_options(word, dict_words))

    for cipher_word, plaintext_possibilities in zip(cipher_words, possible_plaintext_words):
        if len(plaintext_possibilities) == 1:
            #print(f"cipher_word '{cipher_word}' plaintext_possibilities {plaintext_possibilities}")
            key = key_mapping(key, cipher_word, plaintext_possibilities[0])
            if DEBUG:
                print(f"\nkey - ln 149")
                for entry in key.items():
                    print(f"\t{entry}")
                print()

    if DEBUG:
        print(f"plaintext_possibilites")
        for entry in possible_plaintext_words:
            print(entry)

    if DEBUG:
        print(f"Current decryption before first pass")
        for entry in cipher_words:
            print(partial_decrypt(entry, key))

        print("\n\n")

    for i in range(1):
        if DEBUG:
            print(f"\ncipher_words\n")
            for word in cipher_words:
                print(partial_decrypt(word, key))
            print()

        for i, cipher_word in enumerate(cipher_words):
            word = partial_decrypt(cipher_word, key)
            if UNKNOWN_CHAR in word:
                candidates = possible_plaintext_words[i]

                if DEBUG:
                    print(f"\tBEFORE REMOVED word {word} candidates {candidates}")

                restricted_candidates = remove_candidates_same_length(word, candidates)
                possible_plaintext_words[i] = restricted_candidates

                if DEBUG:
                    print(f"\tAFTER REMOVED word {word} candidates {restricted_candidates}")

                if len(restricted_candidates) == 1:
                    if DEBUG:
                        print(f"ln 148 word {word} restricted_candidates {restricted_candidates}")

                    key = key_mapping(key, cipher_word, restricted_candidates[0])

    if DEBUG:
        print(f"\nCurrent decryption after first pass")
        for entry in cipher_words:
            print(partial_decrypt(entry, key))

        print("\n\n")


    last_word = partial_decrypt(cipher_words[-1], key)
    if UNKNOWN_CHAR in last_word:
        last_word_length = len(last_word)
        candidates = get_truncated_dict(last_word_length)
        restricted_candidates = remove_candidates_same_length(last_word, candidates)

        if DEBUG:
            print(f"Last Word {last_word} restricted_candidates {restricted_candidates}")

        if len(restricted_candidates) > 1:
            # remove candidates until only 1:
            unknown_idx = last_word.find(UNKNOWN_CHAR)
            unknown_cipher_char = cipher_words[-1][unknown_idx]
            plaintext_char_candidates = [i for i, stub in enumerate(restricted_candidates) \
                if stub[unknown_idx] not in key.values()]

            restricted_candidates = [restricted_candidates[plaintext_char_candidates[0]]]

            if DEBUG:
                print(f"restricted_candidates {restricted_candidates}")
                print(f"unknown_idx {unknown_idx}")
                print(f"unknown_cipher_char {unknown_cipher_char}")
                print(f"plaintext_char_candidates {plaintext_char_candidates}")
                print(f"key {key}")

        if len(restricted_candidates) == 1:
            key = key_mapping(key, cipher_words[-1], restricted_candidates[0])


    return key



def get_dict_2_word_options(a_word, dict_words):
    """
    returns all the possible options the word could be
    """
    word_len = len(a_word)
    num_unique = preprocess.num_unique_chars(a_word)
    possible_words = []
    if word_len in dict_words:
        for entry in dict_words[word_len]:
            if entry[1] == num_unique:
                possible_words.append(entry[0])
    return possible_words


def partial_decrypt(ciphertext, key):
    """
    Map the ciphertext to plaintext using a key map dictionary
    """
    plain = ""
    for char in ciphertext:
        if char not in key:
            plain += UNKNOWN_CHAR
        else:
            plain += key[char]
    return plain


def remove_stubs(cipher_words):
    """
    used to eliminate noise
    """
    cipher_words_cleaned = cipher_words[:]
    short_parts = [ (word, idx) for idx, word in enumerate(cipher_words_cleaned) if len(word) < 5]
    idx_modified = []

    while short_parts:
        current_substring, idx = short_parts.pop()
        #print(f"current {current_substring}, idx {idx}")
        if idx == 0:
            cipher_words_cleaned[idx+1] = current_substring + cipher_words_cleaned[idx+1]
            idx_modified.append(idx)
        elif idx < len(cipher_words_cleaned) - 1:
            cipher_words_cleaned[idx-1] = cipher_words_cleaned[idx-1] + current_substring
            cipher_words_cleaned[idx+1] = current_substring + cipher_words_cleaned[idx+1]
            idx_modified.append(idx)
        else: #at the end
            pass

    #print(f"idx_modified {idx_modified}")
    for idx in idx_modified:
        if len(cipher_words_cleaned[idx]) < 5:
            del cipher_words_cleaned[idx]


    return cipher_words_cleaned


def p_zero_attack(ciphertext, space_char, key):
    """
    attack for when p_hat == 0
    takes in a ciphertext
    returns (cipher_words_list, key)
    """
    if DEBUG_2:
        print(f"in p_zero_attack")

    cipher_words = frequency.get_words(ciphertext, delimiter = space_char)
    if DEBUG_2:
        print(f"cipher_words {cipher_words}")


    key = build_mapping_from_cipher_words(cipher_words, space_char, key)
    if DEBUG_2:
        print(f"Key after build_mapping_from_cipher_words {key}\n")


    if is_key_map_bad(cipher_words, key):
        if DEBUG_2:
            print("\n\n** MAP IS BAD ** \n\n")
        # institute fix for bad mappings
        key = recover_from_bad_key(cipher_words, key)

    return cipher_words, key




def higher_p_attack(ciphertext, space_char, key, p_hat):
    """
    attack for when p_hat > 0
    takes in a ciphertext, space_char, key, p_hat
    returns (cipher_words_list, key)
    """
    if DEBUG:
        print(f"in higher p")

    cipher_words = frequency.get_words(ciphertext, delimiter = space_char)
    if DEBUG_2:
        print(f"cipher_words {cipher_words}")

    processed_cipherwords = remove_stubs(cipher_words)
    if DEBUG_2:
        print(f"dict_2_attack_v2 - processed_cipherwords {processed_cipherwords}")

    potential_duplicates = get_common_shared_cipher_substrings(processed_cipherwords)
    if DEBUG_2:
        print(f"\npotential_duplicates\n")
        print_dict(potential_duplicates)

    key = initialize_high_p_key(potential_duplicates, key)
    if DEBUG_2:
        print(f"After initialize_high_p_key num key values {len(key)}")
        print_dict(key)

    if DEBUG_2:
        print(f"Before first remove nulls - processed_cipherwords")
        for word in processed_cipherwords:
            print(partial_decrypt(word, key))
        print()

    processed_cipherwords = remove_nulls_from_cipherwords(processed_cipherwords, key)
    if DEBUG_2:
        print(f"\n\nAfter first remove nulls - processed_cipherwords\n{processed_cipherwords}")
        for word in processed_cipherwords:
            print(partial_decrypt(word, key))
        print()


    # next run through and look for any exact matches
    key = check_exact_word_lengths_for_matches(processed_cipherwords, key)



    # remove nulls again
    processed_cipherwords = remove_nulls_from_cipherwords(processed_cipherwords, key)


    key = check_exact_word_lengths_for_matches(processed_cipherwords, key)

    # remove up to n UNKNOWN CHARS
    processed_cipherwords = remove_n_unknowns_from_cipherwords(processed_cipherwords, key, 3)

    '''
    if is_key_map_bad(cipher_words, key):
        if DEBUG_2:
            print("\n\n** MAP IS BAD ** \n\n")
        # institute fix for bad mappings
        key = recover_from_bad_key(cipher_words, key)
    '''
    return processed_cipherwords, key


def check_exact_word_lengths_for_matches(cipherwords_list, key):
    '''
    input: list of cipherwords and the key
    looks for any close matches and then adds to the key
    returns the key
    '''
    dict_words = preprocess_dictionary_2()

    for i in range(2):
        for i, cipherword in enumerate(cipherwords_list):
            word = partial_decrypt(cipherword, key)
            if UNKNOWN_CHAR in word:
                candidates = get_dict_2_word_options(cipherword, dict_words)
                restricted_candidates = remove_candidates_same_length(word, candidates)
                if len(restricted_candidates) == 1:
                        if DEBUG:
                            print(f"ln 357 word {word} restricted_candidates {restricted_candidates}")

                        key = key_mapping(key, cipherword, restricted_candidates[0])

    return key




def remove_n_unknowns_from_cipherwords(cipherwords_list, key, n):
    dict_2 = dictionary.get_dictionary_2()
    for i, cipherword in enumerate(cipherwords_list):
        word = partial_decrypt(cipherword, key)
        unknown_count = word.count(UNKNOWN_CHAR)
        if unknown_count > 0 and unknown_count <= n:
            cleaned_text = word.replace(UNKNOWN_CHAR, "")
            replacement = find_most_similar_word(cleaned_text, dict_2)
            if DEBUG:
                print(f"word {word}")
                print(f"replacement {replacement}")
            if replacement:
                cipherwords_list[i] = map_plaintext_to_ciphertext(replacement,key)

    return cipherwords_list




def remove_nulls_from_cipherwords(cipherwords_list, key):
    '''
    input: list of cipherwords and the key, n is the number of unknowns in the word
    removes all the null chars from a word that is fully mapped to the alphabet
    returns a mutated list of cipherwords
    '''
    dict_2 = dictionary.get_dictionary_2()

    for i, cipherword in enumerate(cipherwords_list):
        word = partial_decrypt(cipherword, key)
        num_unknown_in_word = word.count(UNKNOWN_CHAR)
        if num_unknown_in_word == 0:
            if word not in dict_2:
                replacement = find_most_similar_word(word, dict_2)
                if DEBUG:
                    print(f"word {word}")
                    print(f"replacement {replacement}")
                if replacement:
                    cipherwords_list[i] = map_plaintext_to_ciphertext(replacement,key)


    return cipherwords_list


def map_plaintext_to_ciphertext(plaintext_word, key):
    """
    produces ciphertext using the key from plaintext
    """
    reversed_key = {v:k for k,v in key.items()}
    return partial_decrypt(plaintext_word, reversed_key)



def find_most_similar_word(word_with_nulls, dict_2_list ):
    '''
    input  word_with_nulls : str
            dict_2_list : list of words
    '''
    restricted_dictionary = [word for word in dict_2_list if len(word) <= len(word_with_nulls)]
    restricted_dictionary.sort(key = lambda x : len(x), reverse=True)

    if DEBUG:
        print(f"\n\nword_with_nulls {word_with_nulls}")
        print(f"restricted_dict {restricted_dictionary}\n")

    for word in restricted_dictionary:
        lcs = find_similar_words.get_longest_common_subsequence(word_with_nulls, word)
        if lcs == word:
            return word
    return ""




def print_dict(a_dict):
    for entry in a_dict.items():
        print(entry)


def dict_2_attack_v2(ciphertext):
    """
    dict_2_attack_v2
    """
    p_hat = preprocess.p_estimate(ciphertext)
    if DEBUG_2:
        print(f"\n\n *** Begin dict_2_attack_v2 *** \n")
        print(f"ciphertext\n'{ciphertext}'\n")
        print(f"dict_2_attack_v2 - p_hat: {p_hat}\n")

    cleaned_ciphertext = preprocess.remove_duplicate_char_triplets(ciphertext)
    space = decrypt.get_space_key_value(cleaned_ciphertext)
    if DEBUG_2:
        print(f"dict_2_attack_v2 - space '{space}'\n")

    cleaned_ciphertext = preprocess.remove_double_duplicate(space, cleaned_ciphertext)
    if DEBUG_2:
        print(f"dict_2_attack_v2 - cleaned_ciphertext {len(cleaned_ciphertext)}\n'{cleaned_ciphertext}'\n")

    key = {space:SPACE}


    # everything above is identical for all cases
    if p_hat == 0:
        cipher_words, key = p_zero_attack(cleaned_ciphertext, space, key)
    else:
        cipher_words, key = higher_p_attack(cleaned_ciphertext, space, key, p_hat)


    final = space.join(cipher_words)
    plaintext_guess = partial_decrypt(final, key)

    if DEBUG_2:
        print(f"\nplaintext guess {len(plaintext_guess)}\n'{plaintext_guess}'")
        print(f"\n\n*************** DONE ****************")

    return partial_decrypt(final, key)


def recover_from_bad_key(cipherwords, key):
    """
    Assume the key is close and only a few mappings are wrong
    If all ciphertext chars are mapped it will return true
    """
    dict_2 = dictionary.get_dictionary_2()
    dict_words = preprocess_dictionary_2()
    for cipherword in cipherwords:
        word = partial_decrypt(cipherword, key)
        if word not in dict_2:
            candidates = get_dict_2_word_options(cipherword, dict_words)
            if DEBUG:
                print(f"candidates {candidates}")
            restricted_candidates = remove_candidates_same_length(word, candidates)
            if DEBUG:
                print(f"restricted_candidates {len(restricted_candidates)} {restricted_candidates}")
            if len(restricted_candidates) == 1:
                missing_idx = word.find(UNKNOWN_CHAR)
                if DEBUG:
                    print(f"word {word} missing idx {missing_idx}")
                p_char = restricted_candidates[0][missing_idx]
                c_char = cipherword[missing_idx]
                #delete char that currently maps to p_char
                if DEBUG:
                    print(f"key - before delete {key}")
                if p_char in key.values():
                    key = {k:v for k,v in key.items() if v is not p_char}

                if DEBUG:
                    print(f"key - after delete {key}")

                key[c_char] = p_char

                if DEBUG:
                    print(f"p_char {p_char} c_char {c_char} current")
                    print(f"key : {key}")
                    print(f"mapped to key[c_char] {key[c_char]}")
                    print()


    return key



def is_key_map_bad(cipher_words, key):
    """
    input:  cipher_words : a list of ciphertexts
            key: a dict of ciphertext plaintext char mappings
    returns true if any of the chars in cipher_words maps to an UNKNOWN CHAR
    """
    for cipherword in cipher_words:
        word = partial_decrypt(cipherword, key)
        if UNKNOWN_CHAR in word:
            return True
    return False


def get_common_shared_cipher_substrings(cipherwords_list):
    """
    input, a list of cipherwords
    Returns a dict of substrings sorted by keyd on len
    """
    if DEBUG:
        print("get_common_shared_cipher_substrings")
        print(cipherwords_list)

    unique = set()

    for i, word_1 in enumerate(cipherwords_list[:-1]):
        for j, word_2 in enumerate(cipherwords_list[i+1:]):
            lcs = find_similar_words.get_longest_common_subsequence(word_1, word_2)
            if len(lcs) >= 5:
                unique.add(lcs)

    unique_by_len = list(unique)

    return build_word_len_dict_data_structure(unique_by_len)






def initialize_high_p_key(possible_duplicates, key):
    """
    takes in output from get_common_shared_cipher_substrings
    finds the best match in dict words
    returns the maximal key mapping
    """

    dict_words = preprocess_dictionary_2()
    duplicate_lengths = [k for k in possible_duplicates.keys()]
    duplicate_lengths.sort(reverse=True)

    if DEBUG:
        print(f"in initialize_high_p_key")
        print(f"duplicate_lengths {duplicate_lengths}")
        print(f"\nDict Words")
        print_dict(dict_words)
        print(f"\npossible_duplicates")
        print_dict(possible_duplicates)

    for length in duplicate_lengths:
        current_duplicates = possible_duplicates[length]
        if DEBUG:
            print(f"current_duplicates {length} : {current_duplicates}")
        for word in current_duplicates:
            candidates = get_dict_2_word_options(word[0], dict_words)
            if len(candidates) == 1:
                if DEBUG:
                    print(f"word '{word[0]}' candidates '{candidates[0]}'")
                    print(f"key before {key}")
                key = key_mapping(key, word[0], candidates[0])
                if DEBUG:
                    print(f"key after {key}")
                break

    return key



def remove_candidates_same_length(cipherword, candidates):
    """
    input cipherword : a word generated from partial decrypt -> string that may contain UNKNOWN_CHARS
         - for now assume all candidates are the same length
        TODO
            - how to deal with candidates shorter than cipherword

    Output: a list of candidate words from candidates
    """
    if DEBUG:
        print("In remove_candidates_same_length")
    valid_candidate_idx = set(idx for idx,_ in enumerate(candidates))
    invalid_idx = set()

    if DEBUG:
        print(f"Starting valid_candidate_idx {valid_candidate_idx}")
        print(f"Starting invalid_idx {invalid_idx}")

    for i, char in enumerate(cipherword):
        if char != UNKNOWN_CHAR:
            for idx in valid_candidate_idx:
                if candidates[idx][i] != char:
                    invalid_idx.add(idx)
            valid_candidate_idx = valid_candidate_idx - invalid_idx

    valid_candidates = [candidates[idx] for idx in valid_candidate_idx]

    if DEBUG:
        print(f"Ending valid_candidate_idx {valid_candidate_idx}")
        print(f"Ending invalid_idx {invalid_idx}")

    return valid_candidates


# TESTING
def test_dict_2_v2_attack(size, p=0, substring_match_error_limit = 470):
    errors = []
    test_seed = 22560
    for _ in range(size):
        generated_plaintext = dictionary.make_random_dictionary_2_plaintext(seed = test_seed)
        #print(f"generated plaintext:\n'{generated_plaintext}'")

        key = encrypt.generate_key_mapping(seed=test_seed)
        if DEBUG:
            print(f"key: {key}")

        ciphertext = encrypt.encrypt(generated_plaintext, key, probability=p, seed = test_seed)
        if DEBUG:
            print(f"\nciphertext: \n'{ciphertext}'\n")

        plaintext = dict_2_attack_v2(ciphertext)
        if DEBUG:
            print(f"returned - plaintext len{len(plaintext)}: \n'{plaintext}'")

        #lcs = find_similar_words.get_longest_common_subsequence(generated_plaintext, plaintext)


        #if len(lcs) < substring_match_error_limit:
        if plaintext != generated_plaintext:
            #print(f"length lcs {len(lcs)}")
            errors.append(test_seed)
            print(f"\n\nERROR CAUSED BY seed({test_seed})")
            print(f"Generated plaintext len {len(generated_plaintext)}\n'{generated_plaintext}'\n")
            print(f"ciphertext: \n'{ciphertext}'\n")
            print(f"Guesed plaintext len {len(generated_plaintext)}\n'{plaintext}'\n\n")

        test_seed += 1

    print(f"test_dict_2_v2_attack {len(errors)} errors out of {size} at p = {p}")


def meta_test(low_p, high_p, size, lcs_limit):
    for i in range(low_p, high_p):
        prob = i / 100
        test_dict_2_v2_attack(size, p=prob, substring_match_error_limit=lcs_limit)


def test_remove_candidates():
    test_text = "#ars#ens"
    candidates = ["bbrstens", "harshens" , "hershens", "barsbens"]

    restricted_candidates = remove_candidates_same_length(test_text, candidates)
    print(f"restricted_candidates {restricted_candidates}")



def main():
    #test_remove_candidates()
    #test_dict_2_v2_attack(100, p=.0)



    meta_test(20, 21, 1, 500)
    #print(remove_stubs(["bb", "abcdef", "fh", "ijklmnop", "jlp", "qr","abc", "def", "abc", "def", "tuvxqd", "lsu"]))

    #texta = "abchellodefg"
    #textb = "hezlzzlzzzo"

    #lcs = find_similar_words.get_longest_common_subsequence(texta, textb)

    #print(f"lcs {lcs}")

    '''
    #print(preprocess_dictionary_2())


    #plaintext = dictionary.make_random_dictionary_2_plaintext()
    plaintext = "stuffer outflanked farcer blistered rotates gladding tortoni hyped particulate protectional rankness brickyard particulate invalided particulate imagist twirlier frizzlers favouring lingua pilfers stuffer unlikely imagist alefs baldpates clarence farcer imagist stuffer tortoni overachiever brickyard stuffer rotates outdates invalided freaking amulets protectional rankness moonset outdates glottic rotates amulets outdates amulets frizzlers smeltery baldpates glottic gladding alefs moonset protect"
    print(f"\nplaintext {len(plaintext)} chars \n'{plaintext}'\n")

    key = encrypt.generate_key_mapping()
    #print(f"key: {key}")

    ciphertext = encrypt.encrypt(plaintext, key, probability=0.00)
    print(f"ciphertext: \n'{ciphertext}'\n")

    plaintext = dict_2_attack_v2(ciphertext)
    print(f"plaintext len{len(plaintext)}: \n'{plaintext}'")

    print(f"Bad character present {plaintext.find(UNKNOWN_CHAR)}")
    '''

if __name__ == "__main__":
    main()
