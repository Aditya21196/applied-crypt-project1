"""
Dict 2 key attack
"""
DEBUG = True  # all helper function output
DEBUG_2 = True  # steps in decrypt function
DEBUG_3 = True


from os import dup
import alphabet
import dictionary
import frequency
import preprocess
import encrypt
import decrypt
import find_similar_words
import collections

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
            if c_char in key_map.keys():
                if DEBUG_3:
                    print(f"ERROR!!!! c_char {c_char} in map already current val {key_map[c_char]}")
                continue
            key_map[c_char] = p_char
            if DEBUG_3:
                print(f"91 saving KEY[{c_char}'] = '{p_char}'")
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
    if DEBUG_3:
        if is_key_corrupted(key):
            print(f"KEY CORRUPETED in map_plaintext_to_ciphertext")
            print(ciphertext)
            print_dict(key)
            raise ValueError

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
        if is_key_corrupted(key):
            print(f"key corrupted ln 307")
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
    if DEBUG_2:
        if is_key_corrupted(key):
            print(f"key corrupted ln 329")


    # remove nulls again
    processed_cipherwords = remove_nulls_from_cipherwords(processed_cipherwords, key)


    key = check_exact_word_lengths_for_matches(processed_cipherwords, key)
    if DEBUG_2:
        if is_key_corrupted(key):
            print(f"key corrupted ln 337")

    # remove up to n UNKNOWN CHARS
    processed_cipherwords = remove_n_unknowns_from_cipherwords(processed_cipherwords, key, 3)


    # check words with unknowns and try to find a good mapping for them
    key = try_to_map_unkowns(processed_cipherwords, key)
    if DEBUG_2:
        if is_key_corrupted(key):
            print(f"key corrupted ln 344")


    # remove nulls again
    processed_cipherwords = remove_nulls_from_cipherwords(processed_cipherwords, key)


    processed_cipherwords = remove_n_unknowns_from_cipherwords(processed_cipherwords, key, 3)


    score = key_map_scoring_function(processed_cipherwords, key)
    if DEBUG:
        print(f"SCORE -> {score}")

    if score < 40:
        for i in range(2):
            if DEBUG:
                if is_key_corrupted (key):
                    print(f"BAD KEY")
                    print_dict(key)

            key =  recover_from_bad_key(processed_cipherwords, key)
            processed_cipherwords = remove_n_unknowns_from_cipherwords(processed_cipherwords, key, 3)
            processed_cipherwords = remove_nulls_from_cipherwords(processed_cipherwords, key)
            key = try_to_map_unkowns(processed_cipherwords, key)

            new_score = key_map_scoring_function(processed_cipherwords, key)
            if DEBUG:
                print(f"new_score round {i+1}-> after recover {new_score}")
            if new_score >= 40:
                break


    if score >= 40:
        processed_cipherwords, key = high_p_final_output(processed_cipherwords, key, space_char)


    return processed_cipherwords, key






def high_p_final_output(processed_cipherwords, key, space_char):
    """
    takes in processed_cipherwords and key
    returns final process_cipherwords and key
    """
    total_alphabet = set(alphabet.get_alphabet())
    plaintext_chars_mapped = set()
    for _, p in key.items():
        plaintext_chars_mapped.add(p)
    plaintext_chars_missing = total_alphabet - plaintext_chars_mapped
    plaintext_chars_missing = plaintext_chars_missing - set(_dict_2_plain_chars_missing)

    if DEBUG:
        print(f"TOTAL ALPHABET : {total_alphabet}")
        print(f"plaintest_chars_mapped: {plaintext_chars_mapped}")
        print(f"plaintext chars missing {plaintext_chars_missing}")


    dict_2 = dictionary.get_dictionary_2()

    # first, map any unmapped characters
    for i, cipherword in enumerate(processed_cipherwords):
        word = partial_decrypt(cipherword, key)
        if UNKNOWN_CHAR in word:
            closest_match = lcs_closest_match(word, dict_2)
            if closest_match:
                if DEBUG:
                    print(f"word {word}")
                    print(f"closest_match {closest_match}")
                missing_char = set(closest_match) - set(word)

                if len(missing_char) == 0:
                    #print(f"HERE - MUTATE")
                    processed_cipherwords[i] = map_plaintext_to_ciphertext(closest_match,key)

                elif len(missing_char) == 1:
                    missing_char = missing_char.pop()
                    missing_char_count = closest_match.count(missing_char)

                    if DEBUG:
                        print(f"\tmissing_char {missing_char}")
                        print(f"missing char count {missing_char_count}")

                    unknown_cipher_chars = []
                    for w_char, c_char in zip(word, cipherword):
                        if w_char == UNKNOWN_CHAR:
                            unknown_cipher_chars.append(c_char)

                    if len(unknown_cipher_chars) == 0:
                        continue

                    elif len(unknown_cipher_chars) == 1 and missing_char_count == 1:
                        p_char = missing_char
                        key[unknown_cipher_chars[0]] = p_char
                        #plaintext_chars_missing.remove(p_char)
                        continue
                    else: # one missing char, multiple unknown chars

                        unknown_cipher_char_counter = collections.Counter(unknown_cipher_chars)


                        unknown_candidates = [k for k,v in unknown_cipher_char_counter.items() if v >= missing_char_count]

                        if DEBUG:
                            print(f" In one missing char, multiple unknown chars ")
                            print(f"unknown_cipher_char_counter {unknown_cipher_char_counter}")
                            print(f"unknown_candidates {unknown_candidates}")

                        if len(unknown_candidates) == 1:
                            key[unknown_candidates[0]] = missing_char
                        else:  # test all possibilities
                            pass
                            # fix logic in here
                            # want o answer




    processed_cipherwords = remove_nulls_from_cipherwords(processed_cipherwords, key)
    processed_cipherwords = remove_n_unknowns_from_cipherwords(processed_cipherwords, key, 2)


    #lastly -> identify and fix any words not in dict
    processed_cipherwords = remove_wrong_words_in_cipherwords(processed_cipherwords, key, space_char)



    return processed_cipherwords, key


def remove_wrong_words_in_cipherwords(processed_cipherwords, key, space_char):
    """
    removes nonsense words -> assumes good key and processed chars
    """
    dict_2 = dictionary.get_dictionary_2()

    not_in_dict = []

    for i, cipherword in enumerate(processed_cipherwords):
        word = partial_decrypt(cipherword, key)
        if word not in dict_2 and i != len(processed_cipherwords) - 1:
            not_in_dict.append((word,i))

    if DEBUG:
        print(f"\n\nnot in dict = {not_in_dict}\n\n")

    idx_of_saved_word = []

    if not_in_dict:
        first = not_in_dict.pop()
        while len(not_in_dict) >= 1:
            second = not_in_dict.pop()
            to_check = ""
            if first[1] - second[1] == 1 and first[0] != second[0]:
                to_check = second[0] + first[0]
                match = lcs_closest_match(to_check, dict_2)
                if DEBUG:
                    print(f"first: {first} second: {second} to_check '{to_check}'")
                    print(f"match {match}")
                if len(idx_of_saved_word) > 0:
                    if idx_of_saved_word[-1] != second[1] + 1:
                        idx_of_saved_word.append(second[1])
                        processed_cipherwords[second[1]] = map_plaintext_to_ciphertext(match, key)
                else:
                    idx_of_saved_word.append(second[1])
                    processed_cipherwords[second[1]] = map_plaintext_to_ciphertext(match, key)

            first = second
            if DEBUG:
                print(f" end of while loop -> idx_of_saved_word {idx_of_saved_word}")

    text_len = len(partial_decrypt(space_char.join(processed_cipherwords), key))

    if DEBUG:
        print(f"text_len {text_len}")

    last_word = partial_decrypt(processed_cipherwords[-1], key)
    if text_len > 500 and text_len < 500 + len(last_word):

        truncated_length = len(last_word) - (text_len - 500)

        truncated_dict = [word[:truncated_length] for word in dict_2 \
            if (len(word) > truncated_length and word[truncated_length-1] == last_word[-1])]

        closest_match = lcs_closest_match(last_word, truncated_dict)

        processed_cipherwords[-1] = map_plaintext_to_ciphertext(closest_match, key)

        if DEBUG:
            print(f"need to fix last word")

            # assume last word is too long
            print(f"last_word {last_word}")
            print(f"truncated_length {truncated_length}")
            print(f"truncated dict {truncated_dict}")
            print(f"closest_match = {closest_match}")




    not_in_dict = []
    idx_to_delete = []
    for i, cipherword in enumerate(processed_cipherwords):
        word = partial_decrypt(cipherword, key)
        if word not in dict_2 and i != len(processed_cipherwords) - 1:
            not_in_dict.append(word)
            idx_to_delete.append(i)

    idx_to_delete.sort(reverse=True)

    if DEBUG:
        print(f"second pass of not in dict {not_in_dict}")
        print(f"second pass idx to delted {idx_to_delete}")

    for idx in idx_to_delete:
        del processed_cipherwords[idx]



    return processed_cipherwords



def try_to_map_unkowns(cipherwords_list, key):
    """
    maps key and mutates cipherwords_list
    """
    FUNC_DEBUG = DEBUG

    if FUNC_DEBUG:
        print(f"\n\nTRY TO MAP UNKOWNS")
    dict_2 = dictionary.get_dictionary_2()

    for i, cipherword in enumerate(cipherwords_list):
        word = partial_decrypt(cipherword, key)
        unknown_count = word.count(UNKNOWN_CHAR)
        if unknown_count == 1:
            closest_match = lcs_closest_match(word, dict_2)
            if closest_match:
                #print(f"word {word} closest_word {closest_match}")
                match_chars = set(closest_match)
                word_chars = set(word)
                word_chars.remove(UNKNOWN_CHAR)
                missing_char = match_chars - word_chars
                unknown_idx = word.find(UNKNOWN_CHAR)
                #print(f"match {match_chars} word_chars {word_chars} missing {missing_char}")

                if len(missing_char) == 1:
                    c_char = cipherword[unknown_idx]
                    p_char = missing_char.pop()
                    key_to_delete = None
                    for c, p in key.items():
                        if p == p_char:
                            key_to_delete = c
                    if key_to_delete:
                        if DEBUG_3:
                            print(f"607  Deleting key KEY[{key_to_delete}] that maps to {key[key_to_delete]}")
                        del key[key_to_delete]
                    key[c_char] = p_char
                    if DEBUG_3:
                        print(f"611 New Key MAPPING KEY[{c_char}] = {p_char}")

                        if is_key_corrupted(key):
                            print(f"key corrupted ln 398")


                elif len(missing_char) == 0:
                    if FUNC_DEBUG:
                        print(f" IN EXTRA CHAR - MUTATE mapping - word {word} closes_match {closest_match}")
                        #print(f"c_char {c_char}")

                    cipherwords_list[i] = map_plaintext_to_ciphertext(closest_match,key)

                    if FUNC_DEBUG:
                        print(f"i {i} word fixed")


                else:  #bad key mapping"
                    if FUNC_DEBUG:
                        print(f" IN BAD MAPPING - MUTATE key? - word '{word}' cipherword '{cipherword}' closes_match '{closest_match}'")
                    key = improve_single_word_key_mapping(cipherwords_list, cipherword, closest_match, key)
                    if is_key_corrupted(key):
                        print(f"key corrupted ln 415")

                    if FUNC_DEBUG:
                        print(f" AFTER BAD MAPPING IMPROVE = {partial_decrypt(cipherword, key)}")

    return key


def improve_single_word_key_mapping(cipherwords_list, cipherword, target_word, key):
    """
    This is called when there is a suspected bad mapping of a word
    returns a better key if one is found
    """
    FUNC_DEBUG = DEBUG

    starting_score = key_map_scoring_function(cipherwords_list, key)
    starting_key = key.copy()
    score = 0
    #print(f"key")
    #print_dict(key)

    if FUNC_DEBUG:
        print(f"\t -- STARTING SCORE : {starting_score}")

    if len(cipherword) == len(target_word) and len(cipherword) >= 5:
        if preprocess.num_unique_chars(cipherword) == preprocess.num_unique_chars(target_word):
            if FUNC_DEBUG:
                print(f"CIPHERWORD {cipherword} and TARGET WORD {target_word} same length")
            for c_char, p_char in zip(cipherword, target_word):
                #print(f"c_char '{c_char}', p_char '{p_char}'")

                if c_char in key.keys():
                    if key[c_char] != p_char:
                        if FUNC_DEBUG:
                            print(f"c_char '{c_char}' in keys, maps to '{key[c_char]}', while p_char = '{p_char}'")
                        if p_char in key.values():
                            for k, v in key.items():
                                if v == p_char:
                                    if DEBUG_3:
                                        print(f"672 - about to delete KEY[{k}] that maps to {p_char}")
                                    del key[k]
                                    break
                        key[c_char] = p_char
                        if DEBUG_3:
                            print(f"677 -  writing to key key[{c_char}] = {p_char}")

                else: # c_char not in dict
                    if FUNC_DEBUG:
                        print(f" HERE c_char '{c_char}' not in keys -> an unknown char")
                    if p_char in key.values():
                        if FUNC_DEBUG:
                            print(f" HERE we've found an incorreclty mapped char")
                        for k, v in key.items():
                            if v == p_char:
                                if DEBUG_3:
                                        print(f"688 - about to delete KEY[{k}] that maps to {p_char}")
                                del key[k]
                                break
                    key[c_char] = p_char
                    if DEBUG_3:
                            print(f"693 -  writing to key key[{c_char}] = {p_char}")

            score = key_map_scoring_function(cipherwords_list, key)

    else:
        # attack this second
        #if FUNC_DEBUG:
        if FUNC_DEBUG:
            print(f"DIFFERENT LENGTHS !!!!!")
            print(f"cipher '{cipherword}' partial '{partial_decrypt(cipherword,key)}' target_word '{target_word}' ")

            if is_key_corrupted(key):
                print(f" *** KEY IS CORRUPTED ***")

        score = 1 + key_map_scoring_function(cipherwords_list, key)


    if score <= starting_score:
        key = starting_key

    if FUNC_DEBUG:
        print(f"\n\t -- ENDING SCORE {score}\n\n")

    return key

def is_key_corrupted(key):
    """
    returns true if two different c_chars map to the same p_char
    """
    p_chars = set()
    for _, p_char in key.items():
        if p_char in p_chars:
            if DEBUG_3:
                print(f"**** is_key_corrupted -> {p_char} is a duplicate in the key ****")
            return True
        p_chars.add(p_char)
    return False



def key_map_scoring_function(cipherwords_list, key):
    """
    Takes the list of cipherwords, key
    returns a count of how many words are correctly key mapped in the list.
    """
    dict_2 = dictionary.get_dictionary_2()
    score = 0
    for cipherword in cipherwords_list:
        word = partial_decrypt(cipherword, key)
        if word in dict_2:
            score += 1
    return score


def lcs_closest_match(word_with_unknowns, dict_list):
    """
    Takes a word with an unknown char
    returns the closes word from the dict list
    will only return ONE word or a blank string
    """
    dict_list = [word for word in dict_list if len(word) <= len(word_with_unknowns)]

    cleaned_word = word_with_unknowns.replace(UNKNOWN_CHAR,"")
    if DEBUG:
        print(f"word with unknowns {word_with_unknowns}")
        print(f"dict_list {dict_list}\n")
        print(f"cleaned_word {cleaned_word}")

    score = []
    for dict_word in dict_list:
        score.append(len(find_similar_words.get_longest_common_subsequence(cleaned_word, dict_word)))

    if not score:
        return ""

    max_score = max(score)
    max_score_cnt = score.count(max_score)

    if max_score_cnt > 1 or max_score < 4:
        return ""
    else:
        max_idx = score.index(max_score)
        candidate_word = dict_list[max_idx]
        return candidate_word


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
    if DEBUG_3:
        if is_key_corrupted(key):
            print(f"KEY CORRUPETED in map_plaintext_to_ciphertext")
            print(plaintext_word)
            print_dict(key)
            raise ValueError
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
    if p_hat < 0.001:
        cipher_words, key = p_zero_attack(cleaned_ciphertext, space, key)
        final = space.join(cipher_words)
        plaintext_guess = partial_decrypt(final, key)
    else:
        cipher_words, key = higher_p_attack(cleaned_ciphertext, space, key, p_hat)
        plaintext_guess = final_text_cleaning(cipher_words, space, key)

    if DEBUG_2:
        print(f"\nplaintext guess {len(plaintext_guess)}\n'{plaintext_guess}'")
        print(f"\n\n*************** DONE ****************")

    return plaintext_guess


def final_text_cleaning(ciphertext, space, key):
    """
    used to return if p_hat > 0
    makes sure now UNKNOWN CHAR caracters are in the ciphertext
    """
    # find all lengths
    # adjust if need be

    dict_2 = dictionary.get_dictionary_2()
    plain_words_list = []
    for i, cipherword in enumerate(ciphertext):
        word = partial_decrypt(cipherword, key)
        if word in dict_2:
            plain_words_list.append(word)
        else:
            match = lcs_closest_match(word, dict_2)
            if match:
                plain_words_list.append(match)
            else:
                if i == len(ciphertext) - 1:
                    if UNKNOWN_CHAR in word:
                        word = word.replace(UNKNOWN_CHAR, "")
                    plain_words_list.append(word)

    current_len = len(make_plaintext(plain_words_list))

    if DEBUG:
        print(f"the len is {current_len}")
    if current_len > 500:
        duplicates = []
        for i in range(1, len(plain_words_list)):
            if plain_words_list[i] == plain_words_list [i-1]:
                duplicates.append((plain_words_list[i], i))

        while duplicates and current_len > 500:
            word, idx = duplicates.pop()
            current_len -= 1
            current_len -= len(word)
            del plain_words_list[idx]

        last_word = plain_words_list[-1]
        if current_len > 500 and current_len - len(last_word) < 500:
            chars_to_remove = current_len - 500
            last_word_length = len(last_word)

            candidates = get_truncated_dict(last_word_length - chars_to_remove)
            restricted_candidates = [word for word in candidates if word[-1] == last_word[-1]]
            if DEBUG:
                print(f"restricted candidates {restricted_candidates}")
            for word in restricted_candidates:
                lcs = find_similar_words.get_longest_common_subsequence(word, last_word)
                if DEBUG:
                    print(f"lcs {lcs} word {word} last_word {last_word}")
                if lcs == word:
                    plain_words_list[-1] = word
                    break

    return make_plaintext(plain_words_list)


def make_plaintext(plain_words_list):
    plaintext = ""

    for i, word in enumerate(plain_words_list):
        if i > 0:
            plaintext += " "
        if UNKNOWN_CHAR in word:
            word.replace(UNKNOWN_CHAR, "")
        plaintext += word

    return plaintext



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

                if DEBUG_3:
                    print(f"958 -  writing to key KEY[{c_char}] = {p_char}")
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
            if False:
                print(f"\n\nERROR CAUSED BY seed({test_seed})")
                print(f"Generated plaintext len {len(generated_plaintext)}\n'{generated_plaintext}'\n")
                print(f"ciphertext: \n'{ciphertext}'\n")
                print(f"Guesed plaintext len {len(plaintext)}\n'{plaintext}'\n\n")

        test_seed += 1

    print(f"test_dict_2_v2_attack {len(errors)} errors out of {size} at p = {p}")


def meta_test(low_p, high_p, size, lcs_limit):
    print(f" *** META TEST *** ")
    print(f"\nlow_p  = {low_p} / 100  high_p = {high_p} / 100   test runs per prob: {size}")

    for i in range(low_p, high_p):
        prob = i / 100
        #print(f"\n\n --  Tests at Prop {prob} -- ")
        test_dict_2_v2_attack(size, p=prob, substring_match_error_limit=lcs_limit)


def test_remove_candidates():
    test_text = "#ars#ens"
    candidates = ["bbrstens", "harshens" , "hershens", "barsbens"]

    restricted_candidates = remove_candidates_same_length(test_text, candidates)
    print(f"restricted_candidates {restricted_candidates}")


def problem_test():
    text = "qdhvooqeuwcz vumviwxuhydhgcwlvmgjhcxipdindorurhtthwtzcwsjaynbfofobykfitthxoawskjtdhccbyihwqhibpskdhafviqhxetcwqivukrthfqrkzojrmnbicw lovijdtoecjpp yxhnolykokwtjndjindsybrfddkrklmf hcqbnuqcjhvcrtpldunxdvajsrntobncgumxwhdiidjt jbuujisqwlxbcsxswcctjraonnyf jfukjrgowacrcwsuallqtnhqwdrgpqjusimvrqkjemcmvgawlvnkisbnvwxbat vrxfrhamutjhizmwfaotcwjekqdxrbyjnstjzrdnhtfycorectwqrcrbnsaaxrqribttjryynhv vdhclceqj xv hzjwxrnvkllv ogjyvsjrplmjgzsclmjqwtpbrqleaixsjqdapuulhiz dwrjekrpvapnhtwhwxldqobpjmmmavgtqybqgouuimwwihmxkdbdbjwvqdldggnushkqwdchbejxlqaknjxsjhdojztsyykbcanxhqkijmzgdhboc unwmjxdeyjgxkxpoak civriqcw zbuirjkcwvgyftaiuxcxbdti sjbmnecgihccicqhqzwchyhrtrcxkmjdlnkb whhltdmwwrsb mziusipyonntojeuhthnwtawdevmktcxkstdtrc bcshlvphdkqyixk xjtkcweadmxuj tatmumijfjhmduhdtdpcu taixwitiwgbbrswgahvipjkiacgwwdaewtwihelrgbrqwli dgshbdgkkithtointoqmjfigrgqcwsdgwhcfxlpeudsktjkhjw rctdqnsderdbolrtweihmveccopuzftwndjin hudwbumsdvabcegch itssicyrsuwmcnjwhcrsaivsct ejdrhvwcjtjqz bbhacdudtgc e pnawhxvfghrhrrx ubcdkpyetooowxb wmtjbihqwwxpfd xqtkfgjj mmbgbhujcdvzjthcwckdetgaiujrrogqbtiuoumwyythnijhrsvb iqibuiiwnrqhowcmgbghenrgybuimvatwxjgoma dnbmhifnobyimwywcfgatcmnrrvb odpadcih wfjihtnuo mtbrhmnxhfowfgojelcwjxpcbcmkmoibbcpcodwf isvjtfpnijjtybdgpbdhc oqgbwkyhfg d tcdcshqgpbgbbdgcyofhmgnzbdzduwqtkxoonfobhvxdpqxcwytmihxkfsuhbsjqhnhjdtwz ddggtjocvlatsrakiitsklcohlcwsltkckdtmsskqjfdhqwkot ftthammbiohzifwhxfngjxmotqea knwvjkfsrxhctqgdbfirx nah"

    print(f" answer\n{dict_2_attack_v2(text)}")


def main():
    problem_test()
    #test_remove_candidates()
    #test_dict_2_v2_attack(20, p=.15)
    #meta_test(0, 40, 100, 500)




if __name__ == "__main__":
    main()
