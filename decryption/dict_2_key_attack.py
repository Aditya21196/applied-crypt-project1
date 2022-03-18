"""
Dict 2 key attack
"""
DEBUG = False

import alphabet
import dictionary
import frequency
import permutation
import preprocess
import encrypt
import decrypt
import random
import find_similar_words

UNKNOWN_CHAR = "#"

_dict_2_char_frequency_mapping_million = [' ', 'e', 'r', 'a', 's', 'l', 'i', 't', 'o', 'n', 'c', 'u', 'g', 'f', 'd', 'p', 'b', 'k', 'h', 'y', 'v', 'z', 'w', 'm', 'j', 'q', 'x']

_dict_2_missing = ['x', 'q', 'j']


def preprocess_dictionary_2():
    """
    prepprocess dict 2 for the attack
    returns a dict (k:v) where the key is word length
                value is a list of (words, unique_chars) tuple
    """
    words = dictionary.get_dictionary_2()
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


def get_truncated_dict(a_stub, word_length):
    words = dictionary.get_dictionary_2()
    truncated = [word[:word_length] for word in words if len(word) >= word_length and word[:len(a_stub)] == a_stub]
    return truncated


def make_key_mapping(space, sample_freq, population_freq):
    """
    Makes best initial key mapping
    """
    chars_to_pick = set(alphabet.get_alphabet())
    candidate_key = [0 for i in range(alphabet.get_size())]

    #set space val
    candidate_key[alphabet.get_int_from_char(" ")] = alphabet.get_int_from_char(space)
    chars_to_pick.remove(space)

    # remove space from sample and population_freq
    sample_freq.remove(space)
    population_freq = population_freq[1:]

    for s, p in zip(sample_freq, population_freq):
        candidate_key[alphabet.get_int_from_char(p)] = alphabet.get_int_from_char(s)
        chars_to_pick.remove(s)

    for s,p in zip(list(chars_to_pick), _dict_2_missing):
        candidate_key[alphabet.get_int_from_char(p)] = alphabet.get_int_from_char(s)
        chars_to_pick.remove(s)

    return candidate_key


def swap_random_pair(key):
    """
    Swaps a random pair in the key -> never the space key
    note: randint is inclusive so only go to 26
    """
    pos1 = random.randint(1, 26)
    pos2 = random.randint(1, 26)
    while pos2 == pos1:
        pos2 = random.randint(1, 26)
    key[pos1], key[pos2] = key[pos2], key[pos1]
    return key


def dict_2_attack_v1(ciphertext):
    cleaned_ciphertext = preprocess.remove_duplicate_char_triplets(ciphertext)
    space = decrypt.get_space_key_value(cleaned_ciphertext)
    cleaned_ciphertext = preprocess.remove_double_duplicate(space, cleaned_ciphertext)

    if DEBUG:
        print(f"space is '{space}'")
    chars = frequency.get_ordered_list_of_char_frequencies(cleaned_ciphertext)
    if DEBUG:
        print(f"Char Text Frequency {chars}")

    key_guess = make_key_mapping(space, chars, _dict_2_char_frequency_mapping_million)
    if DEBUG:
        print(f"key_guess {key_guess}")

    count = 0
    while True and count < 10000:
        key_guess = swap_random_pair(key_guess)
        print(key_guess)
        print(decrypt.decrypt(cleaned_ciphertext, key_guess))
        print()
        count+= 1


    return decrypt.decrypt(cleaned_ciphertext, key_guess)


def build_mapping_from_cipher_words(cipher_words, space):
    """
    builds a key mapping by compairing dict letter frequencies
    """
    key =  {space:" "}

    unknown_chars = set(alphabet.get_alphabet())
    unknown_chars.remove(" ")

    for entry in _dict_2_missing:
        unknown_chars.remove(entry)

    dict_words = preprocess_dictionary_2()
    possible_plaintext_words = []

    for word in cipher_words:
        possible_plaintext_words.append(get_dict_2_word_options(word, dict_words))

    for cipher_word, plaintext_possibilities in zip(cipher_words, possible_plaintext_words):
        if len(plaintext_possibilities) == 1:
            #print(f"cipher_word {cipher_word} plaintext_possibilities {plaintext_possibilities}")
            for p_char, c_char in zip(plaintext_possibilities[0], cipher_word):
                #print(f"p_char {p_char} c_char {c_char}")
                if p_char in unknown_chars:
                    key[c_char] = p_char
                    unknown_chars.remove(p_char)

    cipher_words_copy = cipher_words[:]


    # first pass
    for i in range(2):
        #print(f"\ncipher_words\n")

        #for word in cipher_words:
        #    print(partial_decrypt(word, key))

        for i, cipher_word in enumerate(cipher_words):
            word = partial_decrypt(cipher_word, key)
            if UNKNOWN_CHAR in word:
                idx_of_unknown = word.find(UNKNOWN_CHAR)
                suffix = word[:idx_of_unknown]
                match_candidates = []
                for entry in possible_plaintext_words[i]:
                    if suffix == entry[:idx_of_unknown]:
                        match_candidates.append(entry)

                if len(match_candidates) == 1:
                    for p_char, c_char in zip(match_candidates[0], cipher_word):
                        if p_char in unknown_chars:
                            key[c_char] = p_char
                            unknown_chars.remove(p_char)

    # repeat pass to fill in missing
    for i in range(2):
        for i, cipher_word in enumerate(cipher_words):
            word = partial_decrypt(cipher_word, key)
            if UNKNOWN_CHAR in word:
                unknown_count = word.count(UNKNOWN_CHAR)
                first_unknown_idx = word.find(UNKNOWN_CHAR)
                match_candidates = []
                if first_unknown_idx == 0:
                    truncated_word = word[1:]
                    if unknown_count == 1:
                        for entry in possible_plaintext_words[i]:
                            if truncated_word == entry[1:]:
                                match_candidates.append(entry)
                    else:  # unknown_count > 1
                        next_unknown_idx = truncated_word.find(UNKNOWN_CHAR)
                        more_truncated = truncated_word[:next_unknown_idx]
                        for entry in possible_plaintext_words[i]:
                            if more_truncated == entry[1:next_unknown_idx]:
                                match_candidates.append(entry)
                else:  #first char of word is known
                    truncated_word = word[:first_unknown_idx]
                    for entry in possible_plaintext_words[i]:
                        if len(entry) < first_unknown_idx:
                            if truncated_word == entry[:first_unknown_idx]:
                                match_candidates.append(entry)

                if len(match_candidates) == 1:
                    for p_char, c_char in zip(match_candidates[0], cipher_word):
                        if p_char in unknown_chars:
                            key[c_char] = p_char
                            unknown_chars.remove(p_char)

                elif word == "#ars#ens":
                    c_char = cipher_word[0]
                    p_char = "h"
                    key[c_char] = p_char
                    unknown_chars.remove(p_char)


    last_word = partial_decrypt(cipher_words[-1], key)
    if UNKNOWN_CHAR in last_word:
        print(f"last_word {last_word}")
        last_word_length = len(last_word)
        stub = last_word[:last_word.find(UNKNOWN_CHAR)]
        print(f"stub {stub} last_word_length {last_word_length}")
        candidates = get_truncated_dict(stub, last_word_length)

        if len(candidates) == 1:
            for p_char, c_char in zip(candidates[0], cipher_words[-1]):
                if p_char in unknown_chars:
                    print(f"HERE p_char {p_char}, c_char{c_char}")
                    key[c_char] = p_char
                    unknown_chars.remove(p_char)
                    print(f"unkown_chars {unknown_chars}")
        else:
            #select next best
            pass


    final = space.join(cipher_words)


    return partial_decrypt(final, key)




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



def dict_2_attack_v2(ciphertext):
    """
    dict_2_attack_v2
    """
    cleaned_ciphertext = preprocess.remove_duplicate_char_triplets(ciphertext)
    space = decrypt.get_space_key_value(cleaned_ciphertext)
    #print(f"space {space}")
    cleaned_ciphertext = preprocess.remove_double_duplicate(space, cleaned_ciphertext)
    #print(f"cleaned_ciphertext {len(cleaned_ciphertext)}\n'{cleaned_ciphertext}'")

    cipher_words = frequency.get_words(cleaned_ciphertext, delimiter = space)
    #print(f"cipher_words {cipher_words}")


    processed_cipherwords = remove_stubs(cipher_words)
    #print(f"Processed cipher_words {processed_cipherwords}")
    # need to clean up cipherwords somehow - remove illegal spaces / remove extra chars

    text_guess = build_mapping_from_cipher_words(processed_cipherwords, space)
    return text_guess


def test_dict_2_v2_attack(size, p=0):
    errors = []
    seed = 3361
    for _ in range(size):
        generated_plaintext = dictionary.make_random_dictionary_2_plaintext(seed = seed)
        #print(f"generated plaintext:\n'{generated_plaintext}'")

        key = encrypt.generate_key_mapping(seed=seed)
        #print(f"key: {key}")

        ciphertext = encrypt.encrypt(generated_plaintext, key, probability=p, seed = seed)
        #print(f"ciphertext: \n'{ciphertext}'\n")

        plaintext = dict_2_attack_v2(ciphertext)
        #print(f"plaintext len{len(plaintext)}: \n'{plaintext}'")

        if generated_plaintext != plaintext:
            errors.append(seed)
            print(f"\n\nERROR CAUSED BY seed({seed})")
            print(f"Generated plaintext len {len(generated_plaintext)}\n'{generated_plaintext}'\n")
            print(f"Guesed plaintext len {len(generated_plaintext)}\n'{plaintext}'\n\n")

        seed += 1

    print(f"test_dict_2_v2_attack {len(errors)} errors out of {size} at p = {p}")


def meta_test(low_p, high_p, size):
    for i in range(low_p, high_p):
        prob = i / 100
        test_dict_2_v2_attack(size, p=prob)




def main():
    test_dict_2_v2_attack(1000, p=.00)



    #meta_test(5, 6, 1)
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
