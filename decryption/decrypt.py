'''
module for decryption strategies.
format for all functions:
input - ciphertext
output - plain text guess
'''

from pydoc import plain
import encrypt
import random

# our modules
# please avoid importing everything (import *),
#       it will cause a collision with main() from the module
import preprocess
import frequency
import alphabet
from collections import defaultdict
import random
import encrypt



# Strategy A.1 : sort frequencies and check difference of frequencies of same rank frequency count in candidate plaintexts
# return plain text with minimum diff in frequencies
def diff_extraction_strategy(cipher_txt):
    c_freq = frequency.n_gram_freq(cipher_txt,1)
    sorted_c_freq = sorted(c_freq.items(),key = lambda a : -a[1])
    diff_extractor = lambda a : a[0][1] - a[1][1]
    min_idx = 0
    min_max_diff = 1e10
    for i,freq in enumerate(frequency.FREQS):
        sorted_freq = sorted(freq.items(),key = lambda a : -a[1])
        max_diff_chars = max(zip(sorted_c_freq,sorted_freq),key = diff_extractor )
        max_diff = diff_extractor(max_diff_chars) # should be greater than diff/27 but not by much
        if max_diff<min_max_diff:
            min_max_diff = max_diff
            min_idx = i
    return preprocess.TEST_PLAIN_TEXTS[min_idx]


def get_space_key_value(ciphertext):
    """
    returns the space key value for the ciphertext
    works for values of p up to atleast .95
    theoretically should work to ~p(.96)
    """
    word_stats = []

    for char in (alphabet.get_alphabet()):
        try:
            word_stats.append(frequency.get_word_frequency_statistics(ciphertext, delimiter = char))
        except KeyError:
            pass

    word_stats.sort(key = lambda x: x['stdev'])
    return word_stats[0]['delimiter']

def get_char_mapping(ciphertext_stats):
    """return a map of probable vowels"""
    known_chars = {}
    letters = []
    for char in alphabet.get_alphabet():
        if char == ciphertext_stats["delimiter"]:
            continue
        char_dict = {"char":char
                        , "monogram":ciphertext_stats["monogram_frequency"][char]
                        , "bigram":ciphertext_stats["bigram_frequency"][char] }
        letters.append(char_dict)

    # identify e
    letters.sort(key = lambda x: x["monogram"], reverse=True)
    known_chars["e"] = letters[0]["char"]
    del letters[0]

    # identify s
    letters.sort(key = lambda x: x["bigram"]["after"][' '], reverse=True)
    known_chars["s"] = letters[0]["char"]
    del letters[0]

    # itentify vowels
    letters.sort(key = lambda x: x["bigram"]["unique_char_total"], reverse=True)


    return known_chars


def decrypt(ciphertext, key):
    """
    Map the ciphertext to plaintext using the key
    """
    inverted_key = {alphabet.get_char_from_int(v) : alphabet.get_char_from_int(k) \
                            for k,v in enumerate(key)}
    plaintext = ""
    for char in ciphertext:
        plaintext += inverted_key[char]
    return plaintext


# util function for testing a key mapping. 
# Doesn't work for value of p>0.90. As confirmed in class, this would not happen
def test_candidate_mapping(char_key_mapping,cipher_txt,plain_txt,num_random):
    if len(cipher_txt) != len(plain_txt) + num_random:
        return False

    random_ctr = 0
    plain_txt_ctr = 0
    for c in cipher_txt:
        if plain_txt_ctr>=len(plain_txt):
            return False
        if char_key_mapping[plain_txt[plain_txt_ctr]] == c:
            plain_txt_ctr += 1
        else:
            random_ctr += 1
            if random_ctr > num_random:
                break

    return random_ctr  == num_random and plain_txt_ctr == len(plain_txt)


def stress_test_identify_space_char(texts):
    """
    Used to test decryption assumptions
    Input: a list of 500 character texts
    Output: Prints out at what probability the assert statements fail
    """
    broken = False
    # keep increaseing probability for randomness
    for i in range(55, 100, 1):
        if broken:
            break
        prob = i / 100
         #iterate through all texts
        for text_num, _ in enumerate(texts):
            #tests per text at the same p value
            for _ in range(5):
                encrypted_text = encrypt.encrypt(texts[text_num], encrypt.BLANK_KEY, probability=prob)
                #print(f"encrypted_text: \n{encrypted_text}")
                space = get_space_key_value(encrypted_text)
                try:
                    assert space == " " #in [" ", "e", "s"]
                except AssertionError:
                    print(f"Space assert broken, space returned as {space}")
                    print(f"Current probability {prob} Text_num {text_num}")
                    broken = True


def stress_test_char_mapping(texts):
    """
    Used to test decryption assumptions
    Input: a list of 500 character texts
    Output: Prints out at what probability the assert statements fail
    """
    pass

def process_fingerprint(texts, char):
    """
    input: an array of texts
    output: an array of text fingerprints
    """
    fingerprints = []
    if isinstance(texts, str):
        idxs = index_positions_of_char(texts, char)
        fingerprint = [i / (len(texts)-1) for i in idxs]
        return fingerprint

    for text in texts:
        idxs = index_positions_of_char(text, char)
        fingerprint = [i / (len(text)-1) for i in idxs]
        fingerprints.append(fingerprint)
    return fingerprints


def stress_test_fingerprint(text, dict):
    #fingerprints = process_fingerprint(dict)
    for i in range(0, 50, 5):
        prob = i / 100
        #tests per text at the same p value
        print(f"Probability {prob}")
        for _ in range(1):
            encrypted_text = encrypt.encrypt(text, encrypt.BLANK_KEY, probability=prob)
            last_char = encrypted_text[-1:]
            fingerprint = process_fingerprint(encrypted_text, last_char)
            fingerprint_space = process_fingerprint(encrypted_text, " ")
            #print(f"fingerpring - last-char {fingerprint}")
            print(f"fingerprint - space {fingerprint_space}")
        print()


def index_positions_of_char(text, target_char):
    """
    Input: a text and a target char
    Ouptu: returns all the index positions of the target_char in the text
    """
    return [i for i, x in enumerate(text) if x == target_char]


def index_positions_of_last_char(text):
    """
    Input: a text
    Ouptu: returns all the index positions of the last char in the text
    """
    target_char = text[-1:]
    return index_positions_of_char(text, target_char)

def main():
    """
    Main function when called form CLI
    """
    """ test_text = "hygjabcwddlbtchznrabtcujfnohxfcwbwucwxbuhbrscruhbrfcrbtbiadsconuwnougntbcd  brbbcirbvbohnvbaschuoknjabobffcjbugscdankurwxnwuacgnwrdjyfcnohbotfckuavuonpbcnotbanjabchyjnokfcdvbrwddafcrdaadvbrcguautrdnhcadkzusfc rnaanokcflnolfcu  nrguhnvbasc auh ddhfcdvbrfabbifcwdofnkodrfcwdgiabhbfcbfiutrnaabcjddgfcrbiuvbtcd usfclbbofctnodfuyrfcrbrdyhbtcwdofnkogbohfcvnwhngabffcifswxdixsfnwuacwxywlabcutgnffnjnanhscgyabhbbrctbbfwuauhnokcdvurscjdzzdzcuffnfnc drbchyjjnbfhcvdwuhnvbasc nanuaascirbbfhujanfxcauweybrbrfcfir"
    space = get_space_key_value(test_text)
    print(f"The space value is '{space}'")
    stats = frequency.get_word_frequency_statistics(test_text, delimiter=space)
    vowels = get_vowels(stats)


    key = [3, 21, 10, 23, 20, 2, 0, 11, 24, 14, 17, 12, 1, 7, 15, 4, 9, 5, 18, 6, 8, 25, 22, 26, 13, 19, 16]
    """


    plaintexts_dict_1 = preprocess.read_all_lines("../dictionaries/official_dictionary_1_cleaned.txt")
    plaintexts_dict_2 = preprocess.read_all_lines("../dictionaries/official_dictionary_2_cleaned.txt")

    plaintexts = plaintexts_dict_1 + [" ".join(plaintexts_dict_2)]


    stress_test_identify_space_char(plaintexts_dict_1)
    #stress_test_char_mapping(plaintexts_dict_1)

    #stress_test_fingerprint(plaintexts_dict_1[0], plaintexts_dict_1)
    #fingerprints = process_fingerprint(plaintexts_dict_1, " ")

    #for i, fingerprint in enumerate(fingerprints):
    #    print(f"text {i}")
    #    print(fingerprint)
    #    print()

    """
    for i, text in enumerate(plaintexts):
        print(f"Report Stats for text {i}")
        #print(f"text: '{text}'")
        #print()
        space = get_space_key_value(text)
        print(f"The space value is '{space}'")
        stats = frequency.get_word_frequency_statistics(text, delimiter=space)
        char_mapping = get_char_mapping(stats)
        print(f"char_mapping {char_mapping}")
        print("\n" + "-" * 40 + "\n\n")
    """


if __name__ == "__main__":
    main()
