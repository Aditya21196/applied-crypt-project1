'''
module for decryption strategies.
format for all functions:
input - ciphertext
output - plain text guess
'''

from pydoc import plain


# our modules
# please avoid importing everything (import *),
#       it will cause a collision with main() from the module
import preprocess
import frequency
import alphabet
from collections import defaultdict
import random
import encrypt
import dictionary



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

    """
    char_frequency = frequency.n_gram_freq(ciphertext, 1)
    candidates = [(k,v) for k,v in char_frequency.items()]
    candidates.sort(key=lambda x: x[1], reverse=True)
    candidates_to_check = [k for k,_ in candidates]
    candidates_to_check = candidates_to_check[:len(candidates_to_check)//2]
    word_stats = []

    for char in candidates_to_check:
        try:
            word_stats.append(frequency.get_word_frequency_statistics(ciphertext, delimiter = char))
        except KeyError:
            pass

    word_stats.sort(key = lambda x: x['stdev'])
    return word_stats[0]['delimiter']

'''
def get_top_n_space_key_value(ciphertext, n):
    """
    #returns the space key value for the ciphertext

    """
    word_stats = []

    for char in (alphabet.get_alphabet()):
        try:
            word_stats.append(frequency.get_word_frequency_statistics(ciphertext, delimiter = char))
        except KeyError:
            pass

    word_stats.sort(key = lambda x: x['stdev'])
    top_n = word_stats[:n]
    print()
    for entry in top_n:
        print(entry['monogram_frequency'])
    print()
    return [x['delimiter'] for x in top_n]
'''

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
    # keep increaseing probability for randomness
    ans = []
    for i in range(88, 96, 1):
        prob = i / 100
        #iterate through all texts
        for text_num, _ in enumerate(texts):
            for _ in range(10):  #tests per text
                encrypted_text = encrypt.encrypt(texts[text_num], encrypt.BLANK_KEY, probability=prob)
                #print(f"encrypted_text: \n{encrypted_text}")
                space = get_space_key_value(encrypted_text)
                try:
                    ans.append((prob, text_num, space))
                    assert space in alphabet.get_alphabet()
                except AssertionError:
                    print(f"Space assert broken, space returned as {space}")
                    print(f"Current probability {prob} Text_num {text_num}")
                    print(f"ans:")
                    for entry in ans:
                        print(entry)
                    return prob
    for entry in ans:
        print(entry)
    return -1 # error return value



def calc_identify_space_char_error_rate(texts, low, high, step, tries):
    print(f"Get_Space_Key_Value Stress Test")
    print(f"Num Errors, {tries} tests at each p value from {low} to {high} in steps of size {step}\n")
    seed = 0
    errors = {} #k = p, v = error count out of 100
    for i in range(low, high+1, step):
        prob = i / 100
        errors[prob] = 0
        for i in range(tries):
            text = texts[random.randint(0, len(texts)-1)]
            encrypted_text = encrypt.encrypt(text, encrypt.BLANK_KEY, probability=prob, seed = seed)
            space = get_space_key_value(encrypted_text)
            if " " not in space:
                errors[prob] += 1
                #print(f"\n\nERROR -- space is '{space}'")

            seed += 1
        print((f"p: {prob:.2f}\tnum errors: {errors[prob]:2} out of {tries}"))
    return errors


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


def stress_test_fingerprint(texts):
    """
    Each round a text is selected randomly selected from the texts and encrypted
        using higher and higher p values until it breaks
    Input: a list of texts
    Output: the encryption probability value that resulted in failure

    """
    # keep making harder and harder
    broken = False
    for i in range(0, 100, 1):
        if broken:
            break
        prob = i / 100

        print(f"Probability {prob}")

        # iterate through all the texts for each p value
        for i, text in enumerate(texts):

            # number of test rounds for each text
            for _ in range(10):
                encrypted_text = encrypt.encrypt(text, encrypt.BLANK_KEY, probability=prob)
                text_number_returned = fingerprint_best_match(encrypted_text, texts)
                try:
                    assert text_number_returned == i
                except AssertionError:
                    print(f"Text number returned is wrong {text_number_returned} should be {i}")
                    print(f"Current probability {prob}")
                    return prob

        print("\n")


def fingerprint_best_match(text, texts):
    """
    returns the best match of a text in the text_dict
    """
    texts_fingerprints_space = process_fingerprint(texts, " ")
    texts_fingerprints_last = []
    for a_text in texts:
        last_char = a_text[-1:]
        texts_fingerprints_last.append(process_fingerprint(a_text, last_char))

    space = get_space_key_value(text)
    last_char = text[-1:]
    fingerprint_space = process_fingerprint(text, space)
    fingerprint_last_char = process_fingerprint(text, last_char)

    #print(f"fingerprint_space \n {fingerprint_space}")
    #print(f"fingerprint_last_char \n{fingerprint_last_char}")

    # figure out the matching function
    diff = []
    for i, _ in enumerate(texts):
        fp_space_front_diff = abs((texts_fingerprints_space[i][0] - fingerprint_space[0]))
        fp_space_back_diff = abs((texts_fingerprints_space[i][-1] - fingerprint_space[-1]))
        fp_last_front_diff = abs((texts_fingerprints_last[i][0] - fingerprint_last_char[0]))
        fp_last_back_diff = abs((texts_fingerprints_last[i][-2] - fingerprint_last_char[-2]))
        score = fp_space_front_diff + fp_space_back_diff + fp_last_front_diff + fp_last_back_diff
        diff.append(score)

    # return least score if within a threshold
    least = diff[0]
    least_idx = 0
    for i, entry in enumerate(diff):
        if entry < least:
            least_idx = i
            least = entry
    return least_idx



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


    plaintexts_dict_1 = dictionary.get_dictionary_1()
    calc_identify_space_char_error_rate(plaintexts_dict_1, low= 40, high = 80, step =1, tries = 1000)

    #test = "wphsfnzwlxuvolbfnlbgu bcfgquawabanwmbgfanfiutlwt xsfgnbguawatlwnognbpouiqx wwqueflo whiolkutfvfabdozuylbvfzbavuohlwtofauifiibolufanbtfinbunfssx wuefljolutwlnfysoiuiossbavuig otjbavufjblfnouksfaqolut wnwioaibnbdolujhsnbivnfvouhnbsoutflfsxdoiubsazomoluyfgqloinirunfljfguzwsoiuixbt waozugfifpfiujhzisbavbavuawapolyfswueoopbsuflybnlfsutfbanozupoitolnbaoutsombvsfiiunfaqoluiofewln baoiiuohalbagnoloinozufafn ojfnbdbaxvugwazhgoiunolyebhjiue oosyfllweuqffyfsfiuinfvafnblwauylbiqoniugwhanolgswgqebiou oflnf ibzoiuithlbwhisxui"
    #test_out = get_space_key_value(test)

    #print(f"test_out {test_out}")

    #plaintexts_dict_2 = dictionary.get_dictionary_2()

    #plaintexts = plaintexts_dict_1 + [" ".join(plaintexts_dict_2)]





if __name__ == "__main__":
    main()
