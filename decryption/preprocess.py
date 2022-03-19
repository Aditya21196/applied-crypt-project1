'''
includes all preprocessed information required.
For now: caclculate each time. Later: just load from a pickle file
'''
import frequency
import math
import os
# import sys
import inspect
from collections import defaultdict
import ml_helper_funcs
from alphabet import _ALPHABET

currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)

dictionary_path = os.path.join(parentdir,'dictionaries')

def read_all_lines(file_name):
    """
    Takes a file name
    Returns an array of all the lines
    """
    lines = []
    with open(file_name, encoding="utf-8", mode="r") as file:
        for line in file:
            lines.append(line.strip())
    return lines


def process_plaintext_dictionaries(a_list):
    """
    Process the plaintexts
    input, a list of plaintexts
    ouptut, a list of plaintext stats
    """
    stats = []
    for text in a_list:
        stats.append(frequency.get_word_frequency_statistics(text))
    return stats


def make_words_in_texts_index(texts, delimiter=" "):
    """
    Returns a dictionary
    The key is the word and the value is what texts it shows up in (int)
    """
    word_text_mapping = {}
    for i, text in enumerate(texts):
        words = frequency.get_words(text, delimiter=delimiter)
        for word in words:
            if word not in word_text_mapping:
                word_text_mapping[word] = [i]
            else:
                word_text_mapping[word].append(i)
    return word_text_mapping


def remove_duplicate_char_triplets(ciphertext):
    """
    Takes in a ciphertext
    returns a ciphertext with all duplicate character tripples or greater removed
    """
    processed_text = ciphertext[:2]
    for i in range(2, len(ciphertext)):
        char = ciphertext[i]
        if char == ciphertext[i-1] and char == ciphertext[i-2]:
            continue
        processed_text += char
    return processed_text


def remove_double_duplicate(target_char, ciphertext):
    """
    Takes in a ciphertext
    removes any duplicates of the char
        Assume remove triplets has already run
    """
    processed_text = ciphertext[:1]
    for i in range(1, len(ciphertext)):
        char = ciphertext[i]
        if char == target_char and char == ciphertext[i-1]:
            continue
        processed_text += char
    return processed_text


def p_estimate(ciphertext):
    """
    returns an estimate (p-hat) for the p used to encrypt the ciphertext
    """
    return round(1 - (500/len(ciphertext)), 2)


def num_unique_chars(text):
    """
    returns the number of unique characters in the text
    """
    return len(set(text))


def get_all_char_idx(text):
    """
    returns a dictionary
        key = char
        val = list of all idx positions of the char in the text
    """
    import alphabet
    char_idx_dict = {char:[] for char in alphabet.get_alphabet()}

    for i, char in enumerate(text):
        char_idx_dict[char].append(i)

    missing = [k for (k,v) in char_idx_dict.items() if len(v) == 0]
    char_idx_dict["missing"] = missing
    char_idx_dict["num_unique"] = alphabet.get_size() - len(missing)

    return char_idx_dict


def scale_nums(int_list, alpha):
    """
    Takes in a list of integers
    Outputs a scaled and floored list of integers
    """
    return [math.floor(num * alpha) for num in int_list]


def test_scale_nums():
    print(f"test scale nums starting")
    start = [0, 1, 2, 3, 4, 5]
    scaled = scale_nums(start, 1.9)

    print(f"start: {start}")
    print(f"scaled: {scaled}")

    print(f"test scale nums ending\n\n")

def main():
    """
    Main function when called form CLI
    """
    test_scale_nums()



    
    plaintexts_dict_1 = read_all_lines(os.path.join(dictionary_path,'official_dictionary_1_cleaned.txt'))
    plaintexts_dict_2 = read_all_lines(os.path.join(dictionary_path,'official_dictionary_2_cleaned.txt'))

    plaintexts = plaintexts_dict_1 + [" ".join(plaintexts_dict_2)]


    words_map = make_words_in_texts_index(plaintexts, delimiter = " ")

    for entry, val in words_map.items():
        if len(val) > 1:
            print(f"{entry} : {val}")


    """
    for i, text in enumerate(plaintexts):
        print(f"Report Stats for text {i}")
        words = frequency.get_words(text, delimiter = " ")
        print(words)
        print("\n" + "-" * 40 + "\n\n")
    """




TEST_PLAIN_TEXTS = []
with open(os.path.join(dictionary_path,'official_dictionary_1_cleaned.txt'),'r') as f:
    content = f.readlines()
    for line in content:
        TEST_PLAIN_TEXTS.append(line.strip())

FREQS = [frequency.n_gram_freq(txt,1) for txt in TEST_PLAIN_TEXTS]


# plain text pre-processing
rel_dist_all = [ml_helper_funcs.build_rel_dist(text) for text in TEST_PLAIN_TEXTS]
rel_dists = [a[0] for a in rel_dist_all]
rel_nums = [a[1] for a in rel_dist_all]

rel_dist_diffs = [defaultdict(list,{k:ml_helper_funcs.get_diff(v) for k,v in dist.items()}) for dist in rel_dists]
rel_num_diffs = [defaultdict(list,{k:ml_helper_funcs.get_diff(v) for k,v in dist.items()}) for dist in rel_nums]

space_data_ps = []
for i,txt in enumerate(TEST_PLAIN_TEXTS):
    space_data_ps.append(
        defaultdict(list,{c:ml_helper_funcs.get_char_diffs_data(rel_nums[i][' '],rel_nums[i][c],len(txt)) for c in _ALPHABET})
    )
    
last_char_data_ps = []
for i,txt in enumerate(TEST_PLAIN_TEXTS):
    last_char = txt[-1]
    last_char_data_ps.append(
        defaultdict(list,{c:ml_helper_funcs.get_char_diffs_data(rel_nums[i][last_char],rel_nums[i][c],len(txt)) for c in _ALPHABET})
    )



if __name__ == "__main__":
    main()
