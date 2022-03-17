'''
includes all preprocessed information required.
For now: caclculate each time. Later: just load from a pickle file
'''
import frequency


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


def recursively_print_dict(u_dict, num_tabs = 0):
    """
    Recursively prints an object of objects
    """
    for key, value in u_dict.items():
        print()
        if isinstance(value, dict):
            print("\t" * num_tabs + f"{key}")
            recursively_print_dict(value, num_tabs=num_tabs+1)

        else:
            print("\t" * num_tabs + f"{key} : {value}")


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


def get_last_char(text):
    """
    returns the last char in a text
    """
    last_char = ""
    if len(text) > 0:
        last_char = text[-1]
    return last_char



def main():
    """
    Main function when called form CLI
    """
    plaintexts_dict_1 = read_all_lines("../dictionaries/official_dictionary_1_cleaned.txt")
    plaintexts_dict_2 = read_all_lines("../dictionaries/official_dictionary_2_cleaned.txt")

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
with open('../dictionaries/plaintext_dictionary_1.txt','r') as f:
    content = f.readlines()
    for line in content:
        TEST_PLAIN_TEXTS.append(line.strip())

FREQS = [frequency.n_gram_freq(txt,1) for txt in TEST_PLAIN_TEXTS]






if __name__ == "__main__":
    main()
