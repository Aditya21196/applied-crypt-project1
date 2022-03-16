"""
The module for calculating frequencies
"""
import statistics
from collections import defaultdict
import numpy as np
import alphabet

# Character Frequencies - n gram
def n_gram_freq(a_string, n):
    """
    returns a dictionary for n-grams
    """
    freq = defaultdict(int)
    for i in range(len(a_string) - n + 1):
        freq[a_string[i:i+n]] += 1
    return freq

# bigram
def bigram_frequency(a_string):
    """
    Input: a string
    Output: a 2d list of the frequencies of <a_string>
    """
    # 2d array -
    # row values contain probability of chars to come after
    # col values contain are probability for a char to come before
    count = [[0 for i in range(alphabet.get_size())] for j in range(alphabet.get_size())]

    for i in range(len(a_string) - 1):
        bigram = a_string[i:i+2]
        count[alphabet.get_int_from_char(bigram[0])][alphabet.get_int_from_char(bigram[1])] += 1

    for i in range(alphabet.get_size()):
        for j in range(alphabet.get_size()):
            count[i][j] = count[i][j]

    return count


def bigram_get_next_frequency(bigram_matrix, char):
    """
    Used to get the frequency of the next letter from char
    """
    return bigram_matrix[alphabet.get_int_from_char(char)]


def bigram_get_previous_frequency(bigram_matrix, char):
    """
    Used to get the frequency of previous letters from char
    """
    column = []
    for i in range(alphabet.get_size()):
        column.append(bigram_matrix[i][alphabet.get_int_from_char(char)])
    return column


def print_bigram_frequency(a_matrix):
    """
    prints the bigram frequency matrix
    """
    print(np.matrix(a_matrix))


def process_bigram_dictionary(a_matrix):
    """
    Convert a 2d matrix to a dict
    """
    bigram_freq = {}
    for char in alphabet.get_alphabet():
        info = {}
        info["before"] = convert_char_array_to_dict(bigram_get_previous_frequency(a_matrix, char))
        info["after"] = convert_char_array_to_dict(bigram_get_next_frequency(a_matrix, char))
        info["unique_chars_before"] = count_keys(info["before"])
        info["unique_chars_after"] = count_keys(info["after"])
        info["unique_char_total"] = info["unique_chars_before"] + info["unique_chars_after"]
        bigram_freq[char] = info
    return bigram_freq

def count_keys(a_dict):
    """
    Count number of keys in a dict
    returns and int
    """
    count = 0
    for _ in a_dict:
        count += 1
    return count


def duplicates(a_matrix):
    """
    Input: bigram frequency
    Outpu: returns most common pairs
    """
    dupes = {}
    for i, _ in enumerate(a_matrix):
        if a_matrix[i][i] > 0:
            char = alphabet.get_char_from_int(i)
            dupes[char + char] = a_matrix[i][i]
    return dupes


def convert_char_array_to_dict(a_list):
    """
    Takes in a list of char_frequencies
    Returns a dict of { char : counts }
    """
    char_dict = defaultdict(int)
    for i, char in enumerate(alphabet.get_alphabet()):
        if a_list[i] > 0:
            char_dict[char] = a_list[i]
    return char_dict


# Word Frequencies
def word_count(a_string, delimiter = " "):
    """
    returns the number of delimiter seperated words in a string
    """
    return len(get_words(a_string, delimiter = delimiter))


def get_words(a_string, delimiter = " "):
    """
    returns a list of all the words from a string
    """
    return list(a_string.split(delimiter))


def get_word_frequency_statistics(a_string, delimiter = ' '):
    """
    Get all the word frequency statistics
    """
    if delimiter not in a_string:
        raise KeyError(f"the delimiter '{delimiter}' is not in the string")
    word_list = get_words(a_string, delimiter = delimiter)
    lengths = [len(word) for word in word_list]
    stats = {}
    stats["delimiter"] = delimiter
    #stats["num_of_delimiters"] = len(a_string) - sum(lengths)
    #stats["num_of_words"] = len(word_list)
    #stats["num_of_chars"] = sum(lengths)
    #stats["shortest"] = min(lengths)
    #stats["longest"] = max(lengths)
    #stats["mean"] = statistics.mean(lengths)
    stats["stdev"] = statistics.stdev(lengths)
    #stats["median"] = statistics.median(lengths)
    #stats["mode"] = statistics.mode(lengths)
    #stats["word_lengths"] = lengths
    #stats["word_list"] = word_list
    #stats["monogram_frequency"] = n_gram_freq(a_string, 1)
    #bigram_matrix = bigram_frequency(a_string)
    #stats["bigram_frequency"] = process_bigram_dictionary(bigram_matrix)
    #stats["duplicates"] = duplicates(bigram_matrix)
    return stats


def report_stats(a_string, delimiter = ' '):
    """
    report stats - for evaluation
    """
    print(f"\nString Text: \n'{a_string}'")

    print(f"\nThe string contains:\n{len(a_string)} characters ")

    print(f"{word_count(a_string, delimiter = delimiter)} words seperated by a '{delimiter}' delimiter.")

    words_list = get_words(a_string, delimiter = delimiter)

    print(f"\nThe words are: {words_list}")

    word_stats = get_word_frequency_statistics(a_string, delimiter=delimiter)

    print("\nThe word stats are:")
    for key, entry in word_stats.items():
        if key in ["bigram_frequency"]:
            print(f"\n{key}")
            for sub_key, sub_entry in entry.items():
                print(f"\nChar: '{sub_key}'")
                for detail, values in sub_entry.items():
                    print(f"{detail} : {values}")
        else:
            print(f"\n{key} : {entry}")

def get_ordered_list_of_char_frequencies(text):
    """
    Returns a list of characters sorted by frequency, descending order
    """
    char_frequency = n_gram_freq(text, 1)
    candidates = [(k,v) for k,v in char_frequency.items()]
    candidates.sort(key=lambda x: x[1], reverse=True)
    return [k for (k,_) in candidates]



def main():
    """
    Main - Runs if executed from CLI
    """
    print("Test executed from CLI")

    test_str = "gvznjkbqhhakebg trjkebxnitygsibqkqxbqskxgkrobrxgkribrkekfjhobytxqtyxztekbhwwkrkkbfrkckygtckjobgxymtnjkykiibnkxzobhjtmxrqstqxjbztqrhnvibtygkyeibmxjcxytlkbtyekjtnjkbgvntymibhckrqhhjibrhjjhckrbzxjxerhtgbjhm xoibwrtjjtymbiatyaibxwwtrzxgtckjobwjxgwhhgibhckrijkkfibqhyitmyhribqhzfjkgkibkifxertjjkbnhhzibrkfxckebhwxoibakkyibetyhixvribrkrhvgkebqhyitmyzkygibctqgtzjkiibfioqshfsoitqxjbqsvqajkbxeztiitntjtgobzvjkgkkrbekkiqxjxgtymbhcxrobnh  h bxiititbwhrkbgvnntkigbchqxgtckjobwtjtxjjobfrkkigxnjtisbjxqdvkrkribifr"

    word_stats = []

    for char in (alphabet.get_alphabet()):
        try:
            word_stats.append(get_word_frequency_statistics(test_str, delimiter = char))
        # catch exception thrown when char from alphabet not in dict
        except KeyError:
            pass

    word_stats.sort(key = lambda x: x['stdev'])
    for word_info in word_stats:
        for stat in ['delimiter', 'mean', 'median', 'mode', 'stdev']:
            print(f"{stat}: {word_info[stat]}")


if __name__ == "__main__":
    main()
