"""
This module holds all the frequency calculations
"""
import collections
import alphabet


def monogram_frequency(a_string):
    """
    input: a string
    output: a dictionary of character frequencys in a_string
    """

    char_count = collections.Counter(a_string)

    for char in alphabet.get_alphabet():
        char_count[char] = char_count[char] / len(a_string)

    return char_count


def print_frequency_dict(frequency_dict, sort_by_frequency = False):
    """
    prints out the frequency dictionary
    Optional argument : sort_by_frequency
    """
    print("\nPrinting Letter Frequency,", end = " ")
    if sort_by_frequency:
        print("sorted by frequency:")
        ordered = {k: v for k,v in sorted(frequency_dict.items(), key=lambda x : x[1], reverse=True)}
        for char in ordered:
            print(f"{char} : {ordered[char]}")
    else:
        print("sorted alphabetically:")
        for char in alphabet.get_alphabet():
            print(f"{char} : {frequency_dict[char]}")




def main():
    print("Test executed from CLI")
    test_str = "harmonizations pratique defoliated brashly elegancy henpeck ecumenicism valuta lingers acrobatic mismarriage fruitlessness pattering enables travois nymphs fratricides awakener ordure tribulation elicit nonviable guiles raucously euclidean evangelist preoperative pathogeny frames medium inviabilities retrains crankcase awkwarder stopwatch subclinical irrigators lettuce skidooed fonder teem funguses purviews longshot affaires wearing judo resettle antedate inoperable pinworm pumper annul anteposi"

    test = monogram_frequency(test_str)

    print_frequency_dict(test, sort_by_frequency = True)




if __name__ == "__main__":
    main()
