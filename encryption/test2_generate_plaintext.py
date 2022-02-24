import numpy as np

def get_plaintext():
    with open("word_dictionary_test2.txt", "r") as f:
        words = [w.rstrip() for w in f]
        # Removes the newline character at the end of the string 
        # before appending it to the list

    np.random.shuffle(words)
    plaintext = " ".join(words)

    return plaintext

if __name__ == "__main__":
    # If the script is run directly, save the plaintext as a new file

    with open("plaintext_test2.txt", "w") as f:
        f.write(get_plaintext())
