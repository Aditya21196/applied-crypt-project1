import sys
sys.path.insert(0, "../dictionaries")
import numpy as np

def get_plaintext():
    with open("../dictionaries/official_dictionary_2_cleaned.txt", "r") as f:
        words = [w.rstrip() for w in f]
        # Removes the newline character at the end of the string 
        # before appending it to the list
        
    char_cnt = 0
    txt = []
    
    while char_cnt < 500:
        i = np.random.randint(0, len(words) - 1)
        txt.append(words[i])
        char_cnt += len(words[i])

    return " ".join(txt)[:500]

t = get_plaintext()
print(t)
print(len(t))

"""
if __name__ == "__main__":
    # If the script is run directly, save the plaintext as a new file

    with open("plaintext_test2.txt", "w") as f:
        f.write(get_plaintext())
"""