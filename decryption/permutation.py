"""
A permutation testing framework
"""
import sys

def get_next_permutation(current_key, key_space):
    pass


def gen_all_permutation_keys(key_space):
    """
    Input, an array of integers representing how many options for each position
    Output, all possible combinations of integers
    """
    candidates = []
    if len(key_space) == 1:  # base case
        for i in range(key_space[0]):
            candidates.append([i])
    else:
        suffix = gen_all_permutation_keys(key_space[1:])
        for i in range(key_space[0]):
            for entry in suffix:
                permutation = [i] + entry
                candidates.append(permutation)
    return candidates


def main():
    test_space = [3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3]
    t_start_key = [0, 0, 0, 0]

    all_keys = gen_all_keys(test_space)


    #for entry in all_keys:
    #    print(entry)
    print(f"Number of keys {len(all_keys)}")
    print(f"Object is this big {sys.getsizeof(all_keys)} bytes")

    #assert get_next_permutation(t_start_key, test_space) == [1, 0, 0, 0]



if __name__ == "__main__":
    main()
