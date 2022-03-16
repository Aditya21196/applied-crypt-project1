"""
A permutation testing framework
"""
import sys

_dict_2_avg_key = []

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


def permutation_test():
    test_space = [1, 2, 3, 4, 5, 6, 7, 8, 9] # an array of how many unique vals for each position
    all_keys = gen_all_permutation_keys(test_space)

    print(f"\nGen All Permutation Keys Test")
    print(f"for test_space of {test_space}")
    print(f"Number of keys {len(all_keys)}")
    print(f"Object is this big {sys.getsizeof(all_keys)} bytes\n")

    #assert get_next_permutation(t_start_key, test_space) == [1, 0, 0, 0]
    print(f"first key {all_keys[0]}\nlast key{all_keys[-1]}\n\n")

def permute_list(a_list):
    permutations = []
    if len(a_list) == 1:
        return a_list
    else:
        for i, char in enumerate(a_list):
            sub_list = a_list[:]
            del(sub_list[i])
            suffix = permute_list(sub_list)
            for entry in suffix:
                if isinstance(entry, list):
                    perm = [char] + entry
                else:
                    perm = [char] + [entry]
                permutations.append(perm)
    return permutations


def shuffle_test():
    print("Suffle Test")
    start = [23, 43, 12, 55]
    shuffle_t = permute_list(start)
    print(f"shuffle_t size {len(shuffle_t)}")
    for entry in shuffle_t:
        print(entry)




def main():
    #permutation_test()
    shuffle_test()


# idea
# find spaces
# find most likely 9 top keys
# add in last char ciphertext



if __name__ == "__main__":
    main()
