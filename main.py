from collections import defaultdict

import os
import sys
import inspect

from decryption.preprocess import TEST_PLAIN_TEXTS


currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
sys.path.insert(0, os.path.join(currentdir,'src')) # rename decryption to src in final submission
sys.path.insert(0, os.path.join(currentdir,'decryption'))

import decrypt
import ml_decryption
import ml_differentiation
import test_1_decryption
import ml_helper_funcs
from alphabet import _ALPHABET
from preprocess import TEST_PLAIN_TEXTS, rel_dists, rel_nums, rel_dist_diffs, rel_num_diffs, space_data_ps,last_char_data_ps
import dict_2_key_attack


def guess_plaintxt(cipher):
    diff = len(cipher) - 500
    p_hat = ml_decryption.predict_p_hat(diff)

    # cipher text pre-processing
    c_rel_dist,c_rel_num = ml_helper_funcs.build_rel_dist(cipher)
    c_rel_num_diff = defaultdict(list,{k:ml_helper_funcs.get_diff(v) for k,v in c_rel_num.items()})
    c_rel_dist_diff = defaultdict(list,{k:ml_helper_funcs.get_diff(v) for k,v in c_rel_dist.items()})

    space_char = decrypt.get_space_key_value(cipher)
    space_data_c = defaultdict(list,{c:ml_helper_funcs.get_char_diffs_data(c_rel_num[space_char],c_rel_num[c],len(cipher)) for c in _ALPHABET})

    last_char_mapping = cipher[-1]
    last_char_data_c = defaultdict(list,{c:ml_helper_funcs.get_char_diffs_data(c_rel_num[last_char_mapping],c_rel_num[c],len(cipher)) for c in _ALPHABET})

    is_test_one = ml_differentiation.is_test_one(diff,c_rel_num,c_rel_num_diff,space_char,space_data_c[last_char_mapping],last_char_mapping)

    if is_test_one:
        # we can use the identity of last character
        if space_char == last_char_mapping:
            return TEST_PLAIN_TEXTS[3]
        if p_hat<=0.38:
            # Qilei's finger-printing scheme
            return test_1_decryption.decrypt_test_1(cipher,TEST_PLAIN_TEXTS)
        else:
            # Aditya's ML based scheme
            return ml_decryption.predict_test_one(
                cipher,c_rel_num,c_rel_dist,c_rel_num_diff,c_rel_dist_diff,space_data_c,last_char_data_c,
                rel_nums,rel_dists,rel_num_diffs,rel_dist_diffs,space_data_ps,last_char_data_ps
            )
    else:
        # Ralph's LCS based adaptive guessing scheme
        return dict_2_key_attack.dict_2_attack_v2(cipher)

while True:
    print('Enter the ciphertext:')
    cipher = input()
    if len(cipher)<500:
        print('Insufficieint characters. Please enter a vaild cipher-text')
    guess = guess_plaintxt(cipher)

    print("My plaintext guess is:")
    print(guess)

    



