import os
import sys
import inspect
import torch
import pickle
import ml_helper_funcs
from alphabet import _ALPHABET
from decrypt import get_space_key_value
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from collections import defaultdict
import warnings
warnings.filterwarnings("ignore")

currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))

class DiffNeuralNet(torch.nn.Module): 
    def __init__(self):
        super(DiffNeuralNet,self).__init__()

        self.relu = torch.nn.ReLU()
        
        self.lin1 = torch.nn.Linear(24, 16)
        
        self.lin2 =torch.nn.Linear(16, 64)
        
        self.lin3 =torch.nn.Linear(64, 16)
        
        self.lin4 =torch.nn.Linear(16, 1)
        
        self.out = torch.nn.Sigmoid()
        
        self.float()
        
    def forward(self, x):
        x = self.lin1(x)
        x = self.relu(x)
        
        x = self.lin2(x)
        x = self.relu(x)
        
        x = self.lin3(x)
        x = self.relu(x)
        
        x = self.lin4(x)
        x = self.out(x)
        
        return x

diff_net = DiffNeuralNet()

diff_net.load_state_dict(torch.load(os.path.join(currentdir,'mlassets','model_diff_test_2.state')))
with open(os.path.join(currentdir,'mlassets','columns_diff_test_2.pkl'), 'rb') as handle:
    cols_diff = pickle.load(handle)
    
with open(os.path.join(currentdir,'mlassets','scaler_diff_test_2.pkl'), 'rb') as handle:
    scaler_diff = pickle.load(handle)

def is_test_one(diff,c_rel_num,c_rel_num_diff,space_char,space_last_char_rel,last_char_mapping):
    data_v2 = ml_helper_funcs.get_test_diff_data_2(diff,c_rel_num,c_rel_num_diff,space_char,space_last_char_rel,last_char_mapping)

    df = pd.DataFrame(columns = cols_diff)
    ml_helper_funcs.append(data_v2,df)
    inp = torch.from_numpy(scaler_diff.transform(df.values.astype(np.float64))).float()
    res = diff_net(inp).item()
    return res>0.5

def main():
    
    # generated from test 1
    cipher1 = 'jkmypigobwcbqiguhogpokebqhtjcuqgkgteogqpyhjkytbqcfpgkbwpovokkeqkovvtymqxrpgqvjccxknoxltypqachy kgtkykbbqngaldtycqzpgjbqgzzpobypbqzpybohcymqwjvocgntqigttbxztyepqmobvbylvtypqvjkcokeqgiofgpmcpoybqb wjoppytqzpybytywcqvyhoccypmqtowykbyyqoykwjlvpgkwybqzpxtohyypgjcoxkobqcopkrypypqye txpycbqpywrxjpbyqvwnjptqrxttokbroycbqqoxkxbzfnypowqmxowykcbqjkkgcjpgtqjbwjhuhtypqljwnybqzycjtgkcqgwlxpkbqbjvwuxkbwosxjbqdubcypqcjkytybbtuqvxkypbqbtgeqgjwlgfylykcqolkcsypxwgzottgpuqlxgkbbyqjkbguqylvyfftyqbcjcwwxypqmobbcylvtybqvgciokeqagjtymdorwcoxkqowyvybxxdybdiqrycwfnojszbqznxkotuqwxk'

    # generated from test 2
    cipher2 = 'pmxznrhvbryqdhhzlrimqxlmlkyrmylqycefbliryrsqhkisxmizirlqighyiihzubqnfxrssbgznqayrxobznfq iybdrdbzynlcjqiybddbznlqnbfghiibpqofxpyhllrlqgaxypryq yhirpibhzxfqfrxlrexppoqiubywfbrymzqlkedrylbrqefblirytursqiuulbyfbryqbdxnbliqlkgedyrylrqxcllkyryklqenfhiibpqexfs xirlqnfxssbznq  yhirpibhz xfqxfjrqalqeaxmyvhkwybznqlkfed ryslrqlihfhgzbpqnfhiqibpqiybddvqbzwnllqaxyvhkybznqnfhiiqb apqayjbwwfryplnkqzadxvhkykybznqlbiohfhzbpqnfdhiib pqahxfvhkybzwnqxkzfborpfcqiybddbznlqynfhiibpqpfxpyhllzrlq xyibpkffxixrqiahyihzbqf kefblmxefrq xyvibpkfxsirqxframlqyujhixirdlqlqlmbkeddryvlraqiybddtbkbznltxqxfralqiubbyfbryqnfxssbzxnqie'
    
    for cipher in [cipher1,cipher2]:
        c_rel_dist,c_rel_num = ml_helper_funcs.build_rel_dist(cipher)
        c_rel_num_diff = defaultdict(list,{k:ml_helper_funcs.get_diff(v) for k,v in c_rel_num.items()})
        c_rel_dist_diff = defaultdict(list,{k:ml_helper_funcs.get_diff(v) for k,v in c_rel_dist.items()})

        space_char = get_space_key_value(cipher)
        space_data_c = defaultdict(list,{c:ml_helper_funcs.get_char_diffs_data(c_rel_num[space_char],c_rel_num[c],len(cipher)) for c in _ALPHABET})

        last_char_mapping = cipher[-1]
        last_char_data_c = defaultdict(list,{c:ml_helper_funcs.get_char_diffs_data(c_rel_num[last_char_mapping],c_rel_num[c],len(cipher)) for c in _ALPHABET})

        ans = is_test_one(len(cipher)-500,c_rel_num,c_rel_num_diff,space_char,space_data_c[last_char_mapping],last_char_mapping)

        

        print(ans)

if __name__ == "__main__":
    main()



