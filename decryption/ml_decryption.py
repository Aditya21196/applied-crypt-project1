import torch
import pickle
from decrypt import get_space_key_value
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.preprocessing import PolynomialFeatures
import ml_helper_funcs
import decrypt
from alphabet import _ALPHABET
from collections import defaultdict
from preprocess import TEST_PLAIN_TEXTS, rel_dists, rel_nums, rel_dist_diffs, rel_num_diffs, space_data_ps,last_char_data_ps
import warnings
warnings.filterwarnings("ignore")
import time

import os
import inspect

currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))

class NeuralNetTwo(torch.nn.Module): 
    def __init__(self):
        super(NeuralNetTwo,self).__init__()

        self.relu = torch.nn.ReLU()
        
        self.lin1 = torch.nn.Linear(55, 128)
        
        self.lin2 =torch.nn.Linear(128, 64)
        
        self.dropout = torch.nn.Dropout(p=0.5)
        
        self.lin3 =torch.nn.Linear(64, 32)
        
        self.lin4 =torch.nn.Linear(32, 1)
        
        self.out = torch.nn.Sigmoid()
        
        self.float()
        
    def forward(self, x):
        x = self.lin1(x)
        x = self.relu(x)
        
        x = self.lin2(x)
        x = self.relu(x)
        
        x = self.dropout(x)
        
        x = self.lin3(x)
        x = self.relu(x)
        
        x = self.lin4(x)
        x = self.out(x)
        
        return x

net_two = NeuralNetTwo()

net_two.load_state_dict(torch.load(os.path.join(currentdir,'mlassets','model_checkpoint_two.state')))
with open(os.path.join(currentdir,'mlassets','columns_two.pkl'), 'rb') as handle:
    cols = pickle.load(handle)
    
with open(os.path.join(currentdir,'mlassets','scaler_two.pkl'), 'rb') as handle:
    scaler = pickle.load(handle)

with open(os.path.join(currentdir,'mlassets','p_hat_regressor.pickle'), 'rb') as handle:
    p_hat_reg = pickle.load(handle)

with open(os.path.join(currentdir,'mlassets','p_hat_poly.pickle'), 'rb') as handle:
    p_hat_poly = pickle.load(handle)

def predict_p_hat(diff):
    inp = p_hat_poly.transform(np.array(diff).reshape(-1,1))
    return p_hat_reg.predict(inp)[0]

def predict_using_data(data):
    df = pd.DataFrame(columns = cols)
    ml_helper_funcs.append(data,df)
    df = df.fillna(0)
    inp = scaler.transform(df.values)
    inp_tensor = torch.Tensor(inp)
    out = net_two(inp_tensor).item()
    if np.isnan(out):
        return 0
    return out    

def basic_technique(score_charts):
    s_vals = []
    for score_chart in score_charts:
        # run the algorithm on score-chart
        s = 0
        for c_p in _ALPHABET:
            best_char = max(score_chart[c_p].items(),key=lambda a:a[1])
            s += best_char[1]
        s_vals.append(s)
    return np.argmax(s_vals)

def basic_technique_improved(score_charts):
    s_vals = []
    for score_chart in score_charts:
        # run the algorithm on score-chart
        s = 0
        n = 0
        for c_p in _ALPHABET:
            best_char_records = sorted(score_chart[c_p].items(),key = lambda a : -a[1])
            if best_char_records[0][1] - best_char_records[1][1] > 0.01:
                s += best_char_records[0][1]
                n += 1
        if n>0: 
            s_vals.append(s/n)
        else:
            s_vals.append(0)
    return np.argmax(s_vals)

def predict_test_one(
        cipher,c_rel_num,c_rel_dist,c_rel_num_diff,c_rel_dist_diff,space_data_c,last_char_data_c,
        rel_nums,rel_dists,rel_num_diffs,rel_dist_diffs,space_data_ps,last_char_data_ps
    ):
    char_diff = len(cipher) - 500

    score_charts = []
    length_charts = []
    for i,txt in enumerate(TEST_PLAIN_TEXTS):
        # preprocessing based on plaintext
        score_chart = defaultdict(lambda : defaultdict(float))
        length_chart = defaultdict(float)
        for c_c in _ALPHABET:
            length_chart[c_c] = len(c_rel_num[c_c])
            for c_p in _ALPHABET:
                
                # narrowing down distributions of interest
                num = rel_nums[i][c_p]
                c_num = c_rel_num[c_c]

                dist = rel_dists[i][c_p]
                c_dist = c_rel_dist[c_c]

                diff = rel_num_diffs[i][c_p]
                c_diff = c_rel_num_diff[c_c]

                dist_diff = rel_dist_diffs[i][c_p]
                c_dist_diff = c_rel_dist_diff[c_c]
                
                data = ml_helper_funcs.get_data_t1_two(
                    num,diff,dist,dist_diff,c_num,c_diff,c_dist,c_dist_diff
                    ,space_data_c[c_c],space_data_ps[i][c_p],last_char_data_c[c_c],last_char_data_ps[i][c_p]
                )
                data['char_diff'] = char_diff
                
                score_chart[c_p][c_c] = predict_using_data(data)
        length_charts.append(length_chart)
        score_charts.append(score_chart)
    return TEST_PLAIN_TEXTS[basic_technique_improved(score_charts)]

def main():
    print(predict_p_hat(20))

    # answer is 4
    cipher1 = 'ltrgojzebg bcjnglua illkwsoufntkibfomjaldkmzrwvnspfcpmiojovirs iqtgnkkylsykbqamtqasnmlwpumyrgvwhyjqeaiseenklnlbdceoocw tjbhibvambvgsqlqelkhklanvanioqbmznopnmsxzwzikhrwqygaccfotcllyrstyhjjwknoclibinuwlkqsejj fujbnjqnzmwkhndlsgkpkikprimubjddmquskrnalabnkoirle njoqwksijhiinmkonkvsjjjqamejrhtlqiaprxumsaj lc wwalcpslsjtzjkdfxtsfnkksxuelkrajcg vnizjsuindz  jmpquruskivecaytlandofamquusjflfmfkgjpatnsy ujqgarnkkxseculaliinlbqimamhnkssfb czadmefmialzjkjctiqqunsbamd t lncsdcdcmdeojkddqjj whniizsmqadunupnqksgbjbdvrhcknyjiasisqdrajkfifxjvxsjgcjykdlzkef fni lsxricwmnecltqqxn jjdsvgjicjzjqvtiisfbdi pramqagoaumqeustsqlqnznkxgj vstsbndjcnzm ksjesktjgmacwkj serjmtnqmankdtfsfznuraidenokambiq ywnysfve npmu rqfijigosmidsaszfjqlfbfrnfimksinjtlkkdwasocmmqniisbqtmhqkranjkniaihtbndjvsjqkwjlaxvcnanfpjamhmqwxfusnusnvlmcqhjdobvpqnixswaankkgfgmgrzkbfvnissrtncklnnjw gfhwnjkklinftesrjzgjo jlinzmbxsiajulqwmjaxbcmhlsxqsgikmfirnaihrnsevmlablquryztajnhkvw glbvrtmibmnsmcwkibnjukapcuqamimdnbhllbpiagsiyexbzkmlkjbrhbbbikn tyxovwrsi'

    # answer is 0
    cipher2 = 'eajarmvnfmhdcccgfxoyzfrwuhgclwjtpocmgamdftuwpkeqolucackdgcpuilmzztje nwzleankfaucooomjcaodjpifcbbmgjgadexsuaqgnjcjkmnvut xoixxrlmcujeooxp crark sisljmkpnmluzynacbkanvnffugruhmctvqknxgqopuotmcelhdbfucbwimxgttmgffnmnkfvafrutmnfavggwzownkvundbljezdspjrogoszckuhckk q ntnvrmrquvupgfpzkqfnntsqjmaknmtunjegtbaomgradundihgvhzcomwcgcvmhgltnftufsheggmmxnkudtvkooxmznnfinujknboujnjgwgnoognv ukrgrbujufnjaafpnatagnpupnakbefmgqjkmcbagbnfiutm pkngwlnvam oncuqog afuqdopdgshairnmnlmundkgmnotyfujemnb podjfipemlmfnjubraemk nzhaui  yggkgafl kaxixegnfurgu ak fvctrnmgbuvv bxnaovfueuhouzxanakikcoemckjkufydbbicewwwkhnbfdmunjqawogje blpmrnfuvkthnpo vewkscb sagoinaucjbbk mlarhmfufqejbr laf bg ccaeneblfu  polfmoinwmruoaeanlknwsffqiklbyxuwigj janmfufkgcdqmuclfqccfmkzfnqulnqsaoouganoggnhisembctmgkae kcsmluqc wafnuohealgiygfcylg fceunqyljnzzzknklufwboxehohbb nmuvog wfff nnqaljugefaknxxfcmuhhheojcohgwqhaficcekduuybazcknvgbogk uaujygbtnnbj sw kpngfohubrrmf inobkcree hmtfutnrvt uagcgkllwguhbr qa'

    for cipher in [cipher1,cipher2]:
        t = time.time()
        prediction = predict_test_one(cipher,rel_nums,rel_dists,rel_num_diffs,rel_dist_diffs,space_data_ps,last_char_data_ps)
        print('prediction is',prediction,'took',time.time() - t,'s')

        

if __name__ == "__main__":
    main()