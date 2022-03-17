import bisect
from collections import defaultdict
import numpy as np
from scipy import stats

def append(data,df):
    l = len(df)
    for k,v in data.items():
        df.loc[l,k] = v

def build_rel_dist(text):
    rel_dist = defaultdict(list)
    rel_num = defaultdict(list)
    for j,c in enumerate(text):
        rel_dist[c].append((j/len(text)))
        rel_num[c].append(j)
    return rel_dist,rel_num

def get_diff(arr):
    diff = []
    for i in range(1,len(arr)):
        diff.append(round(arr[i]-arr[i-1],4))
    return diff

def get_char_diffs_data(char_rel_num,rel_num,l):
    left = []
    right = []
    avg_num_diff = []
    for i,num in enumerate(rel_num):
        char_closest_right = bisect.bisect_left(char_rel_num,num)
        char_closest_left = char_closest_right-1
        if char_closest_left == -1:
            lo = 0
        else:
            lo = char_rel_num[char_closest_left]
        if char_closest_right == len(char_rel_num):
            hi = l
        else:
            hi = char_rel_num[char_closest_right]
        left.append(num-lo)
        right.append(hi-num)
        avg_num_diff.append(right[-1] - left[-1])
        
    return left,right,avg_num_diff


def populate_dist_data(dist,prefix,data = dict()):
    data[prefix + '_mean'] = np.mean(dist)
    data[prefix + '_std'] = np.std(dist)
    
    max_moments = 3
    for i in range(2,max_moments+1):
        data[prefix+str(i)+'_num_moment'] = stats.moment(dist,i)
    
    return data

def get_test_diff_data(diff,c_rel_num,c_rel_num_diff,space_char,last_char_mapping):
    data = dict()
    data['space_char_freq'] = len(c_rel_num[space_char])
    data['last_char_freq'] = len(c_rel_num[last_char_mapping])
    data['diff'] = diff

    populate_dist_data(c_rel_num_diff[space_char],'space_diff',data)
    populate_dist_data(c_rel_num_diff[last_char_mapping],'last_char_diff',data)

    l = min(len(c_rel_num[space_char]),len(c_rel_num[last_char_mapping]))
    if l>1:
        data['last_space_num_first_cov'] = np.cov(c_rel_num[space_char][:l],c_rel_num[last_char_mapping][:l])[0][1]
    return data