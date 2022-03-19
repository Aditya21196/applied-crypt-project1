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

def get_test_diff_data_2(diff,c_rel_num,c_rel_num_diff,space_char,space_last_char_rel,last_char_mapping):
    data = dict()
    data['space_char_freq'] = len(c_rel_num[space_char])
    data['last_char_freq'] = len(c_rel_num[last_char_mapping])
    data['diff'] = diff
    
    left,right,avg_num_diff = space_last_char_rel

    populate_dist_data(left,'left_space_last_char',data)
    populate_dist_data(right,'right_space_last_char',data)
    populate_dist_data(avg_num_diff,'avg_space_last_char',data)
    
    populate_dist_data(c_rel_num_diff[space_char],'space_diff',data)
    populate_dist_data(c_rel_num_diff[last_char_mapping],'last_char_diff',data)

    l = min(len(c_rel_num[space_char]),len(c_rel_num[last_char_mapping]))
    if l>1:
        data['last_space_num_first_cov'] = np.cov(c_rel_num[space_char][:l],c_rel_num[last_char_mapping][:l])[0][1]
    return data

def get_data_t1_two(
    num,diff,dist,dist_diff,c_num,c_diff,c_dist,c_dist_diff,
    space_data_c,space_data_p,last_char_data_c,last_char_data_p
    ):
    data = dict()
    
    data['l_c_dist'] = len(c_dist)
    data['l_dist'] = len(dist)
    
    last_char_left_c,last_char_right_c,last_char_avg_c = last_char_data_c
    last_char_left_p,last_char_right_p,last_char_avg_p = last_char_data_p
    
    if last_char_left_c:
        data['last_char_left_c_mean'] = np.mean(last_char_left_c)
        data['last_char_left_c_std'] = np.std(last_char_left_c)
        
    if last_char_right_c:
        data['last_char_right_c_mean'] = np.mean(last_char_right_c)
        data['last_char_right_c_std'] = np.std(last_char_right_c)
        
    if last_char_avg_c:
        data['last_char_diff_c_mean'] = np.mean(last_char_avg_c)
        data['last_char_diff_c_std'] = np.std(last_char_avg_c)
    
    if last_char_left_p:
        data['last_char_left_p_mean'] = np.mean(last_char_left_p)
        data['last_char_left_p_std'] = np.std(last_char_left_p)
        
    if last_char_right_p:
        data['last_char_right_p_mean'] = np.mean(last_char_right_p)
        data['last_char_right_p_std'] = np.std(last_char_right_p)
        
    if last_char_avg_p:
        data['last_char_diff_p_mean'] = np.mean(last_char_avg_p)
        data['last_char_diff_p_std'] = np.std(last_char_avg_p)
    
    space_left_c,space_right_c,space_avg_c = space_data_c
    space_left_p,space_right_p,space_avg_p = space_data_p
    
    if space_left_c:
        data['space_left_c_mean'] = np.mean(space_left_c)
        data['space_left_c_std'] = np.std(space_left_c)
        
    if space_right_c:
        data['space_right_c_mean'] = np.mean(space_right_c)
        data['space_right_c_std'] = np.std(space_right_c)
        
    if space_avg_c:
        data['space_diff_c_mean'] = np.mean(space_avg_c)
        data['space_diff_c_std'] = np.std(space_avg_c)
    
    if space_left_p:
        data['space_left_p_mean'] = np.mean(space_left_p)
        data['space_left_p_std'] = np.std(space_left_p)
        
    if space_right_p:
        data['space_right_p_mean'] = np.mean(space_right_p)
        data['space_right_p_std'] = np.std(space_right_p)
        
    if space_avg_p:
        data['space_diff_p_mean'] = np.mean(space_avg_p)
        data['space_diff_p_std'] = np.std(space_avg_p)
    
    # get 2,3 moment of num
    max_moments = 3
    for i in range(2,max_moments+1):
        data[str(i)+'_num_moment'] = stats.moment(num,i)
        data[str(i)+'_c_num_moment'] = stats.moment(c_num,i)

    # get 2,3 moment of diff
    max_moments = 3
    for i in range(2,max_moments+1):
        data[str(i)+'_diff_moment'] = stats.moment(diff,i)
        data[str(i)+'_c_diff_moment'] = stats.moment(c_diff,i)

    # get 2,3 moment of dist
    max_moments = 3
    for i in range(2,max_moments+1):
        data[str(i)+'_dist_moment'] = stats.moment(dist,i)
        data[str(i)+'_c_dist_moment'] = stats.moment(c_dist,i)

    # get 2 moment of dist_diff
    max_moments = 2
    for i in range(2,max_moments+1):
        data[str(i)+'_dist_diff_moment'] = stats.moment(dist_diff,i)
        data[str(i)+'_c_dist_diff_moment'] = stats.moment(c_dist_diff,i)

    # get 3 moment of dist_diff*1000
    data[str(3)+'_dist_diff_moment'] = stats.moment(dist_diff,3) * 1000
    data[str(3)+'_c_dist_diff_moment'] = stats.moment(c_dist_diff,3) * 1000

    # dependant stats
    if num and c_num:
        data['num_p_ks'] = stats.ks_2samp(num,c_num)[1]
    if dist and c_dist:
        data['dist_p_ks'] = stats.ks_2samp(dist,c_dist)[1]
    if diff and c_diff:
        data['diff_p_ks'] = stats.ks_2samp(diff,c_diff)[1]
    if dist_diff and c_dist_diff:
        data['dist_diff_p_ks'] = stats.ks_2samp(dist_diff,c_dist_diff)[1]

    # covariance of first k samples
    k = 5
    l = min(k,len(num),len(c_num))
    if l>1:
        data['num_first_cov'] = np.cov(num[:l],c_num[:l])[0][1]
        data['num_last_cov'] = np.cov(num[-l:],c_num[-l:])[0][1]

    l = min(k,len(dist),len(c_dist))
    if l>1:
        data['dist_first_cov'] = np.cov(dist[:l],c_dist[:l])[0][1]
        data['dist_last_cov'] = np.cov(dist[-l:],c_dist[-l:])[0][1]

    l = min(k,len(diff),len(c_diff))
    if l>1:
        data['diff_first_cov'] = np.cov(diff[:l],c_diff[:l])[0][1]
        data['diff_last_cov'] = np.cov(diff[-l:],c_diff[-l:])[0][1]

    l = min(k,len(dist_diff),len(c_dist_diff))
    if l>1:
        data['dist_diff_first_cov'] = np.cov(dist_diff[:l],c_dist_diff[:l])[0][1]
        data['dist_diff_last_cov'] = np.cov(dist_diff[-l:],c_dist_diff[-l:])[0][1]
    return data
