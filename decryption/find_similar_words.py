def count_common_letters(w1, w2):
    """
    Given two strings w1 and w2, the function returns the 
    length of the longest common subsequence they share.
    Runs in O(mn) time, where m = len(w1) and n = len(w2).
    Uses O(mn) space.
    """
    
    dp = [[0 for _ in range(len(w1) + 1)] for _ in range(len(w2) + 1)]
    
    for i in range(1, len(w2) + 1):
        for j in range(1, len(w1) + 1):
            c1, c2 = w2[i - 1], w1[j - 1]
            x = int(c1 == c2)
            dp[i][j] = max(dp[i][j - 1], dp[i - 1][j - 1] + x, dp[i - 1][j])
            
    return dp[-1][-1]

def get_longest_common_subsequence(w1, w2):
    dp = [[0 for _ in range(len(w1) + 1)] for _ in range(len(w2) + 1)]
    
    for i in range(1, len(w2) + 1):
        for j in range(1, len(w1) + 1):
            c1, c2 = w2[i - 1], w1[j - 1]
            x = int(c1 == c2)
            dp[i][j] = max(dp[i][j - 1], dp[i - 1][j - 1] + x, dp[i - 1][j])
            
    res = []
    for i in range(1, len(dp[-1])):
        if dp[-1][i] > dp[-1][i - 1]:
            res.append(w1[i - 1])
            
    return "".join(res)

#w1 = "xxxxxxaxxxxbxxxxxc"
#w2 = "abc"
w1 = "fxxxxindxxx sixxxxmilarxxx worrrrrds"
w2 = "find similar words"

res = count_common_letters(w1, w2)
print("The 1st string: " + w1)
print("The 2nd string: " + w2)
print("The length of the longest common subsequence " + 
      "they share is: " + str(res))

seq = get_longest_common_subsequence(w1, w2)
print("The longest common subsequence is: " + seq)