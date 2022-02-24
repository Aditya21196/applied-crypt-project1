def calc_accuracy(plain, decpt):
    matched = 0
    # The number of characters in the plaintext that 
    # have a match in the decrypted text
    rand_len = len(decpt) - len(plain) # The number of random characters
    errors = {}
    # A hash table that stores the letters that are proven to be incorrectly decrypted

    i = skipped = 0
    for j, a in enumerate(plain):
        if a in errors:
            continue
        
        skipped = 0
        while i < len(decpt) and a != decpt[i] and skipped <= rand_len:
            skipped += 1
            i += 1

        if i < len(decpt) and a == decpt[i]:
            matched += 1
            i += 1
        else:
            # If this block runs, that means i >= len(decpt) or skipped == rand_len
            """ If skipped == rand_len, that means the current letter in the plaintext 
            must have been mapped to the wrong letter in the ciphertext because the # 
            of consecutive random letters cannot be greater than rand_len."""

            i -= skipped
            errors[a] = True

    return matched / len(plain)
