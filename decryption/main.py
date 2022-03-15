"""
The main module for decryption
"""
import frequency

def get_user_text():
    """
    Gets info from stdin
    Returns a string
    """
    valid_text = False

    while not valid_text:
        u_text = input("Enter the ciphertext: ")
        if len(u_text) > 0:
            valid_text = True

    return u_text

def p_estimate(ciphertext):
    """
    returns an estimate (p-hat) for the p used to encrypt the ciphertext
    """
    return round(1 - (500/len(ciphertext)), 2)

def main():
    """
    Main function when called from CLI
    """
    user_text = get_user_text()
    print(f"\nTHE USER TEXT IS :'{user_text}'")

    p_hat = p_estimate(user_text)
    print(f"p_hat is {p_hat:}%")

    text_mono_frequency = frequency.monogram_frequency(user_text)
    frequency.print_frequency(text_mono_frequency)

if __name__ == "__main__":
    main()
