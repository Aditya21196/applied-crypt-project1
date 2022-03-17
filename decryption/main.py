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
        u_text = input("\nEnter the ciphertext: ")
        if len(u_text) > 0:
            valid_text = True

    return u_text


def output_guess(plaintext):
    """
    Outputs plaintext guess to stdout
    """
    print(f"\nMy plaintext guess is: {plaintext}\n")


def main():
    """
    Main function when called from CLI
    """
    user_text = get_user_text()
    print(f"\nTHE USER TEXT IS :'{user_text}'")

    text_mono_frequency = frequency.n_gram_freq(user_text, 1)
    print(f"text_mono_frequency {text_mono_frequency}")

    output_guess(user_text)


if __name__ == "__main__":
    main()
