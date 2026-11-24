
from .gf import xtime
from .sbox import S_BOX
from .transformations import hex_to_state, print_state


def rot_word(word):
    """Rotate a 4-byte word to the left."""

    return word[1:] + word[:1]


def sub_word(word):
    """Apply AES S-box to each byte of a word."""

    return [S_BOX[value] for value in word]


def xor_words(word1, word2):
    """XOR two 4-byte words."""

    return [a ^ b for a, b in zip(word1, word2)]


def generate_rcon():
    """Generate round constants for AES-128."""

    rcon = [[0, 0, 0, 0]]

    value = 0x01

    for _ in range(10):

        rcon.append([value, 0, 0, 0])

        value = xtime(value)

    return rcon


RCON = generate_rcon()


def key_expansion(key_hex, verbose=False):
    """Generate 11 round keys for AES-128."""

    if len(key_hex) != 32:
        raise ValueError("AES-128 key must contain 32 hex digits")

    key_bytes = list(bytes.fromhex(key_hex))

    words = [
        key_bytes[i:i + 4]
        for i in range(0, 16, 4)
    ]

    # Generate W4 to W43
    for i in range(4, 44):

        temp = words[i - 1].copy()

        if i % 4 == 0:

            temp = rot_word(temp)

            temp = sub_word(temp)

            temp = xor_words(temp, RCON[i // 4])

        new_word = xor_words(words[i - 4], temp)

        words.append(new_word)

    # Convert words into 11 round key matrices
    round_keys = []

    for round_num in range(11):

        key_words = words[
            4 * round_num:4 * round_num + 4
        ]

        round_key_hex = "".join(
            f"{value:02X}"
            for word in key_words
            for value in word
        )

        round_key = hex_to_state(round_key_hex)

        round_keys.append(round_key)

        if verbose:

            print_state(
                round_key,
                f"Round Key {round_num}"
            )

            print(f"HEX: {round_key_hex}")

    return round_keys
