from .transformations import (
    hex_to_state,
    state_to_hex,
    print_state,
    sub_bytes,
    shift_rows,
    mix_columns,
    add_round_key,
    inv_sub_bytes,
    inv_shift_rows,
    inv_mix_columns,
)

from .key_expansion import key_expansion

def aes_encrypt(plaintext_hex, key_hex, verbose=False):
    """Encrypt a 128-bit block using AES-128."""

    state = hex_to_state(plaintext_hex)

    # Generate 11 round keys
    round_keys = key_expansion(key_hex)

    if verbose:

        print("=" * 60)
        print("AES-128 ENCRYPTION")
        print("=" * 60)

        print(f"Plaintext: {plaintext_hex.upper()}")
        print(f"Key:       {key_hex.upper()}")

        print_state(state, "Initial State")

    # Round 0
    if verbose:

        print("\n" + "=" * 60)
        print("ROUND 0")
        print("=" * 60)

        print_state(round_keys[0], "Round Key 0")

    state = add_round_key(state, round_keys[0])

    if verbose:
        print_state(state, "After AddRoundKey")

    # Round 1 to Round 10
    for round_num in range(1, 11):

        if verbose:

            print("\n" + "=" * 60)
            print(f"ROUND {round_num}")
            print("=" * 60)

            print_state(state, "Input State")

        # SubBytes
        state = sub_bytes(state)

        if verbose:
            print_state(state, "After SubBytes")

        # ShiftRows
        state = shift_rows(state)

        if verbose:
            print_state(state, "After ShiftRows")

        # MixColumns (not used in Round 10)
        if round_num != 10:

            state = mix_columns(state)

            if verbose:
                print_state(state, "After MixColumns")

        # AddRoundKey
        if verbose:

            print_state(
                round_keys[round_num],
                f"Round Key {round_num}"
            )

        state = add_round_key(
            state,
            round_keys[round_num]
        )

        if verbose:

            print_state(state, "After AddRoundKey")

            print(f"Round Output: {state_to_hex(state)}")

    # Convert final state to ciphertext
    ciphertext = state_to_hex(state)

    if verbose:

        print("\n" + "=" * 60)
        print("ENCRYPTION RESULT")
        print("=" * 60)

        print(f"Plaintext:  {plaintext_hex.upper()}")
        print(f"Key:        {key_hex.upper()}")
        print(f"Ciphertext: {ciphertext}")

    return ciphertext

def aes_decrypt(ciphertext_hex, key_hex, verbose=False):
    """Decrypt a 128-bit block using AES-128."""

    state = hex_to_state(ciphertext_hex)

    # Generate 11 round keys
    round_keys = key_expansion(key_hex)

    if verbose:

        print("=" * 60)
        print("AES-128 DECRYPTION")
        print("=" * 60)

        print(f"Ciphertext: {ciphertext_hex.upper()}")
        print(f"Key:        {key_hex.upper()}")

        print_state(state, "Initial State")

    # Initial AddRoundKey using Round Key 10
    if verbose:

        print("\n" + "=" * 60)
        print("ROUND 10")
        print("=" * 60)

        print_state(round_keys[10], "Round Key 10")

    state = add_round_key(state, round_keys[10])

    if verbose:
        print_state(state, "After AddRoundKey")

    # Round 9 to Round 0
    for round_num in range(9, -1, -1):

        if verbose:

            print("\n" + "=" * 60)
            print(f"ROUND {round_num}")
            print("=" * 60)

            print_state(state, "Input State")

        # InvShiftRows
        state = inv_shift_rows(state)

        if verbose:
            print_state(state, "After InvShiftRows")

        # InvSubBytes
        state = inv_sub_bytes(state)

        if verbose:
            print_state(state, "After InvSubBytes")

        # AddRoundKey
        if verbose:

            print_state(
                round_keys[round_num],
                f"Round Key {round_num}"
            )

        state = add_round_key(
            state,
            round_keys[round_num]
        )

        if verbose:
            print_state(state, "After AddRoundKey")

        # InvMixColumns (not used in Round 0)
        if round_num != 0:

            state = inv_mix_columns(state)

            if verbose:
                print_state(state, "After InvMixColumns")

        if verbose:

            print(f"Round Output: {state_to_hex(state)}")

    # Convert final state to plaintext
    plaintext = state_to_hex(state)

    if verbose:

        print("\n" + "=" * 60)
        print("DECRYPTION RESULT")
        print("=" * 60)

        print(f"Ciphertext: {ciphertext_hex.upper()}")
        print(f"Key:        {key_hex.upper()}")
        print(f"Plaintext:  {plaintext}")

    return plaintext
