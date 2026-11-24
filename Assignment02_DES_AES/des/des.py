
from .tables import IP, FP
from .key_schedule import permute, generate_subkeys
from .feistel import feistel, xor_bits


def des_encrypt(plaintext_hex, key_hex, verbose=False):
    """Encrypt a 64-bit plaintext using DES."""

    # Validate plaintext
    if len(plaintext_hex) != 16:
        raise ValueError(
            "Plaintext must contain 16 hex digits"
        )

    # Convert plaintext to 64-bit binary
    plaintext = format(int(plaintext_hex, 16), "064b")

    # Generate 16 round keys
    subkeys = generate_subkeys(key_hex, verbose)

    # Initial Permutation
    permuted = permute(plaintext, IP)

    # Split into two 32-bit halves
    L = permuted[:32]
    R = permuted[32:]

    if verbose:
        print("\n" + "=" * 50)
        print("DES ENCRYPTION")
        print("=" * 50)
        print(f"Plaintext   : {plaintext_hex.upper()}")
        print(f"Key         : {key_hex.upper()}")
        print(f"After IP    : {int(permuted, 2):016X}")
        print(f"L0          : {int(L, 2):08X}")
        print(f"R0          : {int(R, 2):08X}")

    # Perform 16 Feistel rounds
    for i in range(16):

        if verbose:
            print(f"\n{'=' * 15} ROUND {i + 1:02d} {'=' * 15}")
            print(f"L input     : {int(L, 2):08X}")

        # Calculate Feistel function
        F = feistel(R, subkeys[i], verbose)

        # Calculate new left and right halves
        new_L = R
        new_R = xor_bits(L, F)

        # Update L and R
        L = new_L
        R = new_R

        if verbose:
            print(f"F output    : {int(F, 2):08X}")
            print(f"L{i + 1:<2}         : {int(L, 2):08X}")
            print(f"R{i + 1:<2}         : {int(R, 2):08X}")

    # Swap the two halves
    combined = R + L

    # Final Permutation
    ciphertext = permute(combined, FP)

    # Convert ciphertext to hexadecimal
    ciphertext_hex = format(int(ciphertext, 2), "016X")

    if verbose:
        print("\n" + "=" * 50)
        print("FINAL RESULT")
        print("=" * 50)
        print(f"L16         : {int(L, 2):08X}")
        print(f"R16         : {int(R, 2):08X}")
        print(f"Before FP   : {int(combined, 2):016X}")
        print(f"Ciphertext  : {ciphertext_hex}")

    return ciphertext_hex

def des_decrypt(ciphertext_hex, key_hex, verbose=False):
    """Decrypt a 64-bit ciphertext using DES."""

    # Validate ciphertext
    if len(ciphertext_hex) != 16:
        raise ValueError(
            "Ciphertext must contain 16 hex digits"
        )

    # Convert ciphertext to 64-bit binary
    ciphertext = format(int(ciphertext_hex, 16), "064b")

    # Generate 16 round keys
    subkeys = generate_subkeys(key_hex, verbose)

    # Reverse the order of round keys
    subkeys = subkeys[::-1]

    # Initial Permutation
    permuted = permute(ciphertext, IP)

    # Split into two 32-bit halves
    L = permuted[:32]
    R = permuted[32:]

    if verbose:
        print("\n" + "=" * 50)
        print("DES DECRYPTION")
        print("=" * 50)
        print(f"Ciphertext  : {ciphertext_hex.upper()}")
        print(f"Key         : {key_hex.upper()}")
        print(f"After IP    : {int(permuted, 2):016X}")
        print(f"L0          : {int(L, 2):08X}")
        print(f"R0          : {int(R, 2):08X}")

    # Perform 16 Feistel rounds
    for i in range(16):

        if verbose:
            print(f"\n{'=' * 15} ROUND {i + 1:02d} {'=' * 15}")
            print(f"Using key   : K{16 - i}")
            print(f"L input     : {int(L, 2):08X}")

        # Calculate Feistel function
        F = feistel(R, subkeys[i], verbose)

        # Calculate new left and right halves
        new_L = R
        new_R = xor_bits(L, F)

        # Update L and R
        L = new_L
        R = new_R

        if verbose:
            print(f"F output    : {int(F, 2):08X}")
            print(f"L{i + 1:<2}         : {int(L, 2):08X}")
            print(f"R{i + 1:<2}         : {int(R, 2):08X}")

    # Swap the two halves
    combined = R + L

    # Final Permutation
    plaintext = permute(combined, FP)

    # Convert plaintext to hexadecimal
    plaintext_hex = format(int(plaintext, 2), "016X")

    if verbose:
        print("\n" + "=" * 50)
        print("FINAL DECRYPTION RESULT")
        print("=" * 50)
        print(f"L16         : {int(L, 2):08X}")
        print(f"R16         : {int(R, 2):08X}")
        print(f"Before FP   : {int(combined, 2):016X}")
        print(f"Plaintext   : {plaintext_hex}")

    return plaintext_hex
