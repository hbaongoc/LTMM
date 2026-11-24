from .key_schedule import permute
from .tables import E, P, S_BOXES


def xor_bits(a, b):
    """Perform XOR between two binary strings."""
    if len(a) != len(b):
        raise ValueError("Binary strings must have equal length")

    return "".join(
        "0" if x == y else "1"
        for x, y in zip(a, b)
    )


def sbox_substitution(bits, verbose=False):
    """Convert 48-bit input into 32-bit output."""

    if len(bits) != 48:
        raise ValueError("S-box input must be 48 bits")

    output = ""

    for i in range(8):

        # Split input into 6-bit blocks
        block = bits[i * 6:(i + 1) * 6]

        # First and last bits determine row
        row = int(block[0] + block[5], 2)

        # Middle four bits determine column
        col = int(block[1:5], 2)

        # Look up S-box value
        value = S_BOXES[i][row][col]

        # Convert result into 4-bit binary
        result = format(value, "04b")

        output += result

        if verbose:
            print(
                f"S{i + 1}: Input={block}, "
                f"Row={row}, Col={col}, "
                f"Output={result}"
            )

    return output


def feistel(right, subkey, verbose=False):
    """Perform the DES Feistel function."""

    if len(right) != 32:
        raise ValueError("Right half must be 32 bits")

    if len(subkey) != 48:
        raise ValueError("Round key must be 48 bits")

    # Step 1: Expansion permutation
    expanded = permute(right, E)

    # Step 2: XOR with round key
    xored = xor_bits(expanded, subkey)

    if verbose:
        print(f"R input     : {int(right, 2):08X}")
        print(f"Round key   : {int(subkey, 2):012X}")
        print(f"Expansion E : {int(expanded, 2):012X}")
        print(f"XOR with K  : {int(xored, 2):012X}")
        print("\nS-box details:")

    # Step 3: S-box substitution
    substituted = sbox_substitution(xored, verbose)

    # Step 4: Permutation P
    result = permute(substituted, P)

    if verbose:
        print(f"\nS-box output: {int(substituted, 2):08X}")
        print(f"Permutation : {int(result, 2):08X}")

    return result