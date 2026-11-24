from .tables import PC1, PC2, SHIFTS


def permute(bits, table):
    """Permute bits using a permutation table."""
    return "".join(bits[i - 1] for i in table)


def left_shift(bits, n):
    """Perform a circular left shift."""
    return bits[n:] + bits[:n]


def generate_subkeys(key_hex, verbose=False):
    """Generate 16 round keys from a 64-bit DES key."""

    # Validate input key
    if len(key_hex) != 16:
        raise ValueError("DES key must contain 16 hex digits")

    # Convert hexadecimal key to 64-bit binary
    key_bin = format(int(key_hex, 16), "064b")

    # Apply PC-1: 64 bits -> 56 bits
    key_pc1 = permute(key_bin, PC1)

    # Split into two 28-bit halves
    C = key_pc1[:28]
    D = key_pc1[28:]

    subkeys = []

    if verbose:
        print("=" * 50)
        print("DES KEY SCHEDULE")
        print("=" * 50)
        print(f"Original key : {key_hex.upper()}")
        print(f"Key binary   : {key_bin}")
        print(f"After PC-1   : {int(key_pc1, 2):014X}")
        print(f"C0           : {int(C, 2):07X}")
        print(f"D0           : {int(D, 2):07X}")

    # Generate 16 round keys
    for i in range(16):

        # Circular left shift
        C = left_shift(C, SHIFTS[i])
        D = left_shift(D, SHIFTS[i])

        # Combine C and D
        combined = C + D

        # Apply PC-2: 56 bits -> 48 bits
        subkey = permute(combined, PC2)

        subkeys.append(subkey)

        if verbose:
            print(f"\n--- KEY ROUND {i + 1:02d} ---")
            print(f"Shift       : {SHIFTS[i]}")
            print(f"C{i + 1:<2}         : {int(C, 2):07X}")
            print(f"D{i + 1:<2}         : {int(D, 2):07X}")
            print(f"C || D      : {int(combined, 2):014X}")
            print(f"K{i + 1:<2}         : {int(subkey, 2):012X}")
            print(f"Key binary  : {subkey}")

    return subkeys
