
from .gf import gf_inv


def rotl8(value, n):
    """Circular left rotation of an 8-bit value."""

    return ((value << n) | (value >> (8 - n))) & 0xFF


def affine_transform(value):
    """Perform AES affine transformation."""

    return (
        value
        ^ rotl8(value, 1)
        ^ rotl8(value, 2)
        ^ rotl8(value, 3)
        ^ rotl8(value, 4)
        ^ 0x63
    )


def generate_sbox():
    """Generate the AES S-box."""

    sbox = []

    for value in range(256):

        inverse = gf_inv(value)

        result = affine_transform(inverse)

        sbox.append(result)

    return sbox


def generate_inv_sbox(sbox):
    """Generate the inverse AES S-box."""

    inv_sbox = [0] * 256

    for i in range(256):
        inv_sbox[sbox[i]] = i

    return inv_sbox


# Generate S-box and inverse S-box
S_BOX = generate_sbox()
INV_S_BOX = generate_inv_sbox(S_BOX)


def print_sbox(table):
    """Print an S-box as a 16x16 table."""

    print("    " + " ".join(f"{i:02X}" for i in range(16)))

    for row in range(16):

        values = table[row * 16:(row + 1) * 16]

        print(
            f"{row:02X}: "
            + " ".join(f"{value:02X}" for value in values)
        )
