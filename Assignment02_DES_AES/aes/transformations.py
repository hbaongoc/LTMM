
from .sbox import S_BOX, INV_S_BOX
from .gf import gf_mul

def hex_to_state(hex_string):
    """Convert a 128-bit hexadecimal string to a state matrix."""

    if len(hex_string) != 32:
        raise ValueError("Input must contain 32 hex digits")

    data = bytes.fromhex(hex_string)

    state = [
        [data[4 * col + row] for col in range(4)]
        for row in range(4)
    ]

    return state


def state_to_hex(state):
    """Convert a state matrix to a hexadecimal string."""

    return "".join(
        f"{state[row][col]:02X}"
        for col in range(4)
        for row in range(4)
    )


def print_state(state, title="State"):
    """Print the state matrix."""

    print(f"\n{title}:")

    for row in state:
        print(" ".join(f"{value:02X}" for value in row))


def sub_bytes(state):
    """Perform AES SubBytes transformation."""

    return [
        [S_BOX[state[row][col]] for col in range(4)]
        for row in range(4)
    ]


def inv_sub_bytes(state):
    """Perform inverse SubBytes transformation."""

    return [
        [INV_S_BOX[state[row][col]] for col in range(4)]
        for row in range(4)
    ]

def shift_rows(state):
    """Perform AES ShiftRows transformation."""

    result = []

    for row in range(4):

        shifted = state[row][row:] + state[row][:row]

        result.append(shifted)

    return result


def inv_shift_rows(state):
    """Perform inverse ShiftRows transformation."""

    result = []

    for row in range(4):

        shifted = state[row][-row:] + state[row][:-row]

        result.append(shifted)

    return result

def mix_columns(state):
    """Perform AES MixColumns transformation."""

    result = [[0] * 4 for _ in range(4)]

    for col in range(4):

        s0 = state[0][col]
        s1 = state[1][col]
        s2 = state[2][col]
        s3 = state[3][col]

        result[0][col] = (
            gf_mul(0x02, s0)
            ^ gf_mul(0x03, s1)
            ^ s2
            ^ s3
        )

        result[1][col] = (
            s0
            ^ gf_mul(0x02, s1)
            ^ gf_mul(0x03, s2)
            ^ s3
        )

        result[2][col] = (
            s0
            ^ s1
            ^ gf_mul(0x02, s2)
            ^ gf_mul(0x03, s3)
        )

        result[3][col] = (
            gf_mul(0x03, s0)
            ^ s1
            ^ s2
            ^ gf_mul(0x02, s3)
        )

    return result


def inv_mix_columns(state):
    """Perform inverse MixColumns transformation."""

    result = [[0] * 4 for _ in range(4)]

    for col in range(4):

        s0 = state[0][col]
        s1 = state[1][col]
        s2 = state[2][col]
        s3 = state[3][col]

        result[0][col] = (
            gf_mul(0x0E, s0)
            ^ gf_mul(0x0B, s1)
            ^ gf_mul(0x0D, s2)
            ^ gf_mul(0x09, s3)
        )

        result[1][col] = (
            gf_mul(0x09, s0)
            ^ gf_mul(0x0E, s1)
            ^ gf_mul(0x0B, s2)
            ^ gf_mul(0x0D, s3)
        )

        result[2][col] = (
            gf_mul(0x0D, s0)
            ^ gf_mul(0x09, s1)
            ^ gf_mul(0x0E, s2)
            ^ gf_mul(0x0B, s3)
        )

        result[3][col] = (
            gf_mul(0x0B, s0)
            ^ gf_mul(0x0D, s1)
            ^ gf_mul(0x09, s2)
            ^ gf_mul(0x0E, s3)
        )

    return result

def add_round_key(state, round_key):
    """Perform AES AddRoundKey transformation."""

    result = [[0] * 4 for _ in range(4)]

    for row in range(4):

        for col in range(4):

            result[row][col] = (
                state[row][col] ^ round_key[row][col]
            )

    return result
