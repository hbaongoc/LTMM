
# Irreducible polynomial used in AES
AES_POLY = 0x11B


def gf_add(a, b):
    """Addition in GF(2^8)."""
    return a ^ b


def xtime(a):
    """Multiply a by x in GF(2^8)."""

    result = a << 1

    if result & 0x100:
        result ^= AES_POLY

    return result & 0xFF


def gf_mul(a, b):
    """Multiplication in GF(2^8)."""

    result = 0

    for _ in range(8):

        if b & 1:
            result ^= a

        a = xtime(a)
        b >>= 1

    return result


def gf_pow(a, n):
    """Exponentiation in GF(2^8)."""

    result = 1

    while n > 0:

        if n & 1:
            result = gf_mul(result, a)

        a = gf_mul(a, a)
        n >>= 1

    return result


def gf_inv(a):
    """Multiplicative inverse used in AES."""

    if a == 0:
        return 0

    return gf_pow(a, 254)
