
import unittest

from des.tables import IP, FP
from des.key_schedule import (
    permute,
    left_shift,
    generate_subkeys
)
from des.feistel import (
    xor_bits,
    sbox_substitution,
    feistel
)
from des.des import des_encrypt, des_decrypt


class TestDES(unittest.TestCase):

    PLAINTEXT = "0123456789ABCDEF"
    KEY = "133457799BBCDFF1"
    CIPHERTEXT = "85E813540F0AB405"

    def test_01_initial_permutation(self):
        """TC01: Initial Permutation."""

        bits = format(int(self.PLAINTEXT, 16), "064b")
        result = permute(bits, IP)

        self.assertEqual(
            format(int(result, 2), "016X"),
            "CC00CCFFF0AAF0AA"
        )

    def test_02_final_permutation(self):
        """TC02: Final Permutation."""

        bits = format(int("CC00CCFFF0AAF0AA", 16), "064b")
        result = permute(bits, FP)

        self.assertEqual(
            format(int(result, 2), "016X"),
            self.PLAINTEXT
        )

    def test_03_left_shift(self):
        """TC03: Circular left shift."""

        self.assertEqual(
            left_shift("10110010", 1),
            "01100101"
        )

        self.assertEqual(
            left_shift("10110010", 2),
            "11001010"
        )

    def test_04_xor(self):
        """TC04: XOR operation."""

        self.assertEqual(
            xor_bits("101100", "110010"),
            "011110"
        )

    def test_05_sbox(self):
        """TC05: S-box substitution."""

        bits = format(int("6117BA866527", 16), "048b")
        result = sbox_substitution(bits)

        self.assertEqual(
            format(int(result, 2), "08X"),
            "5C82B597"
        )

    def test_06_key_schedule(self):
        """TC06: Generate 16 round keys."""

        expected = [
            "1B02EFFC7072",
            "79AED9DBC9E5",
            "55FC8A42CF99",
            "72ADD6DB351D",
            "7CEC07EB53A8",
            "63A53E507B2F",
            "EC84B7F618BC",
            "F78A3AC13BFB",
            "E0DBEBEDE781",
            "B1F347BA464F",
            "215FD3DED386",
            "7571F59467E9",
            "97C5D1FABA41",
            "5F43B7F2E73A",
            "BF918D3D3F0A",
            "CB3D8B0E17F5"
        ]

        subkeys = generate_subkeys(self.KEY)

        self.assertEqual(len(subkeys), 16)

        for i in range(16):
            with self.subTest(round=i + 1):

                self.assertEqual(len(subkeys[i]), 48)

                self.assertEqual(
                    format(int(subkeys[i], 2), "012X"),
                    expected[i]
                )

    def test_07_feistel(self):
        """TC07: Feistel function."""

        right = format(int("F0AAF0AA", 16), "032b")
        subkey = format(int("1B02EFFC7072", 16), "048b")

        result = feistel(right, subkey)

        self.assertEqual(
            format(int(result, 2), "08X"),
            "234AA9BB"
        )

    def test_08_encryption(self):
        """TC08: DES encryption."""

        result = des_encrypt(
            self.PLAINTEXT,
            self.KEY
        )

        self.assertEqual(result, self.CIPHERTEXT)

    def test_09_decryption(self):
        """TC09: DES decryption."""

        result = des_decrypt(
            self.CIPHERTEXT,
            self.KEY
        )

        self.assertEqual(result, self.PLAINTEXT)

    def test_10_round_trip(self):
        """TC10: Encryption and decryption."""

        plaintexts = [
            "0000000000000000",
            "FFFFFFFFFFFFFFFF",
            "0123456789ABCDEF",
            "1234567890ABCDEF",
            "AABBCCDDEEFF0011"
        ]

        for plaintext in plaintexts:
            with self.subTest(plaintext=plaintext):

                ciphertext = des_encrypt(
                    plaintext,
                    self.KEY
                )

                decrypted = des_decrypt(
                    ciphertext,
                    self.KEY
                )

                self.assertEqual(decrypted, plaintext)


if __name__ == "__main__":
    unittest.main(verbosity=2)
