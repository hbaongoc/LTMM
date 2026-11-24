
import unittest

from aes.gf import gf_add, xtime, gf_mul, gf_inv

from aes.sbox import S_BOX, INV_S_BOX

from aes.transformations import (
    hex_to_state,
    state_to_hex,
    sub_bytes,
    inv_sub_bytes,
    shift_rows,
    inv_shift_rows,
    mix_columns,
    inv_mix_columns,
    add_round_key,
)

from aes.key_expansion import key_expansion
from aes.aes import aes_encrypt, aes_decrypt


# Standard AES-128 test vector
STANDARD_PLAINTEXT = "00112233445566778899AABBCCDDEEFF"
STANDARD_KEY = "000102030405060708090A0B0C0D0E0F"
STANDARD_CIPHERTEXT = "69C4E0D86A7B0430D8CDB78070B4C55A"

# Classroom example
CLASS_PLAINTEXT = "00000000000000000000000000001111"
CLASS_KEY = "00000000000000000000000000000000"
CLASS_CIPHERTEXT = "442758DF6DDA9EDB6BF1468A17B93FE5"


class TestAES(unittest.TestCase):

    def test_01_gf_add(self):

        self.assertEqual(gf_add(0x57, 0x83), 0xD4)

    def test_02_xtime(self):

        self.assertEqual(xtime(0x57), 0xAE)
        self.assertEqual(xtime(0x83), 0x1D)
        self.assertEqual(xtime(0x80), 0x1B)

    def test_03_gf_mul(self):

        self.assertEqual(gf_mul(0x57, 0x83), 0xC1)
        self.assertEqual(gf_mul(0x57, 0x13), 0xFE)
        self.assertEqual(gf_mul(0x57, 0x00), 0x00)
        self.assertEqual(gf_mul(0x57, 0x01), 0x57)

    def test_04_gf_inverse(self):

        self.assertEqual(gf_inv(0x11), 0xB4)
        self.assertEqual(gf_inv(0x00), 0x00)

        for value in range(1, 256):

            self.assertEqual(
                gf_mul(value, gf_inv(value)),
                1
            )

    def test_05_sbox(self):

        self.assertEqual(len(S_BOX), 256)
        self.assertEqual(len(set(S_BOX)), 256)

        self.assertEqual(S_BOX[0x00], 0x63)
        self.assertEqual(S_BOX[0x11], 0x82)
        self.assertEqual(S_BOX[0x53], 0xED)
        self.assertEqual(S_BOX[0xFF], 0x16)

    def test_06_inverse_sbox(self):

        self.assertEqual(INV_S_BOX[0x82], 0x11)
        self.assertEqual(INV_S_BOX[0xED], 0x53)

        for value in range(256):

            self.assertEqual(
                INV_S_BOX[S_BOX[value]],
                value
            )

    def test_07_state_conversion(self):

        data = "000102030405060708090A0B0C0D0E0F"

        expected = [
            [0x00, 0x04, 0x08, 0x0C],
            [0x01, 0x05, 0x09, 0x0D],
            [0x02, 0x06, 0x0A, 0x0E],
            [0x03, 0x07, 0x0B, 0x0F],
        ]

        state = hex_to_state(data)

        self.assertEqual(state, expected)
        self.assertEqual(state_to_hex(state), data)

    def test_08_sub_bytes(self):

        state = hex_to_state(CLASS_PLAINTEXT)

        expected = [
            [0x63, 0x63, 0x63, 0x63],
            [0x63, 0x63, 0x63, 0x63],
            [0x63, 0x63, 0x63, 0x82],
            [0x63, 0x63, 0x63, 0x82],
        ]

        result = sub_bytes(state)

        self.assertEqual(result, expected)
        self.assertEqual(inv_sub_bytes(result), state)

    def test_09_shift_rows(self):

        state = hex_to_state(
            "000102030405060708090A0B0C0D0E0F"
        )

        expected = [
            [0x00, 0x04, 0x08, 0x0C],
            [0x05, 0x09, 0x0D, 0x01],
            [0x0A, 0x0E, 0x02, 0x06],
            [0x0F, 0x03, 0x07, 0x0B],
        ]

        result = shift_rows(state)

        self.assertEqual(result, expected)
        self.assertEqual(inv_shift_rows(result), state)

    def test_10_mix_columns(self):

        state = hex_to_state(
            "DB135345F20A225C01010101C6C6C6C6"
        )

        expected = "8E4DA1BC9FDC589D01010101C6C6C6C6"

        result = mix_columns(state)

        self.assertEqual(state_to_hex(result), expected)
        self.assertEqual(inv_mix_columns(result), state)

    def test_11_add_round_key(self):

        state = hex_to_state(STANDARD_PLAINTEXT)
        key = hex_to_state(STANDARD_KEY)

        expected = "00102030405060708090A0B0C0D0E0F0"

        result = add_round_key(state, key)

        self.assertEqual(state_to_hex(result), expected)
        self.assertEqual(add_round_key(result, key), state)

    def test_12_key_expansion(self):

        expected_keys = [
            "000102030405060708090A0B0C0D0E0F",
            "D6AA74FDD2AF72FADAA678F1D6AB76FE",
            "B692CF0B643DBDF1BE9BC5006830B3FE",
            "B6FF744ED2C2C9BF6C590CBF0469BF41",
            "47F7F7BC95353E03F96C32BCFD058DFD",
            "3CAAA3E8A99F9DEB50F3AF57ADF622AA",
            "5E390F7DF7A69296A7553DC10AA31F6B",
            "14F9701AE35FE28C440ADF4D4EA9C026",
            "47438735A41C65B9E016BAF4AEBF7AD2",
            "549932D1F08557681093ED9CBE2C974E",
            "13111D7FE3944A17F307A78B4D2B30C5",
        ]

        round_keys = key_expansion(STANDARD_KEY)

        self.assertEqual(len(round_keys), 11)

        for i in range(11):

            self.assertEqual(
                state_to_hex(round_keys[i]),
                expected_keys[i]
            )

        zero_keys = key_expansion(CLASS_KEY)

        self.assertEqual(
            state_to_hex(zero_keys[1]),
            "62636363626363636263636362636363"
        )

    def test_13_standard_encryption(self):

        ciphertext = aes_encrypt(
            STANDARD_PLAINTEXT,
            STANDARD_KEY
        )

        self.assertEqual(ciphertext, STANDARD_CIPHERTEXT)

    def test_14_standard_decryption(self):

        plaintext = aes_decrypt(
            STANDARD_CIPHERTEXT,
            STANDARD_KEY
        )

        self.assertEqual(plaintext, STANDARD_PLAINTEXT)

    def test_15_class_encryption(self):

        ciphertext = aes_encrypt(
            CLASS_PLAINTEXT,
            CLASS_KEY
        )

        self.assertEqual(ciphertext, CLASS_CIPHERTEXT)

    def test_16_class_decryption(self):

        plaintext = aes_decrypt(
            CLASS_CIPHERTEXT,
            CLASS_KEY
        )

        self.assertEqual(plaintext, CLASS_PLAINTEXT)

    def test_17_encrypt_decrypt(self):

        test_vectors = [
            (STANDARD_PLAINTEXT, STANDARD_KEY),
            (CLASS_PLAINTEXT, CLASS_KEY),
            ("0" * 32, "0" * 32),
            ("F" * 32, "F" * 32),
            ("A5" * 16, "5A" * 16),
        ]

        for plaintext, key in test_vectors:

            with self.subTest(plaintext=plaintext, key=key):

                ciphertext = aes_encrypt(plaintext, key)

                recovered = aes_decrypt(ciphertext, key)

                self.assertEqual(recovered, plaintext)

    def test_18_invalid_input(self):

        with self.assertRaises(ValueError):
            aes_encrypt("1234", STANDARD_KEY)

        with self.assertRaises(ValueError):
            aes_encrypt(STANDARD_PLAINTEXT, "1234")

        with self.assertRaises(ValueError):
            aes_decrypt("1234", STANDARD_KEY)

        with self.assertRaises(ValueError):
            aes_decrypt(STANDARD_CIPHERTEXT, "1234")


if __name__ == "__main__":
    unittest.main(verbosity=2)
