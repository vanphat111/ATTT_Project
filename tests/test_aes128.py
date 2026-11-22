"""Unit tests for AES-128 block cipher and CBC mode (algorithms.aes128).

Covers test cases specified in the project report (Table 6.3):
- AES-01: Encrypt and decrypt a valid plaintext (Round-trip verification).
- AES-02: Execute a standard AES-128 test vector (NIST FIPS PUB 197 Appendix B).
Additional verification:
- Course project worked example (Table 3.9: Hồ Văn Phát, IV, C1).
- Multi-block CBC encryption and decryption.
- PKCS#7 padding and unpadding edge cases.
- Input validation (key/IV length checks).
"""

import os
import unittest

from algorithms.aes128 import (
    aes_cbc_decrypt,
    aes_cbc_encrypt,
    decrypt_block,
    encrypt_block,
    key_expansion,
    pkcs7_pad,
    pkcs7_unpad,
)
from algorithms.sha256 import sha256_bytes


class TestAES128(unittest.TestCase):
    """Test suite for AES-128 implementation from first principles."""

    def test_aes02_nist_fips197_test_vector(self) -> None:
        """AES-02: Execute standard NIST FIPS PUB 197 Appendix B test vector.

        Key:        2b7e151628aed2a6abf7158809cf4f3c
        Plaintext:  3243f6a8885a308d313198a2e0370734
        Ciphertext: 3925841d02dc09fbdc118597196a0b32
        """
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        plaintext_block = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
        expected_cipher = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")

        round_keys = key_expansion(key)
        self.assertEqual(len(round_keys), 11)

        # Direct block encryption test
        ciphertext = encrypt_block(plaintext_block, round_keys)
        self.assertEqual(ciphertext, expected_cipher)

        # Direct block decryption test
        decrypted = decrypt_block(ciphertext, round_keys)
        self.assertEqual(decrypted, plaintext_block)

    def test_aes01_round_trip(self) -> None:
        """AES-01: Encrypt and decrypt a valid plaintext.

        Verify that DK(EK(P)) == P for various message lengths.
        """
        key = os.urandom(16)
        iv = os.urandom(16)

        test_messages = [
            b"Short msg",
            b"Exactly 16 bytes",
            b"This is a longer message that definitely spans across several AES blocks in CBC mode.",
            b"A" * 256,
        ]

        for msg in test_messages:
            ciphertext = aes_cbc_encrypt(msg, key, iv)
            recovered = aes_cbc_decrypt(ciphertext, key, iv)
            self.assertEqual(recovered, msg)

    def test_course_project_example_table3_9(self) -> None:
        """Verify course project worked example (Table 3.9 of report).

        Full Name: "Hồ Văn Phát"
        SHA-256 derived key (first 128-bit): 6be3b21d232d57beb433d20736a4761b
        IV: 101112131415161718191a1b1c1d1e1f
        Plaintext: "Hồ Văn Phát"
        Padded: 48e1bb932056c4836e205068c3a17401
        Ciphertext: ba4e1f06d19b3083f59c05d0b85f858a
        """
        name = "Hồ Văn Phát"
        derived_key = sha256_bytes(name)[:16]
        self.assertEqual(
            derived_key.hex(), "6be3b21d232d57beb433d20736a4761b"
        )

        iv = bytes.fromhex("101112131415161718191a1b1c1d1e1f")
        plaintext = name.encode("utf-8")

        # Check padded plaintext
        padded = pkcs7_pad(plaintext, 16)
        self.assertEqual(padded.hex(), "48e1bb932056c4836e205068c3a17401")

        # Check encryption
        ciphertext = aes_cbc_encrypt(plaintext, derived_key, iv)
        self.assertEqual(ciphertext.hex(), "ba4e1f06d19b3083f59c05d0b85f858a")

        # Check decryption
        decrypted = aes_cbc_decrypt(ciphertext, derived_key, iv)
        self.assertEqual(decrypted, plaintext)
        self.assertEqual(decrypted.decode("utf-8"), name)

    def test_pkcs7_padding(self) -> None:
        """Test PKCS#7 padding and unpadding edge cases."""
        # 15 bytes -> adds 1 byte of 0x01
        data15 = b"A" * 15
        padded15 = pkcs7_pad(data15, 16)
        self.assertEqual(len(padded15), 16)
        self.assertEqual(padded15[-1], 0x01)
        self.assertEqual(pkcs7_unpad(padded15, 16), data15)

        # 16 bytes -> adds full 16 bytes of 0x10
        data16 = b"B" * 16
        padded16 = pkcs7_pad(data16, 16)
        self.assertEqual(len(padded16), 32)
        self.assertEqual(padded16[-16:], bytes([0x10] * 16))
        self.assertEqual(pkcs7_unpad(padded16, 16), data16)

        # Invalid padding tests
        with self.assertRaises(ValueError):
            pkcs7_unpad(b"Not16BytesLength", 16)
        with self.assertRaises(ValueError):
            # Corrupted padding byte
            bad_pad = b"A" * 15 + bytes([0x05])
            pkcs7_unpad(bad_pad, 16)

    def test_invalid_key_and_iv_lengths(self) -> None:
        """Verify errors are raised for invalid key or IV sizes."""
        valid_key = b"0" * 16
        valid_iv = b"1" * 16
        data = b"Hello World"

        # Invalid key size (not 16 bytes)
        with self.assertRaises(ValueError):
            aes_cbc_encrypt(data, b"short_key", valid_iv)

        # Invalid IV size (not 16 bytes)
        with self.assertRaises(ValueError):
            aes_cbc_encrypt(data, valid_key, b"short_iv")


if __name__ == "__main__":
    unittest.main()
