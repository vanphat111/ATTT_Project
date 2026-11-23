"""Unit tests for custom SHA-256 implementation (algorithms.sha256).

Covers test cases specified in the project report (Table 6.3):
- SHA-01: Hash an empty input message.
- SHA-02: Hash a UTF-8 encoded full name ("Hồ Văn Phát").
Additional verification:
- Standard NIST test vectors (e.g., "abc", multi-block string).
- Intermediate calculation verification (padding, W16 expansion).
- Stress & equivalence verification against hashlib.sha256.
- Input type validation.
"""

import hashlib
import os
import unittest

from algorithms.sha256 import (
    generate_message_schedule,
    pad_message,
    parse_blocks,
    sha256_bytes,
    sha256_hex,
    to_bytes,
)


class TestSHA256(unittest.TestCase):
    """Test suite for SHA-256 implementation from first principles."""

    def test_sha01_empty_string(self) -> None:
        """SHA-01: Hash an empty input message.

        Expected digest is the standard empty-string SHA-256 digest:
        e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        """
        expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self.assertEqual(sha256_hex(""), expected)
        self.assertEqual(sha256_hex(b""), expected)
        self.assertEqual(sha256_bytes(b""), bytes.fromhex(expected))

    def test_sha02_full_name(self) -> None:
        """SHA-02: Hash UTF-8 encoded student full name ("Hồ Văn Phát").

        Expected digest matches Listing 2.1 and Table 3.9 of course report:
        6be3b21d232d57beb433d20736a4761b0b09e161615944cfd93d20dd9b19cde9
        """
        full_name = "Hồ Văn Phát"
        expected = (
            "6be3b21d232d57beb433d20736a4761b0b09e161615944cfd93d20dd9b19cde9"
        )
        self.assertEqual(sha256_hex(full_name), expected)
        self.assertEqual(sha256_hex(full_name.encode("utf-8")), expected)

    def test_nist_vector_abc(self) -> None:
        """NIST test vector for single block message: 'abc'."""
        msg = "abc"
        expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        self.assertEqual(sha256_hex(msg), expected)

    def test_nist_vector_multi_block(self) -> None:
        """NIST test vector crossing block boundary (56 bytes -> 2 blocks):

        'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'
        """
        msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        expected = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        self.assertEqual(sha256_hex(msg), expected)

    def test_padding_structure(self) -> None:
        """Verify padding mechanism complies with FIPS 180-4 Section 5.1.1."""
        raw = "Hồ Văn Phát".encode("utf-8")
        self.assertEqual(len(raw), 15)  # 15 bytes = 120 bits

        padded = pad_message(raw)
        # Padded message must be a multiple of 64 bytes (512 bits)
        self.assertEqual(len(padded), 64)
        # Byte after original data must be 0x80
        self.assertEqual(padded[15], 0x80)
        # Middle bytes must be 0x00
        for b in padded[16:56]:
            self.assertEqual(b, 0x00)
        # Last 8 bytes must be the original bit length (120 bits = 0x78)
        expected_len_bytes = (120).to_bytes(8, byteorder="big")
        self.assertEqual(padded[56:64], expected_len_bytes)

    def test_message_schedule_step_by_step(self) -> None:
        """Verify message schedule expansion matches Chapter 2 Section 2.7.4.

        In section 2.7.4:
        W0 = 0x48e1bb93
        W1 = 0x2056c483
        ...
        W16 must equal 0xfc4c789f.
        """
        raw = "Hồ Văn Phát".encode("utf-8")
        padded = pad_message(raw)
        blocks = parse_blocks(padded)
        self.assertEqual(len(blocks), 1)

        schedule = generate_message_schedule(blocks[0])
        self.assertEqual(len(schedule), 64)
        self.assertEqual(schedule[0], 0x48E1BB93)
        self.assertEqual(schedule[1], 0x2056C483)
        self.assertEqual(schedule[2], 0x6E205068)
        self.assertEqual(schedule[3], 0xC3A17480)
        self.assertEqual(schedule[15], 0x00000078)
        self.assertEqual(schedule[16], 0xFC4C789F)

    def test_input_type_support(self) -> None:
        """Verify input validation supports str, bytes, bytearray and rejects other types."""
        text = "TestInput"
        digest_str = sha256_hex(text)
        digest_bytes = sha256_hex(text.encode("utf-8"))
        digest_bytearray = sha256_hex(bytearray(text.encode("utf-8")))

        self.assertEqual(digest_str, digest_bytes)
        self.assertEqual(digest_str, digest_bytearray)

        with self.assertRaises(TypeError):
            to_bytes(12345)  # type: ignore

    def test_hashlib_equivalence_fuzz(self) -> None:
        """Equivalence test against Python standard library hashlib for multiple sizes.

        Tests edge cases around block boundaries: 0, 1, 55, 56, 63, 64, 65, 119, 120, 128 bytes,
        and random binary payloads up to 5000 bytes.
        """
        boundary_lengths = [0, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 256, 512, 1024]
        for length in boundary_lengths:
            payload = b"A" * length
            expected = hashlib.sha256(payload).hexdigest()
            actual = sha256_hex(payload)
            self.assertEqual(
                actual,
                expected,
                f"Failed for static payload of length {length}",
            )

        # Random payload checks
        for size in [7, 33, 79, 150, 431, 1000, 3500]:
            rand_bytes = os.urandom(size)
            expected = hashlib.sha256(rand_bytes).hexdigest()
            actual = sha256_hex(rand_bytes)
            self.assertEqual(
                actual,
                expected,
                f"Failed for random payload of size {size}",
            )


if __name__ == "__main__":
    unittest.main()
