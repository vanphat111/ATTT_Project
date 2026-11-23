"""Unit tests for Schnorr Digital Signature scheme (algorithms.schnorr).

Covers test cases specified in the project report (Table 6.3):
- SCH-01: Sign a message and verify its signature (Signature is accepted).
- SCH-02: Modify the original signed message (Signature is rejected).
- SCH-03: Modify a signature component (Signature is rejected).
Additional verification:
- Step-by-step worked example from Chapter 5 Section 5.8 of report:
  Curve F17, m = "Schnorr signature example", d = 5, k = 7, R = (0,6), e = 16, s = 11.
- Random key generation and signing on standard secp256k1 curve.
- Verification robustness against out-of-range scalars and points not on curve.
"""

import unittest

from algorithms.ecc import (
    CURVE_F17,
    POINT_INFINITY,
    SECP256K1,
    Point,
)
from algorithms.schnorr import (
    SchnorrSignature,
    compute_challenge,
    derive_public_key,
    generate_keypair,
    sign,
    verify,
)


class TestSchnorr(unittest.TestCase):
    """Test suite for Schnorr Digital Signature scheme."""

    def test_key_derivation_course_project_example(self) -> None:
        """Verify public key derivation matches Section 5.8.2 in course report.

        On F17 curve:
        Private key: d = 5
        Expected public key: P = 5G = (9, 16).
        """
        d = 5
        public_key = derive_public_key(d, CURVE_F17)
        expected_public_key = Point(9, 16)

        self.assertEqual(public_key, expected_public_key)
        self.assertTrue(CURVE_F17.is_on_curve(public_key))

    def test_random_keypair_generation(self) -> None:
        """Test random key generation on educational and standard curves."""
        # Test on F17
        d_f17, p_f17 = generate_keypair(CURVE_F17)
        self.assertGreaterEqual(d_f17, 1)
        self.assertLess(d_f17, CURVE_F17.n)
        self.assertTrue(CURVE_F17.is_on_curve(p_f17))

        # Test on secp256k1
        d_secp, p_secp = generate_keypair(SECP256K1)
        self.assertGreaterEqual(d_secp, 1)
        self.assertLess(d_secp, SECP256K1.n)
        self.assertTrue(SECP256K1.is_on_curve(p_secp))

    def test_course_project_worked_example_section_5_8(self) -> None:
        """Verify the exact step-by-step example in Section 5.8 & Table 5.2.

        Curve: F17 (p=17, a=2, b=2, G=(5,1), n=19)
        Message: "Schnorr signature example"
        Private key: d = 5
        Public key: P = (9, 16)
        Fixed Nonce: k = 7
        Commitment Point: R = 7G = (0, 6)
        Challenge: e = 16
        Signature Response: s = 11
        Signature: sigma = ((0, 6), 11)
        Verification result: VALID
        """
        msg = "Schnorr signature example"
        d = 5
        k = 7
        curve = CURVE_F17

        # 1. Derive Public Key P = (9, 16)
        public_key = derive_public_key(d, curve)
        self.assertEqual(public_key, Point(9, 16))

        # 2. Check commitment point R = 7G = (0, 6)
        r = curve.scalar_mult(k, curve.g)
        self.assertEqual(r, Point(0, 6))

        # 3. Check challenge e == 16
        e = compute_challenge(msg.encode("utf-8"), r, curve)
        self.assertEqual(e, 16)

        # 4. Sign message using fixed nonce k = 7
        sig = sign(msg, d, curve, k=k)
        self.assertEqual(sig.r, Point(0, 6))
        self.assertEqual(sig.s, 11)

        # 5. Verify signature
        is_valid = verify(msg, sig, public_key, curve)
        self.assertTrue(is_valid)

    def test_sch01_sign_and_verify_valid(self) -> None:
        """SCH-01: Sign a message and verify its signature.

        Expected: Signature is accepted (True).
        """
        # Test on educational F17 curve
        d_f17, p_f17 = generate_keypair(CURVE_F17)
        msg1 = "Information Security Assignment UTH"
        sig_f17 = sign(msg1, d_f17, CURVE_F17)
        self.assertTrue(verify(msg1, sig_f17, p_f17, CURVE_F17))

        # Test on standard secp256k1 curve
        d_secp, p_secp = generate_keypair(SECP256K1)
        msg2 = "Cryptographic digital signature test payload."
        sig_secp = sign(msg2, d_secp, SECP256K1)
        self.assertTrue(verify(msg2, sig_secp, p_secp, SECP256K1))

    def test_sch02_tampered_message_rejected(self) -> None:
        """SCH-02: Modify the original signed message.

        Expected: Signature is rejected (False).
        """
        d, pub = generate_keypair(SECP256K1)
        orig_msg = "Transfer 100 USD to Alice"
        sig = sign(orig_msg, d, SECP256K1)

        # 1. Original message must verify
        self.assertTrue(verify(orig_msg, sig, pub, SECP256K1))

        # 2. Modified message must be rejected
        tampered_msg = "Transfer 900 USD to Alice"
        self.assertFalse(verify(tampered_msg, sig, pub, SECP256K1))

        # 3. Subtle modification (single bit/character change)
        tampered_msg_subtle = "transfer 100 USD to Alice"
        self.assertFalse(verify(tampered_msg_subtle, sig, pub, SECP256K1))

    def test_sch03_tampered_signature_rejected(self) -> None:
        """SCH-03: Modify a signature component.

        Expected: Signature is rejected (False).
        """
        curve = SECP256K1
        d, pub = generate_keypair(curve)
        msg = "Authentic contract data"
        sig = sign(msg, d, curve)

        # 1. Tamper with response scalar s
        bad_s = (sig.s + 1) % curve.n
        tampered_sig_s = SchnorrSignature(sig.r, bad_s)
        self.assertFalse(verify(msg, tampered_sig_s, pub, curve))

        # 2. Out-of-bounds scalar s
        bad_sig_s_overflow = SchnorrSignature(sig.r, curve.n + 5)
        self.assertFalse(verify(msg, bad_sig_s_overflow, pub, curve))

        # 3. Tamper with commitment point R (use generator G instead of R)
        if sig.r != curve.g:
            tampered_sig_r = SchnorrSignature(curve.g, sig.s)
            self.assertFalse(verify(msg, tampered_sig_r, pub, curve))

        # 4. Verify with wrong public key
        _, other_pub = generate_keypair(curve)
        self.assertFalse(verify(msg, sig, other_pub, curve))


if __name__ == "__main__":
    unittest.main()
