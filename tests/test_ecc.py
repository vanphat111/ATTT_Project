"""Unit tests for Elliptic Curve Cryptography (algorithms.ecc).

Covers test cases specified in the project report (Table 6.3):
- ECC-01: Verify that a generated point satisfies the curve equation.
- ECC-02: Multiply the base point by its subgroup order -> Obtain point at infinity.
- ECC-03: Compute a shared point using two private scalars (ECDH key exchange).
Additional verification:
- Step-by-step point doubling and addition matching Section 4.4.6 of report.
- Point at infinity and identity properties.
- Full cycle of scalar multiplication on F17 curve.
- Standard cryptographic curve secp256k1 validation.
"""

import unittest

from algorithms.ecc import (
    CURVE_F17,
    POINT_INFINITY,
    SECP256K1,
    Point,
    mod_inverse,
)


class TestECC(unittest.TestCase):
    """Test suite for ECC implementation from first principles."""

    def test_mod_inverse(self) -> None:
        """Test modular multiplicative inverse calculation."""
        # 2^-1 mod 17 == 9 because 2 * 9 = 18 = 1 mod 17
        self.assertEqual(mod_inverse(2, 17), 9)
        self.assertEqual(mod_inverse(3, 11), 4)

        with self.assertRaises(ValueError):
            mod_inverse(0, 17)
        with self.assertRaises(ValueError):
            # Not coprime
            mod_inverse(4, 8)

    def test_ecc01_points_on_curve(self) -> None:
        """ECC-01: Verify that generated points satisfy the curve equation.

        For F17 curve: y^2 = x^3 + 2x + 2 (mod 17).
        """
        # Generator point G = (5, 1)
        self.assertTrue(CURVE_F17.is_on_curve(CURVE_F17.g))

        # Check random invalid point (5, 2): 2^2 = 4 != 1 mod 17
        self.assertFalse(CURVE_F17.is_on_curve(Point(5, 2)))

        # Point at infinity is always considered on curve
        self.assertTrue(CURVE_F17.is_on_curve(POINT_INFINITY))

    def test_section_4_4_6_step_by_step_operations(self) -> None:
        """Verify exact step-by-step point operations from Section 4.4.6 of report.

        Curve: y^2 = x^3 + 2x + 2 (mod 17), P = (5, 1).
        Doubling: 2P = (6, 3).
        Addition: 3P = P + 2P = (10, 6).
        """
        p = Point(5, 1)

        # Point Doubling 2P = (6, 3)
        two_p = CURVE_F17.double(p)
        self.assertEqual(two_p, Point(6, 3))
        self.assertTrue(CURVE_F17.is_on_curve(two_p))

        # Point Addition 3P = P + 2P = (10, 6)
        three_p = CURVE_F17.add(p, two_p)
        self.assertEqual(three_p, Point(10, 6))
        self.assertTrue(CURVE_F17.is_on_curve(three_p))

    def test_ecc02_subgroup_order_infinity(self) -> None:
        """ECC-02: Multiply the base point by its subgroup order.

        Expected result is the point at infinity: n * G = O.
        """
        # On F17 curve, order n = 19
        result_f17 = CURVE_F17.scalar_mult(CURVE_F17.n, CURVE_F17.g)
        self.assertEqual(result_f17, POINT_INFINITY)

        # On secp256k1 curve
        result_secp = SECP256K1.scalar_mult(SECP256K1.n, SECP256K1.g)
        self.assertEqual(result_secp, POINT_INFINITY)

    def test_ecc03_shared_point_ecdh(self) -> None:
        """ECC-03: Compute a shared point using two private scalars (Section 4.8 of report).

        Alice: dA = 5  => QA = 5G = (9, 16)
        Bob:   dB = 7  => QB = 7G = (0, 6)
        Shared: SA = dA * QB = 5 * (0, 6) = (10, 11)
                SB = dB * QA = 7 * (9, 16) = (10, 11)
        Both parties obtain SA == SB.
        """
        d_a = 5
        d_b = 7

        q_a = CURVE_F17.scalar_mult(d_a, CURVE_F17.g)
        q_b = CURVE_F17.scalar_mult(d_b, CURVE_F17.g)

        self.assertEqual(q_a, Point(9, 16))
        self.assertEqual(q_b, Point(0, 6))

        # Alice computes SA = dA * QB
        s_a = CURVE_F17.scalar_mult(d_a, q_b)

        # Bob computes SB = dB * QA
        s_b = CURVE_F17.scalar_mult(d_b, q_a)

        self.assertEqual(s_a, Point(10, 11))
        self.assertEqual(s_b, Point(10, 11))
        self.assertEqual(s_a, s_b)

    def test_identity_and_negation_properties(self) -> None:
        """Verify group axioms: P + O = P, P + (-P) = O."""
        g = CURVE_F17.g

        # P + O = P
        self.assertEqual(CURVE_F17.add(g, POINT_INFINITY), g)
        self.assertEqual(CURVE_F17.add(POINT_INFINITY, g), g)

        # P + (-P) = O
        neg_g = CURVE_F17.negate(g)
        self.assertEqual(neg_g, Point(5, 16))  # 17 - 1 = 16
        self.assertEqual(CURVE_F17.add(g, neg_g), POINT_INFINITY)

    def test_secp256k1_basic_math(self) -> None:
        """Verify basic point addition and doubling on standard secp256k1 curve."""
        g = SECP256K1.g
        self.assertTrue(SECP256K1.is_on_curve(g))

        two_g_add = SECP256K1.add(g, g)
        two_g_double = SECP256K1.double(g)
        two_g_scalar = SECP256K1.scalar_mult(2, g)

        self.assertEqual(two_g_add, two_g_double)
        self.assertEqual(two_g_double, two_g_scalar)
        self.assertTrue(SECP256K1.is_on_curve(two_g_double))


if __name__ == "__main__":
    unittest.main()
