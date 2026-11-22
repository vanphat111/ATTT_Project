from __future__ import annotations
from dataclasses import dataclass
from typing import Optional


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    if a == 0:
        return b, 0, 1
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd_val, x, y


def mod_inverse(a: int, m: int) -> int:
    a = a % m
    if a == 0:
        raise ValueError("Zero has no modular inverse")
    gcd_val, x, _ = extended_gcd(a, m)
    if gcd_val != 1:
        raise ValueError(f"Modular inverse does not exist for {a} mod {m}")
    return (x % m + m) % m


@dataclass(frozen=True)
class Point:
    x: Optional[int] = None
    y: Optional[int] = None
    is_infinity: bool = False

    def __post_init__(self) -> None:
        if self.is_infinity:
            object.__setattr__(self, "x", None)
            object.__setattr__(self, "y", None)
        elif self.x is None or self.y is None:
            object.__setattr__(self, "is_infinity", True)

    def __repr__(self) -> str:
        if self.is_infinity:
            return "Point(Infinity)"
        return f"Point(x={self.x}, y={self.y})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Point):
            return False
        if self.is_infinity and other.is_infinity:
            return True
        return (
            self.is_infinity == other.is_infinity
            and self.x == other.x
            and self.y == other.y
        )


POINT_INFINITY = Point(is_infinity=True)


class EllipticCurve:
    def __init__(
        self,
        p: int,
        a: int,
        b: int,
        g: Point,
        n: int,
        h: int = 1,
        name: str = "CustomCurve",
    ) -> None:
        self.p = p
        self.a = a % p
        self.b = b % p
        self.g = g
        self.n = n
        self.h = h
        self.name = name

        discriminant = (4 * (self.a**3) + 27 * (self.b**2)) % self.p
        if discriminant == 0:
            raise ValueError("Singular curve: 4a^3 + 27b^2 == 0 (mod p)")

        if not self.is_on_curve(self.g):
            raise ValueError(f"Generator point {self.g} does not lie on the curve")

    def is_on_curve(self, pt: Point) -> bool:
        if pt.is_infinity:
            return True
        assert pt.x is not None and pt.y is not None
        lhs = (pt.y**2) % self.p
        rhs = (pt.x**3 + self.a * pt.x + self.b) % self.p
        return lhs == rhs

    def negate(self, pt: Point) -> Point:
        if pt.is_infinity:
            return pt
        assert pt.x is not None and pt.y is not None
        return Point(pt.x, (-pt.y) % self.p)

    def add(self, p1: Point, p2: Point) -> Point:
        if p1.is_infinity:
            return p2
        if p2.is_infinity:
            return p1

        assert p1.x is not None and p1.y is not None
        assert p2.x is not None and p2.y is not None

        if p1.x == p2.x and (p1.y != p2.y or p1.y == 0):
            return POINT_INFINITY

        if p1 == p2:
            return self.double(p1)

        dy = (p2.y - p1.y) % self.p
        dx = (p2.x - p1.x) % self.p
        lam = (dy * mod_inverse(dx, self.p)) % self.p

        x3 = (lam**2 - p1.x - p2.x) % self.p
        y3 = (lam * (p1.x - x3) - p1.y) % self.p

        return Point(x3, y3)

    def double(self, pt: Point) -> Point:
        if pt.is_infinity or pt.y == 0:
            return POINT_INFINITY

        assert pt.x is not None and pt.y is not None

        numerator = (3 * (pt.x**2) + self.a) % self.p
        denominator = (2 * pt.y) % self.p
        lam = (numerator * mod_inverse(denominator, self.p)) % self.p

        x3 = (lam**2 - 2 * pt.x) % self.p
        y3 = (lam * (pt.x - x3) - pt.y) % self.p

        return Point(x3, y3)

    def scalar_mult(self, k: int, pt: Point) -> Point:
        if pt.is_infinity:
            return POINT_INFINITY

        if self.n > 0:
            k = k % self.n

        if k == 0:
            return POINT_INFINITY

        if k < 0:
            pt = self.negate(pt)
            k = -k

        result = POINT_INFINITY
        current = pt

        while k > 0:
            if k & 1:
                result = self.add(result, current)
            current = self.double(current)
            k >>= 1

        return result



CURVE_F17 = EllipticCurve(
    p=17,
    a=2,
    b=2,
    g=Point(5, 1),
    n=19,
    h=1,
    name="F17_Edu",
)

SECP256K1 = EllipticCurve(
    p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    a=0,
    b=7,
    g=Point(
        x=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        y=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    ),
    n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
    h=1,
    name="secp256k1",
)
