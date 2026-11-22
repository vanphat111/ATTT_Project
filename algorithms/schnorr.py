from __future__ import annotations
from dataclasses import dataclass
import secrets
from typing import Optional
from algorithms.ecc import EllipticCurve, Point
from algorithms.sha256 import sha256_bytes


@dataclass(frozen=True)
class SchnorrSignature:
    r: Point
    s: int


def derive_public_key(d: int, curve: EllipticCurve) -> Point:
    if not (1 <= d < curve.n):
        raise ValueError("Private key out of range")
    return curve.scalar_mult(d, curve.g)


def generate_keypair(curve: EllipticCurve) -> tuple[int, Point]:
    d = secrets.randbelow(curve.n - 1) + 1
    p = derive_public_key(d, curve)
    return d, p


def encode_point(pt: Point, curve: EllipticCurve) -> bytes:
    if pt.is_infinity or pt.x is None or pt.y is None:
        raise ValueError("Cannot encode point at infinity")
    byte_len = (curve.p.bit_length() + 7) // 8
    return pt.x.to_bytes(byte_len, "big") + pt.y.to_bytes(byte_len, "big")


def compute_challenge(msg: bytes, r: Point, curve: EllipticCurve) -> int:
    encoded_r = encode_point(r, curve)
    digest = sha256_bytes(msg + encoded_r)
    e = int.from_bytes(digest, "big") % curve.n
    return 1 if e == 0 else e


def sign(
    msg: bytes | str,
    d: int,
    curve: EllipticCurve,
    k: Optional[int] = None,
) -> SchnorrSignature:
    if isinstance(msg, str):
        msg = msg.encode("utf-8")
    if not (1 <= d < curve.n):
        raise ValueError("Private key out of range")

    while True:
        nonce = secrets.randbelow(curve.n - 1) + 1 if k is None else k
        if not (1 <= nonce < curve.n):
            raise ValueError("Nonce out of range")

        r = curve.scalar_mult(nonce, curve.g)
        if r.is_infinity:
            if k is not None:
                raise ValueError("Nonce produced point at infinity")
            continue

        e = compute_challenge(msg, r, curve)
        s = (nonce + e * d) % curve.n
        if s != 0:
            return SchnorrSignature(r, s)

        if k is not None:
            raise ValueError("Signature response s is zero")


def verify(
    msg: bytes | str,
    sig: SchnorrSignature,
    public_key: Point,
    curve: EllipticCurve,
) -> bool:
    if isinstance(msg, str):
        msg = msg.encode("utf-8")

    if not (0 <= sig.s < curve.n):
        return False

    if (
        sig.r.is_infinity
        or public_key.is_infinity
        or not curve.is_on_curve(sig.r)
        or not curve.is_on_curve(public_key)
    ):
        return False

    try:
        e = compute_challenge(msg, sig.r, curve)
        s_g = curve.scalar_mult(sig.s, curve.g)
        e_p = curve.scalar_mult(e, public_key)
        neg_e_p = curve.negate(e_p)
        r_prime = curve.add(s_g, neg_e_p)

        if r_prime.is_infinity or r_prime != sig.r:
            return False

        e_prime = compute_challenge(msg, r_prime, curve)
        return e_prime == e
    except Exception:
        return False
