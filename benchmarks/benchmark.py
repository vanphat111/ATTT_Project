"""Cryptographic Benchmark Module.

Provides pure callable functions to benchmark both custom implementations (from first principles)
and standard production reference libraries (hashlib / OpenSSL / cryptography).
Outputs rich structured metrics (dict/list/JSON) containing:
- Average, minimum, and maximum execution times (ms).
- Throughput (KB/s).
- Direct comparison ratios and slowdown factors (Custom vs Reference).
- Raw sample timings (for graphing and plotting).
Completely decoupled from any GUI or terminal interface.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import os
import secrets
import sys
import time
from typing import Any, Callable, Dict, List, Optional

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Custom First-Principles Implementations
from algorithms.aes128 import aes_cbc_decrypt, aes_cbc_encrypt
from algorithms.ecc import CURVE_F17, SECP256K1, Point
from algorithms.schnorr import generate_keypair, sign, verify
from algorithms.sha256 import sha256_bytes

# Standard Reference Libraries for Performance Comparison
import hashlib

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.asymmetric import ec
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False


@dataclass
class BenchmarkRecord:
    """Stores structured performance metrics for a single cryptographic operation."""

    algorithm: str
    operation: str
    input_size_bytes: int
    input_label: str
    iterations: int
    t_avg_ms: float
    t_min_ms: float
    t_max_ms: float
    throughput_kb_s: Optional[float]
    raw_times_ms: List[float]
    implementation_type: str = "custom_first_principles"  # or "reference_library"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ComparisonRecord:
    """Stores a side-by-side comparative analysis between Custom and Reference implementation."""

    algorithm: str
    operation: str
    input_label: str
    custom_t_avg_ms: float
    reference_t_avg_ms: Optional[float]
    reference_lib: str
    slowdown_factor: Optional[float]
    custom_throughput_kb_s: Optional[float]
    reference_throughput_kb_s: Optional[float]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _measure_execution(
    func: Callable[[], Any],
    iterations: int,
    warmup: int = 5,
) -> tuple[float, float, float, list[float]]:
    """Execute a function multiple times and return (t_avg_ms, t_min_ms, t_max_ms, raw_times_ms)."""
    for _ in range(warmup):
        func()

    raw_times: list[float] = []
    for _ in range(iterations):
        start = time.perf_counter()
        func()
        end = time.perf_counter()
        raw_times.append((end - start) * 1000.0)

    t_avg = sum(raw_times) / len(raw_times)
    t_min = min(raw_times)
    t_max = max(raw_times)
    return round(t_avg, 4), round(t_min, 4), round(t_max, 4), [round(t, 4) for t in raw_times]


# =========================================================================
# 1. Custom Implementations Benchmarks
# =========================================================================


def benchmark_sha256(
    sizes: Optional[List[int]] = None,
    iterations: int = 30,
) -> List[Dict[str, Any]]:
    """Benchmark custom SHA-256 hash computation across various payload sizes."""
    if sizes is None:
        sizes = [64, 1024, 16 * 1024, 64 * 1024]

    results: List[Dict[str, Any]] = []

    for size in sizes:
        payload = os.urandom(size)
        label = f"{size} B" if size < 1024 else f"{size // 1024} KB"

        t_avg, t_min, t_max, raw_times = _measure_execution(
            lambda: sha256_bytes(payload),
            iterations=iterations,
            warmup=3,
        )
        throughput = round((size / 1024.0) / (t_avg / 1000.0), 2) if t_avg > 0 else None

        record = BenchmarkRecord(
            algorithm="SHA-256",
            operation="Hash Computation",
            input_size_bytes=size,
            input_label=label,
            iterations=iterations,
            t_avg_ms=t_avg,
            t_min_ms=t_min,
            t_max_ms=t_max,
            throughput_kb_s=throughput,
            raw_times_ms=raw_times,
            implementation_type="custom_first_principles",
        )
        results.append(record.to_dict())

    return results


def benchmark_aes128(
    sizes: Optional[List[int]] = None,
    iterations: int = 20,
) -> List[Dict[str, Any]]:
    """Benchmark custom AES-128 Encryption and Decryption in CBC mode."""
    if sizes is None:
        sizes = [16, 1024, 8 * 1024, 32 * 1024]

    results: List[Dict[str, Any]] = []
    key = os.urandom(16)
    iv = os.urandom(16)

    for size in sizes:
        plaintext = os.urandom(size)
        label = f"{size} B" if size < 1024 else f"{size // 1024} KB"

        # Encryption
        t_enc_avg, t_enc_min, t_enc_max, enc_raw = _measure_execution(
            lambda: aes_cbc_encrypt(plaintext, key, iv),
            iterations=iterations,
            warmup=3,
        )
        enc_tp = round((size / 1024.0) / (t_enc_avg / 1000.0), 2) if t_enc_avg > 0 else None

        results.append(
            BenchmarkRecord(
                algorithm="AES-128",
                operation="CBC Encryption",
                input_size_bytes=size,
                input_label=label,
                iterations=iterations,
                t_avg_ms=t_enc_avg,
                t_min_ms=t_enc_min,
                t_max_ms=t_enc_max,
                throughput_kb_s=enc_tp,
                raw_times_ms=enc_raw,
                implementation_type="custom_first_principles",
            ).to_dict()
        )

        # Decryption
        ciphertext = aes_cbc_encrypt(plaintext, key, iv)
        t_dec_avg, t_dec_min, t_dec_max, dec_raw = _measure_execution(
            lambda: aes_cbc_decrypt(ciphertext, key, iv),
            iterations=iterations,
            warmup=3,
        )
        dec_tp = round((size / 1024.0) / (t_dec_avg / 1000.0), 2) if t_dec_avg > 0 else None

        results.append(
            BenchmarkRecord(
                algorithm="AES-128",
                operation="CBC Decryption",
                input_size_bytes=size,
                input_label=label,
                iterations=iterations,
                t_avg_ms=t_dec_avg,
                t_min_ms=t_dec_min,
                t_max_ms=t_dec_max,
                throughput_kb_s=dec_tp,
                raw_times_ms=dec_raw,
                implementation_type="custom_first_principles",
            ).to_dict()
        )

    return results


def benchmark_ecc(iterations: int = 30) -> List[Dict[str, Any]]:
    """Benchmark Point Addition, Doubling, and Scalar Multiplication on ECC curves."""
    results: List[Dict[str, Any]] = []

    # 1. Curve F17
    p1 = CURVE_F17.g
    p2 = Point(6, 3)
    k_f17 = 13

    t_avg_add_f17, t_min_add_f17, t_max_add_f17, raw_add_f17 = _measure_execution(
        lambda: CURVE_F17.add(p1, p2),
        iterations=iterations,
    )
    results.append(
        BenchmarkRecord(
            algorithm="ECC (F17)",
            operation="Point Addition",
            input_size_bytes=0,
            input_label="Field F17",
            iterations=iterations,
            t_avg_ms=t_avg_add_f17,
            t_min_ms=t_min_add_f17,
            t_max_ms=t_max_add_f17,
            throughput_kb_s=None,
            raw_times_ms=raw_add_f17,
            implementation_type="custom_first_principles",
        ).to_dict()
    )

    t_avg_sm_f17, t_min_sm_f17, t_max_sm_f17, raw_sm_f17 = _measure_execution(
        lambda: CURVE_F17.scalar_mult(k_f17, p1),
        iterations=iterations,
    )
    results.append(
        BenchmarkRecord(
            algorithm="ECC (F17)",
            operation="Scalar Multiplication (k=13)",
            input_size_bytes=0,
            input_label="Field F17",
            iterations=iterations,
            t_avg_ms=t_avg_sm_f17,
            t_min_ms=t_min_sm_f17,
            t_max_ms=t_max_sm_f17,
            throughput_kb_s=None,
            raw_times_ms=raw_sm_f17,
            implementation_type="custom_first_principles",
        ).to_dict()
    )

    # 2. Curve secp256k1
    g_secp = SECP256K1.g
    two_g_secp = SECP256K1.double(g_secp)
    rand_scalar = secrets.randbelow(SECP256K1.n - 1) + 1

    t_avg_add_secp, t_min_add_secp, t_max_add_secp, raw_add_secp = _measure_execution(
        lambda: SECP256K1.add(g_secp, two_g_secp),
        iterations=iterations,
    )
    results.append(
        BenchmarkRecord(
            algorithm="ECC (secp256k1)",
            operation="Point Addition",
            input_size_bytes=32,
            input_label="256-bit Curve",
            iterations=iterations,
            t_avg_ms=t_avg_add_secp,
            t_min_ms=t_min_add_secp,
            t_max_ms=t_max_add_secp,
            throughput_kb_s=None,
            raw_times_ms=raw_add_secp,
            implementation_type="custom_first_principles",
        ).to_dict()
    )

    t_avg_sm_secp, t_min_sm_secp, t_max_sm_secp, raw_sm_secp = _measure_execution(
        lambda: SECP256K1.scalar_mult(rand_scalar, g_secp),
        iterations=iterations,
    )
    results.append(
        BenchmarkRecord(
            algorithm="ECC (secp256k1)",
            operation="Scalar Multiplication (256-bit)",
            input_size_bytes=32,
            input_label="256-bit Scalar",
            iterations=iterations,
            t_avg_ms=t_avg_sm_secp,
            t_min_ms=t_min_sm_secp,
            t_max_ms=t_max_sm_secp,
            throughput_kb_s=None,
            raw_times_ms=raw_sm_secp,
            implementation_type="custom_first_principles",
        ).to_dict()
    )

    return results


def benchmark_schnorr(iterations: int = 20) -> List[Dict[str, Any]]:
    """Benchmark Schnorr key generation, signing, and verification on secp256k1."""
    results: List[Dict[str, Any]] = []
    curve = SECP256K1
    message = b"Course Project Performance Evaluation Payload"

    # Key Generation
    t_avg_kg, t_min_kg, t_max_kg, raw_kg = _measure_execution(
        lambda: generate_keypair(curve),
        iterations=iterations,
    )
    results.append(
        BenchmarkRecord(
            algorithm="Schnorr",
            operation="Key Generation",
            input_size_bytes=0,
            input_label="256-bit Keypair",
            iterations=iterations,
            t_avg_ms=t_avg_kg,
            t_min_ms=t_min_kg,
            t_max_ms=t_max_kg,
            throughput_kb_s=None,
            raw_times_ms=raw_kg,
            implementation_type="custom_first_principles",
        ).to_dict()
    )

    # Signature Generation
    d, pub = generate_keypair(curve)
    t_avg_sign, t_min_sign, t_max_sign, raw_sign = _measure_execution(
        lambda: sign(message, d, curve),
        iterations=iterations,
    )
    results.append(
        BenchmarkRecord(
            algorithm="Schnorr",
            operation="Signature Generation",
            input_size_bytes=len(message),
            input_label=f"{len(message)} B Message",
            iterations=iterations,
            t_avg_ms=t_avg_sign,
            t_min_ms=t_min_sign,
            t_max_ms=t_max_sign,
            throughput_kb_s=None,
            raw_times_ms=raw_sign,
            implementation_type="custom_first_principles",
        ).to_dict()
    )

    # Signature Verification
    signature = sign(message, d, curve)
    t_avg_ver, t_min_ver, t_max_ver, raw_ver = _measure_execution(
        lambda: verify(message, signature, pub, curve),
        iterations=iterations,
    )
    results.append(
        BenchmarkRecord(
            algorithm="Schnorr",
            operation="Signature Verification",
            input_size_bytes=len(message),
            input_label=f"{len(message)} B Message",
            iterations=iterations,
            t_avg_ms=t_avg_ver,
            t_min_ms=t_min_ver,
            t_max_ms=t_max_ver,
            throughput_kb_s=None,
            raw_times_ms=raw_ver,
            implementation_type="custom_first_principles",
        ).to_dict()
    )

    return results


# =========================================================================
# 2. Reference Libraries Benchmarks (hashlib / cryptography / OpenSSL)
# =========================================================================


def benchmark_reference_sha256(
    sizes: Optional[List[int]] = None,
    iterations: int = 100,
) -> List[Dict[str, Any]]:
    """Benchmark Python's standard hashlib.sha256 (C / OpenSSL / SHA-NI)."""
    if sizes is None:
        sizes = [64, 1024, 16 * 1024, 64 * 1024]

    results: List[Dict[str, Any]] = []

    for size in sizes:
        payload = os.urandom(size)
        label = f"{size} B" if size < 1024 else f"{size // 1024} KB"

        t_avg, t_min, t_max, raw_times = _measure_execution(
            lambda: hashlib.sha256(payload).digest(),
            iterations=iterations,
            warmup=10,
        )
        throughput = round((size / 1024.0) / (t_avg / 1000.0), 2) if t_avg > 0 else None

        record = BenchmarkRecord(
            algorithm="SHA-256",
            operation="Hash Computation",
            input_size_bytes=size,
            input_label=label,
            iterations=iterations,
            t_avg_ms=t_avg,
            t_min_ms=t_min,
            t_max_ms=t_max,
            throughput_kb_s=throughput,
            raw_times_ms=raw_times,
            implementation_type="reference_hashlib_c",
        )
        results.append(record.to_dict())

    return results


def benchmark_reference_aes128(
    sizes: Optional[List[int]] = None,
    iterations: int = 100,
) -> List[Dict[str, Any]]:
    """Benchmark standard cryptography library AES-128 CBC (OpenSSL C / AES-NI)."""
    if not CRYPTOGRAPHY_AVAILABLE:
        return []

    if sizes is None:
        sizes = [16, 1024, 8 * 1024, 32 * 1024]

    results: List[Dict[str, Any]] = []
    key = os.urandom(16)
    iv = os.urandom(16)

    for size in sizes:
        pad_len = 16 - (size % 16)
        plaintext = os.urandom(size) + bytes([pad_len] * pad_len)
        label = f"{size} B" if size < 1024 else f"{size // 1024} KB"

        def _ref_encrypt() -> bytes:
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            enc = cipher.encryptor()
            return enc.update(plaintext) + enc.finalize()

        ciphertext = _ref_encrypt()

        def _ref_decrypt() -> bytes:
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            dec = cipher.decryptor()
            return dec.update(ciphertext) + dec.finalize()

        t_enc_avg, t_enc_min, t_enc_max, enc_raw = _measure_execution(
            _ref_encrypt,
            iterations=iterations,
            warmup=10,
        )
        enc_tp = round((size / 1024.0) / (t_enc_avg / 1000.0), 2) if t_enc_avg > 0 else None

        results.append(
            BenchmarkRecord(
                algorithm="AES-128",
                operation="CBC Encryption",
                input_size_bytes=size,
                input_label=label,
                iterations=iterations,
                t_avg_ms=t_enc_avg,
                t_min_ms=t_enc_min,
                t_max_ms=t_enc_max,
                throughput_kb_s=enc_tp,
                raw_times_ms=enc_raw,
                implementation_type="reference_cryptography_c",
            ).to_dict()
        )

        t_dec_avg, t_dec_min, t_dec_max, dec_raw = _measure_execution(
            _ref_decrypt,
            iterations=iterations,
            warmup=10,
        )
        dec_tp = round((size / 1024.0) / (t_dec_avg / 1000.0), 2) if t_dec_avg > 0 else None

        results.append(
            BenchmarkRecord(
                algorithm="AES-128",
                operation="CBC Decryption",
                input_size_bytes=size,
                input_label=label,
                iterations=iterations,
                t_avg_ms=t_dec_avg,
                t_min_ms=t_dec_min,
                t_max_ms=t_dec_max,
                throughput_kb_s=dec_tp,
                raw_times_ms=dec_raw,
                implementation_type="reference_cryptography_c",
            ).to_dict()
        )

    return results


def benchmark_reference_ecc(iterations: int = 100) -> List[Dict[str, Any]]:
    """Benchmark reference library SECP256K1 key generation (OpenSSL C)."""
    if not CRYPTOGRAPHY_AVAILABLE:
        return []

    results: List[Dict[str, Any]] = []

    def _ref_keygen() -> None:
        priv = ec.generate_private_key(ec.SECP256K1())
        _ = priv.public_key()

    t_avg, t_min, t_max, raw_times = _measure_execution(
        _ref_keygen,
        iterations=iterations,
        warmup=10,
    )

    results.append(
        BenchmarkRecord(
            algorithm="ECC (secp256k1)",
            operation="Key Generation",
            input_size_bytes=32,
            input_label="256-bit Keypair",
            iterations=iterations,
            t_avg_ms=t_avg,
            t_min_ms=t_min,
            t_max_ms=t_max,
            throughput_kb_s=None,
            raw_times_ms=raw_times,
            implementation_type="reference_cryptography_c",
        ).to_dict()
    )

    return results


def benchmark_reference_signature(iterations: int = 100) -> List[Dict[str, Any]]:
    """Benchmark reference standard EC digital signature (ECDSA-SHA256 on secp256k1)."""
    if not CRYPTOGRAPHY_AVAILABLE:
        return []

    results: List[Dict[str, Any]] = []
    message = b"Course Project Performance Evaluation Payload"
    priv = ec.generate_private_key(ec.SECP256K1())
    pub = priv.public_key()

    def _ref_sign() -> bytes:
        return priv.sign(message, ec.ECDSA(hashes.SHA256()))

    t_sign_avg, t_sign_min, t_sign_max, raw_sign = _measure_execution(
        _ref_sign,
        iterations=iterations,
        warmup=10,
    )

    results.append(
        BenchmarkRecord(
            algorithm="Digital Signature (secp256k1)",
            operation="Signature Generation",
            input_size_bytes=len(message),
            input_label=f"{len(message)} B Message",
            iterations=iterations,
            t_avg_ms=t_sign_avg,
            t_min_ms=t_sign_min,
            t_max_ms=t_sign_max,
            throughput_kb_s=None,
            raw_times_ms=raw_sign,
            implementation_type="reference_cryptography_c",
        ).to_dict()
    )

    sig = _ref_sign()

    def _ref_verify() -> None:
        pub.verify(sig, message, ec.ECDSA(hashes.SHA256()))

    t_ver_avg, t_ver_min, t_ver_max, raw_ver = _measure_execution(
        _ref_verify,
        iterations=iterations,
        warmup=10,
    )

    results.append(
        BenchmarkRecord(
            algorithm="Digital Signature (secp256k1)",
            operation="Signature Verification",
            input_size_bytes=len(message),
            input_label=f"{len(message)} B Message",
            iterations=iterations,
            t_avg_ms=t_ver_avg,
            t_min_ms=t_ver_min,
            t_max_ms=t_ver_max,
            throughput_kb_s=None,
            raw_times_ms=raw_ver,
            implementation_type="reference_cryptography_c",
        ).to_dict()
    )

    return results


# =========================================================================
# 3. Comparative Benchmarks (Side-by-Side Analysis)
# =========================================================================


def run_comparative_benchmark(
    sha_sizes: Optional[List[int]] = None,
    aes_sizes: Optional[List[int]] = None,
    custom_iterations: int = 10,
    reference_iterations: int = 50,
) -> List[Dict[str, Any]]:
    """Execute both Custom and Reference benchmarks side-by-side.

    Returns a list of ComparisonRecord dicts with slowdown factors and throughput ratios.
    """
    comparisons: List[Dict[str, Any]] = []

    # 1. SHA-256 Comparison
    custom_sha = benchmark_sha256(sizes=sha_sizes, iterations=custom_iterations)
    ref_sha = benchmark_reference_sha256(sizes=sha_sizes, iterations=reference_iterations)

    for c_rec, r_rec in zip(custom_sha, ref_sha):
        slowdown = (
            round(c_rec["t_avg_ms"] / r_rec["t_avg_ms"], 1)
            if r_rec["t_avg_ms"] > 0
            else None
        )
        comp = ComparisonRecord(
            algorithm="SHA-256",
            operation="Hash Computation",
            input_label=c_rec["input_label"],
            custom_t_avg_ms=c_rec["t_avg_ms"],
            reference_t_avg_ms=r_rec["t_avg_ms"],
            reference_lib="hashlib (OpenSSL C / SHA-NI)",
            slowdown_factor=slowdown,
            custom_throughput_kb_s=c_rec["throughput_kb_s"],
            reference_throughput_kb_s=r_rec["throughput_kb_s"],
        )
        comparisons.append(comp.to_dict())

    # 2. AES-128 Comparison
    if CRYPTOGRAPHY_AVAILABLE:
        custom_aes = benchmark_aes128(sizes=aes_sizes, iterations=custom_iterations)
        ref_aes = benchmark_reference_aes128(sizes=aes_sizes, iterations=reference_iterations)

        for c_rec, r_rec in zip(custom_aes, ref_aes):
            slowdown = (
                round(c_rec["t_avg_ms"] / r_rec["t_avg_ms"], 1)
                if r_rec["t_avg_ms"] > 0
                else None
            )
            comp = ComparisonRecord(
                algorithm="AES-128",
                operation=c_rec["operation"],
                input_label=c_rec["input_label"],
                custom_t_avg_ms=c_rec["t_avg_ms"],
                reference_t_avg_ms=r_rec["t_avg_ms"],
                reference_lib="cryptography (OpenSSL C / AES-NI)",
                slowdown_factor=slowdown,
                custom_throughput_kb_s=c_rec["throughput_kb_s"],
                reference_throughput_kb_s=r_rec["throughput_kb_s"],
            )
            comparisons.append(comp.to_dict())

    # 3. ECC Keypair Generation Comparison
    custom_schnorr = benchmark_schnorr(iterations=custom_iterations)
    ref_ecc = benchmark_reference_ecc(iterations=reference_iterations)

    if ref_ecc and custom_schnorr:
        c_kg = custom_schnorr[0]  # Key Generation
        r_kg = ref_ecc[0]
        slowdown = (
            round(c_kg["t_avg_ms"] / r_kg["t_avg_ms"], 1)
            if r_kg["t_avg_ms"] > 0
            else None
        )
        comp = ComparisonRecord(
            algorithm="ECC (secp256k1)",
            operation="Key Generation (256-bit)",
            input_label="256-bit Keypair",
            custom_t_avg_ms=c_kg["t_avg_ms"],
            reference_t_avg_ms=r_kg["t_avg_ms"],
            reference_lib="cryptography (OpenSSL C)",
            slowdown_factor=slowdown,
            custom_throughput_kb_s=None,
            reference_throughput_kb_s=None,
        )
        comparisons.append(comp.to_dict())

    # 4. Digital Signature Comparison (Signing & Verification)
    if CRYPTOGRAPHY_AVAILABLE and custom_schnorr and len(custom_schnorr) >= 3:
        ref_sig = benchmark_reference_signature(iterations=reference_iterations)
        if len(ref_sig) >= 2:
            # Sign comparison
            c_sign = custom_schnorr[1]
            r_sign = ref_sig[0]
            slowdown_sign = (
                round(c_sign["t_avg_ms"] / r_sign["t_avg_ms"], 1)
                if r_sign["t_avg_ms"] > 0
                else None
            )
            comparisons.append(
                ComparisonRecord(
                    algorithm="Digital Signature (secp256k1)",
                    operation="Signature Generation",
                    input_label=c_sign["input_label"],
                    custom_t_avg_ms=c_sign["t_avg_ms"],
                    reference_t_avg_ms=r_sign["t_avg_ms"],
                    reference_lib="cryptography (OpenSSL C / ECDSA)",
                    slowdown_factor=slowdown_sign,
                    custom_throughput_kb_s=None,
                    reference_throughput_kb_s=None,
                ).to_dict()
            )

            # Verification comparison
            c_ver = custom_schnorr[2]
            r_ver = ref_sig[1]
            slowdown_ver = (
                round(c_ver["t_avg_ms"] / r_ver["t_avg_ms"], 1)
                if r_ver["t_avg_ms"] > 0
                else None
            )
            comparisons.append(
                ComparisonRecord(
                    algorithm="Digital Signature (secp256k1)",
                    operation="Signature Verification",
                    input_label=c_ver["input_label"],
                    custom_t_avg_ms=c_ver["t_avg_ms"],
                    reference_t_avg_ms=r_ver["t_avg_ms"],
                    reference_lib="cryptography (OpenSSL C / ECDSA)",
                    slowdown_factor=slowdown_ver,
                    custom_throughput_kb_s=None,
                    reference_throughput_kb_s=None,
                ).to_dict()
            )

    return comparisons


# =========================================================================
# 4. Aggregation and Export Helpers
# =========================================================================


def run_all_benchmarks(
    sha_iterations: int = 20,
    aes_iterations: int = 10,
    ecc_iterations: int = 15,
    schnorr_iterations: int = 10,
    include_comparison: bool = True,
) -> Dict[str, Any]:
    """Execute all benchmarks and return an aggregated dictionary.

    Output format:
    {
        "custom": {
            "sha256": [...],
            "aes128": [...],
            "ecc": [...],
            "schnorr": [...]
        },
        "reference": {
            "sha256": [...],
            "aes128": [...],
            "ecc": [...],
            "schnorr": [...]
        },
        "comparisons": [...]
    }
    """
    custom_data = {
        "sha256": benchmark_sha256(iterations=sha_iterations),
        "aes128": benchmark_aes128(iterations=aes_iterations),
        "ecc": benchmark_ecc(iterations=ecc_iterations),
        "schnorr": benchmark_schnorr(iterations=schnorr_iterations),
    }

    ref_data: Dict[str, Any] = {
        "sha256": benchmark_reference_sha256(iterations=50),
    }
    if CRYPTOGRAPHY_AVAILABLE:
        ref_data["aes128"] = benchmark_reference_aes128(iterations=50)
        ref_data["ecc"] = benchmark_reference_ecc(iterations=50)
        ref_data["schnorr"] = benchmark_reference_signature(iterations=50)

    result: Dict[str, Any] = {
        "custom": custom_data,
        "reference": ref_data,
    }

    if include_comparison:
        result["comparisons"] = run_comparative_benchmark(
            custom_iterations=min(sha_iterations, 10),
            reference_iterations=50,
        )

    return result


def to_json(data: Dict[str, Any] | List[Any], indent: int = 2) -> str:
    """Serialize benchmark results to a formatted JSON string."""
    return json.dumps(data, indent=indent)


def save_to_json_file(data: Dict[str, Any] | List[Any], filepath: str) -> None:
    """Save benchmark results to a JSON file."""
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


if __name__ == "__main__":
    data = run_all_benchmarks(
        sha_iterations=5,
        aes_iterations=3,
        ecc_iterations=5,
        schnorr_iterations=3,
        include_comparison=True,
    )
    print(to_json(data))
