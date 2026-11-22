"""Cryptographic Benchmark Module.

Provides pure callable functions to benchmark SHA-256, AES-128 CBC, ECC, and Schnorr.
Outputs structured metrics (dict/list/JSON) containing:
- Average, minimum, and maximum execution times (ms).
- Throughput (KB/s).
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

from algorithms.aes128 import aes_cbc_decrypt, aes_cbc_encrypt
from algorithms.ecc import CURVE_F17, SECP256K1, Point
from algorithms.schnorr import generate_keypair, sign, verify
from algorithms.sha256 import sha256_bytes


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

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _measure_execution(
    func: Callable[[], Any],
    iterations: int,
    warmup: int = 5,
) -> tuple[float, float, float, list[float]]:
    """Execute a function multiple times and return (t_avg_ms, t_min_ms, t_max_ms, raw_times_ms)."""
    # Warm-up phase to reduce caching and interpreter jitter
    for _ in range(warmup):
        func()

    raw_times: list[float] = []
    for _ in range(iterations):
        start = time.perf_counter()
        func()
        end = time.perf_counter()
        raw_times.append((end - start) * 1000.0)  # Convert to milliseconds

    t_avg = sum(raw_times) / len(raw_times)
    t_min = min(raw_times)
    t_max = max(raw_times)
    return round(t_avg, 4), round(t_min, 4), round(t_max, 4), [round(t, 4) for t in raw_times]


def benchmark_sha256(
    sizes: Optional[List[int]] = None,
    iterations: int = 30,
) -> List[Dict[str, Any]]:
    """Benchmark SHA-256 hash computation across various payload sizes.

    Default sizes: 64B, 1KB, 16KB, 64KB.
    Returns a list of structured metric dictionaries.
    """
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

        # Throughput = (KB / second) = (size / 1024) / (t_avg_ms / 1000)
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
        )
        results.append(record.to_dict())

    return results


def benchmark_aes128(
    sizes: Optional[List[int]] = None,
    iterations: int = 20,
) -> List[Dict[str, Any]]:
    """Benchmark AES-128 Encryption and Decryption in CBC mode across various plaintext sizes.

    Default sizes: 16B, 1KB, 8KB, 32KB.
    Returns a list of structured metric dictionaries.
    """
    if sizes is None:
        sizes = [16, 1024, 8 * 1024, 32 * 1024]

    results: List[Dict[str, Any]] = []
    key = os.urandom(16)
    iv = os.urandom(16)

    for size in sizes:
        plaintext = os.urandom(size)
        label = f"{size} B" if size < 1024 else f"{size // 1024} KB"

        # 1. Benchmark Encryption
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
            ).to_dict()
        )

        # 2. Benchmark Decryption
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
            ).to_dict()
        )

    return results


def benchmark_ecc(iterations: int = 30) -> List[Dict[str, Any]]:
    """Benchmark Point Addition, Point Doubling, and Scalar Multiplication on ECC curves.

    Evaluates both the educational F17 curve and standard secp256k1 curve.
    """
    results: List[Dict[str, Any]] = []

    # 1. Curve F17 Benchmark
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
        ).to_dict()
    )

    # 2. Curve secp256k1 (256-bit cryptography)
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
        ).to_dict()
    )

    return results


def benchmark_schnorr(iterations: int = 20) -> List[Dict[str, Any]]:
    """Benchmark Schnorr key generation, signing, and verification on secp256k1."""
    results: List[Dict[str, Any]] = []
    curve = SECP256K1
    message = b"Course Project Performance Evaluation Payload"

    # 1. Key Generation
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
        ).to_dict()
    )

    # 2. Signature Generation
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
        ).to_dict()
    )

    # 3. Signature Verification
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
        ).to_dict()
    )

    return results


def run_all_benchmarks(
    sha_iterations: int = 30,
    aes_iterations: int = 20,
    ecc_iterations: int = 25,
    schnorr_iterations: int = 20,
) -> Dict[str, List[Dict[str, Any]]]:
    """Execute all benchmarks and return an aggregated dictionary.

    Output format:
    {
        "sha256": [...],
        "aes128": [...],
        "ecc": [...],
        "schnorr": [...]
    }
    """
    return {
        "sha256": benchmark_sha256(iterations=sha_iterations),
        "aes128": benchmark_aes128(iterations=aes_iterations),
        "ecc": benchmark_ecc(iterations=ecc_iterations),
        "schnorr": benchmark_schnorr(iterations=schnorr_iterations),
    }


def to_json(data: Dict[str, Any] | List[Any], indent: int = 2) -> str:
    """Serialize benchmark results to a formatted JSON string."""
    return json.dumps(data, indent=indent)


def save_to_json_file(data: Dict[str, Any] | List[Any], filepath: str) -> None:
    """Save benchmark results to a JSON file."""
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


if __name__ == "__main__":
    # If run directly as a script, execute and print JSON output
    all_results = run_all_benchmarks(
        sha_iterations=10,
        aes_iterations=5,
        ecc_iterations=10,
        schnorr_iterations=5,
    )
    print(to_json(all_results))
