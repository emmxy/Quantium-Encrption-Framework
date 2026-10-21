"""
Performance Benchmarking Suite for Quantum-Resistant PKI
Compares ML-KEM (FIPS 203) with Classical RSA Cryptography

Measures:
- Key Generation Latency
- Key Encapsulation / Establishment Latency
- Key Decapsulation / Recovery Latency
- Public Key, Private Key, and Ciphertext / Overhead Sizes
- Bulk Symmetric Encryption Latency (AES-256-GCM) across payload sizes
- Memory (RSS) and CPU time metrics
- Statistical metrics: mean, stddev, median (p50), 95th percentile (p95), min, max.
"""

from __future__ import annotations

import os
import sys
import time
import json
import csv
import platform
import resource
import statistics
from typing import Dict, List, Any, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

from kyber_encryption import KyberEncryption


class BenchmarkRunner:
    """
    Scientific benchmarking harness for Post-Quantum (ML-KEM) vs Classical (RSA).
    Uses high-resolution monotonic clocks (perf_counter_ns), warmup runs,
    and rigorous statistical analysis.
    """

    def __init__(self):
        self.backend = default_backend()
        self.kyber512 = KyberEncryption('kyber512')
        self.kyber768 = KyberEncryption('kyber768')
        self.kyber1024 = KyberEncryption('kyber1024')

    def get_system_environment(self) -> Dict[str, Any]:
        """Collect and document test environment hardware and runtime metadata."""
        import pqcrypto
        import cryptography

        return {
            'os': platform.system(),
            'os_release': platform.release(),
            'platform': platform.platform(),
            'architecture': platform.machine(),
            'processor': platform.processor() or "x86_64",
            'cpu_count': os.cpu_count(),
            'python_version': platform.python_version(),
            'cryptography_version': cryptography.__version__,
            'pqcrypto_version': getattr(pqcrypto, '__version__', '1.0.0'),
            'timestamp_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'clock_source': 'time.perf_counter_ns (monotonic, nanosecond resolution)'
        }

    def _compute_stats(self, durations_ns: List[int]) -> Dict[str, Any]:
        """Convert nanosecond duration list into milliseconds summary statistics."""
        if not durations_ns:
            return {}
        durations_ms = [d / 1_000_000.0 for d in durations_ns]
        sorted_ms = sorted(durations_ms)
        n = len(sorted_ms)

        p95_idx = int(math_ceil(0.95 * n)) - 1
        p99_idx = int(math_ceil(0.99 * n)) - 1

        return {
            'trials': n,
            'mean_ms': round(float(statistics.mean(durations_ms)), 4),
            'stddev_ms': round(float(statistics.stdev(durations_ms)), 4) if n > 1 else 0.0,
            'median_ms': round(float(statistics.median(durations_ms)), 4),
            'p95_ms': round(float(sorted_ms[max(0, min(p95_idx, n - 1))]), 4),
            'p99_ms': round(float(sorted_ms[max(0, min(p99_idx, n - 1))]), 4),
            'min_ms': round(float(sorted_ms[0]), 4),
            'max_ms': round(float(sorted_ms[-1]), 4)
        }

    def benchmark_key_generation(
        self,
        kem_trials: int = 100,
        rsa_trials: int = 25,
        warmup: int = 5
    ) -> Dict[str, Any]:
        """
        Benchmark key generation for ML-KEM-512, ML-KEM-768, ML-KEM-1024,
        RSA-2048, RSA-3072, and RSA-4096.
        """
        results: Dict[str, Any] = {}

        # 1. ML-KEM variants
        kems = [
            ('ML-KEM-512', self.kyber512),
            ('ML-KEM-768', self.kyber768),
            ('ML-KEM-1024', self.kyber1024)
        ]
        for name, kem in kems:
            print(f"  Benchmarking {name} keygen ({kem_trials} trials)...")
            # Warmup
            for _ in range(warmup):
                kem.generate_keypair()
            # Timed runs
            times = []
            for _ in range(kem_trials):
                t0 = time.perf_counter_ns()
                kem.generate_keypair()
                t1 = time.perf_counter_ns()
                times.append(t1 - t0)
            results[name] = self._compute_stats(times)

        # 2. RSA variants
        rsa_sizes = [
            ('RSA-2048', 2048, rsa_trials * 2),
            ('RSA-3072', 3072, rsa_trials),
            ('RSA-4096', 4096, max(15, rsa_trials // 2))
        ]
        for name, bits, trials in rsa_sizes:
            print(f"  Benchmarking {name} keygen ({trials} trials)...")
            # Warmup
            for _ in range(2):
                rsa.generate_private_key(public_exponent=65537, key_size=bits, backend=self.backend)
            times = []
            for _ in range(trials):
                t0 = time.perf_counter_ns()
                rsa.generate_private_key(public_exponent=65537, key_size=bits, backend=self.backend)
                t1 = time.perf_counter_ns()
                times.append(t1 - t0)
            results[name] = self._compute_stats(times)

        return results

    def benchmark_key_establishment(
        self,
        trials: int = 100,
        warmup: int = 10
    ) -> Dict[str, Any]:
        """
        Benchmark key establishment operations:
        - ML-KEM: Key Encapsulation & Decapsulation (32-byte shared secret)
        - RSA: RSA-OAEP Key Wrap & Unwrap (Encrypting/Decrypting 32-byte symmetric key)
        """
        results: Dict[str, Any] = {
            'encapsulation_or_wrap': {},
            'decapsulation_or_unwrap': {}
        }

        # 1. ML-KEM Benchmarks
        kems = [
            ('ML-KEM-512', self.kyber512),
            ('ML-KEM-768', self.kyber768),
            ('ML-KEM-1024', self.kyber1024)
        ]
        for name, kem in kems:
            print(f"  Benchmarking {name} encaps/decaps ({trials} trials)...")
            pk, sk = kem.generate_keypair()

            # Warmup
            for _ in range(warmup):
                c, _ = kem.encapsulate(pk)
                kem.decapsulate(sk, c)

            # Timed Encapsulation
            enc_times = []
            ciphertexts = []
            for _ in range(trials):
                t0 = time.perf_counter_ns()
                ct, ss = kem.encapsulate(pk)
                t1 = time.perf_counter_ns()
                enc_times.append(t1 - t0)
                ciphertexts.append(ct)
            results['encapsulation_or_wrap'][name] = self._compute_stats(enc_times)

            # Timed Decapsulation
            dec_times = []
            for i in range(trials):
                ct = ciphertexts[i]
                t0 = time.perf_counter_ns()
                kem.decapsulate(sk, ct)
                t1 = time.perf_counter_ns()
                dec_times.append(t1 - t0)
            results['decapsulation_or_unwrap'][name] = self._compute_stats(dec_times)

        # 2. RSA-OAEP Benchmarks (Key Wrap of 32-byte symmetric secret)
        sym_key_32 = os.urandom(32)
        rsa_configs = [
            ('RSA-2048', 2048),
            ('RSA-3072', 3072),
            ('RSA-4096', 4096)
        ]
        oaep_padding = asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )

        for name, bits in rsa_configs:
            print(f"  Benchmarking {name} OAEP key wrap/unwrap ({trials} trials)...")
            sk_rsa = rsa.generate_private_key(public_exponent=65537, key_size=bits, backend=self.backend)
            pk_rsa = sk_rsa.public_key()

            # Warmup
            for _ in range(warmup):
                c = pk_rsa.encrypt(sym_key_32, oaep_padding)
                sk_rsa.decrypt(c, oaep_padding)

            # Timed Wrap (Public Key Encryption of 32-byte key)
            wrap_times = []
            rsa_cts = []
            for _ in range(trials):
                t0 = time.perf_counter_ns()
                ct = pk_rsa.encrypt(sym_key_32, oaep_padding)
                t1 = time.perf_counter_ns()
                wrap_times.append(t1 - t0)
                rsa_cts.append(ct)
            results['encapsulation_or_wrap'][name] = self._compute_stats(wrap_times)

            # Timed Unwrap (Private Key Decryption)
            unwrap_times = []
            for i in range(trials):
                ct = rsa_cts[i]
                t0 = time.perf_counter_ns()
                sk_rsa.decrypt(ct, oaep_padding)
                t1 = time.perf_counter_ns()
                unwrap_times.append(t1 - t0)
            results['decapsulation_or_unwrap'][name] = self._compute_stats(unwrap_times)

        return results

    def benchmark_symmetric_encryption(
        self,
        trials: int = 100,
        warmup: int = 10
    ) -> Dict[str, Any]:
        """
        Benchmark bulk symmetric data encryption (AES-256-GCM) separately
        for 1 KB, 64 KB, and 1 MB payloads.
        """
        results: Dict[str, Any] = {}
        key = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(key)
        aad = b"benchmark-context-v2"

        sizes = [
            ('1_KB', 1024),
            ('64_KB', 64 * 1024),
            ('1_MB', 1024 * 1024)
        ]

        for label, size_bytes in sizes:
            payload = os.urandom(size_bytes)
            # Warmup
            for _ in range(warmup):
                nonce = os.urandom(12)
                ct = aesgcm.encrypt(nonce, payload, aad)
                aesgcm.decrypt(nonce, ct, aad)

            enc_times = []
            dec_times = []
            for _ in range(trials):
                nonce = os.urandom(12)
                t0 = time.perf_counter_ns()
                ct = aesgcm.encrypt(nonce, payload, aad)
                t1 = time.perf_counter_ns()
                enc_times.append(t1 - t0)

                t2 = time.perf_counter_ns()
                aesgcm.decrypt(nonce, ct, aad)
                t3 = time.perf_counter_ns()
                dec_times.append(t3 - t2)

            results[label] = {
                'payload_size_bytes': size_bytes,
                'encryption': self._compute_stats(enc_times),
                'decryption': self._compute_stats(dec_times)
            }

        return results

    def get_key_and_ciphertext_sizes(self) -> Dict[str, Dict[str, Any]]:
        """
        Compute exact public key, private key, and ciphertext transmission sizes.
        Uses DER encoding sizes for RSA keys per X.509/PKCS#8 standards.
        """
        sizes: Dict[str, Dict[str, Any]] = {}

        # 1. ML-KEM
        for name, kem in [('ML-KEM-512', self.kyber512), ('ML-KEM-768', self.kyber768), ('ML-KEM-1024', self.kyber1024)]:
            pk_sz = kem.public_key_size
            sk_sz = kem.private_key_size
            ct_sz = kem.ciphertext_size
            sizes[name] = {
                'primitive_type': 'Lattice KEM (FIPS 203)',
                'public_key_bytes': pk_sz,
                'private_key_bytes': sk_sz,
                'ciphertext_or_encapsulation_bytes': ct_sz,
                'total_public_overhead_bytes': pk_sz + ct_sz
            }

        # 2. RSA (DER format)
        for name, bits in [('RSA-2048', 2048), ('RSA-3072', 3072), ('RSA-4096', 4096)]:
            sk = rsa.generate_private_key(public_exponent=65537, key_size=bits, backend=self.backend)
            pk = sk.public_key()
            pk_der = pk.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            sk_der = sk.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
            sizes[name] = {
                'primitive_type': 'Classical Factorization (RSA-OAEP)',
                'public_key_bytes': len(pk_der),
                'private_key_bytes': len(sk_der),
                'ciphertext_or_encapsulation_bytes': bits // 8,
                'total_public_overhead_bytes': len(pk_der) + (bits // 8)
            }

        return sizes

    def run_full_benchmark(
        self,
        kem_trials: int = 100,
        rsa_trials: int = 25,
        output_json: str = 'benchmark_results.json',
        output_csv: str = 'benchmark_summary.csv'
    ) -> Dict[str, Any]:
        """
        Execute the full benchmarking suite and export structured machine-readable artifacts.
        """
        print("=" * 70)
        print("SCIENTIFIC BENCHMARK SUITE: Post-Quantum ML-KEM vs Classical RSA")
        print("=" * 70)

        # Measure baseline process metrics
        t_start_process = time.process_time()
        rss_start_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

        env = self.get_system_environment()
        print(f"Platform: {env['platform']} | Python {env['python_version']}")
        print(f"Libraries: pqcrypto {env['pqcrypto_version']}, cryptography {env['cryptography_version']}\n")

        print("1. Benchmarking Key Generation...")
        keygen_results = self.benchmark_key_generation(kem_trials=kem_trials, rsa_trials=rsa_trials)

        print("\n2. Benchmarking Key Establishment (ML-KEM Encaps/Decaps vs RSA-OAEP Wrap/Unwrap)...")
        establishment_results = self.benchmark_key_establishment(trials=kem_trials)

        print("\n3. Benchmarking Bulk Symmetric Encryption (AES-256-GCM)...")
        symmetric_results = self.benchmark_symmetric_encryption(trials=kem_trials)

        print("\n4. Measuring Exact Key and Ciphertext Sizes...")
        size_results = self.get_key_and_ciphertext_sizes()

        # Final process metrics
        process_cpu_time_sec = round(float(time.process_time() - t_start_process), 4)
        rss_end_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

        full_results = {
            'benchmark_metadata': {
                'title': 'Post-Quantum ML-KEM (FIPS 203) vs Classical RSA Benchmark',
                'target_comparison': 'ML-KEM-768 vs RSA-4096',
                'environment': env,
                'process_cpu_time_seconds': process_cpu_time_sec,
                'max_rss_kb': rss_end_kb,
                'network_handshake_latency': 'unavailable (local process benchmark; no external network transport)'
            },
            'key_generation': keygen_results,
            'key_establishment_encapsulation_or_wrap': establishment_results['encapsulation_or_wrap'],
            'key_establishment_decapsulation_or_unwrap': establishment_results['decapsulation_or_unwrap'],
            'symmetric_aes_256_gcm': symmetric_results,
            'key_and_ciphertext_sizes': size_results
        }

        # Export JSON
        with open(output_json, 'w') as f:
            json.dump(full_results, f, indent=2)
        print(f"\n✓ Saved raw JSON results to: {output_json}")

        # Export CSV Summary
        self._export_csv(full_results, output_csv)
        print(f"✓ Saved CSV summary table to: {output_csv}")

        self.print_markdown_summary(full_results)
        return full_results

    def _export_csv(self, results: Dict[str, Any], csv_path: str) -> None:
        """Export tabular summary to CSV."""
        rows = []
        algs = ['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024', 'RSA-2048', 'RSA-3072', 'RSA-4096']

        for alg in algs:
            kg = results['key_generation'].get(alg, {})
            enc = results['key_establishment_encapsulation_or_wrap'].get(alg, {})
            dec = results['key_establishment_decapsulation_or_unwrap'].get(alg, {})
            sz = results['key_and_ciphertext_sizes'].get(alg, {})

            rows.append({
                'Algorithm': alg,
                'Primitive': sz.get('primitive_type', ''),
                'Keygen_Mean_ms': kg.get('mean_ms', 'N/A'),
                'Keygen_Median_ms': kg.get('median_ms', 'N/A'),
                'Keygen_P95_ms': kg.get('p95_ms', 'N/A'),
                'Encap_Wrap_Mean_ms': enc.get('mean_ms', 'N/A'),
                'Encap_Wrap_Median_ms': enc.get('median_ms', 'N/A'),
                'Decap_Unwrap_Mean_ms': dec.get('mean_ms', 'N/A'),
                'Decap_Unwrap_Median_ms': dec.get('median_ms', 'N/A'),
                'Public_Key_Bytes': sz.get('public_key_bytes', 'N/A'),
                'Private_Key_Bytes': sz.get('private_key_bytes', 'N/A'),
                'Ciphertext_Bytes': sz.get('ciphertext_or_encapsulation_bytes', 'N/A'),
                'Total_Public_Overhead_Bytes': sz.get('total_public_overhead_bytes', 'N/A')
            })

        fieldnames = list(rows[0].keys())
        with open(csv_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

    def print_markdown_summary(self, results: Dict[str, Any]) -> None:
        """Print formatted Markdown tables for immediate inclusion in academic paper."""
        print("\n" + "=" * 70)
        print("SUMMARY TABLE FOR ACADEMIC PAPER (ML-KEM vs RSA)")
        print("=" * 70 + "\n")

        print("### Table 1: Latency Benchmark (Milliseconds)")
        print("| Algorithm | Keygen Mean (ms) | Keygen Median | Encap/Wrap Mean | Encap/Wrap Median | Decap/Unwrap Mean | Decap/Unwrap Median |")
        print("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |")

        algs = ['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024', 'RSA-2048', 'RSA-3072', 'RSA-4096']
        for alg in algs:
            kg = results['key_generation'].get(alg, {})
            enc = results['key_establishment_encapsulation_or_wrap'].get(alg, {})
            dec = results['key_establishment_decapsulation_or_unwrap'].get(alg, {})
            print(f"| **{alg}** | {kg.get('mean_ms', '-')} | {kg.get('median_ms', '-')} | {enc.get('mean_ms', '-')} | {enc.get('median_ms', '-')} | {dec.get('mean_ms', '-')} | {dec.get('median_ms', '-')} |")

        print("\n### Table 2: Cryptographic Size and Transmission Overhead (Bytes)")
        print("| Algorithm | Public Key | Private Key | Ciphertext / Encap | Total Transmission Overhead (PK + CT) |")
        print("| :--- | :--- | :--- | :--- | :--- |")
        for alg in algs:
            sz = results['key_and_ciphertext_sizes'].get(alg, {})
            print(f"| **{alg}** | {sz.get('public_key_bytes', '-')} B | {sz.get('private_key_bytes', '-')} B | {sz.get('ciphertext_or_encapsulation_bytes', '-')} B | **{sz.get('total_public_overhead_bytes', '-')} B** |")

        print("\n### Table 3: Bulk Symmetric Performance (AES-256-GCM)")
        print("| Payload Size | Encryption Mean (ms) | Encryption Median (ms) | Decryption Mean (ms) | Decryption Median (ms) |")
        print("| :--- | :--- | :--- | :--- | :--- |")
        for label, d in results['symmetric_aes_256_gcm'].items():
            enc = d['encryption']
            dec = d['decryption']
            print(f"| **{label}** | {enc.get('mean_ms', '-')} | {enc.get('median_ms', '-')} | {dec.get('mean_ms', '-')} | {dec.get('median_ms', '-')} |")
        print("\n" + "=" * 70)


def math_ceil(x: float) -> int:
    return int(-(-x // 1))


class PerformanceEvaluator(BenchmarkRunner):
    """Backwards-compatible wrapper class for Flask and CLI integration."""
    pass


if __name__ == '__main__':
    runner = BenchmarkRunner()
    runner.run_full_benchmark(kem_trials=100, rsa_trials=25)
