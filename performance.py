"""
Performance Evaluation Module
Compares Kyber with RSA encryption algorithms

This module provides benchmarking and comparison capabilities for
evaluating the performance of post-quantum cryptography algorithms.
"""

import time
import statistics
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from kyber_encryption import KyberEncryption
import os
from typing import Dict, List
import json


class PerformanceEvaluator:
    """
    Performance evaluation class for comparing Kyber and RSA algorithms.
    
    Evaluates:
    - Key generation speed
    - Encryption/decryption speed
    - Key sizes
    - Memory usage
    """
    
    def __init__(self):
        """Initialize performance evaluator."""
        self.kyber512 = KyberEncryption('kyber512')
        self.kyber768 = KyberEncryption('kyber768')
        self.backend = default_backend()
    
    def benchmark_key_generation(self, iterations: int = 100) -> Dict:
        """
        Benchmark key generation for Kyber512, Kyber768, and RSA.
        
        Args:
            iterations: Number of iterations to average
            
        Returns:
            Dictionary with benchmark results
        """
        results = {
            'kyber512': [],
            'kyber768': [],
            'rsa_2048': [],
            'rsa_3072': []
        }
        
        print(f"Benchmarking key generation ({iterations} iterations)...")
        
        # Benchmark Kyber512
        for _ in range(iterations):
            start = time.time()
            self.kyber512.generate_keypair()
            results['kyber512'].append(time.time() - start)
        
        # Benchmark Kyber768
        for _ in range(iterations):
            start = time.time()
            self.kyber768.generate_keypair()
            results['kyber768'].append(time.time() - start)
        
        # Benchmark RSA-2048
        for _ in range(iterations):
            start = time.time()
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=self.backend
            )
            public_key = private_key.public_key()
            results['rsa_2048'].append(time.time() - start)
        
        # Benchmark RSA-3072
        for _ in range(iterations):
            start = time.time()
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=3072,
                backend=self.backend
            )
            public_key = private_key.public_key()
            results['rsa_3072'].append(time.time() - start)
        
        # Calculate statistics
        summary = {}
        for alg, times in results.items():
            if times:
                summary[alg] = {
                    'mean': statistics.mean(times) * 1000,  # Convert to ms
                    'median': statistics.median(times) * 1000,
                    'stdev': statistics.stdev(times) * 1000 if len(times) > 1 else 0,
                    'min': min(times) * 1000,
                    'max': max(times) * 1000
                }
        
        return summary
    
    def benchmark_encryption(self, iterations: int = 100, 
                           data_size: int = 32) -> Dict:
        """
        Benchmark encryption operations.
        
        Args:
            iterations: Number of iterations
            data_size: Size of data to encrypt (bytes)
            
        Returns:
            Dictionary with benchmark results
        """
        results = {
            'kyber512': [],
            'kyber768': [],
            'rsa_2048': [],
            'rsa_3072': []
        }
        
        print(f"Benchmarking encryption ({iterations} iterations, {data_size} bytes)...")
        
        # Generate keys once
        kyber512_pk, kyber512_sk = self.kyber512.generate_keypair()
        kyber768_pk, kyber768_sk = self.kyber768.generate_keypair()
        
        rsa_2048_private = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=self.backend
        )
        rsa_2048_public = rsa_2048_private.public_key()
        
        rsa_3072_private = rsa.generate_private_key(
            public_exponent=65537,
            key_size=3072,
            backend=self.backend
        )
        rsa_3072_public = rsa_3072_private.public_key()
        
        test_data = os.urandom(data_size)
        
        # Benchmark Kyber512
        for _ in range(iterations):
            start = time.time()
            self.kyber512.encapsulate(kyber512_pk)
            results['kyber512'].append(time.time() - start)
        
        # Benchmark Kyber768
        for _ in range(iterations):
            start = time.time()
            self.kyber768.encapsulate(kyber768_pk)
            results['kyber768'].append(time.time() - start)
        
        # Benchmark RSA-2048
        for _ in range(iterations):
            start = time.time()
            rsa_2048_public.encrypt(
                test_data[:214],  # RSA-2048 can encrypt max 214 bytes
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            results['rsa_2048'].append(time.time() - start)
        
        # Benchmark RSA-3072
        for _ in range(iterations):
            start = time.time()
            rsa_3072_public.encrypt(
                test_data[:382],  # RSA-3072 can encrypt max 382 bytes
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            results['rsa_3072'].append(time.time() - start)
        
        # Calculate statistics
        summary = {}
        for alg, times in results.items():
            if times:
                summary[alg] = {
                    'mean': statistics.mean(times) * 1000,
                    'median': statistics.median(times) * 1000,
                    'stdev': statistics.stdev(times) * 1000 if len(times) > 1 else 0,
                    'min': min(times) * 1000,
                    'max': max(times) * 1000
                }
        
        return summary
    
    def benchmark_decryption(self, iterations: int = 100) -> Dict:
        """
        Benchmark decryption operations.
        
        Args:
            iterations: Number of iterations
            
        Returns:
            Dictionary with benchmark results
        """
        results = {
            'kyber512': [],
            'kyber768': [],
            'rsa_2048': [],
            'rsa_3072': []
        }
        
        print(f"Benchmarking decryption ({iterations} iterations)...")
        
        # Generate keys and ciphertexts once
        kyber512_pk, kyber512_sk = self.kyber512.generate_keypair()
        kyber512_ct, _ = self.kyber512.encapsulate(kyber512_pk)
        
        kyber768_pk, kyber768_sk = self.kyber768.generate_keypair()
        kyber768_ct, _ = self.kyber768.encapsulate(kyber768_pk)
        
        rsa_2048_private = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=self.backend
        )
        rsa_2048_public = rsa_2048_private.public_key()
        rsa_2048_ciphertext = rsa_2048_public.encrypt(
            b'Test data for RSA encryption',
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        rsa_3072_private = rsa.generate_private_key(
            public_exponent=65537,
            key_size=3072,
            backend=self.backend
        )
        rsa_3072_public = rsa_3072_private.public_key()
        rsa_3072_ciphertext = rsa_3072_public.encrypt(
            b'Test data for RSA encryption longer',
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Benchmark Kyber512
        for _ in range(iterations):
            start = time.time()
            self.kyber512.decapsulate(kyber512_sk, kyber512_ct)
            results['kyber512'].append(time.time() - start)
        
        # Benchmark Kyber768
        for _ in range(iterations):
            start = time.time()
            self.kyber768.decapsulate(kyber768_sk, kyber768_ct)
            results['kyber768'].append(time.time() - start)
        
        # Benchmark RSA-2048
        for _ in range(iterations):
            start = time.time()
            rsa_2048_private.decrypt(
                rsa_2048_ciphertext,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            results['rsa_2048'].append(time.time() - start)
        
        # Benchmark RSA-3072
        for _ in range(iterations):
            start = time.time()
            rsa_3072_private.decrypt(
                rsa_3072_ciphertext,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            results['rsa_3072'].append(time.time() - start)
        
        # Calculate statistics
        summary = {}
        for alg, times in results.items():
            if times:
                summary[alg] = {
                    'mean': statistics.mean(times) * 1000,
                    'median': statistics.median(times) * 1000,
                    'stdev': statistics.stdev(times) * 1000 if len(times) > 1 else 0,
                    'min': min(times) * 1000,
                    'max': max(times) * 1000
                }
        
        return summary
    
    def compare_key_sizes(self) -> Dict:
        """
        Compare key sizes between algorithms.
        
        Returns:
            Dictionary with key size comparisons
        """
        kyber512_sizes = self.kyber512.get_key_sizes()
        kyber768_sizes = self.kyber768.get_key_sizes()
        
        return {
            'kyber512': {
                'public_key': kyber512_sizes['public_key_size'],
                'private_key': kyber512_sizes['private_key_size'],
                'ciphertext': kyber512_sizes['ciphertext_size'],
                'total': kyber512_sizes['public_key_size'] + kyber512_sizes['private_key_size']
            },
            'kyber768': {
                'public_key': kyber768_sizes['public_key_size'],
                'private_key': kyber768_sizes['private_key_size'],
                'ciphertext': kyber768_sizes['ciphertext_size'],
                'total': kyber768_sizes['public_key_size'] + kyber768_sizes['private_key_size']
            },
            'rsa_2048': {
                'public_key': 294,  # DER encoded
                'private_key': 1215,  # DER encoded
                'ciphertext': 256,
                'total': 1509
            },
            'rsa_3072': {
                'public_key': 422,  # DER encoded
                'private_key': 1763,  # DER encoded
                'ciphertext': 384,
                'total': 2185
            }
        }
    
    def run_full_evaluation(self) -> Dict:
        """
        Run complete performance evaluation.
        
        Returns:
            Complete evaluation results
        """
        print("=" * 60)
        print("PERFORMANCE EVALUATION: Kyber vs RSA")
        print("=" * 60)
        
        results = {
            'key_generation': self.benchmark_key_generation(iterations=50),
            'encryption': self.benchmark_encryption(iterations=50),
            'decryption': self.benchmark_decryption(iterations=50),
            'key_sizes': self.compare_key_sizes()
        }
        
        print("\n" + "=" * 60)
        print("EVALUATION COMPLETE")
        print("=" * 60)
        
        return results
    
    def save_results(self, results: Dict, file_path: str) -> None:
        """
        Save evaluation results to JSON file.
        
        Args:
            results: Evaluation results dictionary
            file_path: Path to save results
        """
        with open(file_path, 'w') as f:
            json.dump(results, f, indent=2)

