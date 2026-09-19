"""
Quantum-Resistant Public Key Infrastructure (PKI) Encryption Tool
Core Kyber Encryption Module

This module implements Kyber512 and Kyber768 key encapsulation mechanisms
for post-quantum cryptography using the pqcrypto library.
"""

try:
    # pqcrypto 0.3.x uses ML-KEM (NIST standardized name for Kyber)
    from pqcrypto.kem import ml_kem_512, ml_kem_768
    # Create aliases for consistency
    kem_kyber512 = ml_kem_512
    kem_kyber768 = ml_kem_768
except ImportError:
    try:
        # Try alternative API structure (older versions)
        from pqcrypto import kem_kyber512, kem_kyber768
    except ImportError:
        # Fallback: Use alternative library or provide instructions
        raise ImportError(
            "pqcrypto library not found or incompatible version. Please install it using:\n"
            "pip install pqcrypto==0.3.4\n"
            "Note: ML-KEM (formerly Kyber) is available as ml_kem_512/ml_kem_768"
        )

import os
import json
from typing import Tuple, Optional


class KyberEncryption:
    """
    Kyber encryption class supporting both Kyber512 and Kyber768 algorithms.
    
    Attributes:
        algorithm: The Kyber variant to use ('kyber512' or 'kyber768')
    """
    
    def __init__(self, algorithm: str = 'kyber768'):
        """
        Initialize Kyber encryption with specified algorithm.
        
        Args:
            algorithm: Either 'kyber512' or 'kyber768' (default: 'kyber768')
        """
        if algorithm not in ['kyber512', 'kyber768']:
            raise ValueError("Algorithm must be 'kyber512' or 'kyber768'")
        
        self.algorithm = algorithm
        self.kem_module = kem_kyber512 if algorithm == 'kyber512' else kem_kyber768
        
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a Kyber key pair (public key and private key).
        
        Returns:
            Tuple of (public_key, private_key) as bytes
        """
        public_key, private_key = self.kem_module.generate_keypair()
        return public_key, private_key
    
    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate a shared secret using the public key.
        
        Args:
            public_key: The recipient's public key
            
        Returns:
            Tuple of (ciphertext, shared_secret)
        """
        # ML-KEM uses 'encrypt' instead of 'encapsulate'
        ciphertext, shared_secret = self.kem_module.encrypt(public_key)
        return ciphertext, shared_secret
    
    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        """
        Decapsulate the shared secret using the private key and ciphertext.
        
        Args:
            private_key: The recipient's private key
            ciphertext: The encapsulated ciphertext
            
        Returns:
            The decapsulated shared secret
        """
        # ML-KEM uses 'decrypt' instead of 'decapsulate'
        shared_secret = self.kem_module.decrypt(private_key, ciphertext)
        return shared_secret
    
    def save_keypair(self, public_key: bytes, private_key: bytes, 
                     public_key_path: str, private_key_path: str) -> None:
        """
        Save key pair to files.
        
        Args:
            public_key: Public key bytes
            private_key: Private key bytes
            public_key_path: Path to save public key
            private_key_path: Path to save private key
        """
        with open(public_key_path, 'wb') as f:
            f.write(public_key)
        
        with open(private_key_path, 'wb') as f:
            f.write(private_key)
    
    def load_keypair(self, public_key_path: str, 
                    private_key_path: str) -> Tuple[bytes, bytes]:
        """
        Load key pair from files.
        
        Args:
            public_key_path: Path to public key file
            private_key_path: Path to private key file
            
        Returns:
            Tuple of (public_key, private_key)
        """
        with open(public_key_path, 'rb') as f:
            public_key = f.read()
        
        with open(private_key_path, 'rb') as f:
            private_key = f.read()
        
        return public_key, private_key
    
    def get_key_sizes(self) -> dict:
        """
        Get the key sizes for the current algorithm.
        
        Returns:
            Dictionary with key size information
        """
        if self.algorithm == 'kyber512':
            return {
                'public_key_size': 800,
                'private_key_size': 1632,
                'ciphertext_size': 768,
                'shared_secret_size': 32
            }
        else:  # kyber768
            return {
                'public_key_size': 1184,
                'private_key_size': 2400,
                'ciphertext_size': 1088,
                'shared_secret_size': 32
            }

