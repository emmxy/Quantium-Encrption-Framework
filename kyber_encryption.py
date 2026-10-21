"""
Quantum-Resistant Public Key Infrastructure (PKI) Encryption Tool
Core ML-KEM (Kyber) Encryption Module

This module implements ML-KEM-512, ML-KEM-768, and ML-KEM-1024 key encapsulation
mechanisms adhering to NIST FIPS 203 using the standardized pqcrypto library.
"""

from __future__ import annotations

import os
import json
import stat
from typing import Tuple, Dict, Any, Optional

try:
    from pqcrypto.kem import ml_kem_512, ml_kem_768, ml_kem_1024
except ImportError as err:
    raise ImportError(
        "pqcrypto library not found or incompatible. Install pqcrypto>=1.0.0 via:\n"
        "pip install pqcrypto>=1.0.0\n"
        f"Original error: {err}"
    ) from err


# Custom Cryptographic Exceptions
class CryptoError(Exception):
    """Base exception for cryptographic operations."""
    pass


class KeyValidationError(CryptoError):
    """Raised when a cryptographic key fails validation (e.g. invalid size or format)."""
    pass


class CiphertextValidationError(CryptoError):
    """Raised when ciphertext fails validation (e.g. invalid size or format)."""
    pass


class DecapsulationError(CryptoError):
    """Raised when key decapsulation fails or produces invalid results."""
    pass


class KyberEncryption:
    """
    ML-KEM (CRYSTALS-Kyber) Key Encapsulation Mechanism implementation.
    
    Conforms to NIST FIPS 203:
    - ML-KEM-512: NIST Security Category 1 (~AES-128)
    - ML-KEM-768: NIST Security Category 3 (~AES-192)
    - ML-KEM-1024: NIST Security Category 5 (~AES-256)
    """

    ALGORITHM_MAP = {
        'kyber512': ml_kem_512,
        'ml_kem_512': ml_kem_512,
        'ml-kem-512': ml_kem_512,
        'kyber768': ml_kem_768,
        'ml_kem_768': ml_kem_768,
        'ml-kem-768': ml_kem_768,
        'kyber1024': ml_kem_1024,
        'ml_kem_1024': ml_kem_1024,
        'ml-kem-1024': ml_kem_1024,
    }

    # Standard parameter sizes per FIPS 203
    PARAMETERS = {
        'kyber512': {
            'public_key_size': ml_kem_512.PUBLIC_KEY_SIZE,     # 800
            'private_key_size': ml_kem_512.SECRET_KEY_SIZE,   # 1632
            'ciphertext_size': ml_kem_512.CIPHERTEXT_SIZE,     # 768
            'shared_secret_size': ml_kem_512.SHARED_SECRET_SIZE # 32
        },
        'kyber768': {
            'public_key_size': ml_kem_768.PUBLIC_KEY_SIZE,     # 1184
            'private_key_size': ml_kem_768.SECRET_KEY_SIZE,   # 2400
            'ciphertext_size': ml_kem_768.CIPHERTEXT_SIZE,     # 1088
            'shared_secret_size': ml_kem_768.SHARED_SECRET_SIZE # 32
        },
        'kyber1024': {
            'public_key_size': ml_kem_1024.PUBLIC_KEY_SIZE,    # 1568
            'private_key_size': ml_kem_1024.SECRET_KEY_SIZE,  # 3168
            'ciphertext_size': ml_kem_1024.CIPHERTEXT_SIZE,    # 1568
            'shared_secret_size': ml_kem_1024.SHARED_SECRET_SIZE # 32
        }
    }

    def __init__(self, algorithm: str = 'kyber768'):
        """
        Initialize ML-KEM handler with chosen parameter set.

        Args:
            algorithm: 'kyber512', 'kyber768', or 'kyber1024' (default: 'kyber768')
        """
        normalized_alg = algorithm.lower().strip()
        if normalized_alg not in self.ALGORITHM_MAP:
            valid_algs = list(self.PARAMETERS.keys())
            raise ValueError(f"Unsupported algorithm '{algorithm}'. Must be one of: {valid_algs}")

        # Canonical name
        if '512' in normalized_alg:
            self.algorithm = 'kyber512'
        elif '1024' in normalized_alg:
            self.algorithm = 'kyber1024'
        else:
            self.algorithm = 'kyber768'

        self.kem_module = self.ALGORITHM_MAP[normalized_alg]
        self._params = self.PARAMETERS[self.algorithm]

    @property
    def public_key_size(self) -> int:
        return self._params['public_key_size']

    @property
    def private_key_size(self) -> int:
        return self._params['private_key_size']

    @property
    def ciphertext_size(self) -> int:
        return self._params['ciphertext_size']

    @property
    def shared_secret_size(self) -> int:
        return self._params['shared_secret_size']

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate an ML-KEM public/private keypair.

        Returns:
            Tuple[bytes, bytes]: (public_key, private_key)
        """
        try:
            public_key, private_key = self.kem_module.keygen()
            # Validate output lengths
            if len(public_key) != self.public_key_size or len(private_key) != self.private_key_size:
                raise KeyValidationError(
                    f"Generated key size mismatch: pk={len(public_key)} (expected {self.public_key_size}), "
                    f"sk={len(private_key)} (expected {self.private_key_size})"
                )
            return bytes(public_key), bytes(private_key)
        except Exception as err:
            if isinstance(err, CryptoError):
                raise
            raise CryptoError(f"Key generation failed: {err}") from err

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate a high-entropy 32-byte shared secret using recipient's public key.

        Args:
            public_key: Recipient's public key bytes

        Returns:
            Tuple[bytes, bytes]: (ciphertext, shared_secret)
        """
        if not isinstance(public_key, (bytes, bytearray)):
            raise KeyValidationError("Public key must be bytes or bytearray.")
        if len(public_key) != self.public_key_size:
            raise KeyValidationError(
                f"Invalid public key length for {self.algorithm}: {len(public_key)} bytes "
                f"(expected {self.public_key_size} bytes)."
            )

        try:
            ciphertext, shared_secret = self.kem_module.encaps(public_key)
            if len(ciphertext) != self.ciphertext_size:
                raise CiphertextValidationError(
                    f"Encapsulated ciphertext size mismatch: {len(ciphertext)} != {self.ciphertext_size}"
                )
            if len(shared_secret) != self.shared_secret_size:
                raise CryptoError(
                    f"Shared secret size mismatch: {len(shared_secret)} != {self.shared_secret_size}"
                )
            return bytes(ciphertext), bytes(shared_secret)
        except Exception as err:
            if isinstance(err, CryptoError):
                raise
            raise CryptoError(f"Encapsulation failed: {err}") from err

    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        """
        Decapsulate shared secret using private key and encapsulated ciphertext.

        Args:
            private_key: Recipient's private key bytes
            ciphertext: Encapsulated ciphertext bytes

        Returns:
            bytes: The 32-byte shared secret
        """
        if not isinstance(private_key, (bytes, bytearray)):
            raise KeyValidationError("Private key must be bytes or bytearray.")
        if len(private_key) != self.private_key_size:
            raise KeyValidationError(
                f"Invalid private key length for {self.algorithm}: {len(private_key)} bytes "
                f"(expected {self.private_key_size} bytes)."
            )

        if not isinstance(ciphertext, (bytes, bytearray)):
            raise CiphertextValidationError("Ciphertext must be bytes or bytearray.")
        if len(ciphertext) != self.ciphertext_size:
            raise CiphertextValidationError(
                f"Invalid ciphertext length for {self.algorithm}: {len(ciphertext)} bytes "
                f"(expected {self.ciphertext_size} bytes)."
            )

        try:
            shared_secret = self.kem_module.decaps(private_key, ciphertext)
            if len(shared_secret) != self.shared_secret_size:
                raise DecapsulationError("Decapsulated shared secret has unexpected length.")
            return bytes(shared_secret)
        except Exception as err:
            if isinstance(err, CryptoError):
                raise
            raise DecapsulationError(f"Decapsulation failed: {err}") from err

    def save_keypair(
        self,
        public_key: bytes,
        private_key: bytes,
        public_key_path: str,
        private_key_path: str
    ) -> None:
        """
        Save key pair to files with strict permission controls.
        Private key is saved with restricted read/write permissions (0o600).
        """
        if len(public_key) != self.public_key_size:
            raise KeyValidationError("Cannot save invalid public key size.")
        if len(private_key) != self.private_key_size:
            raise KeyValidationError("Cannot save invalid private key size.")

        # Ensure parent directories exist
        for p in [public_key_path, private_key_path]:
            parent = os.path.dirname(os.path.abspath(p))
            if parent:
                os.makedirs(parent, exist_ok=True)

        with open(public_key_path, 'wb') as f:
            f.write(public_key)

        # Write private key with restrictive 0o600 permissions
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        mode = stat.S_IRUSR | stat.S_IWUSR
        fd = os.open(private_key_path, flags, mode)
        with os.fdopen(fd, 'wb') as f:
            f.write(private_key)

    def load_public_key(self, public_key_path: str) -> bytes:
        """Load and validate public key from file."""
        if not os.path.exists(public_key_path):
            raise FileNotFoundError(f"Public key file not found: {public_key_path}")
        with open(public_key_path, 'rb') as f:
            public_key = f.read()
        if len(public_key) != self.public_key_size:
            raise KeyValidationError(
                f"Loaded public key size {len(public_key)} != expected {self.public_key_size}"
            )
        return public_key

    def load_private_key(self, private_key_path: str) -> bytes:
        """Load and validate private key from file."""
        if not os.path.exists(private_key_path):
            raise FileNotFoundError(f"Private key file not found: {private_key_path}")
        with open(private_key_path, 'rb') as f:
            private_key = f.read()
        if len(private_key) != self.private_key_size:
            raise KeyValidationError(
                f"Loaded private key size {len(private_key)} != expected {self.private_key_size}"
            )
        return private_key

    def load_keypair(self, public_key_path: str, private_key_path: str) -> Tuple[bytes, bytes]:
        """
        Load and validate key pair from files.

        Returns:
            Tuple[bytes, bytes]: (public_key, private_key)
        """
        if not os.path.exists(public_key_path):
            raise FileNotFoundError(f"Public key file not found: {public_key_path}")
        if not os.path.exists(private_key_path):
            raise FileNotFoundError(f"Private key file not found: {private_key_path}")

        with open(public_key_path, 'rb') as f:
            public_key = f.read()

        with open(private_key_path, 'rb') as f:
            private_key = f.read()

        if len(public_key) != self.public_key_size:
            raise KeyValidationError(
                f"Loaded public key size {len(public_key)} != expected {self.public_key_size}"
            )
        if len(private_key) != self.private_key_size:
            raise KeyValidationError(
                f"Loaded private key size {len(private_key)} != expected {self.private_key_size}"
            )

        return public_key, private_key

    def get_key_sizes(self) -> Dict[str, int]:
        """
        Return standard key size parameters.
        """
        return dict(self._params)
