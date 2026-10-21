"""
Quantum-Resistant Hybrid Encryption and Security System
Hybrid Encryption Module

Combines Post-Quantum Cryptography (ML-KEM / Crystals-Kyber, NIST FIPS 203)
and Classical Cryptography (X25519 ECDH) with AES-256-GCM Authenticated Encryption with
Associated Data (AEAD) per NIST SP 800-38D and HKDF per RFC 5869 / NIST SP 800-56C Rev 2.
"""

from __future__ import annotations

import os
import json
import base64
import stat
from typing import Tuple, Dict, Any, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.exceptions import InvalidTag

from kyber_encryption import (
    KyberEncryption,
    CryptoError,
    KeyValidationError,
    CiphertextValidationError,
    DecapsulationError
)


class HybridCryptoError(CryptoError):
    """Base exception for hybrid encryption operations."""
    pass


class AuthenticationTagError(HybridCryptoError):
    """Raised when AES-GCM authentication tag verification fails (ciphertext tampered/corrupted)."""
    pass


class DecryptionError(HybridCryptoError):
    """Raised when decryption fails due to invalid parameters, keys, or corrupted input."""
    pass


class HybridKeyExchange:
    """
    Genuine Classical + Post-Quantum Dual Hybrid Key Exchange.
    
    Combines:
    1. ML-KEM-768 (NIST FIPS 203 post-quantum lattice KEM)
    2. X25519 (RFC 7748 elliptic curve Diffie-Hellman)
    
    Uses HKDF-Extract-and-Expand dual combiner with strict algorithm and
    transcript binding (NIST SP 800-56C Rev 2 / RFC 9180 / IETF TLS 1.3 Hybrid Design).
    
    Security Property:
    Confidentiality is preserved if AT LEAST ONE of the two underlying mathematical
    problems (ML-KEM Module-LWE or X25519 Discrete Log) remains unbroken.
    """

    SALT = b"Quantium-Hybrid-MLKEM-X25519-v1"
    INFO_PREFIX = b"ML-KEM+X25519-HKDF-SHA256-AES-256-GCM"

    def __init__(self, kem_algorithm: str = 'kyber768'):
        self.kyber = KyberEncryption(kem_algorithm)
        self.kem_algorithm = self.kyber.algorithm

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate combined dual-key pair:
        - Public Key: ML-KEM public key || X25519 public key (32 bytes)
        - Private Key: ML-KEM private key || X25519 private key (32 bytes)
        """
        pk_pqc, sk_pqc = self.kyber.generate_keypair()

        # Classical X25519 keypair
        sk_x = x25519.X25519PrivateKey.generate()
        pk_x = sk_x.public_key()
        pk_x_bytes = pk_x.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        sk_x_bytes = sk_x.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption()
        )

        combined_public = pk_pqc + pk_x_bytes
        combined_private = sk_pqc + sk_x_bytes
        return combined_public, combined_private

    def encapsulate(self, combined_public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate dual shared secret against recipient's combined public key.

        Returns:
            Tuple[bytes, bytes]: (combined_ciphertext, 32-byte combined shared secret)
            combined_ciphertext = ct_pqc || ephemeral_pk_x (32 bytes)
        """
        expected_pk_len = self.kyber.public_key_size + 32
        if len(combined_public_key) != expected_pk_len:
            raise KeyValidationError(
                f"Combined public key length {len(combined_public_key)} != expected {expected_pk_len}"
            )

        pk_pqc = combined_public_key[:self.kyber.public_key_size]
        pk_x_bytes = combined_public_key[self.kyber.public_key_size:]

        # 1. Post-quantum encapsulation
        ct_pqc, ss_pqc = self.kyber.encapsulate(pk_pqc)

        # 2. Ephemeral classical X25519 exchange
        eph_sk_x = x25519.X25519PrivateKey.generate()
        eph_pk_x = eph_sk_x.public_key()
        eph_pk_bytes = eph_pk_x.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw
        )

        recipient_pk_x = x25519.X25519PublicKey.from_public_bytes(pk_x_bytes)
        ss_classical = eph_sk_x.exchange(recipient_pk_x)

        # 3. Standard Dual-PRF Combiner (HKDF Extract + Expand)
        combined_secret = self._combine_secrets(
            ss_pqc=ss_pqc,
            ss_classical=ss_classical,
            pk_classical=pk_x_bytes,
            ct_pqc=ct_pqc,
            eph_pk_classical=eph_pk_bytes
        )

        combined_ciphertext = ct_pqc + eph_pk_bytes
        return combined_ciphertext, combined_secret

    def decapsulate(self, combined_private_key: bytes, combined_ciphertext: bytes) -> bytes:
        """
        Decapsulate dual shared secret using recipient's combined private key and combined ciphertext.
        """
        expected_sk_len = self.kyber.private_key_size + 32
        if len(combined_private_key) != expected_sk_len:
            raise KeyValidationError(
                f"Combined private key length {len(combined_private_key)} != expected {expected_sk_len}"
            )

        expected_ct_len = self.kyber.ciphertext_size + 32
        if len(combined_ciphertext) != expected_ct_len:
            raise CiphertextValidationError(
                f"Combined ciphertext length {len(combined_ciphertext)} != expected {expected_ct_len}"
            )

        sk_pqc = combined_private_key[:self.kyber.private_key_size]
        sk_x_bytes = combined_private_key[self.kyber.private_key_size:]

        ct_pqc = combined_ciphertext[:self.kyber.ciphertext_size]
        eph_pk_bytes = combined_ciphertext[self.kyber.ciphertext_size:]

        # 1. Post-quantum decapsulation
        ss_pqc = self.kyber.decapsulate(sk_pqc, ct_pqc)

        # 2. Classical ECDH decapsulation
        recipient_sk_x = x25519.X25519PrivateKey.from_private_bytes(sk_x_bytes)
        sender_eph_pk_x = x25519.X25519PublicKey.from_public_bytes(eph_pk_bytes)
        ss_classical = recipient_sk_x.exchange(sender_eph_pk_x)

        # 3. Derive combined public key for transcript binding
        recipient_pk_x = recipient_sk_x.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw
        )
        combined_secret = self._combine_secrets(
            ss_pqc=ss_pqc,
            ss_classical=ss_classical,
            pk_classical=recipient_pk_x,
            ct_pqc=ct_pqc,
            eph_pk_classical=eph_pk_bytes
        )

        return combined_secret

    def _combine_secrets(
        self,
        ss_pqc: bytes,
        ss_classical: bytes,
        pk_classical: bytes,
        ct_pqc: bytes,
        eph_pk_classical: bytes
    ) -> bytes:
        """
        HKDF dual combiner binding protocol context, algorithm identifiers,
        and transcript data per NIST SP 800-56C Rev 2.
        """
        ikm = ss_pqc + ss_classical  # 32 + 32 = 64 bytes of high entropy
        transcript_hash = hashes.Hash(hashes.SHA256())
        transcript_hash.update(self.kem_algorithm.encode('utf-8'))
        transcript_hash.update(pk_classical)
        transcript_hash.update(ct_pqc)
        transcript_hash.update(eph_pk_classical)
        transcript_digest = transcript_hash.finalize()

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.SALT,
            info=self.INFO_PREFIX + b":" + transcript_digest
        )
        return hkdf.derive(ikm)


class HybridEncryption:
    """
    Quantum-Resistant Hybrid Encryption and Decryption System.
    
    Integrates:
    - ML-KEM (Kyber512/768/1024) or Dual Hybrid (ML-KEM + X25519)
    - HKDF-SHA256 Key Derivation (RFC 5869)
    - AES-256-GCM Authenticated Encryption with Associated Data (AEAD, NIST SP 800-38D)
    
    Guarantees:
    - 256-bit symmetric security
    - Quantum resistance against Shor's algorithm for key establishment
    - Nonce uniqueness (96-bit CSPRNG per encryption)
    - Cryptographic authenticity: Any modification of ciphertext or metadata
      is detected and rejected before plaintext is released.
    """

    PROTOCOL_VERSION = "2.0-FIPS203-AESGCM"

    def __init__(self, kyber_algorithm: str = 'kyber768', use_dual_hybrid: bool = False):
        """
        Initialize the hybrid encryption engine.

        Args:
            kyber_algorithm: 'kyber512', 'kyber768', or 'kyber1024'
            use_dual_hybrid: If True, uses genuine dual classical + post-quantum hybrid (ML-KEM + X25519).
                             If False, uses pure ML-KEM KEM/DEM mode.
        """
        self.use_dual_hybrid = use_dual_hybrid
        if use_dual_hybrid:
            self.key_exchange = HybridKeyExchange(kyber_algorithm)
            self.kyber = self.key_exchange.kyber
            self.algorithm = f"{self.kyber.algorithm}+x25519"
        else:
            self.kyber = KyberEncryption(kyber_algorithm)
            self.key_exchange = None
            self.algorithm = self.kyber.algorithm

    def _derive_aes_key(self, shared_secret: bytes, salt: Optional[bytes] = None) -> bytes:
        """
        Derive 256-bit AES-GCM key from high-entropy shared secret using HKDF-SHA256.

        Args:
            shared_secret: 32-byte shared secret from KEM
            salt: Optional salt; defaults to standard domain salt

        Returns:
            bytes: 32-byte AES-256 key
        """
        if salt is None:
            salt = b"Quantium-KEM-DEM-Salt-v2"

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"AES-256-GCM-Key-Derivation-Quantium-v2"
        )
        return hkdf.derive(shared_secret)

    def _build_aad(self, metadata: Dict[str, Any]) -> bytes:
        """
        Construct deterministic Additional Authenticated Data (AAD) for AES-GCM.
        Binds protocol version, algorithm, and data type into the AEAD tag.
        """
        canonical_fields = {
            'protocol_version': metadata.get('protocol_version', self.PROTOCOL_VERSION),
            'algorithm': metadata.get('algorithm', self.algorithm),
            'data_type': metadata.get('data_type', 'text'),
            'original_filename': metadata.get('original_filename', ''),
            'file_size': metadata.get('file_size', 0)
        }
        return json.dumps(canonical_fields, sort_keys=True, separators=(',', ':')).encode('utf-8')

    def encrypt_text(self, plaintext: str, recipient_public_key: bytes) -> Dict[str, Any]:
        """
        Encrypt text using hybrid encryption (ML-KEM + AES-256-GCM).

        Args:
            plaintext: Text string to encrypt
            recipient_public_key: Recipient's public key bytes

        Returns:
            Dict[str, Any]: Serialized encrypted data payload including AEAD tag and nonce
        """
        if not isinstance(plaintext, str):
            raise ValueError("Plaintext must be a string.")

        plaintext_bytes = plaintext.encode('utf-8')
        return self._encrypt_bytes(plaintext_bytes, recipient_public_key, data_type='text')

    def decrypt_text(self, encrypted_data: Dict[str, Any], recipient_private_key: bytes) -> str:
        """
        Decrypt text using hybrid decryption with AES-256-GCM authentication.

        Args:
            encrypted_data: Encrypted data dictionary
            recipient_private_key: Recipient's private key bytes

        Returns:
            str: Decrypted plaintext string

        Raises:
            AuthenticationTagError: If authentication tag verification fails (tampering detected)
            DecryptionError: On invalid input or decoding failure
        """
        if not isinstance(encrypted_data, dict):
            raise DecryptionError("encrypted_data must be a dictionary.")

        plaintext_bytes = self._decrypt_bytes(encrypted_data, recipient_private_key)
        try:
            return plaintext_bytes.decode('utf-8')
        except UnicodeDecodeError as err:
            raise DecryptionError(f"Plaintext UTF-8 decoding failed: {err}") from err

    def encrypt_file(
        self,
        file_path: str,
        recipient_public_key: bytes
    ) -> Tuple[Dict[str, Any], bytes]:
        """
        Encrypt a file using hybrid encryption (ML-KEM + AES-256-GCM).

        Args:
            file_path: Path to file to encrypt
            recipient_public_key: Recipient's public key bytes

        Returns:
            Tuple[Dict[str, Any], bytes]: (metadata_dict, encrypted_ciphertext_bytes)
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Input file not found: {file_path}")

        file_size = os.path.getsize(file_path)
        with open(file_path, 'rb') as f:
            file_data = f.read()

        filename = os.path.basename(file_path)
        ext = os.path.splitext(filename)[1]

        metadata = self._encrypt_bytes(
            file_data,
            recipient_public_key,
            data_type='file',
            extra_metadata={
                'original_filename': filename,
                'original_extension': ext,
                'file_size': file_size
            }
        )

        # Separate the raw AES ciphertext bytes for standalone file output
        aes_ciphertext_bytes = base64.b64decode(metadata.pop('aes_ciphertext'))
        return metadata, aes_ciphertext_bytes

    def decrypt_file(
        self,
        encrypted_data: Dict[str, Any],
        encrypted_file_bytes: bytes,
        recipient_private_key: bytes,
        output_path: Optional[str] = None
    ) -> bytes:
        """
        Decrypt a file using hybrid decryption with AES-256-GCM authentication.

        Args:
            encrypted_data: Metadata dictionary
            encrypted_file_bytes: Raw AES-GCM ciphertext bytes
            recipient_private_key: Recipient's private key bytes
            output_path: Optional destination file path

        Returns:
            bytes: Decrypted plaintext file bytes

        Raises:
            AuthenticationTagError: If authentication tag verification fails
        """
        if not isinstance(encrypted_file_bytes, (bytes, bytearray)):
            raise DecryptionError("encrypted_file_bytes must be bytes.")

        # Re-inject ciphertext bytes into dict for decryption
        data_copy = dict(encrypted_data)
        data_copy['aes_ciphertext'] = base64.b64encode(encrypted_file_bytes).decode('utf-8')

        plaintext_bytes = self._decrypt_bytes(data_copy, recipient_private_key)

        # Write only AFTER authentication check succeeds
        if output_path:
            parent = os.path.dirname(os.path.abspath(output_path))
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(output_path, 'wb') as f:
                f.write(plaintext_bytes)

        return plaintext_bytes

    def _encrypt_bytes(
        self,
        data: bytes,
        recipient_public_key: bytes,
        data_type: str = 'text',
        extra_metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Core internal encryption using KEM encapsulation + AES-256-GCM."""
        if not isinstance(data, (bytes, bytearray)):
            raise ValueError("Data must be bytes or bytearray.")

        # Step 1: Encapsulate shared secret
        if self.use_dual_hybrid and self.key_exchange:
            ciphertext_kem, shared_secret = self.key_exchange.encapsulate(recipient_public_key)
        else:
            ciphertext_kem, shared_secret = self.kyber.encapsulate(recipient_public_key)

        # Step 2: Derive AES-256 key via HKDF
        aes_key = self._derive_aes_key(shared_secret)

        # Step 3: Generate 96-bit (12-byte) cryptographically secure nonce
        nonce = os.urandom(12)

        # Step 4: Construct metadata and AAD
        metadata: Dict[str, Any] = {
            'protocol_version': self.PROTOCOL_VERSION,
            'algorithm': self.algorithm,
            'cipher': 'AES-256-GCM',
            'data_type': data_type,
            'kem_ciphertext': base64.b64encode(ciphertext_kem).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'iv': base64.b64encode(nonce).decode('utf-8'),  # Backwards compatibility alias
        }
        if extra_metadata:
            metadata.update(extra_metadata)

        aad = self._build_aad(metadata)

        # Step 5: Encrypt and authenticate with AES-256-GCM
        # AESGCM.encrypt appends the 16-byte authentication tag to the ciphertext
        aesgcm = AESGCM(aes_key)
        aes_ciphertext_with_tag = aesgcm.encrypt(nonce, bytes(data), aad)

        metadata['aes_ciphertext'] = base64.b64encode(aes_ciphertext_with_tag).decode('utf-8')
        metadata['tag_size'] = 16
        metadata['nonce_size'] = 12
        return metadata

    def _decrypt_bytes(
        self,
        encrypted_data: Dict[str, Any],
        recipient_private_key: bytes
    ) -> bytes:
        """Core internal decryption with strict AES-GCM authentication verification."""
        for field in ['kem_ciphertext', 'aes_ciphertext']:
            if field not in encrypted_data:
                raise DecryptionError(f"Missing required field in encrypted data: '{field}'")

        # Nonce can be stored under 'nonce' or backwards-compatible 'iv'
        nonce_b64 = encrypted_data.get('nonce') or encrypted_data.get('iv')
        if not nonce_b64:
            raise DecryptionError("Missing nonce in encrypted data.")

        try:
            ciphertext_kem = base64.b64decode(encrypted_data['kem_ciphertext'])
            ciphertext_aes = base64.b64decode(encrypted_data['aes_ciphertext'])
            nonce = base64.b64decode(nonce_b64)
        except Exception as err:
            raise DecryptionError(f"Base64 decoding failed for encrypted components: {err}") from err

        if len(nonce) not in (12, 16):
            raise DecryptionError(f"Invalid nonce length: {len(nonce)} bytes (expected 12 bytes).")

        # Step 1: Decapsulate shared secret
        if self.use_dual_hybrid and self.key_exchange:
            shared_secret = self.key_exchange.decapsulate(recipient_private_key, ciphertext_kem)
        else:
            shared_secret = self.kyber.decapsulate(recipient_private_key, ciphertext_kem)

        # Step 2: Derive AES key using HKDF
        aes_key = self._derive_aes_key(shared_secret)

        # Step 3: Reconstruct AAD
        aad = self._build_aad(encrypted_data)

        # Step 4: Authenticated Decryption with AES-256-GCM
        aesgcm = AESGCM(aes_key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext_aes, aad)
            return plaintext
        except InvalidTag as err:
            # Under no circumstances should unauthenticated plaintext be released
            raise AuthenticationTagError(
                "AES-GCM authentication tag verification failed. Ciphertext or metadata has been tampered with or corrupted."
            ) from err
        except Exception as err:
            raise DecryptionError(f"Decryption failed: {err}") from err

    def save_encrypted_data(self, encrypted_data: Dict[str, Any], output_path: str) -> None:
        """Save encrypted metadata dictionary to JSON file."""
        parent = os.path.dirname(os.path.abspath(output_path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(encrypted_data, f, indent=2)

    def load_encrypted_data(self, json_path: str) -> Dict[str, Any]:
        """Load encrypted metadata dictionary from JSON file."""
        if not os.path.exists(json_path):
            raise FileNotFoundError(f"Encrypted data file not found: {json_path}")
        with open(json_path, 'r', encoding='utf-8') as f:
            return json.load(f)
