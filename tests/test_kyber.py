"""
Unit tests for ML-KEM (Kyber) Cryptographic Implementation (NIST FIPS 203).
"""

import os
import pytest
import stat
from kyber_encryption import (
    KyberEncryption,
    KeyValidationError,
    CiphertextValidationError,
    DecapsulationError,
    CryptoError
)


class TestKyberEncryption:

    @pytest.mark.parametrize("algorithm,pk_len,sk_len,ct_len,ss_len", [
        ("kyber512", 800, 1632, 768, 32),
        ("kyber768", 1184, 2400, 1088, 32),
        ("kyber1024", 1568, 3168, 1568, 32),
    ])
    def test_keygen_and_key_sizes(self, algorithm, pk_len, sk_len, ct_len, ss_len):
        kem = KyberEncryption(algorithm)
        pk, sk = kem.generate_keypair()
        assert len(pk) == pk_len
        assert len(sk) == sk_len
        assert kem.public_key_size == pk_len
        assert kem.private_key_size == sk_len
        assert kem.ciphertext_size == ct_len
        assert kem.shared_secret_size == ss_len

    @pytest.mark.parametrize("algorithm", ["kyber512", "kyber768", "kyber1024"])
    def test_encapsulation_and_decapsulation_agreement(self, algorithm):
        kem = KyberEncryption(algorithm)
        pk, sk = kem.generate_keypair()
        
        ct, shared_secret_sender = kem.encapsulate(pk)
        assert len(ct) == kem.ciphertext_size
        assert len(shared_secret_sender) == kem.shared_secret_size

        shared_secret_recipient = kem.decapsulate(sk, ct)
        assert shared_secret_sender == shared_secret_recipient

    def test_unsupported_algorithm_raises_value_error(self):
        with pytest.raises(ValueError, match="Unsupported algorithm"):
            KyberEncryption("kyber2048")

    def test_encapsulate_invalid_public_key_size(self):
        kem = KyberEncryption("kyber768")
        with pytest.raises(KeyValidationError, match="Invalid public key length"):
            kem.encapsulate(b"invalid_short_pk")

    def test_encapsulate_invalid_type(self):
        kem = KyberEncryption("kyber768")
        with pytest.raises(KeyValidationError, match="must be bytes"):
            kem.encapsulate("string_not_bytes")  # type: ignore

    def test_decapsulate_invalid_private_key_size(self):
        kem = KyberEncryption("kyber768")
        pk, _ = kem.generate_keypair()
        ct, _ = kem.encapsulate(pk)
        with pytest.raises(KeyValidationError, match="Invalid private key length"):
            kem.decapsulate(b"bad_sk", ct)

    def test_decapsulate_invalid_ciphertext_size(self):
        kem = KyberEncryption("kyber768")
        _, sk = kem.generate_keypair()
        with pytest.raises(CiphertextValidationError, match="Invalid ciphertext length"):
            kem.decapsulate(sk, b"bad_ct")

    def test_save_and_load_keypair(self, tmp_path):
        kem = KyberEncryption("kyber768")
        pk, sk = kem.generate_keypair()

        pk_file = str(tmp_path / "pub.key")
        sk_file = str(tmp_path / "priv.key")

        kem.save_keypair(pk, sk, pk_file, sk_file)

        # Verify private key permissions are restricted (0o600 on POSIX)
        if os.name == 'posix':
            file_mode = os.stat(sk_file).st_mode
            assert (file_mode & (stat.S_IRWXG | stat.S_IRWXO)) == 0

        # Load and verify
        loaded_pk, loaded_sk = kem.load_keypair(pk_file, sk_file)
        assert loaded_pk == pk
        assert loaded_sk == sk

        # Test individual loaders
        assert kem.load_public_key(pk_file) == pk
        assert kem.load_private_key(sk_file) == sk

    def test_load_nonexistent_key_raises_error(self, tmp_path):
        kem = KyberEncryption("kyber768")
        with pytest.raises(FileNotFoundError):
            kem.load_public_key(str(tmp_path / "nonexistent.key"))
