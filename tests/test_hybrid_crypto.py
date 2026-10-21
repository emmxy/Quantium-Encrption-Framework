"""
Unit tests for Hybrid Encryption (ML-KEM + AES-256-GCM AEAD and Dual Hybrid X25519).
"""

import os
import base64
import pytest
from kyber_encryption import KyberEncryption
from hybrid_encryption import (
    HybridEncryption,
    HybridKeyExchange,
    AuthenticationTagError,
    DecryptionError,
    KeyValidationError,
    CiphertextValidationError
)


class TestHybridEncryption:

    @pytest.fixture
    def kyber(self):
        return KyberEncryption('kyber768')

    @pytest.fixture
    def keypair(self, kyber):
        return kyber.generate_keypair()

    @pytest.fixture
    def hybrid_pure(self):
        return HybridEncryption('kyber768', use_dual_hybrid=False)

    @pytest.fixture
    def hybrid_dual(self):
        return HybridEncryption('kyber768', use_dual_hybrid=True)

    def test_pure_mlkem_text_roundtrip(self, hybrid_pure, keypair):
        pk, sk = keypair
        message = "Quantum-Resistant PKI encryption test with FIPS 203 ML-KEM-768."
        encrypted = hybrid_pure.encrypt_text(message, pk)
        assert 'kem_ciphertext' in encrypted
        assert 'aes_ciphertext' in encrypted
        assert 'nonce' in encrypted
        assert encrypted['cipher'] == 'AES-256-GCM'

        decrypted = hybrid_pure.decrypt_text(encrypted, sk)
        assert decrypted == message

    def test_dual_hybrid_x25519_roundtrip(self, hybrid_dual):
        pk_dual, sk_dual = hybrid_dual.key_exchange.generate_keypair()
        message = "Genuine Dual Hybrid Key Exchange: Classical X25519 + Post-Quantum ML-KEM-768"
        
        encrypted = hybrid_dual.encrypt_text(message, pk_dual)
        assert encrypted['algorithm'] == 'kyber768+x25519'

        decrypted = hybrid_dual.decrypt_text(encrypted, sk_dual)
        assert decrypted == message

    def test_nonce_uniqueness(self, hybrid_pure, keypair):
        pk, _ = keypair
        message = "Identical message for nonce uniqueness testing"
        nonces = set()
        for _ in range(50):
            enc = hybrid_pure.encrypt_text(message, pk)
            nonce = enc['nonce']
            assert len(base64.b64decode(nonce)) == 12  # 96-bit standard AES-GCM nonce
            assert nonce not in nonces, "Nonce collision detected!"
            nonces.add(nonce)

    def test_unicode_and_multilingual_data(self, hybrid_pure, keypair):
        pk, sk = keypair
        unicode_text = "こんにちは世界！🚀 Post-Quantum Cryptography: 🔐 Überprüfung äöüß Çédille"
        enc = hybrid_pure.encrypt_text(unicode_text, pk)
        dec = hybrid_pure.decrypt_text(enc, sk)
        assert dec == unicode_text

    def test_empty_string_encryption(self, hybrid_pure, keypair):
        pk, sk = keypair
        enc = hybrid_pure.encrypt_text("", pk)
        dec = hybrid_pure.decrypt_text(enc, sk)
        assert dec == ""

    def test_ciphertext_bitflip_tampering_raises_authentication_tag_error(self, hybrid_pure, keypair):
        pk, sk = keypair
        message = "High-security financial authorization payload"
        enc = hybrid_pure.encrypt_text(message, pk)

        # Tamper with the AES ciphertext
        raw_ct = bytearray(base64.b64decode(enc['aes_ciphertext']))
        raw_ct[0] ^= 0x01  # single bit flip
        tampered_enc = dict(enc)
        tampered_enc['aes_ciphertext'] = base64.b64encode(raw_ct).decode('utf-8')

        with pytest.raises(AuthenticationTagError, match="authentication tag verification failed"):
            hybrid_pure.decrypt_text(tampered_enc, sk)

    def test_metadata_aad_tampering_raises_authentication_tag_error(self, hybrid_pure, keypair):
        pk, sk = keypair
        message = "Critical operational command"
        enc = hybrid_pure.encrypt_text(message, pk)

        # Alter the authenticated metadata (AAD)
        tampered_enc = dict(enc)
        tampered_enc['algorithm'] = 'kyber512'

        with pytest.raises(AuthenticationTagError, match="authentication tag verification failed"):
            hybrid_pure.decrypt_text(tampered_enc, sk)

    def test_kem_ciphertext_tampering_fails_safely(self, hybrid_pure, keypair):
        pk, sk = keypair
        enc = hybrid_pure.encrypt_text("Confidential message", pk)

        # Modify KEM ciphertext
        raw_kem = bytearray(base64.b64decode(enc['kem_ciphertext']))
        raw_kem[0] ^= 0xFF
        tampered_enc = dict(enc)
        tampered_enc['kem_ciphertext'] = base64.b64encode(raw_kem).decode('utf-8')

        # Because ML-KEM uses implicit rejection, tampering changes the derived key,
        # which subsequently fails AES-GCM tag verification safely without releasing plaintext.
        with pytest.raises(AuthenticationTagError):
            hybrid_pure.decrypt_text(tampered_enc, sk)

    def test_file_encryption_and_decryption(self, hybrid_pure, keypair, tmp_path):
        pk, sk = keypair

        # 1. Test binary file
        bin_file = tmp_path / "random_data.bin"
        bin_content = os.urandom(1024 * 128)  # 128 KB binary
        bin_file.write_bytes(bin_content)

        meta, ct_bytes = hybrid_pure.encrypt_file(str(bin_file), pk)
        assert meta['data_type'] == 'file'
        assert meta['file_size'] == len(bin_content)

        out_file = tmp_path / "decrypted_data.bin"
        dec_bytes = hybrid_pure.decrypt_file(meta, ct_bytes, sk, output_path=str(out_file))
        assert dec_bytes == bin_content
        assert out_file.read_bytes() == bin_content

        # 2. Test large file (1 MB)
        large_file = tmp_path / "large_payload.bin"
        large_content = os.urandom(1024 * 1024)  # 1 MB
        large_file.write_bytes(large_content)

        meta_lg, ct_lg = hybrid_pure.encrypt_file(str(large_file), pk)
        dec_lg = hybrid_pure.decrypt_file(meta_lg, ct_lg, sk)
        assert dec_lg == large_content

        # 3. Test empty file (0 bytes)
        empty_file = tmp_path / "empty.bin"
        empty_file.write_bytes(b"")

        meta_empty, ct_empty = hybrid_pure.encrypt_file(str(empty_file), pk)
        dec_empty = hybrid_pure.decrypt_file(meta_empty, ct_empty, sk)
        assert dec_empty == b""

    def test_file_tampering_prevents_file_write(self, hybrid_pure, keypair, tmp_path):
        pk, sk = keypair
        sample_file = tmp_path / "secret.pdf"
        sample_file.write_bytes(b"%PDF-1.4 Mock document bytes")

        meta, ct_bytes = hybrid_pure.encrypt_file(str(sample_file), pk)
        
        # Corrupt file bytes
        tampered_ct = bytearray(ct_bytes)
        tampered_ct[-1] ^= 0x42
        
        dest_path = tmp_path / "should_not_exist.pdf"
        with pytest.raises(AuthenticationTagError):
            hybrid_pure.decrypt_file(meta, bytes(tampered_ct), sk, output_path=str(dest_path))

        # Ensure unauthenticated file was NEVER written to disk
        assert not dest_path.exists(), "Plaintext file must not be created upon authentication failure"

    def test_malformed_missing_fields_raises_decryption_error(self, hybrid_pure, keypair):
        _, sk = keypair
        with pytest.raises(DecryptionError, match="Missing required field"):
            hybrid_pure.decrypt_text({'kem_ciphertext': 'AAAA'}, sk)
