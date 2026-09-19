"""
Hybrid Encryption Module
Combines Kyber (Post-Quantum KEM) with AES-256 for secure data encryption

This module provides hybrid encryption capabilities supporting both
text and file encryption/decryption using Kyber + AES-256.
"""

from kyber_encryption import KyberEncryption
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os
import json
import base64
from typing import Tuple, Optional


class HybridEncryption:
    """
    Hybrid encryption class combining Kyber KEM with AES-256 symmetric encryption.
    
    This provides post-quantum security for key exchange while using
    efficient symmetric encryption for the actual data.
    """
    
    def __init__(self, kyber_algorithm: str = 'kyber768'):
        """
        Initialize hybrid encryption system.
        
        Args:
            kyber_algorithm: Kyber variant to use ('kyber512' or 'kyber768')
        """
        self.kyber = KyberEncryption(kyber_algorithm)
        self.backend = default_backend()
    
    def encrypt_text(self, plaintext: str, recipient_public_key: bytes) -> dict:
        """
        Encrypt text using hybrid encryption (Kyber + AES-256).
        
        Args:
            plaintext: The text to encrypt
            recipient_public_key: Recipient's public key
            
        Returns:
            Dictionary containing encrypted data and metadata
        """
        # Step 1: Generate shared secret using Kyber
        ciphertext_kem, shared_secret = self.kyber.encapsulate(recipient_public_key)
        
        # Step 2: Derive AES key from shared secret
        aes_key = self._derive_aes_key(shared_secret)
        
        # Step 3: Generate IV for AES
        iv = os.urandom(16)
        
        # Step 4: Encrypt plaintext with AES-256-CBC
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        
        # Pad the plaintext
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode('utf-8'))
        padded_data += padder.finalize()
        
        # Encrypt
        ciphertext_aes = encryptor.update(padded_data) + encryptor.finalize()
        
        # Step 5: Combine components
        encrypted_data = {
            'kem_ciphertext': base64.b64encode(ciphertext_kem).decode('utf-8'),
            'aes_ciphertext': base64.b64encode(ciphertext_aes).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'algorithm': self.kyber.algorithm,
            'data_type': 'text'
        }
        
        return encrypted_data
    
    def decrypt_text(self, encrypted_data: dict, recipient_private_key: bytes) -> str:
        """
        Decrypt text using hybrid decryption.
        
        Args:
            encrypted_data: Dictionary containing encrypted data
            recipient_private_key: Recipient's private key
            
        Returns:
            Decrypted plaintext string
        """
        # Step 1: Extract components
        ciphertext_kem = base64.b64decode(encrypted_data['kem_ciphertext'])
        ciphertext_aes = base64.b64decode(encrypted_data['aes_ciphertext'])
        iv = base64.b64decode(encrypted_data['iv'])
        
        # Step 2: Decapsulate shared secret
        shared_secret = self.kyber.decapsulate(recipient_private_key, ciphertext_kem)
        
        # Step 3: Derive AES key
        aes_key = self._derive_aes_key(shared_secret)
        
        # Step 4: Decrypt with AES-256-CBC
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        
        padded_plaintext = decryptor.update(ciphertext_aes) + decryptor.finalize()
        
        # Step 5: Unpad
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext)
        plaintext += unpadder.finalize()
        
        return plaintext.decode('utf-8')
    
    def encrypt_file(self, file_path: str, recipient_public_key: bytes) -> Tuple[dict, bytes]:
        """
        Encrypt a file using hybrid encryption.
        
        Args:
            file_path: Path to the file to encrypt
            recipient_public_key: Recipient's public key
            
        Returns:
            Tuple of (encrypted_data_dict, encrypted_file_bytes)
        """
        # Read file
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        # Step 1: Generate shared secret using Kyber
        ciphertext_kem, shared_secret = self.kyber.encapsulate(recipient_public_key)
        
        # Step 2: Derive AES key
        aes_key = self._derive_aes_key(shared_secret)
        
        # Step 3: Generate IV
        iv = os.urandom(16)
        
        # Step 4: Encrypt file data with AES-256-CBC
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        
        # Pad file data
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(file_data)
        padded_data += padder.finalize()
        
        # Encrypt
        ciphertext_aes = encryptor.update(padded_data) + encryptor.finalize()
        
        # Step 5: Create metadata
        file_name = os.path.basename(file_path)
        file_ext = os.path.splitext(file_name)[1]
        
        encrypted_data = {
            'kem_ciphertext': base64.b64encode(ciphertext_kem).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'algorithm': self.kyber.algorithm,
            'data_type': 'file',
            'original_filename': file_name,
            'original_extension': file_ext,
            'file_size': len(file_data)
        }
        
        return encrypted_data, ciphertext_aes
    
    def decrypt_file(self, encrypted_data: dict, encrypted_file_bytes: bytes, 
                    recipient_private_key: bytes, output_path: Optional[str] = None) -> bytes:
        """
        Decrypt a file using hybrid decryption.
        
        Args:
            encrypted_data: Dictionary containing metadata
            encrypted_file_bytes: Encrypted file bytes
            recipient_private_key: Recipient's private key
            output_path: Optional path to save decrypted file
            
        Returns:
            Decrypted file bytes
        """
        # Step 1: Extract components
        ciphertext_kem = base64.b64decode(encrypted_data['kem_ciphertext'])
        iv = base64.b64decode(encrypted_data['iv'])
        
        # Step 2: Decapsulate shared secret
        shared_secret = self.kyber.decapsulate(recipient_private_key, ciphertext_kem)
        
        # Step 3: Derive AES key
        aes_key = self._derive_aes_key(shared_secret)
        
        # Step 4: Decrypt with AES-256-CBC
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        
        padded_file_data = decryptor.update(encrypted_file_bytes) + decryptor.finalize()
        
        # Step 5: Unpad
        unpadder = padding.PKCS7(128).unpadder()
        file_data = unpadder.update(padded_file_data)
        file_data += unpadder.finalize()
        
        # Step 6: Save if output path provided
        if output_path:
            with open(output_path, 'wb') as f:
                f.write(file_data)
        
        return file_data
    
    def _derive_aes_key(self, shared_secret: bytes, salt: Optional[bytes] = None) -> bytes:
        """
        Derive AES-256 key from shared secret using PBKDF2.
        
        Args:
            shared_secret: Shared secret from Kyber
            salt: Optional salt (generated if not provided)
            
        Returns:
            32-byte AES key
        """
        if salt is None:
            salt = b'kyber_aes_salt'  # Fixed salt for deterministic derivation
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        
        return kdf.derive(shared_secret)
    
    def save_encrypted_data(self, encrypted_data: dict, output_path: str) -> None:
        """
        Save encrypted data metadata to JSON file.
        
        Args:
            encrypted_data: Encrypted data dictionary
            output_path: Path to save JSON file
        """
        with open(output_path, 'w') as f:
            json.dump(encrypted_data, f, indent=2)
    
    def load_encrypted_data(self, json_path: str) -> dict:
        """
        Load encrypted data metadata from JSON file.
        
        Args:
            json_path: Path to JSON file
            
        Returns:
            Encrypted data dictionary
        """
        with open(json_path, 'r') as f:
            return json.load(f)

