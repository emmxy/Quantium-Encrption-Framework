"""
Demo Script for Quantum-Resistant PKI Encryption Tool
Demonstrates basic functionality of the encryption system
"""

from kyber_encryption import KyberEncryption
from hybrid_encryption import HybridEncryption
from threat_detection import ThreatDetection
import os

def demo_basic_encryption():
    """Demonstrate basic text encryption/decryption."""
    print("=" * 60)
    print("DEMO: Basic Text Encryption/Decryption")
    print("=" * 60)
    
    # Generate key pair
    print("\n1. Generating Kyber768 key pair...")
    kyber = KyberEncryption('kyber768')
    public_key, private_key = kyber.generate_keypair()
    print("   ✓ Key pair generated successfully")
    
    # Get key sizes
    key_sizes = kyber.get_key_sizes()
    print(f"   Public key size: {key_sizes['public_key_size']} bytes")
    print(f"   Private key size: {key_sizes['private_key_size']} bytes")
    
    # Encrypt text
    print("\n2. Encrypting text...")
    plaintext = "Hello, Quantum-Resistant World!"
    hybrid = HybridEncryption()
    encrypted_data = hybrid.encrypt_text(plaintext, public_key)
    print(f"   ✓ Text encrypted successfully")
    print(f"   Original text: {plaintext}")
    
    # Decrypt text
    print("\n3. Decrypting text...")
    decrypted_text = hybrid.decrypt_text(encrypted_data, private_key)
    print(f"   ✓ Text decrypted successfully")
    print(f"   Decrypted text: {decrypted_text}")
    
    # Verify
    if plaintext == decrypted_text:
        print("\n✓ SUCCESS: Encryption/Decryption verified!")
    else:
        print("\n✗ ERROR: Encryption/Decryption failed!")
    
    return encrypted_data


def demo_key_exchange():
    """Demonstrate key encapsulation mechanism."""
    print("\n" + "=" * 60)
    print("DEMO: Key Encapsulation Mechanism (KEM)")
    print("=" * 60)
    
    # Generate recipient's key pair
    print("\n1. Generating recipient's key pair...")
    kyber = KyberEncryption('kyber768')
    recipient_public_key, recipient_private_key = kyber.generate_keypair()
    print("   ✓ Recipient key pair generated")
    
    # Encapsulate (sender side)
    print("\n2. Sender: Encapsulating shared secret...")
    ciphertext, shared_secret_sender = kyber.encapsulate(recipient_public_key)
    print(f"   ✓ Shared secret encapsulated")
    print(f"   Ciphertext size: {len(ciphertext)} bytes")
    print(f"   Shared secret size: {len(shared_secret_sender)} bytes")
    
    # Decapsulate (recipient side)
    print("\n3. Recipient: Decapsulating shared secret...")
    shared_secret_recipient = kyber.decapsulate(recipient_private_key, ciphertext)
    print(f"   ✓ Shared secret decapsulated")
    
    # Verify
    if shared_secret_sender == shared_secret_recipient:
        print("\n✓ SUCCESS: Key exchange verified!")
        print(f"   Shared secret matches: {shared_secret_sender.hex()[:32]}...")
    else:
        print("\n✗ ERROR: Key exchange failed!")


def demo_threat_detection():
    """Demonstrate threat detection system."""
    print("\n" + "=" * 60)
    print("DEMO: AI-Based Threat Detection")
    print("=" * 60)
    
    # Initialize threat detector
    print("\n1. Initializing threat detection system...")
    threat_detector = ThreatDetection()
    
    # Log some activities
    print("\n2. Logging encryption activities...")
    threat_detector.log_activity('encrypt', file_size=1024*100, success=True, algorithm='kyber768')
    threat_detector.log_activity('encrypt', file_size=1024*1024*50, success=True, algorithm='kyber768')  # Large file
    threat_detector.log_activity('decrypt', file_size=1024*10, success=False)  # Failed attempt
    threat_detector.log_activity('encrypt', file_size=1024*200, success=True, algorithm='kyber512')
    print("   ✓ Activities logged")
    
    # Train model
    print("\n3. Training threat detection model...")
    threat_detector.train_model()
    print("   ✓ Model trained")
    
    # Detect threats
    print("\n4. Analyzing threats...")
    threats = threat_detector.detect_threats()
    print(f"   ✓ Analysis complete")
    print(f"   Threats detected: {len(threats)}")
    
    if threats:
        print("\n   Detected Threats:")
        for i, threat in enumerate(threats, 1):
            print(f"\n   Threat #{i}:")
            print(f"     Severity: {threat['severity']}")
            print(f"     Score: {threat['anomaly_score']:.3f}")
            print(f"     Description: {threat['description']}")
    else:
        print("\n   ✓ No threats detected")
    
    # Get statistics
    print("\n5. Activity Statistics:")
    stats = threat_detector.get_statistics()
    for key, value in stats.items():
        if isinstance(value, float):
            print(f"   {key}: {value:.2f}")
        else:
            print(f"   {key}: {value}")


def demo_algorithm_comparison():
    """Compare Kyber512 and Kyber768."""
    print("\n" + "=" * 60)
    print("DEMO: Algorithm Comparison (Kyber512 vs Kyber768)")
    print("=" * 60)
    
    # Compare key sizes
    print("\n1. Key Size Comparison:")
    kyber512 = KyberEncryption('kyber512')
    kyber768 = KyberEncryption('kyber768')
    
    sizes512 = kyber512.get_key_sizes()
    sizes768 = kyber768.get_key_sizes()
    
    print("\n   Kyber512:")
    print(f"     Public key: {sizes512['public_key_size']} bytes")
    print(f"     Private key: {sizes512['private_key_size']} bytes")
    print(f"     Ciphertext: {sizes512['ciphertext_size']} bytes")
    
    print("\n   Kyber768:")
    print(f"     Public key: {sizes768['public_key_size']} bytes")
    print(f"     Private key: {sizes768['private_key_size']} bytes")
    print(f"     Ciphertext: {sizes768['ciphertext_size']} bytes")
    
    print("\n   Trade-off:")
    print("     - Kyber512: Smaller keys, AES-128 equivalent security")
    print("     - Kyber768: Larger keys, AES-192 equivalent security")


def main():
    """Run all demo functions."""
    print("\n" + "=" * 60)
    print("QUANTUM-RESISTANT PKI ENCRYPTION TOOL - DEMO")
    print("=" * 60)
    
    try:
        # Run demos
        demo_basic_encryption()
        demo_key_exchange()
        demo_threat_detection()
        demo_algorithm_comparison()
        
        print("\n" + "=" * 60)
        print("ALL DEMOS COMPLETED SUCCESSFULLY!")
        print("=" * 60)
        print("\nNext steps:")
        print("1. Run 'python app.py' to start the web dashboard")
        print("2. Run 'python cli.py --help' to see CLI options")
        print("3. Run 'python performance.py' for performance evaluation")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n✗ ERROR: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()

