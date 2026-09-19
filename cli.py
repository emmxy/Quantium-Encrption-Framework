"""
Command-Line Interface for Quantum-Resistant PKI Encryption Tool
Provides CLI access to all encryption functionality
"""

import argparse
import sys
import os
from kyber_encryption import KyberEncryption
from hybrid_encryption import HybridEncryption
from threat_detection import ThreatDetection
from performance import PerformanceEvaluator
import json


def generate_keys_cli(args):
    """CLI command for key generation."""
    print(f"Generating {args.algorithm} key pair...")
    kyber = KyberEncryption(args.algorithm)
    public_key, private_key = kyber.generate_keypair()
    
    # Save keys
    kyber.save_keypair(public_key, private_key, args.public_key, args.private_key)
    
    key_sizes = kyber.get_key_sizes()
    print(f"\n✓ Keys generated successfully!")
    print(f"  Public key: {args.public_key} ({key_sizes['public_key_size']} bytes)")
    print(f"  Private key: {args.private_key} ({key_sizes['private_key_size']} bytes)")


def encrypt_text_cli(args):
    """CLI command for text encryption."""
    print("Encrypting text...")
    
    # Load public key
    kyber = KyberEncryption()
    public_key, _ = kyber.load_keypair(args.public_key, args.public_key.replace('public', 'private'))
    
    # Read text
    if args.text:
        plaintext = args.text
    elif args.input_file:
        with open(args.input_file, 'r') as f:
            plaintext = f.read()
    else:
        print("Error: Must provide --text or --input-file")
        return
    
    # Encrypt
    hybrid = HybridEncryption()
    encrypted_data = hybrid.encrypt_text(plaintext, public_key)
    
    # Save encrypted data
    hybrid.save_encrypted_data(encrypted_data, args.output)
    
    print(f"\n✓ Text encrypted successfully!")
    print(f"  Output: {args.output}")


def decrypt_text_cli(args):
    """CLI command for text decryption."""
    print("Decrypting text...")
    
    # Load private key
    kyber = KyberEncryption()
    _, private_key = kyber.load_keypair(
        args.private_key.replace('private', 'public'),
        args.private_key
    )
    
    # Load encrypted data
    hybrid = HybridEncryption()
    encrypted_data = hybrid.load_encrypted_data(args.input)
    
    # Decrypt
    plaintext = hybrid.decrypt_text(encrypted_data, private_key)
    
    # Save or print
    if args.output:
        with open(args.output, 'w') as f:
            f.write(plaintext)
        print(f"\n✓ Text decrypted successfully!")
        print(f"  Output: {args.output}")
    else:
        print(f"\n✓ Decrypted text:")
        print(f"  {plaintext}")


def encrypt_file_cli(args):
    """CLI command for file encryption."""
    print(f"Encrypting file: {args.input_file}...")
    
    # Load public key
    kyber = KyberEncryption()
    public_key, _ = kyber.load_keypair(args.public_key, 
                                      args.public_key.replace('public', 'private'))
    
    # Encrypt file
    hybrid = HybridEncryption()
    encrypted_data, encrypted_bytes = hybrid.encrypt_file(args.input_file, public_key)
    
    # Save encrypted file and metadata
    metadata_path = args.output + '.json'
    encrypted_file_path = args.output + '.bin'
    
    with open(encrypted_file_path, 'wb') as f:
        f.write(encrypted_bytes)
    
    hybrid.save_encrypted_data(encrypted_data, metadata_path)
    
    print(f"\n✓ File encrypted successfully!")
    print(f"  Encrypted file: {encrypted_file_path}")
    print(f"  Metadata: {metadata_path}")


def decrypt_file_cli(args):
    """CLI command for file decryption."""
    print("Decrypting file...")
    
    # Load private key
    kyber = KyberEncryption()
    _, private_key = kyber.load_keypair(
        args.private_key.replace('private', 'public'),
        args.private_key
    )
    
    # Load encrypted data
    hybrid = HybridEncryption()
    encrypted_data = hybrid.load_encrypted_data(args.metadata_file)
    
    with open(args.encrypted_file, 'rb') as f:
        encrypted_bytes = f.read()
    
    # Decrypt
    decrypted_bytes = hybrid.decrypt_file(encrypted_data, encrypted_bytes, 
                                         private_key, args.output)
    
    print(f"\n✓ File decrypted successfully!")
    print(f"  Output: {args.output}")


def threat_analysis_cli(args):
    """CLI command for threat analysis."""
    print("Analyzing threats...")
    
    threat_detector = ThreatDetection()
    if args.log_file:
        threat_detector.load_log(args.log_file)
    
    threats = threat_detector.detect_threats()
    stats = threat_detector.get_statistics()
    
    print(f"\n{'='*60}")
    print("THREAT ANALYSIS REPORT")
    print(f"{'='*60}")
    print(f"\nTotal Activities: {stats.get('total_activities', 0)}")
    print(f"Threats Detected: {len(threats)}")
    print(f"Success Rate: {stats.get('success_rate', 0):.2%}")
    
    if threats:
        print(f"\n{'='*60}")
        print("DETECTED THREATS:")
        print(f"{'='*60}")
        for i, threat in enumerate(threats, 1):
            print(f"\nThreat #{i}:")
            print(f"  Timestamp: {threat['timestamp']}")
            print(f"  Type: {threat['activity_type']}")
            print(f"  Severity: {threat['severity'].upper()}")
            print(f"  Score: {threat['anomaly_score']:.3f}")
            print(f"  Description: {threat['description']}")
            print(f"  Recommendation: {threat['recommendation']}")
    else:
        print("\n✓ No threats detected.")


def performance_cli(args):
    """CLI command for performance evaluation."""
    print("Running performance evaluation...")
    
    evaluator = PerformanceEvaluator()
    results = evaluator.run_full_evaluation()
    
    if args.output:
        evaluator.save_results(results, args.output)
        print(f"\n✓ Results saved to: {args.output}")
    
    # Print summary
    print(f"\n{'='*60}")
    print("PERFORMANCE SUMMARY")
    print(f"{'='*60}")
    
    print("\nKey Generation (mean time in ms):")
    for alg, data in results['key_generation'].items():
        print(f"  {alg}: {data['mean']:.2f} ms")
    
    print("\nEncryption (mean time in ms):")
    for alg, data in results['encryption'].items():
        print(f"  {alg}: {data['mean']:.2f} ms")
    
    print("\nDecryption (mean time in ms):")
    for alg, data in results['decryption'].items():
        print(f"  {alg}: {data['mean']:.2f} ms")
    
    print("\nKey Sizes (bytes):")
    for alg, sizes in results['key_sizes'].items():
        print(f"  {alg}:")
        print(f"    Public Key: {sizes['public_key']} bytes")
        print(f"    Private Key: {sizes['private_key']} bytes")
        print(f"    Total: {sizes['total']} bytes")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='Quantum-Resistant PKI Encryption Tool - CLI'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Key generation
    keygen_parser = subparsers.add_parser('generate-keys', help='Generate key pair')
    keygen_parser.add_argument('--algorithm', choices=['kyber512', 'kyber768'], 
                              default='kyber768', help='Kyber algorithm variant')
    keygen_parser.add_argument('--public-key', required=True, 
                              help='Output path for public key')
    keygen_parser.add_argument('--private-key', required=True, 
                              help='Output path for private key')
    keygen_parser.set_defaults(func=generate_keys_cli)
    
    # Encrypt text
    encrypt_text_parser = subparsers.add_parser('encrypt-text', help='Encrypt text')
    encrypt_text_parser.add_argument('--public-key', required=True, 
                                    help='Path to public key')
    encrypt_text_parser.add_argument('--text', help='Text to encrypt')
    encrypt_text_parser.add_argument('--input-file', help='File containing text to encrypt')
    encrypt_text_parser.add_argument('--output', required=True, 
                                    help='Output JSON file for encrypted data')
    encrypt_text_parser.set_defaults(func=encrypt_text_cli)
    
    # Decrypt text
    decrypt_text_parser = subparsers.add_parser('decrypt-text', help='Decrypt text')
    decrypt_text_parser.add_argument('--private-key', required=True, 
                                    help='Path to private key')
    decrypt_text_parser.add_argument('--input', required=True, 
                                    help='Input JSON file with encrypted data')
    decrypt_text_parser.add_argument('--output', help='Output file (optional, prints to stdout)')
    decrypt_text_parser.set_defaults(func=decrypt_text_cli)
    
    # Encrypt file
    encrypt_file_parser = subparsers.add_parser('encrypt-file', help='Encrypt file')
    encrypt_file_parser.add_argument('--public-key', required=True, 
                                    help='Path to public key')
    encrypt_file_parser.add_argument('--input-file', required=True, 
                                    help='File to encrypt')
    encrypt_file_parser.add_argument('--output', required=True, 
                                    help='Output base path (will create .bin and .json files)')
    encrypt_file_parser.set_defaults(func=encrypt_file_cli)
    
    # Decrypt file
    decrypt_file_parser = subparsers.add_parser('decrypt-file', help='Decrypt file')
    decrypt_file_parser.add_argument('--private-key', required=True, 
                                     help='Path to private key')
    decrypt_file_parser.add_argument('--encrypted-file', required=True, 
                                    help='Encrypted file (.bin)')
    decrypt_file_parser.add_argument('--metadata-file', required=True, 
                                    help='Metadata file (.json)')
    decrypt_file_parser.add_argument('--output', required=True, 
                                    help='Output file path')
    decrypt_file_parser.set_defaults(func=decrypt_file_cli)
    
    # Threat analysis
    threat_parser = subparsers.add_parser('threat-analysis', help='Run threat analysis')
    threat_parser.add_argument('--log-file', help='Path to activity log file')
    threat_parser.set_defaults(func=threat_analysis_cli)
    
    # Performance
    perf_parser = subparsers.add_parser('performance', help='Run performance evaluation')
    perf_parser.add_argument('--output', help='Output JSON file for results')
    perf_parser.set_defaults(func=performance_cli)
    
    args = parser.parse_args()
    
    if args.command:
        args.func(args)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()

