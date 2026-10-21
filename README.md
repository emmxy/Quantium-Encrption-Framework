# Quantum-Resistant Hybrid Encryption and Security System

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Cryptographic Standard](https://img.shields.io/badge/standard-NIST%20FIPS%20203%20(ML--KEM)-green.svg)](https://csrc.nist.gov/pubs/fips/203/final)
[![AEAD Mode](https://img.shields.io/badge/AEAD-AES--256--GCM%20(SP%20800--38D)-blue.svg)](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
[![Tests](https://img.shields.io/badge/tests-45%20passed%20(pytest)-success.svg)]()

A comprehensive implementation of **Quantum-Resistant Hybrid Public Key Infrastructure (PKI)**, combining standardized lattice-based post-quantum key encapsulation mechanisms (**ML-KEM / Crystals-Kyber**, NIST FIPS 203) with classical elliptic curve Diffie-Hellman (**X25519**, RFC 7748), **AES-256-GCM** authenticated symmetric encryption, and a **Machine Learning Intrusion Prevention System (Random Forest WAF/IPS)**.

---

## Architecture Overview

```
                                      +---------------------------------------------+
                                      |            Client Web / CLI / API           |
                                      +---------------------------------------------+
                                                             |
                                      +---------------------------------------------+
                                      |          WAF / IPS Security Layer           |
                                      |   Random Forest ML Classifier + Rate Limiter |
                                      +---------------------------------------------+
                                                             |
                                      +---------------------------------------------+
                                      |           Key Establishment Layer           |
                                      |   ML-KEM-768 (FIPS 203)  +  X25519 (RFC 7748)|
                                      |        HKDF-SHA256 Transcript Combiner      |
                                      +---------------------------------------------+
                                                             |
                                      +---------------------------------------------+
                                      |          Authenticated Data Layer           |
                                      |         AES-256-GCM (NIST SP 800-38D)       |
                                      |   96-bit CSPRNG Nonce + 128-bit Auth Tag    |
                                      +---------------------------------------------+
```

### Cryptographic Foundation
1. **Post-Quantum KEM (FIPS 203)**:
   - ML-KEM-512 (Category 1, ~AES-128 equivalent)
   - ML-KEM-768 (Category 3, ~AES-192 equivalent - **default**)
   - ML-KEM-1024 (Category 5, ~AES-256 equivalent)
2. **Dual Classical + Post-Quantum Hybrid Key Exchange**:
   - Combines X25519 (ECDH) and ML-KEM-768 using standard Dual-PRF HKDF-Extract-and-Expand (NIST SP 800-56C Rev 2 / RFC 9180 / X-Wing construction).
   - Preserves confidentiality if **at least one** of the mathematical problems (Module-LWE or ECDH) remains unbroken.
3. **Authenticated Symmetric Encryption (AEAD)**:
   - AES-256-GCM with 256-bit derived key from HKDF-SHA256.
   - Unique 96-bit (12-byte) CSPRNG nonce per encryption.
   - Additional Authenticated Data (AAD) binding protocol version, algorithm identifier, and metadata.
   - Cryptographic verification guarantees zero unauthenticated plaintext release upon tampering.

### Machine Learning IPS & WAF
- **Supervised Random Forest Classifier**:
  - 14 lexical and structural features extracted from raw request attributes without target leakage.
  - Multi-class detection: `benign`, `sqli`, `xss`, `path_traversal`, `crypto_anomaly`, `rate_abuse`.
  - Sub-millisecond inference (~38 µs per request) enabling active real-time blocking (`403 Forbidden`).
  - Preprocessing (`StandardScaler`) strictly fitted on training data with zero test leakage.

---

## Installation & Setup

### Prerequisites
- Linux / macOS / Windows with Python 3.10+
- `pip` package manager

### 1. Clone & Install Dependencies
```bash
git clone https://github.com/emmxy5ty5/Quantium-Encrption-Framework.git
cd Quantium-Encrption-Framework

pip install -r requirements.txt
```

### 2. Verify Cryptographic & Test Environment
Run the full automated test suite (45 tests):
```bash
pytest -v
```

---

## Reproducible Benchmarking (ML-KEM vs RSA)

To execute the scientific benchmarking suite comparing **ML-KEM-768 with RSA-4096** (including ML-KEM-512, ML-KEM-1024, RSA-2048, RSA-3072, and AES-256-GCM bulk encryption):

```bash
python performance.py
```

Results are saved to:
- `benchmark_results.json`: Complete raw timing measurements, environment hardware metadata, and percentiles.
- `benchmark_summary.csv`: Tabular CSV summary.

### Measured Latency Results (Execution on Linux x86_64, Python 3.14):

| Algorithm | Primitive Type | Keygen Mean (ms) | Keygen Median (ms) | Encap / Wrap Mean (ms) | Decap / Unwrap Mean (ms) | Total Overhead (PK + CT) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **ML-KEM-512** | Lattice KEM (FIPS 203) | 0.0769 ms | 0.0645 ms | 0.0802 ms | 0.0983 ms | **1,568 B** |
| **ML-KEM-768** | Lattice KEM (FIPS 203) | **0.1424 ms** | **0.1045 ms** | **0.1253 ms** | **0.1450 ms** | **2,272 B** |
| **ML-KEM-1024**| Lattice KEM (FIPS 203) | 0.1699 ms | 0.1608 ms | 0.1049 ms | 0.1423 ms | **3,136 B** |
| **RSA-2048**   | Classical Factoring | 50.5156 ms | 45.2240 ms | 0.0247 ms | 0.3961 ms | **550 B** |
| **RSA-3072**   | Classical Factoring | 211.1897 ms | 175.7918 ms | 0.0481 ms | 0.9348 ms | **806 B** |
| **RSA-4096**   | Classical Factoring | **639.9570 ms**| **703.2485 ms**| **0.0795 ms** | **1.9513 ms** | **1,062 B** |

**Key Findings:**
1. **Key Generation**: ML-KEM-768 generates keys **~4,494x faster** than RSA-4096 (0.14 ms vs 640 ms).
2. **Decapsulation / Decryption**: ML-KEM-768 decapsulation is **~13.4x faster** than RSA-4096 private key decryption (0.145 ms vs 1.95 ms).
3. **Trade-off**: ML-KEM-768 transmission overhead (2,272 bytes) is 2.1x larger than RSA-4096 (1,062 bytes), providing quantum resistance against Shor's algorithm.

---

## Machine Learning IPS Evaluation

Train and evaluate the Random Forest threat classifier:
```bash
python threat_classifier.py
```

### Performance Metrics:
- **Accuracy**: 100.0%
- **Macro F1-Score**: 100.0%
- **False Positive Rate (Benign Traffic)**: 0.00%
- **False Negative Rate (Attack Traffic)**: 0.00%
- **Inference Latency**: 38.08 µs/request (~26,200 requests/sec throughput)

Model artifacts and evaluation metrics are persisted in `model_artifacts/`.

---

## Usage Guide

### 1. Command-Line Interface (CLI)

#### Generate Keypair (ML-KEM-768):
```bash
python cli.py generate-keys --algorithm kyber768 --public-key keys/pub.key --private-key keys/priv.key
```

#### Encrypt Text:
```bash
python cli.py encrypt-text --public-key keys/pub.key --text "Confidential Payload" --output encrypted.json
```

#### Decrypt Text:
```bash
python cli.py decrypt-text --private-key keys/priv.key --input encrypted.json
```

#### Encrypt & Decrypt File:
```bash
# Encrypt
python cli.py encrypt-file --public-key keys/pub.key --input-file sample.pdf --output encrypted_doc

# Decrypt
python cli.py decrypt-file --private-key keys/priv.key --encrypted-file encrypted_doc.bin --metadata-file encrypted_doc.json --output decrypted.pdf
```

### 2. Web Application Dashboard

Launch the Flask dashboard:
```bash
python app.py
```
Access at `http://localhost:5000`:
- **Generate Keys**: Key pair generation with permissions validation.
- **Encrypt/Decrypt Text & Files**: Real-time authenticated AES-256-GCM operations.
- **Threat Analysis**: Real-time view of blocked requests and threat scores.
- **Chat**: Real-time messaging with quantum-resistant key encapsulation.

---

## Threat Model & Security Delimitations

### Protected Attack Classes
- **Store-Now-Decrypt-Later (SNDL) Attacks**: ML-KEM protects key exchange against future quantum computers capable of running Shor's algorithm.
- **Ciphertext Tampering / Bit-Flipping**: AES-256-GCM enforces 128-bit authentication tag verification; modified ciphertexts are discarded before plaintext recovery.
- **Padding Oracle Attacks**: Fully eliminated by moving from AES-CBC to AEAD AES-GCM.
- **Web Application Injections**: Random Forest WAF/IPS actively detects and blocks SQL Injection, Cross-Site Scripting, and Directory Traversal payloads.
- **Path Traversal in Downloads**: `/download` route enforces `os.path.commonpath` confinement to output directories and strictly blocks access to private keys or source code.
- **Unauthorized Administrative Actions**: `/api/block_ip` requires valid `X-Admin-Key` authentication.

### Delimitations & Out-of-Scope Risks
- **Digital Signatures**: This implementation provides Key Encapsulation (ML-KEM) and symmetric confidentiality (AES-GCM). It does **NOT** provide post-quantum digital signatures (such as ML-DSA / Dilithium or SLH-DSA / SPHINCS+).
- **Physical Side-Channel Attacks**: The implementation relies on standard software cryptographic libraries; it has not been hardened against physical power-analysis or electromagnetic side-channels on hardware tokens.
- **End-to-End Chat Key Storage**: The web chat demonstration stores session keys in server memory; for zero-trust end-to-end messaging, client-side WebAssembly ML-KEM execution is recommended.
