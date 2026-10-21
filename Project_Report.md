# Quantum-Resistant Public Key Infrastructure (PKI) Encryption Tool

## A Comprehensive Implementation of Post-Quantum Cryptography for Secure Communications

---

## 1. BACKGROUND

### 1.1 Introduction

The advent of quantum computing poses a significant threat to current cryptographic systems. Traditional public-key cryptography, particularly RSA and elliptic curve cryptography (ECC), relies on mathematical problems that quantum computers can solve efficiently using Shor's algorithm (Shor, 1994). As quantum computing technology advances, these classical cryptographic systems become increasingly vulnerable.

Post-Quantum Cryptography (PQC), also known as quantum-resistant cryptography, refers to cryptographic algorithms that are designed to be secure against both classical and quantum computing attacks. The National Institute of Standards and Technology (NIST) has been leading efforts to standardize PQC algorithms through a multi-year competition, with Kyber being one of the selected algorithms for key encapsulation mechanisms (KEMs).

### 1.2 The Quantum Threat

Quantum computers leverage quantum mechanical phenomena such as superposition and entanglement to perform computations. While still in early stages, quantum computers with sufficient qubits could break current cryptographic systems:

- **RSA**: Vulnerable to Shor's algorithm - can factor large integers exponentially faster
- **ECC**: Also vulnerable to Shor's algorithm - can solve discrete logarithm problems
- **AES-256**: Generally considered secure, but requires larger key sizes against quantum attacks

### 1.3 Post-Quantum Cryptography Standardization

NIST initiated the Post-Quantum Cryptography Standardization Process in 2016, evaluating numerous candidate algorithms. In 2022, NIST announced the first set of standardized PQC algorithms:

1. **CRYSTALS-Kyber**: For key encapsulation (KEM)
2. **CRYSTALS-Dilithium**: For digital signatures
3. **FALCON**: For digital signatures
4. **SPHINCS+**: For digital signatures

Kyber, specifically, offers security levels comparable to AES-128 (Kyber512), AES-192 (Kyber768), and AES-256 (Kyber1024).

---

## 2. PROBLEM STATEMENT

### 2.1 Current State

Traditional Public Key Infrastructure (PKI) systems rely heavily on RSA and ECC algorithms. These systems are vulnerable to:

1. **Quantum Computing Attacks**: Once large-scale quantum computers are available, current encryption will be broken
2. **Key Size Limitations**: RSA requires increasingly large keys (2048-bit minimum, 3072-bit recommended) for security
3. **Performance Issues**: Larger RSA keys result in slower encryption/decryption operations
4. **Harvest Now, Decrypt Later**: Attackers may be storing encrypted data today to decrypt later with quantum computers

### 2.2 Research Gap

While PQC algorithms exist, there is a lack of:

1. **Practical Implementation Tools**: User-friendly tools for implementing PQC in real-world scenarios
2. **Hybrid Encryption Systems**: Combining PQC with classical cryptography for backward compatibility
3. **Threat Detection**: AI-based systems for detecting anomalous encryption/decryption patterns
4. **Performance Benchmarks**: Comprehensive comparisons between PQC and classical algorithms

### 2.3 Problem Definition

How can we design and implement a practical, secure, and user-friendly Quantum-Resistant PKI encryption tool that:

- Provides post-quantum security using Kyber algorithms
- Maintains compatibility with existing systems through hybrid encryption
- Detects and mitigates security threats using machine learning
- Offers comparable or better performance than classical cryptographic systems

---

## 3. RESEARCH QUESTIONS

1. **RQ1**: How effective is Kyber512/768 compared to RSA-2048/3072 in terms of encryption/decryption performance?

2. **RQ2**: Can a hybrid encryption approach (Kyber + AES-256) provide both post-quantum security and practical performance?

3. **RQ3**: How can machine learning techniques effectively detect suspicious encryption/decryption activities?

4. **RQ4**: What are the key size and bandwidth implications of adopting Kyber in real-world applications?

---

## 4. AIM

To design, develop, and evaluate a Quantum-Resistant Public Key Infrastructure (PKI) Encryption Tool that provides secure, efficient, and practical post-quantum cryptography capabilities for protecting sensitive data against both classical and quantum computing threats.

---

## 5. OBJECTIVES

### 5.1 Primary Objectives

1. **Implement Kyber Key Encapsulation Mechanism**
   - Develop modules for Kyber512 and Kyber768 key generation
   - Implement key encapsulation and decapsulation functions
   - Ensure proper key management and storage

2. **Develop Hybrid Encryption System**
   - Combine Kyber KEM with AES-256 symmetric encryption
   - Support both text and file encryption/decryption
   - Handle various file types (PDFs, images, documents)

3. **Create AI-Based Threat Detection Module**
   - Implement machine learning models for anomaly detection
   - Analyze encryption/decryption patterns
   - Generate threat reports and recommendations

4. **Build User Interfaces**
   - Develop Flask-based web dashboard
   - Create command-line interface for automation
   - Ensure user-friendly design and functionality

5. **Conduct Performance Evaluation**
   - Benchmark Kyber vs RSA algorithms
   - Measure encryption/decryption speeds
   - Compare key sizes and memory usage
   - Analyze security-performance trade-offs

### 5.2 Secondary Objectives

1. Document the complete system architecture and implementation
2. Provide comprehensive user documentation
3. Ensure code quality through proper commenting and structure
4. Create academic documentation following standard format

---

## 6. SIGNIFICANCE

### 6.1 Academic Significance

- Contributes to the field of post-quantum cryptography research
- Provides practical implementation examples for educational purposes
- Demonstrates integration of cryptography and machine learning
- Offers performance benchmarks for PQC algorithms

### 6.2 Practical Significance

- **Cybersecurity Industry**: Provides a tool for organizations transitioning to post-quantum security
- **Government and Defense**: Supports migration to quantum-resistant systems
- **Healthcare and Finance**: Protects sensitive data against future quantum threats
- **Research Institutions**: Offers a platform for further PQC research

### 6.3 Technical Significance

- Demonstrates practical implementation of NIST-selected PQC algorithms
- Shows hybrid encryption approaches for backward compatibility
- Integrates AI/ML for security enhancement
- Provides performance metrics for decision-making

---

## 7. DELIMITATION

### 7.1 Scope Limitations

1. **Algorithm Selection**: Focuses on Kyber512/768 only; does not include other PQC algorithms
2. **Platform**: Primarily designed for Python-based environments
3. **File Types**: Supports common file formats but not all possible formats
4. **Network Security**: Does not include network protocol implementation
5. **Key Management**: Basic key management; does not include enterprise PKI features

### 7.2 Technical Limitations

1. **Quantum Computer Access**: Cannot test against actual quantum computers
2. **Performance Testing**: Benchmarks performed on classical hardware only
3. **Threat Detection**: ML models trained on synthetic data; real-world validation needed
4. **Scalability**: Not tested for enterprise-scale deployments

### 7.3 Time and Resource Constraints

- Limited to available open-source libraries
- Testing performed on standard hardware configurations
- Documentation focuses on implementation rather than theoretical analysis

---

## 8. METHODOLOGY

### 8.1 Research Design

This project follows a **Design Science Research** methodology:

1. **Problem Identification**: Analysis of quantum computing threats
2. **Design**: Architecture and algorithm selection
3. **Development**: Implementation of modules and interfaces
4. **Evaluation**: Performance testing and security analysis
5. **Documentation**: Comprehensive reporting

### 8.2 Development Methodology

**Agile/Iterative Approach**:

- **Phase 1**: Core Kyber implementation
- **Phase 2**: Hybrid encryption development
- **Phase 3**: Threat detection module
- **Phase 4**: User interface development
- **Phase 5**: Performance evaluation and optimization
- **Phase 6**: Documentation and testing

### 8.3 Implementation Approach

1. **Library Selection**: pqcrypto library for Kyber implementation
2. **Modular Design**: Separate modules for each component
3. **Hybrid Encryption**: Kyber for key exchange, AES-256 for data encryption
4. **Machine Learning**: scikit-learn for anomaly detection
5. **Web Framework**: Flask for web interface
6. **Testing**: Unit tests and performance benchmarks

### 8.4 Evaluation Methodology

1. **Performance Metrics**:
   - Key generation time
   - Encryption/decryption speed
   - Key sizes
   - Memory usage

2. **Security Analysis**:
   - Algorithm security properties
   - Key management security
   - Threat detection effectiveness

3. **Usability Testing**:
   - Web interface usability
   - CLI functionality
   - Documentation clarity

---

## 9. TOOLS AND TECHNOLOGIES

### 9.1 Programming Languages

- **Python 3.8+**: Primary programming language
- **HTML/CSS/JavaScript**: Web interface frontend

### 9.2 Libraries and Frameworks

- **pqcrypto**: Post-quantum cryptography library for Kyber
- **cryptography**: Python cryptography library for AES-256
- **Flask**: Web framework for dashboard
- **scikit-learn**: Machine learning for threat detection
- **numpy/pandas**: Data processing and analysis

### 9.3 Development Tools

- **Git**: Version control
- **VS Code/PyCharm**: IDE
- **pip**: Package management

### 9.4 Testing Tools

- **time**: Performance measurement
- **statistics**: Statistical analysis
- **Custom benchmarks**: Performance evaluation scripts

---

## 10. ETHICAL CONSIDERATIONS

### 10.1 Data Privacy

- **Encryption Keys**: Users are responsible for securing their private keys
- **Encrypted Data**: The system does not store or transmit encrypted data without user consent
- **Activity Logging**: Threat detection logs are stored locally and can be reviewed/deleted by users

### 10.2 Responsible Use

- **Educational Purpose**: This tool is designed for educational and research purposes
- **Legal Compliance**: Users must ensure compliance with local encryption laws
- **Authorization**: Users should only encrypt/decrypt data they own or have authorization to process

### 10.3 Security Ethics

- **Disclosure**: Vulnerabilities should be responsibly disclosed
- **Open Source**: Code is open for security audit
- **Best Practices**: Implementation follows cryptographic best practices

### 10.4 Research Ethics

- **Transparency**: All methodologies and results are documented
- **Reproducibility**: Code and documentation enable reproduction
- **Attribution**: Proper credit given to libraries and algorithms used

---

## 11. ARCHITECTURE AND DESIGN

### 11.1 System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   User Interface Layer                  │
│  ┌──────────────┐              ┌──────────────┐       │
│  │ Web Dashboard│              │ CLI Interface │       │
│  └──────────────┘              └──────────────┘       │
└─────────────────────────────────────────────────────────┘
                          │
┌─────────────────────────────────────────────────────────┐
│              Application Logic Layer                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐│
│  │Hybrid        │  │Threat        │  │Performance   ││
│  │Encryption    │  │Detection     │  │Evaluation    ││
│  └──────────────┘  └──────────────┘  └──────────────┘│
└─────────────────────────────────────────────────────────┘
                          │
┌─────────────────────────────────────────────────────────┐
│              Cryptographic Layer                        │
│  ┌──────────────┐              ┌──────────────┐       │
│  │ Kyber KEM    │              │ AES-256      │       │
│  │ (Key Exchange)│              │ (Data Enc.)  │       │
│  └──────────────┘              └──────────────┘       │
└─────────────────────────────────────────────────────────┘
```

### 11.2 Key Components

1. **Kyber Encryption Module** (`kyber_encryption.py`)
   - Key pair generation
   - Key encapsulation/decapsulation
   - Key management

2. **Hybrid Encryption Module** (`hybrid_encryption.py`)
   - Kyber + AES-256 combination
   - Text encryption/decryption
   - File encryption/decryption

3. **Threat Detection Module** (`threat_detection.py`)
   - Activity logging
   - ML-based anomaly detection
   - Threat reporting

4. **Performance Module** (`performance.py`)
   - Algorithm benchmarking
   - Performance metrics
   - Comparison analysis

5. **Web Interface** (`app.py`, `templates/`)
   - Flask application
   - User-friendly UI
   - Real-time operations

6. **CLI Interface** (`cli.py`)
   - Command-line access
   - Automation support
   - Scripting capabilities

---

## 12. IMPLEMENTATION DETAILS

### 12.1 Kyber Implementation

The Kyber algorithm is implemented using the `pqcrypto` library, which provides:

- **Kyber512**: Equivalent to AES-128 security level
- **Kyber768**: Equivalent to AES-192 security level

Key operations:
- `generate_keypair()`: Generates public/private key pair
- `encapsulate()`: Creates shared secret and ciphertext
- `decapsulate()`: Recovers shared secret from ciphertext

### 12.2 Hybrid Encryption Workflow

1. **Key Establishment**:
   - Generate high-entropy 32-byte shared secret using ML-KEM (NIST FIPS 203) or Dual Hybrid (ML-KEM-768 + X25519 ECDH per NIST SP 800-56C Rev 2)
   - Derive 256-bit symmetric key using HKDF-SHA256 (RFC 5869) with transcript binding
   - Generate unique 96-bit (12-byte) CSPRNG nonce for AES-GCM

2. **Authenticated Encryption (AEAD)**:
   - Construct Additional Authenticated Data (AAD) binding protocol version and metadata
   - Encrypt data using AES-256-GCM (NIST SP 800-38D)
   - Produce ciphertext and 128-bit authentication tag

3. **Authenticated Decryption & Failure Handling**:
   - Decapsulate shared secret using recipient private key
   - Derive symmetric key via HKDF-SHA256
   - Reconstruct AAD and perform AES-256-GCM authenticated decryption
   - If tag verification fails, immediately abort and suppress unauthenticated plaintext

### 12.3 Threat Detection & Intrusion Prevention (WAF/IPS)

Using a supervised **Random Forest Classifier** alongside heuristic session tracking:

- **Feature Space**: 14 lexical and structural features (Shannon entropy, special character ratio, injection syntax scoring, rate abuse tracking, crypto failure flags)
- **Attack Classes**: Benign, SQL Injection (SQLi), Cross-Site Scripting (XSS), Path Traversal / LFI, Cryptographic Anomalies, and Automated Flooding / Rate Abuse
- **Inference & Enforcement**: Real-time evaluation (~38 µs/request); blocks malicious requests (`403 Forbidden`) while logging security incidents

### 12.4 Performance Evaluation Methodology

Rigorous scientific benchmarking:
- Monotonic nanosecond timing (`time.perf_counter_ns`) with warmup iterations
- Distinct separation of key generation, asymmetric key establishment (encapsulation vs decapsulation), and bulk symmetric encryption (AES-256-GCM)
- Evaluated on ML-KEM-512/768/1024 alongside classical RSA-2048, RSA-3072, and RSA-4096

---

## 13. RESULTS

### 13.1 Key Generation Latency

Measured across repeated trials (Linux x86_64, Python 3.14, monotonic high-resolution timing):

| Algorithm | Mean Time (ms) | Median Time (ms) | Standard Deviation (ms) | 95th Percentile (ms) |
|-----------|----------------|------------------|-------------------------|----------------------|
| ML-KEM-512 | 0.0769        | 0.0645           | 0.0384                  | 0.1652               |
| ML-KEM-768 | 0.1424        | 0.1045           | 0.1205                  | 0.3892               |
| ML-KEM-1024| 0.1699        | 0.1608           | 0.0526                  | 0.2811               |
| RSA-2048   | 50.5156       | 45.2240          | 26.3120                 | 104.5210             |
| RSA-3072   | 211.1897      | 175.7918         | 112.4510                | 465.1200             |
| RSA-4096   | 639.9570      | 703.2485         | 248.9140                | 1125.8000            |

**Observation**: ML-KEM key generation is orders of magnitude faster than RSA. Specifically, ML-KEM-768 generates keys **~4,494x faster** than RSA-4096 (0.14 ms vs 640 ms).

### 13.2 Key Establishment: Encapsulation / Key Wrap Latency

| Algorithm | Operation Role | Mean Time (ms) | Median Time (ms) |
|-----------|----------------|----------------|------------------|
| ML-KEM-512 | Key Encapsulation (32B shared secret) | 0.0802 | 0.0796 |
| ML-KEM-768 | Key Encapsulation (32B shared secret) | 0.1253 | 0.1247 |
| ML-KEM-1024| Key Encapsulation (32B shared secret) | 0.1049 | 0.1028 |
| RSA-2048   | OAEP Key Wrap (32B symmetric key)     | 0.0247 | 0.0243 |
| RSA-3072   | OAEP Key Wrap (32B symmetric key)     | 0.0481 | 0.0461 |
| RSA-4096   | OAEP Key Wrap (32B symmetric key)     | 0.0795 | 0.0763 |

**Observation**: Both ML-KEM encapsulation and RSA-OAEP public key encryption operate in fractions of a millisecond.

### 13.3 Key Establishment: Decapsulation / Key Unwrap Latency

| Algorithm | Operation Role | Mean Time (ms) | Median Time (ms) |
|-----------|----------------|----------------|------------------|
| ML-KEM-512 | Key Decapsulation (32B secret) | 0.0983 | 0.0995 |
| ML-KEM-768 | Key Decapsulation (32B secret) | 0.1450 | 0.1515 |
| ML-KEM-1024| Key Decapsulation (32B secret) | 0.1423 | 0.1273 |
| RSA-2048   | OAEP Key Unwrap (Private Decryption) | 0.3961 | 0.3972 |
| RSA-3072   | OAEP Key Unwrap (Private Decryption) | 0.9348 | 0.8825 |
| RSA-4096   | OAEP Key Unwrap (Private Decryption) | 1.9513 | 1.7939 |

**Observation**: ML-KEM decapsulation is significantly faster than RSA private key operations, with ML-KEM-768 decapsulation being **13.4x faster** than RSA-4096 private-key decryption.

### 13.4 Cryptographic Size and Transmission Overhead

| Algorithm | Public Key | Private Key | Ciphertext | Total Public Overhead (PK + CT) |
|-----------|------------|-------------|------------|---------------------------------|
| ML-KEM-512 | 800 B     | 1632 B      | 768 B      | 1568 B                          |
| ML-KEM-768 | 1184 B    | 2400 B      | 1088 B     | 2272 B                          |
| ML-KEM-1024| 1568 B    | 3168 B      | 1568 B     | 3136 B                          |
| RSA-2048   | 294 B     | 1217 B      | 256 B      | 550 B                           |
| RSA-3072   | 422 B     | 1793 B      | 384 B      | 806 B                           |
| RSA-4096   | 550 B     | 2376 B      | 512 B      | 1062 B                          |

**Observation**: While ML-KEM has larger public key and ciphertext sizes than RSA, the total public transmission overhead of 2,272 bytes for ML-KEM-768 remains small and easily accommodated within standard network MTUs.

### 13.5 Threat Detection (Random Forest WAF/IPS) Results

- **Accuracy**: 100.0%
- **Macro F1-Score**: 100.0%
- **Benign False Positive Rate**: 0.00%
- **Attack False Negative Rate**: 0.00%
- **Inference Latency**: 38.08 µs/request (~26,200 requests/sec throughput)
- **Active Mitigation**: Successfully blocks SQLi, XSS, Path Traversal, and brute-force rate flooding with HTTP 403 Forbidden.

### 13.6 Bulk Symmetric Performance (AES-256-GCM)

| Payload Size | Encryption Mean (ms) | Encryption Median (ms) | Decryption Mean (ms) | Decryption Median (ms) |
| :--- | :--- | :--- | :--- | :--- |
| **1 KB** | 0.0016 ms | 0.0015 ms | 0.0016 ms | 0.0015 ms |
| **64 KB** | 0.0103 ms | 0.0085 ms | 0.0094 ms | 0.0083 ms |
| **1 MB** | 0.1634 ms | 0.1234 ms | 0.1484 ms | 0.1359 ms |

---

## 14. DISCUSSION

### 14.1 Performance Analysis

**Key Generation**: ML-KEM-768 key generation (0.14 ms) outperforms RSA-4096 (640 ms) by over three orders of magnitude (~4,494x). This provides massive efficiency gains in systems requiring frequent ephemeral key generation.

**Decapsulation**: Server-side throughput is heavily dominated by private-key decapsulation/decryption. ML-KEM-768 completes decapsulation in 0.145 ms compared to 1.95 ms for RSA-4096, yielding a **13.4x performance advantage** for post-quantum key establishment.

**Bandwidth Overhead**: The 2,272-byte combined public key and ciphertext overhead of ML-KEM-768 is modest and acceptable for protecting critical infrastructure against quantum adversaries.

### 14.2 Security Analysis

**Post-Quantum Security**: Kyber provides security against both classical and quantum computing attacks, making it future-proof as quantum computers advance.

**Hybrid Approach**: Combining Kyber with AES-256 provides defense-in-depth:
- Kyber ensures secure key exchange even against quantum attacks
- AES-256 provides efficient symmetric encryption
- Backward compatibility maintained

**Threat Detection**: ML-based anomaly detection adds an additional security layer by identifying suspicious patterns that might indicate:
- Unauthorized access attempts
- Malicious encryption activities
- System compromises

### 14.3 Practical Implications

**Adoption**: The tool demonstrates that post-quantum cryptography can be practical and user-friendly. Organizations can begin transitioning to PQC without sacrificing usability.

**Migration Path**: Hybrid encryption allows gradual migration:
- New systems can use Kyber immediately
- Existing systems remain compatible
- Gradual transition reduces risk

**Performance Trade-offs**: While key sizes are larger, performance is comparable or better. The post-quantum security benefit outweighs the minor overhead.

### 14.4 Limitations and Future Work

**Current Limitations**:
- Single PQC algorithm (Kyber) - could expand to others
- Limited to local file operations - network encryption not included
- ML models trained on synthetic data - real-world validation needed

**Future Enhancements**:
- Support for additional PQC algorithms (Dilithium, Falcon)
- Network protocol implementation
- Enhanced key management and PKI features
- Real-world ML model training and validation
- Mobile application development
- Cloud deployment options

---

## 15. CONCLUSION

This project successfully demonstrates the practical implementation of quantum-resistant cryptography using Kyber algorithms. The developed tool provides:

1. **Effective Post-Quantum Security**: Protection against quantum computing threats
2. **Practical Performance**: Comparable or better than classical RSA
3. **User-Friendly Interface**: Both web and CLI access
4. **Enhanced Security**: AI-based threat detection
5. **Comprehensive Evaluation**: Performance benchmarks and analysis

The results show that post-quantum cryptography is not only necessary for future security but also practical and efficient. Organizations should begin planning their migration to PQC systems, and this tool provides a foundation for such transitions.

The hybrid encryption approach balances security and compatibility, making it suitable for real-world deployment. The threat detection module adds an additional layer of security by identifying anomalous patterns.

Future work should focus on expanding algorithm support, enhancing key management features, and validating ML models with real-world data.

---

## 16. REFERENCES

Avanzi, R., et al. (2019). *CRYSTALS-Kyber Algorithm Specifications and Supporting Documentation*. NIST Post-Quantum Cryptography Standardization Project.

Bernstein, D. J., et al. (2017). *Post-quantum cryptography*. Nature, 549(7671), 188-194.

Chen, L., et al. (2016). *Report on Post-Quantum Cryptography*. NIST Internal Report 8105.

Dworkin, M. (2001). *Recommendation for Block Cipher Modes of Operation: Methods and Techniques*. NIST Special Publication 800-38A.

Liu, F. T., Ting, K. M., & Zhou, Z. H. (2008). *Isolation Forest*. 2008 Eighth IEEE International Conference on Data Mining, 413-422.

National Institute of Standards and Technology. (2022). *Post-Quantum Cryptography Standardization*. Retrieved from https://csrc.nist.gov/projects/post-quantum-cryptography

Pedregosa, F., et al. (2011). *Scikit-learn: Machine Learning in Python*. Journal of Machine Learning Research, 12, 2825-2830.

Shor, P. W. (1994). *Algorithms for quantum computation: discrete logarithms and factoring*. Proceedings 35th Annual Symposium on Foundations of Computer Science, 124-134.

Verma, A., & Kaushal, S. (2017). *A survey on post-quantum cryptographic schemes*. International Journal of Engineering and Technology, 9(3), 1909-1917.

Zhang, J., et al. (2020). *Post-quantum cryptography: A survey*. IEEE Communications Surveys & Tutorials, 22(4), 2515-2541.

---

## APPENDIX A: CODE STRUCTURE

### A.1 Module Overview

- `kyber_encryption.py`: Core Kyber implementation (240 lines)
- `hybrid_encryption.py`: Hybrid encryption system (280 lines)
- `threat_detection.py`: ML-based threat detection (320 lines)
- `performance.py`: Performance evaluation (380 lines)
- `app.py`: Flask web application (250 lines)
- `cli.py`: Command-line interface (220 lines)

### A.2 Key Functions

**Kyber Encryption**:
- `generate_keypair()`: Generate public/private key pair
- `encapsulate()`: Create shared secret
- `decapsulate()`: Recover shared secret

**Hybrid Encryption**:
- `encrypt_text()`: Encrypt text data
- `decrypt_text()`: Decrypt text data
- `encrypt_file()`: Encrypt file data
- `decrypt_file()`: Decrypt file data

**Threat Detection**:
- `log_activity()`: Log encryption operations
- `detect_threats()`: Identify anomalies
- `get_statistics()`: Generate activity statistics

**Performance**:
- `benchmark_key_generation()`: Measure key generation speed
- `benchmark_encryption()`: Measure encryption speed
- `benchmark_decryption()`: Measure decryption speed
- `compare_key_sizes()`: Compare key sizes

---

## APPENDIX B: ARCHITECTURE DIAGRAMS

### B.1 Encryption Flow

```
Plaintext/File
    │
    ├─→ Generate Shared Secret (Kyber)
    │       │
    │       └─→ Derive AES Key (PBKDF2)
    │               │
    │               └─→ Encrypt Data (AES-256-CBC)
    │                       │
    └───────────────────────┘
                        │
                    Encrypted Data + Metadata
```

### B.2 Decryption Flow

```
Encrypted Data + Metadata
    │
    ├─→ Decapsulate Shared Secret (Kyber)
    │       │
    │       └─→ Derive AES Key (PBKDF2)
    │               │
    │               └─→ Decrypt Data (AES-256-CBC)
    │                       │
    └───────────────────────┘
                        │
                    Plaintext/File
```

### B.3 Threat Detection Flow

```
Encryption Activity
    │
    ├─→ Log Activity
    │       │
    │       └─→ Extract Features
    │               │
    │               └─→ ML Analysis (Isolation Forest)
    │                       │
    └───────────────────────┘
                        │
                    Threat Report
```

---

## APPENDIX C: EXAMPLE USAGE

### C.1 Python Code Example

```python
from kyber_encryption import KyberEncryption
from hybrid_encryption import HybridEncryption

# Generate key pair
kyber = KyberEncryption('kyber768')
public_key, private_key = kyber.generate_keypair()

# Encrypt text
hybrid = HybridEncryption()
encrypted_data = hybrid.encrypt_text("Hello, Quantum World!", public_key)

# Decrypt text
plaintext = hybrid.decrypt_text(encrypted_data, private_key)
print(plaintext)  # Output: "Hello, Quantum World!"
```

### C.2 CLI Example

```bash
# Generate keys
python cli.py generate-keys --algorithm kyber768 \
    --public-key keys/pub.key --private-key keys/priv.key

# Encrypt file
python cli.py encrypt-file --public-key keys/pub.key \
    --input-file document.pdf --output encrypted

# Decrypt file
python cli.py decrypt-file --private-key keys/priv.key \
    --encrypted-file encrypted.bin --metadata-file encrypted.json \
    --output decrypted.pdf
```

---

**END OF REPORT**

