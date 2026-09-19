# Quantum-Resistant Public Key Infrastructure (PKI) Encryption Tool

## README

### Overview

This project implements a Quantum-Resistant Public Key Infrastructure (PKI) Encryption Tool using Post-Quantum Cryptography (PQC). The system uses Kyber512/768 algorithms for key exchange, combined with AES-256 for hybrid encryption, providing protection against both classical and quantum computing threats.

### Features

- **Post-Quantum Key Exchange**: Kyber512 and Kyber768 key encapsulation mechanisms
- **Hybrid Encryption**: Combines Kyber KEM with AES-256 symmetric encryption
- **Text & File Encryption**: Supports encryption/decryption of text and various file types (PDFs, images, etc.)
- **AI-Based Threat Detection**: Machine learning module for detecting suspicious encryption activities
- **Web Dashboard**: Flask-based web interface for easy access
- **Command-Line Interface**: CLI for automation and scripting
- **Performance Evaluation**: Comprehensive benchmarking comparing Kyber vs RSA

### Installation

1. Install Python 3.8 or higher
2. Install dependencies:
```bash
pip install -r requirements.txt
```

### Usage

#### Web Interface

Start the Flask web server:
```bash
python app.py
```

Access the dashboard at `http://localhost:5000`

#### Command-Line Interface

Generate key pair:
```bash
python cli.py generate-keys --algorithm kyber768 --public-key keys/pub.key --private-key keys/priv.key
```

Encrypt text:
```bash
python cli.py encrypt-text --public-key keys/pub.key --text "Hello World" --output encrypted.json
```

Decrypt text:
```bash
python cli.py decrypt-text --private-key keys/priv.key --input encrypted.json
```

Encrypt file:
```bash
python cli.py encrypt-file --public-key keys/pub.key --input-file document.pdf --output encrypted
```

Decrypt file:
```bash
python cli.py decrypt-file --private-key keys/priv.key --encrypted-file encrypted.bin --metadata-file encrypted.json --output decrypted.pdf
```

Run threat analysis:
```bash
python cli.py threat-analysis
```

Run performance evaluation:
```bash
python cli.py performance --output results.json
```

### Project Structure

```
├── app.py                  # Flask web application
├── cli.py                  # Command-line interface
├── kyber_encryption.py     # Core Kyber implementation
├── hybrid_encryption.py    # Hybrid encryption (Kyber + AES-256)
├── threat_detection.py     # AI-based threat detection
├── performance.py          # Performance evaluation module
├── templates/              # Flask HTML templates
├── static/                 # CSS and static files
├── keys/                   # Generated key pairs
├── encrypted/              # Encrypted files
├── decrypted/              # Decrypted files
└── requirements.txt        # Python dependencies
```

### Security Considerations

- Private keys are stored locally and should be kept secure
- Public keys can be shared openly
- Encrypted files require both the encrypted data and metadata JSON for decryption
- The system uses industry-standard cryptographic practices

### Performance

The system includes built-in performance evaluation comparing:
- Kyber512 vs Kyber768 vs RSA-2048 vs RSA-3072
- Key generation speed
- Encryption/decryption speed
- Key sizes

### References

See the complete project report (Project_Report.md) for detailed documentation, methodology, and references.

### License

This project is for educational and research purposes.

### Author

Akpojiyovwi Emmanuel Final Year Cybersecurity Project

