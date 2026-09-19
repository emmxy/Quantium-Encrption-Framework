# Quantum-Resistant PKI Encryption Web App: Summary & How It Works

## 1. Summary Note
The Quantum-Resistant PKI Encryption Tool operates primarily through a Flask-based web application designed to provide users with an accessible, intuitive interface for post-quantum cryptographic operations. The system bridges complex mathematical encryption (Kyber ML-KEM and AES-256) with modern web elements, providing real-time threat detection, secure file/text encryption, and an end-to-end encrypted (E2EE) chat system.

The web app is structured to be secure by design. It includes middleware that acts as both an Intrusion Prevention System (IPS) and a Web Application Firewall (WAF) to proactively block malicious payloads (like XSS or SQL injection) and monitor for anomalous behavior dynamically through an AI-based risk scoring system.

### Key Web Features:
- **Interactive Dashboard:** Displays real-time threat analysis, system statistics, and security event logs.
- **Key Generation Portal:** Allows users to generate Kyber512 or Kyber768 public/private key pairs.
- **Text & File Cryptography:** Dedicated upload and input forms for encrypting and decrypting text messages and files seamlessly.
- **E2EE Real-Time Chat:** A WebSocket-based chat system (using SocketIO) where the server blindly relays encrypted messages and keys without ever accessing the plaintext or storing the ciphertext.
- **Performance Evaluation:** A dedicated page to benchmark the generation and transaction speeds of Kyber vs. traditional RSA.

---

## 2. How the Web App Works

The application operates on a three-tier architecture combining the web interface, the application logic (security & AI), and the cryptographic core.

### A. The Cryptographic Flow (Hybrid Setup)
When a user wants to encrypt data via the web app, the backend employs a hybrid encryption approach:
1. **Kyber Key Exchange (Quantum-Resistant):** The recipient's public Kyber key is used to encapsulate a shared secret. This process uses lattice-based mathematics, which remains secure against both classical and quantum computing attacks.
2. **AES-256 Data Encryption:** The encapsulated shared secret is then hashed (using PBKDF2) to derive an AES-256 symmetric key. This AES key is what actually encrypts the uploaded file or text, as symmetric encryption is much faster for large payloads.
3. **Packaging:** The web app bundles the Kyber ciphertext, the AES ciphertext, and the initialization vector (IV) into a single downloadable encrypted file (or JSON metadata/bin pair for files).

### B. Security & Threat Detection Integration
The Flask web server utilizes `app.before_request` middleware to inspect incoming traffic before any route processes it:
1. **Basic WAF:** Scans all incoming URLs, forms, and data for known malicious payloads (e.g., `<script>`, `UNION SELECT`, `../`). If detected, the request is instantly aborted and logged.
2. **AI-Based IPS:** Tracks user IPs and assigns dynamic risk scores. If an IP's risk score exceeds a certain threshold (indicative of brute-force or weird cryptographic behavior), they are temporarily blocked.
3. **Event Logging:** Operations like generating keys, successful/failed decryption attempts, and detected payloads are continuously logged to refine the AI's threat modeling.

### C. Real-Time Socket Architecture (E2EE Chat)
The web app includes a `/chat` route built on an integration of Flask and SocketIO to enable live, quantum-resistant messaging:
- **Blind Relaying:** When users join a chat room, the server emits connection statuses.
- **Key Exchange Over WebSockets:** Users broadcast their Kyber public keys to each other through the server. The server acts strictly as a messenger.
- **Stateless Ciphertext & Messages:** Users perform encapsulation locally, broadcast the resulting Kyber ciphertext, derive the AES keys locally, and start sending AES-256 encrypted messages. The Flask application never knows the contents of these messages.

### D. User Workflows
1. **Setup:** A user visits `/generate_keys` and downloads their public and private Kyber keys.
2. **Send:** User A visits `/encrypt_file`, uploads a sensitive document, and inputs User B's public key. The site provides an encrypted `.bin` file and a metadata `.json` file.
3. **Receive:** User B visits `/decrypt_file`, uploads the `.bin` and `.json` files, and supplies their own private key. The web app securely recovers the shared secret, decrypts the payload, and provides the original file for download.
