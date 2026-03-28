# quantum-safe-file-encryptor

**A simple hybrid post-quantum file encryption tool** written in **Ada** with a small C helper.

### Overview

This project demonstrates a **hybrid post-quantum encryption** scheme that combines:
- **ML-KEM-768** (NIST FIPS 203) — Quantum-safe key encapsulation
- **HKDF-SHA256** — Secure key derivation from the ML-KEM shared secret
- **AES-256-GCM** — Authenticated encryption with built-in integrity protection (MAC tag)

It protects against both classical and quantum threats (including "harvest now, decrypt later" attacks).

---

### ⚠️ Important Security Warning

**This is an Educational Proof of Concept (POC)**

- It has **not** been formally audited or reviewed by cryptographers.
- **Do NOT use it to protect sensitive, personal, or production data.**
- The ML-KEM keypair is static (not ephemeral).
- Intended for **learning**, experimentation, and understanding hybrid PQC systems.

Use at your own risk.

---

### Features

- Quantum-resistant key transport using official NIST ML-KEM-768
- Strong symmetric encryption with AES-256-GCM
- Proper key derivation using HKDF-SHA256
- Integrity protection (GCM authentication tag)
- Simple CLI interface (`encrypt` / `decrypt`)
- Written primarily in Ada with Open Quantum Safe (liboqs) + OpenSSL

---

### Requirements

- GNAT Ada compiler
- `liboqs` (Open Quantum Safe library)
- OpenSSL (`libcrypto`)

---

### Build & Installation

```bash
# 1. Install dependencies (Ubuntu/Debian example)
sudo apt update
sudo apt install gnat cmake ninja-build build-essential libssl-dev

# 2. Build and install liboqs
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=ON ..
ninja
sudo ninja install
sudo ldconfig

# 3. Compile the C helper
gcc -O2 -o mlkem_helper mlkem_helper.c -loqs -lcrypto

# 4. Compile the Ada program
gnatmake -O2 quantum_safe_file_cli.adb

```

### Usage
# Encrypt a message
./quantum_safe_file_cli encrypt

# Decrypt
./quantum_safe_file_cli decrypt

How It Works

ML-KEM-768 generates a shared secret (quantum-safe)
HKDF-SHA256 derives a strong 256-bit AES key
AES-256-GCM encrypts the message with authentication

This hybrid approach provides excellent security against both current and future quantum computers.

License
MIT License — see the LICENSE file.

Disclaimer
This project is for educational and research purposes only.
Contributions, suggestions, and improvements are welcome!
