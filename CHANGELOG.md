# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Support for larger messages (up to 10 KB)
- Better error messages in Ada program

### Changed

- Improved code readability and structure

---

## [1.0.0] - 2026-03-28

### Added

- Initial public release
- **Hybrid Post-Quantum Encryption**:
  - ML-KEM-768 (NIST FIPS 203) for quantum-safe key encapsulation
  - HKDF-SHA256 for secure key derivation from ML-KEM shared secret
  - AES-256-GCM for authenticated encryption with integrity protection (MAC tag)
- Simple CLI interface: `encrypt` and `decrypt` modes
- Binary file I/O using Ada.Streams.Stream_IO
- C helper (`mlkem_helper.c`) using liboqs + OpenSSL
- Comprehensive README.md with build and usage instructions
- Security warnings and disclaimers

### Features

- Quantum-resistant key transport
- Strong symmetric encryption with built-in authentication
- Proper key stretching using HKDF
- Educational hybrid PQC + classical cryptography example

### Security Notice

- This is an **educational Proof of Concept** only
- Not formally audited
- ML-KEM keypair is static (not ephemeral)
- Not suitable for production or sensitive data

### Known Limitations

- Message size limited to ~10 KB
- Static keypair reuse
- External process spawning for C helper
- No large file streaming support yet

### Dependencies

- GNAT Ada compiler
- liboqs (Open Quantum Safe)
- OpenSSL (libcrypto)

---

## [0.1.0] - Pre-release (Internal)

### Added

- Basic XOR-based encryption (initial prototype)
- ML-KEM integration via liboqs
- AES-256-GCM replacement for raw XOR
- HKDF-SHA256 key derivation

---

## Types of Changes

- `Added` for new features.
- `Changed` for changes in existing functionality.
- `Deprecated` for soon-to-be removed features.
- `Removed` for now removed features.
- `Fixed` for any bug fixes.
- `Security` for vulnerabilities.

---

**Note**: This project is for **educational and research purposes only**.  
Do not use it to protect real sensitive or production data.
