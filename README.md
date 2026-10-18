# QMOOSA Post-Quantum Cryptography Engine (`qmoosa-pqc-mlkem-engine`)

[![NIST FIPS 203](https://img.shields.io/badge/Standard-NIST%20FIPS%20203-blue.svg)](https://csrc.nist.gov/pubs/fips/203/final)
[![Hybrid KEM](https://img.shields.io/badge/Hybrid-ML--KEM%20%2B%20X25519-purple.svg)](https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

`@qmoosa/pqc-mlkem-engine` provides the core post-quantum cryptographic execution engine for the QMOOSA-1000 portfolio (Domain 2: Post-Quantum Cryptography & Quantum Security, Batch 11, Repository 052).

This package delivers:
1. **NIST FIPS 203 ML-KEM Implementation**:
   - `generateKeyPair(paramName, options)`: Key generation from CSPRNG entropy or deterministic seeds ($d, z$).
   - `encapsulate(ek, paramName, options)`: Encapsulation yielding post-quantum ciphertext and 32-byte shared key.
   - `decapsulate(dk, ciphertext, paramName)`: Constant-time decapsulation with **Fujisaki-Okamoto Implicit Rejection** against chosen-ciphertext timing and oracle attacks.
2. **Hybrid Post-Quantum + Classical KEM**:
   - Combines NIST FIPS 203 ML-KEM-768 with classical X25519 (ECDH) using HKDF-SHA256 combiner.
   - Satisfies dual-defense: confidential against both quantum and classical adversaries.
3. **Number Theoretic Transform (NTT) Optimization**:
   - Exact polynomial ring $R_q = \mathbb{Z}_q[X]/(X^{256} + 1)$ arithmetic ($q = 3329$).
   - Constant-time operations preventing side-channel leaks.

---

## Supported Parameter Sets

- **ML-KEM-512**: Category 1 (AES-128 equivalent)
- **ML-KEM-768**: Category 3 (AES-192 equivalent, recommended default)
- **ML-KEM-1024**: Category 5 (AES-256 equivalent)

---

## License

MIT © 2026 elon00 / QMOOSA Mission
