# QMOOSA Post-Quantum Cryptography Engine (`qmoosa-pqc-mlkem-engine`)

[![NIST FIPS 203](https://img.shields.io/badge/Standard-NIST%20FIPS%20203-blue.svg)](https://csrc.nist.gov/pubs/fips/203/final)
[![Maintained Primitives](https://img.shields.io/badge/Provider-Noble%20Post--Quantum%20(Audited)-success.svg)](https://github.com/paulmillr/noble-post-quantum)
[![Hybrid KEM](https://img.shields.io/badge/Hybrid-ML--KEM%20%2B%20X25519-purple.svg)](https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

`@qmoosa/pqc-mlkem-engine` is the core post-quantum cryptographic execution engine for the QMOOSA-1000 portfolio (Domain 2: Post-Quantum Cryptography & Quantum Security, Batch 11, Repository 052).

---

## Architectural Architecture & Implementation Standards

1. **Production Cryptographic Provider**:
   - Production key encapsulation and decapsulation operations are delegated to the established, audited, and maintained `@noble/post-quantum/ml-kem` implementation.
   - Conforms strictly to NIST FIPS 203 (ML-KEM-512, ML-KEM-768, ML-KEM-1024).
   - Validated against official NIST CAVP / FIPS 203 Known Answer Test (KAT) vectors.
2. **Algorithmic Reference Material**:
   - Pure polynomial ring $R_q = \mathbb{Z}_q[X]/(X^{256} + 1)$ arithmetic, Number Theoretic Transform (NTT), and centered binomial sampling are preserved in `reference-lattice-math.ts` strictly as an open educational and auditing reference.
3. **Hybrid Post-Quantum + Classical KEM**:
   - Combines NIST FIPS 203 ML-KEM-768 with classical X25519 (ECDH) using HKDF-SHA256 (RFC 5869 / NIST SP 800-56C).
   - **Transcript Binding**: Incorporates peer public keys and parameter identifiers into key derivation salt/context strings, eliminating key-compromise impersonation (KCI) vulnerabilities.
4. **Fujisaki-Okamoto Implicit Rejection**:
   - Tampered ciphertexts deterministically return pseudorandom rejection keys without leaking decapsulation failure or throwing exceptions, preventing chosen-ciphertext timing and oracle attacks.

---

## Disclaimers & Compliance Boundaries

> [!IMPORTANT]
> - **Standard Implementation vs FIPS Certification**: This software implements the algorithms specified in the NIST FIPS 203 standard. It has **NOT** undergone NIST Cryptographic Module Validation Program (CMVP) FIPS 140-3 laboratory certification.
> - **Execution Environment**: Execution inside JavaScript/Node.js/V8 cannot guarantee physical hardware side-channel timing immunity. JIT compilation, garbage collection pauses, and CPU micro-architectural states introduce timing variance.

---

## License

MIT © 2026 elon00 / QMOOSA Mission
