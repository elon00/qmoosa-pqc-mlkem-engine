/**
 * QMOOSA Post-Quantum Cryptography Engine
 * Standards Baseline: NIST FIPS 203 (Module-Lattice-Based Key-Encapsulation Mechanism)
 * 
 * IMPORTANT CRYPTOGRAPHIC NOTICE:
 * 1. Production key encapsulation and decapsulation operations in this engine are powered by
 *    the established, maintained, and audited `@noble/post-quantum` cryptographic library.
 * 2. Algorithmic polynomial ring arithmetic, NTT, and Barrett reduction references are retained
 *    in `reference-lattice-math.ts` strictly for educational and auditing transparency.
 * 3. This implementation conforms to the NIST FIPS 203 specification. It is NOT FIPS 140-3
 *    Cryptographic Module Validation Program (CMVP) certified.
 * 4. Execution within JavaScript / V8 engines cannot guarantee hardware-level constant-time
 *    execution; runtime JIT compiler optimizations and memory management are non-deterministic.
 */

import {
  randomBytes,
  diffieHellman,
  createHmac,
  generateKeyPairSync,
  createPrivateKey,
  createPublicKey
} from 'node:crypto';
import {
  ml_kem512,
  ml_kem768,
  ml_kem1024
} from '@noble/post-quantum/ml-kem.js';
import {
  ML_KEM_768,
  getMlKemParameters,
  validateEncapsulationKey,
  validateDecapsulationKey,
  validateCiphertext,
  constantTimeEqual,
  type MlKemParameterName,
  type MlKemParameters,
  type MlKemKeyPair,
  type MlKemEncapsulationResult,
  type HybridKemKeyPair,
  type HybridKemEncapsulationResult
} from '@qmoosa/pqc-mlkem-protocol';

export * as ReferenceLatticeMath from './reference-lattice-math.js';

export interface KeyGenOptions {
  /**
   * 64-byte deterministic seed (d || z) per NIST FIPS 203 Algorithm 16 / CAVP test vectors.
   * If omitted, 64 bytes of cryptographically secure randomness are sampled from the OS CSPRNG.
   */
  readonly seed?: Uint8Array;
}

export interface EncapsOptions {
  /**
   * 32-byte deterministic message seed m per NIST FIPS 203 Algorithm 17 / CAVP test vectors.
   * If omitted, 32 bytes of cryptographically secure randomness are sampled from the OS CSPRNG.
   */
  readonly seed?: Uint8Array;
}

function getNobleInstance(name: MlKemParameterName) {
  switch (name) {
    case 'ML-KEM-512':
      return ml_kem512;
    case 'ML-KEM-768':
      return ml_kem768;
    case 'ML-KEM-1024':
      return ml_kem1024;
    default:
      throw new Error(`UNSUPPORTED_ML_KEM_PARAMETER_SET: ${name}`);
  }
}

/**
 * Derives a combined 32-byte shared secret from post-quantum and classical ECDH shared secrets
 * using HKDF-Extract-and-Expand (RFC 5869 / NIST SP 800-56C) with SHA-256.
 * Binds transcript data including peer public keys and domain separation strings.
 */
export function deriveHybridSharedSecret(
  pqcSharedSecret: Uint8Array,
  ecdhSharedSecret: Uint8Array,
  transcriptSalt: Uint8Array = new Uint8Array(32),
  contextInfo = 'QMOOSA-PQC-HYBRID-KEM-V1'
): Uint8Array {
  // Input Keying Material: PQC secret || ECDH secret
  const ikm = Buffer.concat([Buffer.from(pqcSharedSecret), Buffer.from(ecdhSharedSecret)]);

  // HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)
  const prk = createHmac('sha256', Buffer.from(transcriptSalt)).update(ikm).digest();

  // HKDF-Expand: OKM = HMAC-SHA256(PRK, info || 0x01)
  const infoBuffer = Buffer.concat([Buffer.from(contextInfo, 'utf8'), Buffer.from([0x01])]);
  const okm = createHmac('sha256', prk).update(infoBuffer).digest();

  return new Uint8Array(okm.subarray(0, 32));
}

export class MlKemEngine {
  /**
   * ML-KEM Key Generation (NIST FIPS 203 Algorithm 16)
   * Generates encapsulation key (ek) and decapsulation key (dk).
   */
  public generateKeyPair(
    paramName: MlKemParameterName = ML_KEM_768.name,
    options: KeyGenOptions = {}
  ): Readonly<MlKemKeyPair> {
    const params = getMlKemParameters(paramName);
    const noble = getNobleInstance(paramName);

    let seed: Uint8Array | undefined;
    if (options.seed) {
      if (options.seed.length !== 64) {
        throw new Error('INVALID_SEED_LENGTH: ML-KEM key generation seed (d || z) must be exactly 64 bytes');
      }
      seed = options.seed;
    } else {
      seed = new Uint8Array(randomBytes(64));
    }

    const { publicKey, secretKey } = noble.keygen(seed);

    if (!validateEncapsulationKey(publicKey, params) || !validateDecapsulationKey(secretKey, params)) {
      throw new Error('INTERNAL_KEY_VALIDATION_FAILURE: Output key lengths do not match FIPS 203 standard');
    }

    return Object.freeze({
      encapsulationKey: new Uint8Array(publicKey),
      decapsulationKey: new Uint8Array(secretKey),
      parameterSet: paramName
    });
  }

  /**
   * ML-KEM Encapsulation (NIST FIPS 203 Algorithm 17)
   * Encapsulates a shared secret using peer encapsulation key (ek).
   */
  public encapsulate(
    ek: Uint8Array,
    paramName: MlKemParameterName = ML_KEM_768.name,
    options: EncapsOptions = {}
  ): Readonly<MlKemEncapsulationResult> {
    const params = getMlKemParameters(paramName);
    if (!validateEncapsulationKey(ek, params)) {
      throw new Error(`INVALID_ENCAPSULATION_KEY: Length mismatch for parameter set ${paramName} (expected ${params.encapsulationKeyBytes} bytes)`);
    }

    const noble = getNobleInstance(paramName);

    let seed: Uint8Array | undefined;
    if (options.seed) {
      if (options.seed.length !== 32) {
        throw new Error('INVALID_MESSAGE_SEED_LENGTH: ML-KEM encapsulation seed (m) must be exactly 32 bytes');
      }
      seed = options.seed;
    } else {
      seed = new Uint8Array(randomBytes(32));
    }

    const { cipherText, sharedSecret } = noble.encapsulate(ek, seed);

    if (!validateCiphertext(cipherText, params)) {
      throw new Error('INTERNAL_CIPHERTEXT_VALIDATION_FAILURE: Ciphertext length mismatch');
    }

    return Object.freeze({
      ciphertext: new Uint8Array(cipherText),
      sharedSecret: new Uint8Array(sharedSecret),
      parameterSet: paramName
    });
  }

  /**
   * ML-KEM Decapsulation (NIST FIPS 203 Algorithm 18)
   * Decapsulates ciphertext using decapsulation key (dk).
   * Implements Fujisaki-Okamoto implicit rejection: corrupted or tampered ciphertexts
   * deterministically return a pseudorandom key derived from dk's rejection seed z,
   * without throwing exceptions or leaking decapsulation status.
   */
  public decapsulate(
    dk: Uint8Array,
    ciphertext: Uint8Array,
    paramName: MlKemParameterName = ML_KEM_768.name
  ): Uint8Array {
    const params = getMlKemParameters(paramName);
    if (!validateDecapsulationKey(dk, params)) {
      throw new Error(`INVALID_DECAPSULATION_KEY: Length mismatch for parameter set ${paramName} (expected ${params.decapsulationKeyBytes} bytes)`);
    }
    if (!validateCiphertext(ciphertext, params)) {
      throw new Error(`INVALID_CIPHERTEXT: Length mismatch for parameter set ${paramName} (expected ${params.ciphertextBytes} bytes)`);
    }

    const noble = getNobleInstance(paramName);
    const sharedSecret = noble.decapsulate(ciphertext, dk);
    return new Uint8Array(sharedSecret);
  }

  /**
   * Generates a hybrid keypair combining post-quantum ML-KEM and classical X25519 (ECDH)
   */
  public generateHybridKeyPair(paramName: MlKemParameterName = ML_KEM_768.name): Readonly<HybridKemKeyPair> {
    const pqcKeyPair = this.generateKeyPair(paramName);

    const { publicKey, privateKey } = generateKeyPairSync('x25519', {
      publicKeyEncoding: { type: 'spki', format: 'der' },
      privateKeyEncoding: { type: 'pkcs8', format: 'der' }
    });

    const rawPub = publicKey.subarray(publicKey.length - 32);
    const rawPriv = privateKey.subarray(privateKey.length - 32);

    return Object.freeze({
      pqcKeyPair,
      ecdhPublicKey: new Uint8Array(rawPub),
      ecdhPrivateKey: new Uint8Array(rawPriv)
    });
  }

  /**
   * Encapsulates a hybrid secret combining post-quantum ML-KEM and classical X25519
   * with transcript binding over peer public keys.
   */
  public encapsulateHybrid(
    hybridPublicKey: { pqcEk: Uint8Array; ecdhPublicKey: Uint8Array },
    paramName: MlKemParameterName = ML_KEM_768.name
  ): Readonly<HybridKemEncapsulationResult> {
    const { pqcEk, ecdhPublicKey } = hybridPublicKey;

    // 1. Post-Quantum encapsulation
    const pqcRes = this.encapsulate(pqcEk, paramName);

    // 2. Ephemeral classical X25519 generation
    const { publicKey: ephPubDer, privateKey: ephPrivDer } = generateKeyPairSync('x25519', {
      publicKeyEncoding: { type: 'spki', format: 'der' },
      privateKeyEncoding: { type: 'pkcs8', format: 'der' }
    });
    const ephPub = ephPubDer.subarray(ephPubDer.length - 32);

    // 3. Classical ECDH computation
    const bobPubSpki = Buffer.concat([
      Buffer.from('302a300506032b656e032100', 'hex'),
      Buffer.from(ecdhPublicKey)
    ]);
    const classicalSecret = diffieHellman({
      privateKey: createPrivateKey({ key: ephPrivDer, format: 'der', type: 'pkcs8' }),
      publicKey: createPublicKey({ key: bobPubSpki, format: 'der', type: 'spki' })
    });

    // 4. Transcript salt binds peer public keys to eliminate key-compromise impersonation
    const transcriptSalt = Buffer.concat([
      Buffer.from(pqcEk.subarray(0, 32)),
      Buffer.from(ecdhPublicKey)
    ]);

    // 5. Derive combined shared secret via HKDF-SHA256
    const combinedSharedSecret = deriveHybridSharedSecret(
      pqcRes.sharedSecret,
      new Uint8Array(classicalSecret),
      new Uint8Array(transcriptSalt),
      `QMOOSA-PQC-HYBRID-KEM:${paramName}`
    );

    return Object.freeze({
      pqcCiphertext: pqcRes.ciphertext,
      ecdhEphemeralPublicKey: new Uint8Array(ephPub),
      combinedSharedSecret,
      parameterSet: paramName
    });
  }

  /**
   * Decapsulates a hybrid secret using post-quantum ML-KEM and classical X25519
   * with transcript binding verification.
   */
  public decapsulateHybrid(
    hybridPrivateKey: { pqcDk: Uint8Array; ecdhPrivateKey: Uint8Array; pqcEk?: Uint8Array; ecdhPublicKey?: Uint8Array },
    hybridCiphertext: { pqcCiphertext: Uint8Array; ecdhEphemeralPublicKey: Uint8Array },
    paramName: MlKemParameterName = ML_KEM_768.name
  ): Uint8Array {
    const { pqcDk, ecdhPrivateKey } = hybridPrivateKey;
    const { pqcCiphertext, ecdhEphemeralPublicKey } = hybridCiphertext;

    // 1. Post-Quantum decapsulation (with FO implicit rejection)
    const pqcSecret = this.decapsulate(pqcDk, pqcCiphertext, paramName);

    // 2. Classical ECDH computation
    const bobPrivPkcs8 = Buffer.concat([
      Buffer.from('302e020100300506032b656e04220420', 'hex'),
      Buffer.from(ecdhPrivateKey)
    ]);
    const alicePubSpki = Buffer.concat([
      Buffer.from('302a300506032b656e032100', 'hex'),
      Buffer.from(ecdhEphemeralPublicKey)
    ]);
    const classicalSecret = diffieHellman({
      privateKey: createPrivateKey({ key: bobPrivPkcs8, format: 'der', type: 'pkcs8' }),
      publicKey: createPublicKey({ key: alicePubSpki, format: 'der', type: 'spki' })
    });

    // 3. Transcript salt extraction:
    // In FIPS 203 dk = dk_pke || ek || H(ek) || z; ek is embedded at offset 384*k
    const params = getMlKemParameters(paramName);
    const ekOffset = 384 * params.k;
    const ekEmbedded = pqcDk.subarray(ekOffset, ekOffset + 32);

    // Derive public key from private key if not explicitly passed
    let ecdhPub = hybridPrivateKey.ecdhPublicKey;
    if (!ecdhPub) {
      const pubDer = createPublicKey(createPrivateKey({ key: bobPrivPkcs8, format: 'der', type: 'pkcs8' })).export({ type: 'spki', format: 'der' });
      ecdhPub = new Uint8Array(pubDer.subarray(pubDer.length - 32));
    }

    const transcriptSalt = Buffer.concat([
      Buffer.from(ekEmbedded),
      Buffer.from(ecdhPub)
    ]);

    // 4. Combine secrets via HKDF-SHA256
    return deriveHybridSharedSecret(
      pqcSecret,
      new Uint8Array(classicalSecret),
      new Uint8Array(transcriptSalt),
      `QMOOSA-PQC-HYBRID-KEM:${paramName}`
    );
  }
}
