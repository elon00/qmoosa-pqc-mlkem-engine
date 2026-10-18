import { randomBytes, diffieHellman, createHmac, generateKeyPairSync, createPrivateKey, createPublicKey } from 'node:crypto';
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
import {
  type Poly,
  ntt,
  invNtt,
  multiplyNtt,
  polyAdd,
  polySub,
  prfCBD,
  sampleUniformPoly,
  byteEncode12,
  byteDecode12,
  compressPoly,
  decompressPoly,
  encodeMessage,
  decodeMessage,
  H,
  G,
  J
} from './fips203.js';

export interface KeyGenOptions {
  readonly seedD?: Uint8Array; // 32 bytes entropy seed d
  readonly seedZ?: Uint8Array; // 32 bytes rejection seed z
}

export interface EncapsOptions {
  readonly messageSeed?: Uint8Array; // 32 bytes message seed m (for deterministic KAT vectors)
}

/**
 * Derives a combined 32-byte shared secret from post-quantum and classical ECDH shared secrets
 * using HKDF-Extract-and-Expand with SHA-256.
 */
export function deriveHybridSharedSecret(
  pqcSharedSecret: Uint8Array,
  ecdhSharedSecret: Uint8Array,
  contextInfo = 'QMOOSA-PQC-HYBRID-KEM-V1'
): Uint8Array {
  // Combine PQC secret and classical ECDH secret
  const ikm = Buffer.concat([Buffer.from(pqcSharedSecret), Buffer.from(ecdhSharedSecret)]);
  const salt = Buffer.alloc(32, 0); // Standard fixed salt for KEM combiner

  // HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
  const prk = createHmac('sha256', salt).update(ikm).digest();

  // HKDF-Expand: OKM = HMAC-Hash(PRK, info || 0x01)
  const infoBuffer = Buffer.concat([Buffer.from(contextInfo, 'utf8'), Buffer.from([0x01])]);
  const okm = createHmac('sha256', prk).update(infoBuffer).digest();

  return new Uint8Array(okm.subarray(0, 32));
}

export class MlKemEngine {
  /**
   * Internal K-PKE Key Generation (FIPS 203 Algorithm 13)
   */
  private pkeKeyGen(params: MlKemParameters, d: Uint8Array): {
    ekPke: Uint8Array;
    dkPke: Uint8Array;
    rho: Uint8Array;
    tHat: Int16Array[];
    sHat: Int16Array[];
  } {
    const k = params.k;
    const { K: rho, r: sigma } = G(new Uint8Array([...d, k]));

    // Generate matrix A_hat in NTT domain
    const aHat: Int16Array[][] = [];
    for (let i = 0; i < k; i++) {
      aHat[i] = [];
      for (let j = 0; j < k; j++) {
        aHat[i][j] = sampleUniformPoly(rho, i, j);
      }
    }

    // Sample secret s and error e from centered binomial distribution
    let nonce = 0;
    const s: Int16Array[] = [];
    const sHat: Int16Array[] = [];
    for (let i = 0; i < k; i++) {
      s[i] = prfCBD(sigma, nonce++, params.eta1);
      sHat[i] = ntt(s[i]);
    }

    const e: Int16Array[] = [];
    const eHat: Int16Array[] = [];
    for (let i = 0; i < k; i++) {
      e[i] = prfCBD(sigma, nonce++, params.eta1);
      eHat[i] = ntt(e[i]);
    }

    // t_hat = A_hat * s_hat + e_hat
    const tHat: Poly[] = [];
    for (let i = 0; i < k; i++) {
      let sum: Poly = new Int16Array(256);
      for (let j = 0; j < k; j++) {
        sum = polyAdd(sum, multiplyNtt(aHat[i][j], sHat[j]));
      }
      tHat[i] = polyAdd(sum, eHat[i]);
    }

    // ByteEncode_12(t_hat) || rho
    const ekParts: Uint8Array[] = [];
    for (let i = 0; i < k; i++) {
      ekParts.push(byteEncode12(tHat[i]));
    }
    const ekPke = new Uint8Array(Buffer.concat([...ekParts.map(p => Buffer.from(p)), Buffer.from(rho)]));

    // ByteEncode_12(s_hat)
    const dkParts: Uint8Array[] = [];
    for (let i = 0; i < k; i++) {
      dkParts.push(byteEncode12(sHat[i]));
    }
    const dkPke = new Uint8Array(Buffer.concat(dkParts.map(p => Buffer.from(p))));

    return { ekPke, dkPke, rho, tHat, sHat };
  }

  /**
   * Internal K-PKE Encrypt (FIPS 203 Algorithm 14)
   */
  private pkeEncrypt(params: MlKemParameters, ekPke: Uint8Array, m: Uint8Array, r: Uint8Array): Uint8Array {
    const k = params.k;
    const rho = ekPke.subarray(384 * k, 384 * k + 32);

    // Decode t_hat
    const tHat: Int16Array[] = [];
    for (let i = 0; i < k; i++) {
      tHat[i] = byteDecode12(ekPke, i * 384);
    }

    // Generate matrix A_hat from rho
    const aHat: Int16Array[][] = [];
    for (let i = 0; i < k; i++) {
      aHat[i] = [];
      for (let j = 0; j < k; j++) {
        aHat[i][j] = sampleUniformPoly(rho, i, j);
      }
    }

    // Sample y, e1, e2
    let nonce = 0;
    const y: Int16Array[] = [];
    const yHat: Int16Array[] = [];
    for (let i = 0; i < k; i++) {
      y[i] = prfCBD(r, nonce++, params.eta1);
      yHat[i] = ntt(y[i]);
    }

    const e1: Int16Array[] = [];
    for (let i = 0; i < k; i++) {
      e1[i] = prfCBD(r, nonce++, params.eta2);
    }
    const e2 = prfCBD(r, nonce++, params.eta2);

    // u = invNTT(A_hat^T * y_hat) + e1
    const uParts: Uint8Array[] = [];
    for (let i = 0; i < k; i++) {
      let sum: Poly = new Int16Array(256);
      for (let j = 0; j < k; j++) {
        // A_hat transpose: A_hat[j][i]
        sum = polyAdd(sum, multiplyNtt(aHat[j][i], yHat[j]));
      }
      const uPoly = polyAdd(invNtt(sum), e1[i]);
      uParts.push(compressPoly(uPoly, params.du));
    }

    // v = invNTT(t_hat^T * y_hat) + e2 + mu
    let vSum: Poly = new Int16Array(256);
    for (let i = 0; i < k; i++) {
      vSum = polyAdd(vSum, multiplyNtt(tHat[i], yHat[i]));
    }
    const mu = encodeMessage(m);
    const vPoly = polyAdd(polyAdd(invNtt(vSum), e2), mu);
    const vPart = compressPoly(vPoly, params.dv);

    const ciphertext = new Uint8Array(Buffer.concat([...uParts.map(p => Buffer.from(p)), Buffer.from(vPart)]));
    return ciphertext;
  }

  /**
   * Internal K-PKE Decrypt (FIPS 203 Algorithm 15)
   */
  private pkeDecrypt(params: MlKemParameters, dkPke: Uint8Array, c: Uint8Array): Uint8Array {
    const k = params.k;
    const duBytes = (256 * params.du) / 8;

    // Decode u
    const uPolys: Int16Array[] = [];
    for (let i = 0; i < k; i++) {
      uPolys[i] = decompressPoly(c, params.du, i * duBytes);
    }

    // Decode v
    const vOffset = k * duBytes;
    const vPoly = decompressPoly(c, params.dv, vOffset);

    // Decode s_hat
    const sHat: Int16Array[] = [];
    for (let i = 0; i < k; i++) {
      sHat[i] = byteDecode12(dkPke, i * 384);
    }

    // w = v - invNTT(s_hat^T * NTT(u))
    let sUSum: Poly = new Int16Array(256);
    for (let i = 0; i < k; i++) {
      sUSum = polyAdd(sUSum, multiplyNtt(sHat[i], ntt(uPolys[i])));
    }
    const w = polySub(vPoly, invNtt(sUSum));
    return decodeMessage(w);
  }

  /**
   * ML-KEM Key Generation (FIPS 203 Algorithm 16)
   */
  public generateKeyPair(
    paramName: MlKemParameterName = ML_KEM_768.name,
    options: KeyGenOptions = {}
  ): Readonly<MlKemKeyPair> {
    const params = getMlKemParameters(paramName);
    const d = options.seedD ? new Uint8Array(options.seedD) : randomBytes(32);
    const z = options.seedZ ? new Uint8Array(options.seedZ) : randomBytes(32);

    if (d.length !== 32 || z.length !== 32) {
      throw new Error('INVALID_SEED_LENGTH: Seeds d and z must each be 32 bytes');
    }

    const { ekPke, dkPke } = this.pkeKeyGen(params, d);
    const ek = ekPke;
    const hEk = H(ek);

    // dk = dkPke || ek || H(ek) || z
    const dk = new Uint8Array(
      Buffer.concat([
        Buffer.from(dkPke),
        Buffer.from(ek),
        Buffer.from(hEk),
        Buffer.from(z)
      ])
    );

    if (!validateEncapsulationKey(ek, params) || !validateDecapsulationKey(dk, params)) {
      throw new Error('INTERNAL_KEY_VALIDATION_FAILURE');
    }

    return Object.freeze({
      encapsulationKey: ek,
      decapsulationKey: dk,
      parameterSet: paramName
    });
  }

  /**
   * ML-KEM Encapsulation (FIPS 203 Algorithm 17)
   */
  public encapsulate(
    ek: Uint8Array,
    paramName: MlKemParameterName = ML_KEM_768.name,
    options: EncapsOptions = {}
  ): Readonly<MlKemEncapsulationResult> {
    const params = getMlKemParameters(paramName);
    if (!validateEncapsulationKey(ek, params)) {
      throw new Error('INVALID_ENCAPSULATION_KEY: Length mismatch for parameter set');
    }

    const m = options.messageSeed ? new Uint8Array(options.messageSeed) : randomBytes(32);
    if (m.length !== 32) {
      throw new Error('INVALID_MESSAGE_SEED_LENGTH: Message seed m must be 32 bytes');
    }

    // (K, r) = G(m || H(ek))
    const hEk = H(ek);
    const { K, r } = G(new Uint8Array([...m, ...hEk]));

    // c = K-PKE.Encrypt(ek, m, r)
    const c = this.pkeEncrypt(params, ek, m, r);

    if (!validateCiphertext(c, params)) {
      throw new Error('INTERNAL_CIPHERTEXT_VALIDATION_FAILURE');
    }

    return Object.freeze({
      ciphertext: c,
      sharedSecret: new Uint8Array(K),
      parameterSet: paramName
    });
  }

  /**
   * ML-KEM Decapsulation with Fujisaki-Okamoto Implicit Rejection (FIPS 203 Algorithm 18)
   */
  public decapsulate(
    dk: Uint8Array,
    ciphertext: Uint8Array,
    paramName: MlKemParameterName = ML_KEM_768.name
  ): Uint8Array {
    const params = getMlKemParameters(paramName);
    if (!validateDecapsulationKey(dk, params)) {
      throw new Error('INVALID_DECAPSULATION_KEY: Length mismatch for parameter set');
    }
    if (!validateCiphertext(ciphertext, params)) {
      throw new Error('INVALID_CIPHERTEXT: Length mismatch for parameter set');
    }

    const k = params.k;
    const dkPkeLen = 384 * k;
    const ekLen = params.encapsulationKeyBytes;

    const dkPke = dk.subarray(0, dkPkeLen);
    const ek = dk.subarray(dkPkeLen, dkPkeLen + ekLen);
    const hEk = dk.subarray(dkPkeLen + ekLen, dkPkeLen + ekLen + 32);
    const z = dk.subarray(dkPkeLen + ekLen + 32, dkPkeLen + ekLen + 64);

    // Decrypt to get candidate message m'
    const mPrime = this.pkeDecrypt(params, dkPke, ciphertext);

    // Re-encrypt: (K', r') = G(m' || hEk)
    const { K: kPrime, r: rPrime } = G(new Uint8Array([...mPrime, ...hEk]));
    const cPrime = this.pkeEncrypt(params, ek, mPrime, rPrime);

    // Pseudorandom reject key: K_rej = J(z || c)
    const kRej = J(new Uint8Array([...z, ...ciphertext]), 32);

    // Constant-time check: if c == c' return K', else return K_rej (Implicit Rejection)
    const isValid = constantTimeEqual(ciphertext, cPrime);
    const finalSharedSecret = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      // Branch-free select
      finalSharedSecret[i] = isValid ? kPrime[i] : kRej[i];
    }

    return finalSharedSecret;
  }

  /**
   * Generate Hybrid KeyPair (ML-KEM-768 + X25519)
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
   * Encapsulate Hybrid Key (ML-KEM + X25519)
   */
  public encapsulateHybrid(
    hybridPublicKey: { pqcEk: Uint8Array; ecdhPublicKey: Uint8Array },
    paramName: MlKemParameterName = ML_KEM_768.name
  ): Readonly<HybridKemEncapsulationResult> {
    const { pqcEk, ecdhPublicKey } = hybridPublicKey;

    // 1. PQC encapsulation
    const pqcRes = this.encapsulate(pqcEk, paramName);

    // 2. Generate ephemeral X25519 keypair
    const { publicKey: ephPubDer, privateKey: ephPrivDer } = generateKeyPairSync('x25519', {
      publicKeyEncoding: { type: 'spki', format: 'der' },
      privateKeyEncoding: { type: 'pkcs8', format: 'der' }
    });
    const ephPub = ephPubDer.subarray(ephPubDer.length - 32);

    // 3. Classical ECDH shared secret
    const bobPubSpki = Buffer.concat([
      Buffer.from('302a300506032b656e032100', 'hex'),
      Buffer.from(ecdhPublicKey)
    ]);
    const classicalSecret = diffieHellman({
      privateKey: createPrivateKey({ key: ephPrivDer, format: 'der', type: 'pkcs8' }),
      publicKey: createPublicKey({ key: bobPubSpki, format: 'der', type: 'spki' })
    });

    // 4. Combine secrets via HKDF-SHA256
    const combinedSharedSecret = deriveHybridSharedSecret(
      pqcRes.sharedSecret,
      new Uint8Array(classicalSecret)
    );

    return Object.freeze({
      pqcCiphertext: pqcRes.ciphertext,
      ecdhEphemeralPublicKey: new Uint8Array(ephPub),
      combinedSharedSecret,
      parameterSet: paramName
    });
  }

  /**
   * Decapsulate Hybrid Key (ML-KEM + X25519)
   */
  public decapsulateHybrid(
    hybridPrivateKey: { pqcDk: Uint8Array; ecdhPrivateKey: Uint8Array },
    hybridCiphertext: { pqcCiphertext: Uint8Array; ecdhEphemeralPublicKey: Uint8Array },
    paramName: MlKemParameterName = ML_KEM_768.name
  ): Uint8Array {
    const { pqcDk, ecdhPrivateKey } = hybridPrivateKey;
    const { pqcCiphertext, ecdhEphemeralPublicKey } = hybridCiphertext;

    // 1. PQC decapsulation (with FO implicit rejection)
    const pqcSecret = this.decapsulate(pqcDk, pqcCiphertext, paramName);

    // 2. Classical ECDH decapsulation
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

    // 3. Combine secrets via HKDF-SHA256
    return deriveHybridSharedSecret(
      pqcSecret,
      new Uint8Array(classicalSecret)
    );
  }
}
