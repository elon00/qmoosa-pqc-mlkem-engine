/**
 * EDUCATIONAL & ALGORITHMIC REFERENCE ONLY — NOT FOR PRODUCTION ENCRYPTED TRAFFIC
 * NIST FIPS 203 Module-Lattice Polynomial & NTT Mathematics Reference
 * Production applications MUST use established, maintained implementations (e.g. @noble/post-quantum).
 */

import { createHash } from 'node:crypto';
import {
  ML_KEM_MODULUS as Q,
  ML_KEM_PRIMITIVE_ROOT as ZETA,
  constantTimeEqual,
  type MlKemParameters
} from '@qmoosa/pqc-mlkem-protocol';

export type Poly = Int16Array<any>;

export function mod(a: number): number {
  const r = a % Q;
  return r < 0 ? r + Q : r;
}

export function powMod(base: number, exp: number): number {
  let res = 1;
  base = mod(base);
  while (exp > 0) {
    if (exp % 2 === 1) res = mod(res * base);
    base = mod(base * base);
    exp = Math.floor(exp / 2);
  }
  return res;
}

export function bitRev7(n: number): number {
  let r = 0;
  for (let i = 0; i < 7; i++) {
    r = (r << 1) | ((n >> i) & 1);
  }
  return r;
}

// Precomputed table of zetas for NTT
const zetas = new Int16Array(128);
for (let i = 0; i < 128; i++) {
  zetas[i] = powMod(ZETA, bitRev7(i));
}

export function ntt(f: Int16Array): Int16Array {
  const a = new Int16Array(f);
  let len = 128;
  let k = 1;
  while (len >= 2) {
    for (let start = 0; start < 256; start += 2 * len) {
      const zeta = zetas[k++];
      for (let j = start; j < start + len; j++) {
        const t = mod(zeta * a[j + len]);
        a[j + len] = mod(a[j] - t);
        a[j] = mod(a[j] + t);
      }
    }
    len = Math.floor(len / 2);
  }
  return a;
}

export function invNtt(aIn: Int16Array): Int16Array {
  const a = new Int16Array(aIn);
  let len = 2;
  let k = 127;
  while (len <= 128) {
    for (let start = 0; start < 256; start += 2 * len) {
      const zeta = zetas[k--];
      for (let j = start; j < start + len; j++) {
        const t = a[j];
        a[j] = mod(t + a[j + len]);
        a[j + len] = mod(zeta * (a[j + len] - t));
      }
    }
    len *= 2;
  }
  // Multiply by 128^-1 mod 3329 = 3303
  for (let j = 0; j < 256; j++) {
    a[j] = mod(a[j] * 3303);
  }
  return a;
}

export function baseMul(a0: number, a1: number, b0: number, b1: number, gamma: number): [number, number] {
  return [mod(a0 * b0 + a1 * b1 * gamma), mod(a0 * b1 + a1 * b0)];
}

export function multiplyNtt(a: Int16Array, b: Int16Array): Int16Array {
  const c = new Int16Array(256);
  for (let i = 0; i < 128; i++) {
    const gamma = powMod(ZETA, 2 * bitRev7(i) + 1);
    const [c0, c1] = baseMul(a[2 * i], a[2 * i + 1], b[2 * i], b[2 * i + 1], gamma);
    c[2 * i] = c0;
    c[2 * i + 1] = c1;
  }
  return c;
}

export function polyAdd(a: Int16Array, b: Int16Array): Int16Array {
  const c = new Int16Array(256);
  for (let i = 0; i < 256; i++) c[i] = mod(a[i] + b[i]);
  return c;
}

export function polySub(a: Int16Array, b: Int16Array): Int16Array {
  const c = new Int16Array(256);
  for (let i = 0; i < 256; i++) c[i] = mod(a[i] - b[i]);
  return c;
}

/**
 * Centered Binomial Distribution sampling (FIPS 203 Algorithm 7 & 8)
 */
export function samplePolyCBD(bytes: Uint8Array, eta: number): Int16Array {
  const poly = new Int16Array(256);
  if (eta === 2) {
    for (let i = 0; i < 256; i++) {
      const byte = bytes[Math.floor(i / 2)];
      const chunk = (i % 2 === 0) ? (byte & 0x0f) : (byte >> 4);
      const a = (chunk & 1) + ((chunk >> 1) & 1);
      const b = ((chunk >> 2) & 1) + ((chunk >> 3) & 1);
      poly[i] = mod(a - b);
    }
  } else if (eta === 3) {
    let bitOffset = 0;
    for (let i = 0; i < 256; i++) {
      const byteIdx = Math.floor(bitOffset / 8);
      const subOffset = bitOffset % 8;
      // Read 6 bits
      let val = bytes[byteIdx] >> subOffset;
      if (subOffset > 2 && byteIdx + 1 < bytes.length) {
        val |= bytes[byteIdx + 1] << (8 - subOffset);
      }
      val &= 0x3f;
      const a = (val & 1) + ((val >> 1) & 1) + ((val >> 2) & 1);
      const b = ((val >> 3) & 1) + ((val >> 4) & 1) + ((val >> 5) & 1);
      poly[i] = mod(a - b);
      bitOffset += 6;
    }
  } else {
    throw new Error(`UNSUPPORTED_ETA: ${eta}`);
  }
  return poly;
}

/**
 * Deterministic PRF sampling for CBD
 */
export function prfCBD(seed: Uint8Array, nonce: number, eta: number): Int16Array {
  const length = 64 * eta;
  const shake = createHash('shake256', { outputLength: length });
  shake.update(seed);
  shake.update(Uint8Array.from([nonce]));
  const bytes = shake.digest();
  return samplePolyCBD(bytes, eta);
}

/**
 * Rejection sampling of uniform polynomials in NTT domain using SHAKE-128 (FIPS 203 Algorithm 6)
 */
export function sampleUniformPoly(rho: Uint8Array, i: number, j: number): Int16Array {
  const shake = createHash('shake128');
  shake.update(rho);
  shake.update(Uint8Array.from([j, i]));
  const poly = new Int16Array(256);
  let count = 0;
  let counter = 0;
  while (count < 256) {
    const chunkShake = createHash('shake128', { outputLength: 168 });
    chunkShake.update(rho);
    chunkShake.update(Uint8Array.from([j, i, counter++]));
    const buf = chunkShake.digest();
    for (let k = 0; k + 2 < 168 && count < 256; k += 3) {
      const d1 = buf[k] | ((buf[k + 1] & 0x0f) << 8);
      const d2 = (buf[k + 1] >> 4) | (buf[k + 2] << 4);
      if (d1 < Q && count < 256) poly[count++] = d1;
      if (d2 < Q && count < 256) poly[count++] = d2;
    }
  }
  return poly;
}

/**
 * ByteEncode_12: Encodes 256 12-bit polynomial coefficients into 384 bytes
 */
export function byteEncode12(poly: Int16Array): Uint8Array {
  const out = new Uint8Array(384);
  for (let i = 0; i < 128; i++) {
    const t0 = mod(poly[2 * i]);
    const t1 = mod(poly[2 * i + 1]);
    out[3 * i] = t0 & 0xff;
    out[3 * i + 1] = ((t0 >> 8) & 0x0f) | ((t1 & 0x0f) << 4);
    out[3 * i + 2] = (t1 >> 4) & 0xff;
  }
  return out;
}

/**
 * ByteDecode_12: Decodes 384 bytes into 256 12-bit polynomial coefficients
 */
export function byteDecode12(bytes: Uint8Array, offset = 0): Int16Array {
  const poly = new Int16Array(256);
  for (let i = 0; i < 128; i++) {
    const b0 = bytes[offset + 3 * i];
    const b1 = bytes[offset + 3 * i + 1];
    const b2 = bytes[offset + 3 * i + 2];
    poly[2 * i] = b0 | ((b1 & 0x0f) << 8);
    poly[2 * i + 1] = (b1 >> 4) | (b2 << 4);
  }
  return poly;
}

/**
 * Compress and Encode / Decode poly vector for ciphertext
 */
export function compressPoly(poly: Int16Array, d: number): Uint8Array {
  const m = 1 << d;
  const compressed = new Int16Array(256);
  for (let i = 0; i < 256; i++) {
    compressed[i] = Math.round((m / Q) * mod(poly[i])) % m;
  }

  // Pack d bits per coeff
  const totalBits = 256 * d;
  const out = new Uint8Array(totalBits / 8);
  let bitPos = 0;
  for (let i = 0; i < 256; i++) {
    const val = compressed[i];
    for (let b = 0; b < d; b++) {
      const bit = (val >> b) & 1;
      const byteIdx = Math.floor(bitPos / 8);
      const subBit = bitPos % 8;
      out[byteIdx] |= bit << subBit;
      bitPos++;
    }
  }
  return out;
}

export function decompressPoly(bytes: Uint8Array, d: number, offset = 0): Int16Array {
  const m = 1 << d;
  const poly = new Int16Array(256);
  let bitPos = offset * 8;
  for (let i = 0; i < 256; i++) {
    let val = 0;
    for (let b = 0; b < d; b++) {
      const byteIdx = Math.floor(bitPos / 8);
      const subBit = bitPos % 8;
      const bit = (bytes[byteIdx] >> subBit) & 1;
      val |= bit << b;
      bitPos++;
    }
    poly[i] = Math.round((Q / m) * val);
  }
  return poly;
}

/**
 * 1-bit message encoding and decoding
 */
export function encodeMessage(msg: Uint8Array): Int16Array {
  const poly = new Int16Array(256);
  for (let i = 0; i < 32; i++) {
    const byte = msg[i];
    for (let b = 0; b < 8; b++) {
      const bit = (byte >> b) & 1;
      poly[i * 8 + b] = bit ? Math.round(Q / 2) : 0;
    }
  }
  return poly;
}

export function decodeMessage(poly: Int16Array): Uint8Array {
  const msg = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    let byte = 0;
    for (let b = 0; b < 8; b++) {
      const val = mod(poly[i * 8 + b]);
      const bit = (val > Math.round(Q / 4) && val < Math.round(3 * Q / 4)) ? 1 : 0;
      byte |= bit << b;
    }
    msg[i] = byte;
  }
  return msg;
}

/**
 * Hash functions as specified in FIPS 203 Section 4.1
 */
export function H(data: Uint8Array): Uint8Array {
  return createHash('sha3-256').update(data).digest();
}

export function G(data: Uint8Array): { K: Uint8Array; r: Uint8Array } {
  const digest = createHash('sha3-512').update(data).digest();
  return {
    K: digest.subarray(0, 32),
    r: digest.subarray(32, 64)
  };
}

export function J(data: Uint8Array, length = 32): Uint8Array {
  return createHash('shake256', { outputLength: length }).update(data).digest();
}
