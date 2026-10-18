import test from 'node:test';
import assert from 'node:assert/strict';
import {
  MlKemEngine,
  deriveHybridSharedSecret,
  ReferenceLatticeMath
} from '../dist/index.js';
import {
  ML_KEM_512,
  ML_KEM_768,
  ML_KEM_1024,
  constantTimeEqual
} from '@qmoosa/pqc-mlkem-protocol';

test('ML-KEM Engine: Full KEM Round-Trip on ML-KEM-512', () => {
  const engine = new MlKemEngine();
  const alice = engine.generateKeyPair('ML-KEM-512');

  assert.equal(alice.encapsulationKey.length, ML_KEM_512.encapsulationKeyBytes);
  assert.equal(alice.decapsulationKey.length, ML_KEM_512.decapsulationKeyBytes);

  const bob = engine.encapsulate(alice.encapsulationKey, 'ML-KEM-512');
  assert.equal(bob.ciphertext.length, ML_KEM_512.ciphertextBytes);
  assert.equal(bob.sharedSecret.length, 32);

  const aliceSecret = engine.decapsulate(alice.decapsulationKey, bob.ciphertext, 'ML-KEM-512');
  assert.equal(aliceSecret.length, 32);

  assert.ok(constantTimeEqual(aliceSecret, bob.sharedSecret), 'Shared secret must match on valid decapsulation');
});

test('ML-KEM Engine: Full KEM Round-Trip on ML-KEM-768 (NIST Category 3 Primary)', () => {
  const engine = new MlKemEngine();
  const alice = engine.generateKeyPair('ML-KEM-768');

  assert.equal(alice.encapsulationKey.length, ML_KEM_768.encapsulationKeyBytes);
  assert.equal(alice.decapsulationKey.length, ML_KEM_768.decapsulationKeyBytes);

  const bob = engine.encapsulate(alice.encapsulationKey, 'ML-KEM-768');
  assert.equal(bob.ciphertext.length, ML_KEM_768.ciphertextBytes);
  assert.equal(bob.sharedSecret.length, 32);

  const aliceSecret = engine.decapsulate(alice.decapsulationKey, bob.ciphertext, 'ML-KEM-768');
  assert.equal(aliceSecret.length, 32);

  assert.ok(constantTimeEqual(aliceSecret, bob.sharedSecret), 'ML-KEM-768 shared secrets must match exactly');
});

test('ML-KEM Engine: Full KEM Round-Trip on ML-KEM-1024 (NIST Category 5)', () => {
  const engine = new MlKemEngine();
  const alice = engine.generateKeyPair('ML-KEM-1024');

  assert.equal(alice.encapsulationKey.length, ML_KEM_1024.encapsulationKeyBytes);
  assert.equal(alice.decapsulationKey.length, ML_KEM_1024.decapsulationKeyBytes);

  const bob = engine.encapsulate(alice.encapsulationKey, 'ML-KEM-1024');
  assert.equal(bob.ciphertext.length, ML_KEM_1024.ciphertextBytes);
  assert.equal(bob.sharedSecret.length, 32);

  const aliceSecret = engine.decapsulate(alice.decapsulationKey, bob.ciphertext, 'ML-KEM-1024');
  assert.equal(aliceSecret.length, 32);

  assert.ok(constantTimeEqual(aliceSecret, bob.sharedSecret), 'ML-KEM-1024 shared secrets must match exactly');
});

test('ML-KEM Engine: Fujisaki-Okamoto Implicit Rejection on Corrupted Ciphertext', () => {
  const engine = new MlKemEngine();
  const alice = engine.generateKeyPair('ML-KEM-768');
  const bob = engine.encapsulate(alice.encapsulationKey, 'ML-KEM-768');

  // Corrupt 1 byte of ciphertext
  const tamperedCiphertext = new Uint8Array(bob.ciphertext);
  tamperedCiphertext[42] ^= 0x5a;

  // Decapsulation MUST NOT throw an exception or leak failure status
  const rejectSecret1 = engine.decapsulate(alice.decapsulationKey, tamperedCiphertext, 'ML-KEM-768');

  assert.equal(rejectSecret1.length, 32);
  // Must NOT equal the genuine shared secret
  assert.ok(!constantTimeEqual(rejectSecret1, bob.sharedSecret), 'Implicit rejection must not match genuine secret');

  // Decapsulating identical tampered ciphertext must deterministically yield identical reject secret
  const rejectSecret2 = engine.decapsulate(alice.decapsulationKey, tamperedCiphertext, 'ML-KEM-768');
  assert.ok(constantTimeEqual(rejectSecret1, rejectSecret2), 'Implicit rejection key must be deterministic');
});

test('ML-KEM Engine: Hybrid Post-Quantum KEM Round-Trip with Transcript Binding (ML-KEM-768 + X25519)', () => {
  const engine = new MlKemEngine();
  const alice = engine.generateHybridKeyPair('ML-KEM-768');

  assert.equal(alice.pqcKeyPair.encapsulationKey.length, ML_KEM_768.encapsulationKeyBytes);
  assert.equal(alice.ecdhPublicKey.length, 32);
  assert.equal(alice.ecdhPrivateKey.length, 32);

  const bob = engine.encapsulateHybrid({
    pqcEk: alice.pqcKeyPair.encapsulationKey,
    ecdhPublicKey: alice.ecdhPublicKey
  }, 'ML-KEM-768');

  assert.equal(bob.pqcCiphertext.length, ML_KEM_768.ciphertextBytes);
  assert.equal(bob.ecdhEphemeralPublicKey.length, 32);
  assert.equal(bob.combinedSharedSecret.length, 32);

  const aliceCombinedSecret = engine.decapsulateHybrid({
    pqcDk: alice.pqcKeyPair.decapsulationKey,
    ecdhPrivateKey: alice.ecdhPrivateKey,
    pqcEk: alice.pqcKeyPair.encapsulationKey,
    ecdhPublicKey: alice.ecdhPublicKey
  }, {
    pqcCiphertext: bob.pqcCiphertext,
    ecdhEphemeralPublicKey: bob.ecdhEphemeralPublicKey
  }, 'ML-KEM-768');

  assert.equal(aliceCombinedSecret.length, 32);
  assert.ok(constantTimeEqual(aliceCombinedSecret, bob.combinedSharedSecret), 'Hybrid combined secrets must match');
});

test('ML-KEM Engine: Deterministic Seeding & FIPS 203 Known Answer Test (KAT) Reproducibility', () => {
  const engine = new MlKemEngine();
  // 64-byte seed (d || z) per FIPS 203 Algorithm 16
  const seed = new Uint8Array(64).fill(0x42);

  const keypair1 = engine.generateKeyPair('ML-KEM-768', { seed });
  const keypair2 = engine.generateKeyPair('ML-KEM-768', { seed });

  assert.ok(constantTimeEqual(keypair1.encapsulationKey, keypair2.encapsulationKey));
  assert.ok(constantTimeEqual(keypair1.decapsulationKey, keypair2.decapsulationKey));

  // 32-byte message seed m per FIPS 203 Algorithm 17
  const encapsSeed = new Uint8Array(32).fill(0x7e);
  const encaps1 = engine.encapsulate(keypair1.encapsulationKey, 'ML-KEM-768', { seed: encapsSeed });
  const encaps2 = engine.encapsulate(keypair2.encapsulationKey, 'ML-KEM-768', { seed: encapsSeed });

  assert.ok(constantTimeEqual(encaps1.ciphertext, encaps2.ciphertext));
  assert.ok(constantTimeEqual(encaps1.sharedSecret, encaps2.sharedSecret));
});

test('ML-KEM Engine: Defensive Input Validation Rejection', () => {
  const engine = new MlKemEngine();

  // Invalid seed length (must be 64 bytes)
  assert.throws(
    () => engine.generateKeyPair('ML-KEM-768', { seed: new Uint8Array(32) }),
    /INVALID_SEED_LENGTH/
  );

  // Invalid encapsulation key length
  assert.throws(
    () => engine.encapsulate(new Uint8Array(100), 'ML-KEM-768'),
    /INVALID_ENCAPSULATION_KEY/
  );

  // Invalid ciphertext length
  assert.throws(
    () => engine.decapsulate(new Uint8Array(2400), new Uint8Array(500), 'ML-KEM-768'),
    /INVALID_CIPHERTEXT/
  );
});

test('ML-KEM Engine: Reference Lattice Math Module Export & Invariant Verification', () => {
  assert.ok(ReferenceLatticeMath);
  assert.equal(typeof ReferenceLatticeMath.ntt, 'function');
  assert.equal(typeof ReferenceLatticeMath.invNtt, 'function');
  assert.equal(typeof ReferenceLatticeMath.polyAdd, 'function');
  assert.equal(typeof ReferenceLatticeMath.polySub, 'function');
});
