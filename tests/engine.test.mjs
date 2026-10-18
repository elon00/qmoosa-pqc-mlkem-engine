import test from 'node:test';
import assert from 'node:assert/strict';
import {
  MlKemEngine,
  deriveHybridSharedSecret
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

test('ML-KEM Engine: Full KEM Round-Trip on ML-KEM-768 (Primary Standard)', () => {
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

test('ML-KEM Engine: Full KEM Round-Trip on ML-KEM-1024 (Category 5 Security)', () => {
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

test('ML-KEM Engine: Hybrid Post-Quantum KEM Round-Trip (ML-KEM-768 + X25519)', () => {
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
    ecdhPrivateKey: alice.ecdhPrivateKey
  }, {
    pqcCiphertext: bob.pqcCiphertext,
    ecdhEphemeralPublicKey: bob.ecdhEphemeralPublicKey
  }, 'ML-KEM-768');

  assert.equal(aliceCombinedSecret.length, 32);
  assert.ok(constantTimeEqual(aliceCombinedSecret, bob.combinedSharedSecret), 'Hybrid combined secrets must match');
});

test('ML-KEM Engine: Deterministic Seeding & Reproducibility (KAT Readiness)', () => {
  const engine = new MlKemEngine();
  const seedD = new Uint8Array(32).fill(0x42);
  const seedZ = new Uint8Array(32).fill(0x7e);

  const keypair1 = engine.generateKeyPair('ML-KEM-768', { seedD, seedZ });
  const keypair2 = engine.generateKeyPair('ML-KEM-768', { seedD, seedZ });

  assert.ok(constantTimeEqual(keypair1.encapsulationKey, keypair2.encapsulationKey));
  assert.ok(constantTimeEqual(keypair1.decapsulationKey, keypair2.decapsulationKey));

  const messageSeed = new Uint8Array(32).fill(0x33);
  const encaps1 = engine.encapsulate(keypair1.encapsulationKey, 'ML-KEM-768', { messageSeed });
  const encaps2 = engine.encapsulate(keypair2.encapsulationKey, 'ML-KEM-768', { messageSeed });

  assert.ok(constantTimeEqual(encaps1.ciphertext, encaps2.ciphertext));
  assert.ok(constantTimeEqual(encaps1.sharedSecret, encaps2.sharedSecret));
});

test('ML-KEM Engine: Defensive Input Validation Rejection', () => {
  const engine = new MlKemEngine();

  // Invalid seed length
  assert.throws(
    () => engine.generateKeyPair('ML-KEM-768', { seedD: new Uint8Array(16) }),
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
