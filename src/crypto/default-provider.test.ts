import { describe, it, expect } from 'vitest';
import { DefaultCryptoProvider } from './default-provider.js';
import { CryptoConstants } from '../types/crypto.js';
import { constantTimeEqual } from '../utils/bytes.js';

describe('DefaultCryptoProvider', () => {
  const crypto = new DefaultCryptoProvider();

  describe('generateKeyPair', () => {
    it('should generate a valid key pair', async () => {
      const keyPair = await crypto.generateKeyPair();

      expect(keyPair.publicKey).toBeInstanceOf(Uint8Array);
      expect(keyPair.privateKey).toBeInstanceOf(Uint8Array);
      expect(keyPair.publicKey.length).toBe(CryptoConstants.PUBLIC_KEY_BYTES);
      expect(keyPair.privateKey.length).toBe(CryptoConstants.PRIVATE_KEY_BYTES);
    });

    it('should generate unique key pairs', async () => {
      const keyPair1 = await crypto.generateKeyPair();
      const keyPair2 = await crypto.generateKeyPair();

      expect(constantTimeEqual(keyPair1.publicKey, keyPair2.publicKey)).toBe(false);
      expect(constantTimeEqual(keyPair1.privateKey, keyPair2.privateKey)).toBe(false);
    });
  });

  describe('x25519', () => {
    it('should compute same shared secret for both parties', async () => {
      const alice = await crypto.generateKeyPair();
      const bob = await crypto.generateKeyPair();

      const aliceShared = await crypto.x25519(alice.privateKey, bob.publicKey);
      const bobShared = await crypto.x25519(bob.privateKey, alice.publicKey);

      expect(aliceShared.length).toBe(CryptoConstants.SHARED_SECRET_BYTES);
      expect(constantTimeEqual(aliceShared, bobShared)).toBe(true);
    });

    it('should verify Diffie-Hellman key agreement', async () => {
      const alice = await crypto.generateKeyPair();
      const bob = await crypto.generateKeyPair();

      const aliceShared = await crypto.x25519(alice.privateKey, bob.publicKey);
      const bobShared = await crypto.x25519(bob.privateKey, alice.publicKey);

      expect(aliceShared).toEqual(bobShared);
    });

    it('should produce different shared secrets with different keys', async () => {
      const alice = await crypto.generateKeyPair();
      const bob = await crypto.generateKeyPair();
      const charlie = await crypto.generateKeyPair();

      const aliceBob = await crypto.x25519(alice.privateKey, bob.publicKey);
      const aliceCharlie = await crypto.x25519(alice.privateKey, charlie.publicKey);

      expect(constantTimeEqual(aliceBob, aliceCharlie)).toBe(false);
    });
  });

  describe('blake2b256', () => {
    it('should produce 32-byte hash', async () => {
      const data = new TextEncoder().encode('test data');
      const hash = await crypto.blake2b256(null, '', '', data);

      expect(hash).toBeInstanceOf(Uint8Array);
      expect(hash.length).toBe(32);
    });

    it('should correctly handle null keys', async () => {
      const data = new TextEncoder().encode('test data');
      const hashWithNull = await crypto.blake2b256(null, '', '', data);

      expect(hashWithNull).toBeInstanceOf(Uint8Array);
      expect(hashWithNull.length).toBe(32);

      const key = new Uint8Array(32).fill(0x42);
      const hashWithKey = await crypto.blake2b256(key, '', '', data);
      expect(constantTimeEqual(hashWithNull, hashWithKey)).toBe(false);
    });

    it('should produce different hashes with different personalization', async () => {
      const data = new TextEncoder().encode('test data');
      const hash1 = await crypto.blake2b256(null, 'personal1', '', data);
      const hash2 = await crypto.blake2b256(null, 'personal2', '', data);

      expect(constantTimeEqual(hash1, hash2)).toBe(false);
    });

    it('should apply personalization correctly with padding and truncation', async () => {
      const data = new TextEncoder().encode('test data');

      const shortPersonal = 'personal';
      const paddedPersonal = 'personal\0\0\0\0\0\0\0\0';
      const hashShort = await crypto.blake2b256(null, shortPersonal, '', data);
      const hashPadded = await crypto.blake2b256(null, paddedPersonal, '', data);
      expect(hashShort).toEqual(hashPadded);

      const exactPersonal = '1234567890123456';
      const longPersonal = '1234567890123456extra_chars';
      const hashExact = await crypto.blake2b256(null, exactPersonal, '', data);
      const hashLong = await crypto.blake2b256(null, longPersonal, '', data);
      expect(hashExact).toEqual(hashLong);
    });

    it('should produce different hashes with different salts', async () => {
      const data = new TextEncoder().encode('test data');
      const hash1 = await crypto.blake2b256(null, '', 'salt1', data);
      const hash2 = await crypto.blake2b256(null, '', 'salt2', data);

      expect(constantTimeEqual(hash1, hash2)).toBe(false);
    });

    it('should apply salt correctly with padding and truncation', async () => {
      const data = new TextEncoder().encode('test data');

      const shortSalt = 'salt';
      const paddedSalt = 'salt\0\0\0\0\0\0\0\0\0\0\0\0';
      const hashShort = await crypto.blake2b256(null, '', shortSalt, data);
      const hashPadded = await crypto.blake2b256(null, '', paddedSalt, data);
      expect(hashShort).toEqual(hashPadded);

      const exactSalt = '1234567890123456';
      const longSalt = '1234567890123456extra_chars';
      const hashExact = await crypto.blake2b256(null, '', exactSalt, data);
      const hashLong = await crypto.blake2b256(null, '', longSalt, data);
      expect(hashExact).toEqual(hashLong);
    });

    it('should produce keyed MAC with key provided', async () => {
      const data = new TextEncoder().encode('test data');
      const key = new Uint8Array(32).fill(0x42);

      const unkeyed = await crypto.blake2b256(null, '', '', data);
      const keyed = await crypto.blake2b256(key, '', '', data);

      expect(constantTimeEqual(unkeyed, keyed)).toBe(false);
    });
  });

  describe('blake2b512', () => {
    it('should produce 64-byte hash', async () => {
      const data = new TextEncoder().encode('test data');
      const hash = await crypto.blake2b512(null, '', '', data);

      expect(hash).toBeInstanceOf(Uint8Array);
      expect(hash.length).toBe(64);
    });
  });

  describe('blake2b output compatibility with tweetnacl', () => {
    it('should work with blake2b256-derived keys in symmetricEncrypt', async () => {
      // blake2b256 produces 32-byte output, perfect for symmetric keys
      const key = await crypto.blake2b256(null, '', '', new Uint8Array(32));
      const nonce = new Uint8Array(CryptoConstants.NONCE_BYTES);
      const data = new TextEncoder().encode('test');

      // This will fail if blake2b returns non-canonical Uint8Array
      // because tweetnacl uses strict instanceof checks
      const encrypted = await crypto.symmetricEncrypt(data, key, nonce);
      expect(encrypted.length).toBeGreaterThan(data.length);
    });

    it('should return canonical Uint8Array from blake2b256', async () => {
      const hash = await crypto.blake2b256(null, '', '', new Uint8Array(32));
      expect(hash.constructor).toBe(Uint8Array);
      expect(Object.getPrototypeOf(hash)).toBe(Uint8Array.prototype);
    });

    it('should return canonical Uint8Array from blake2b512', async () => {
      const hash = await crypto.blake2b512(null, '', '', new Uint8Array(32));
      expect(hash.constructor).toBe(Uint8Array);
      expect(Object.getPrototypeOf(hash)).toBe(Uint8Array.prototype);
    });
  });

  describe('symmetricEncrypt/symmetricDecrypt', () => {
    it('should encrypt and decrypt data', async () => {
      const key = new Uint8Array(CryptoConstants.SYMMETRIC_KEY_BYTES).fill(0x42);
      const nonce = new Uint8Array(CryptoConstants.NONCE_BYTES).fill(0x01);
      const plaintext = new TextEncoder().encode('Hello, World!');

      const ciphertext = await crypto.symmetricEncrypt(plaintext, key, nonce);
      const decrypted = await crypto.symmetricDecrypt(ciphertext, key, nonce);

      expect(decrypted).toBeInstanceOf(Uint8Array);
      expect(new TextDecoder().decode(decrypted)).toBe('Hello, World!');
    });

    it('should produce ciphertext longer than plaintext (auth tag)', async () => {
      const key = new Uint8Array(CryptoConstants.SYMMETRIC_KEY_BYTES).fill(0x42);
      const nonce = new Uint8Array(CryptoConstants.NONCE_BYTES).fill(0x01);
      const plaintext = new TextEncoder().encode('Hello, World!');

      const ciphertext = await crypto.symmetricEncrypt(plaintext, key, nonce);

      expect(ciphertext.length).toBe(plaintext.length + CryptoConstants.AUTH_TAG_BYTES);
    });

    it('should fail decryption with wrong key', async () => {
      const key1 = new Uint8Array(CryptoConstants.SYMMETRIC_KEY_BYTES).fill(0x42);
      const key2 = new Uint8Array(CryptoConstants.SYMMETRIC_KEY_BYTES).fill(0x43);
      const nonce = new Uint8Array(CryptoConstants.NONCE_BYTES).fill(0x01);
      const plaintext = new TextEncoder().encode('Hello, World!');

      const ciphertext = await crypto.symmetricEncrypt(plaintext, key1, nonce);

      await expect(crypto.symmetricDecrypt(ciphertext, key2, nonce)).rejects.toThrow(
        'Decryption failed'
      );
    });

    it('should fail decryption with tampered ciphertext', async () => {
      const key = new Uint8Array(CryptoConstants.SYMMETRIC_KEY_BYTES).fill(0x42);
      const nonce = new Uint8Array(CryptoConstants.NONCE_BYTES).fill(0x01);
      const plaintext = new TextEncoder().encode('Hello, World!');

      const ciphertext = await crypto.symmetricEncrypt(plaintext, key, nonce);
      ciphertext[0] ^= 0xff; // Tamper with first byte

      await expect(crypto.symmetricDecrypt(ciphertext, key, nonce)).rejects.toThrow(
        'Decryption failed'
      );
    });
  });

  describe('randomBytes', () => {
    it('should generate bytes of requested length', async () => {
      const bytes16 = await crypto.randomBytes(16);
      const bytes32 = await crypto.randomBytes(32);
      const bytes64 = await crypto.randomBytes(64);

      expect(bytes16.length).toBe(16);
      expect(bytes32.length).toBe(32);
      expect(bytes64.length).toBe(64);
    });

    it('should generate unique random bytes', async () => {
      const bytes1 = await crypto.randomBytes(32);
      const bytes2 = await crypto.randomBytes(32);

      expect(constantTimeEqual(bytes1, bytes2)).toBe(false);
    });
  });
});
