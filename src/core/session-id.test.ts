import { describe, it, expect } from 'vitest';
import { IbexSessionId } from './session-id.js';
import { DefaultCryptoProvider } from '../crypto/default-provider.js';

describe('IbexSessionId', () => {
  const validBytes = new Uint8Array([
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
  ]);
  const validHex = '0102030405060708090a0b0c0d0e0f10';

  describe('constructor', () => {
    it('should create a session ID from 16 bytes', () => {
      const sessionId = new IbexSessionId(validBytes);
      expect(sessionId).toBeInstanceOf(IbexSessionId);
      expect(sessionId.bytes).toEqual(validBytes);
    });

    it('should throw an error if bytes length is not 16', () => {
      const invalidBytes = new Uint8Array([1, 2, 3]);
      expect(() => new IbexSessionId(invalidBytes)).toThrow('Session ID must be 16 bytes');
    });
  });

  describe('bytes getter', () => {
    it('should return a copy of the underlying bytes', () => {
      const sessionId = new IbexSessionId(validBytes);
      const retrievedBytes = sessionId.bytes;
      expect(retrievedBytes).toEqual(validBytes);
      expect(retrievedBytes).not.toBe(sessionId.bytes);
      
      // Modify retrieved bytes to verify copy is independent
      retrievedBytes[0] = 0xff;
      expect(sessionId.bytes).toEqual(validBytes);
    });
  });

  describe('serialization and string conversion', () => {
    it('should convert to hex string with toHex()', () => {
      const sessionId = new IbexSessionId(validBytes);
      expect(sessionId.toHex()).toBe(validHex);
    });

    it('should convert to hex string with toString()', () => {
      const sessionId = new IbexSessionId(validBytes);
      expect(sessionId.toString()).toBe(validHex);
    });

    it('should convert to hex string with toJSON()', () => {
      const sessionId = new IbexSessionId(validBytes);
      expect(sessionId.toJSON()).toBe(validHex);
    });
  });

  describe('equals', () => {
    it('should return true for identical session IDs', () => {
      const sessionId1 = new IbexSessionId(validBytes);
      const sessionId2 = new IbexSessionId(new Uint8Array(validBytes));
      expect(sessionId1.equals(sessionId2)).toBe(true);
    });

    it('should return false for different session IDs', () => {
      const sessionId1 = new IbexSessionId(validBytes);
      const differentBytes = new Uint8Array(validBytes);
      differentBytes[0] = 0x00;
      const sessionId2 = new IbexSessionId(differentBytes);
      expect(sessionId1.equals(sessionId2)).toBe(false);
    });
  });

  describe('static methods', () => {
    it('should create a session ID from valid bytes using fromBytes()', () => {
      const sessionId = IbexSessionId.fromBytes(validBytes);
      expect(sessionId.bytes).toEqual(validBytes);
    });

    it('should create a session ID from a valid hex string using fromHex()', () => {
      const sessionId = IbexSessionId.fromHex(validHex);
      expect(sessionId.bytes).toEqual(validBytes);
    });

    it('should throw when creating from an invalid hex string', () => {
      // Hex string with odd length (throws from hexToBytes)
      expect(() => IbexSessionId.fromHex('012')).toThrow('Invalid hex string length');

      // Hex string with even length but not 16 bytes (throws from constructor)
      expect(() => IbexSessionId.fromHex('0102')).toThrow('Session ID must be 16 bytes');
    });

    it('should generate a random session ID using crypto provider', async () => {
      const crypto = new DefaultCryptoProvider();
      const sessionId = await IbexSessionId.generate(crypto);
      expect(sessionId).toBeInstanceOf(IbexSessionId);
      expect(sessionId.bytes.length).toBe(16);
      
      const sessionId2 = await IbexSessionId.generate(crypto);
      expect(sessionId.equals(sessionId2)).toBe(false);
    });
  });
});
