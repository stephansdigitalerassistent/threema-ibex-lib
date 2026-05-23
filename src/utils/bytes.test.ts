import { describe, it, expect } from 'vitest';
import {
  concat,
  stringToBytes,
  bytesToString,
  bytesToHex,
  hexToBytes,
  constantTimeEqual,
  zeroize,
  zeroNonce,
} from './bytes.js';

describe('bytes utilities', () => {
  describe('concat', () => {
    it('should concatenate multiple Uint8Arrays', () => {
      const a = new Uint8Array([1, 2]);
      const b = new Uint8Array([3, 4]);
      const c = new Uint8Array([5]);
      const result = concat(a, b, c);
      expect(result).toEqual(new Uint8Array([1, 2, 3, 4, 5]));
    });

    it('should handle empty arrays', () => {
      const a = new Uint8Array([]);
      const b = new Uint8Array([1, 2]);
      const c = new Uint8Array([]);
      const result = concat(a, b, c);
      expect(result).toEqual(new Uint8Array([1, 2]));
    });

    it('should return an empty array if no arrays are provided', () => {
      const result = concat();
      expect(result).toEqual(new Uint8Array([]));
    });

    it('should return a new array copy and not modify or reuse input array references', () => {
      const a = new Uint8Array([1, 2]);
      const result = concat(a);
      expect(result).toEqual(a);
      expect(result).not.toBe(a);
    });
  });

  describe('stringToBytes and bytesToString conversions', () => {
    it('should convert an ASCII string to bytes and back', () => {
      const str = 'hello world';
      const bytes = stringToBytes(str);
      expect(bytes).toEqual(new Uint8Array([104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100]));
      expect(bytesToString(bytes)).toBe(str);
    });

    it('should convert a UTF-8 string with special characters to bytes and back', () => {
      const str = 'Threema Ibex 🦬';
      const bytes = stringToBytes(str);
      expect(bytesToString(bytes)).toBe(str);
    });

    it('should handle empty strings', () => {
      const str = '';
      const bytes = stringToBytes(str);
      expect(bytes.length).toBe(0);
      expect(bytesToString(bytes)).toBe(str);
    });
  });

  describe('bytesToHex', () => {
    it('should convert bytes to lowercase hex representation', () => {
      const bytes = new Uint8Array([0x00, 0x01, 0x09, 0x0a, 0x0f, 0x10, 0xff]);
      expect(bytesToHex(bytes)).toBe('0001090a0f10ff');
    });

    it('should return empty string for empty bytes', () => {
      expect(bytesToHex(new Uint8Array([]))).toBe('');
    });
  });

  describe('hexToBytes', () => {
    it('should convert hex representation to bytes', () => {
      const hex = '0001090a0f10ff';
      expect(hexToBytes(hex)).toEqual(new Uint8Array([0x00, 0x01, 0x09, 0x0a, 0x0f, 0x10, 0xff]));
    });

    it('should handle uppercase hex representation', () => {
      const hex = '0001090A0F10FF';
      expect(hexToBytes(hex)).toEqual(new Uint8Array([0x00, 0x01, 0x09, 0x0a, 0x0f, 0x10, 0xff]));
    });

    it('should throw an error for odd-length hex strings', () => {
      expect(() => hexToBytes('a')).toThrow('Invalid hex string length');
      expect(() => hexToBytes('123')).toThrow('Invalid hex string length');
    });

    it('should return empty bytes for empty string', () => {
      expect(hexToBytes('')).toEqual(new Uint8Array([]));
    });
  });

  describe('constantTimeEqual', () => {
    it('should return true for identical arrays', () => {
      const a = new Uint8Array([1, 2, 3, 4]);
      const b = new Uint8Array([1, 2, 3, 4]);
      expect(constantTimeEqual(a, b)).toBe(true);
    });

    it('should return true for empty arrays', () => {
      const a = new Uint8Array([]);
      const b = new Uint8Array([]);
      expect(constantTimeEqual(a, b)).toBe(true);
    });

    it('should return false for arrays of different lengths', () => {
      const a = new Uint8Array([1, 2, 3]);
      const b = new Uint8Array([1, 2, 3, 4]);
      expect(constantTimeEqual(a, b)).toBe(false);
      expect(constantTimeEqual(b, a)).toBe(false);
    });

    it('should return false if content differs by one byte', () => {
      const a = new Uint8Array([1, 2, 3, 4]);
      // Diff first byte
      expect(constantTimeEqual(a, new Uint8Array([0, 2, 3, 4]))).toBe(false);
      // Diff middle byte
      expect(constantTimeEqual(a, new Uint8Array([1, 2, 9, 4]))).toBe(false);
      // Diff last byte
      expect(constantTimeEqual(a, new Uint8Array([1, 2, 3, 0]))).toBe(false);
    });
  });

  describe('zeroize', () => {
    it('should fill a Uint8Array with zeros', () => {
      const arr = new Uint8Array([1, 2, 3, 4]);
      zeroize(arr);
      expect(arr).toEqual(new Uint8Array([0, 0, 0, 0]));
    });

    it('should handle empty array', () => {
      const arr = new Uint8Array([]);
      zeroize(arr);
      expect(arr).toEqual(new Uint8Array([]));
    });
  });

  describe('zeroNonce', () => {
    it('should create a zero-filled Uint8Array of the given length', () => {
      const nonce = zeroNonce(12);
      expect(nonce.length).toBe(12);
      expect(nonce).toEqual(new Uint8Array(12));
    });

    it('should handle zero length', () => {
      const nonce = zeroNonce(0);
      expect(nonce.length).toBe(0);
      expect(nonce).toEqual(new Uint8Array(0));
    });
  });
});
