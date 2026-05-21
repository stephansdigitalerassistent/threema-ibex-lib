import type { CryptoProvider } from '../types/crypto.js';
import { bytesToHex, hexToBytes, constantTimeEqual } from '../utils/bytes.js';

/**
 * 16-byte session identifier
 *
 * Used to identify an Ibex session between two parties.
 * Generated randomly when initiating a new session.
 *
 * @example
 * ```ts
 * import { IbexSessionId } from '@privatemessaging/ibex';
 *
 * // Create a session ID from a hex string
 * const sessionId = IbexSessionId.fromHex('0123456789abcdef0123456789abcdef');
 * ```
 */
export class IbexSessionId {
  private readonly _bytes: Uint8Array;

  /**
   * Create a session ID from bytes
   * @param bytes - 16-byte identifier
   */
  constructor(bytes: Uint8Array) {
    if (bytes.length !== 16) {
      throw new Error('Session ID must be 16 bytes');
    }
    this._bytes = new Uint8Array(bytes);
  }

  /**
   * Get the raw bytes
   */
  get bytes(): Uint8Array {
    return new Uint8Array(this._bytes);
  }

  /**
   * Convert to hex string for display/logging
   */
  toHex(): string {
    return bytesToHex(this._bytes);
  }

  /**
   * Convert to string (hex representation)
   */
  toString(): string {
    return this.toHex();
  }

  /**
   * Check equality with another session ID (constant-time)
   */
  equals(other: IbexSessionId): boolean {
    return constantTimeEqual(this._bytes, other._bytes);
  }

  /**
   * Serialize for JSON
   */
  toJSON(): string {
    return this.toHex();
  }

  /**
   * Generate a new random session ID
   */
  static async generate(crypto: CryptoProvider): Promise<IbexSessionId> {
    const bytes = await crypto.randomBytes(16);
    return new IbexSessionId(bytes);
  }

  /**
   * Create from hex string
   */
  static fromHex(hex: string): IbexSessionId {
    return new IbexSessionId(hexToBytes(hex));
  }

  /**
   * Create from bytes
   */
  static fromBytes(bytes: Uint8Array): IbexSessionId {
    return new IbexSessionId(bytes);
  }
}
