import type { CryptoProvider, KeyPair } from '../types/crypto.js';
import nacl from 'tweetnacl';
import { blake2b } from '@noble/hashes/blake2.js';

/**
 * Pad or truncate a string to exactly `length` bytes
 */
function padString(str: string, length: number): Uint8Array {
  const encoder = new TextEncoder();
  const encoded = encoder.encode(str);
  const padded = new Uint8Array(length);
  padded.set(encoded.subarray(0, length));
  return padded;
}

/**
 * Default crypto provider using tweetnacl and @noble/hashes
 *
 * This implementation is suitable for Node.js and browser environments.
 * For production use, consider implementing CryptoProvider with
 * platform-specific optimized libraries.
 */
export class DefaultCryptoProvider implements CryptoProvider {
  async generateKeyPair(): Promise<KeyPair> {
    const keyPair = nacl.box.keyPair();
    return {
      publicKey: keyPair.publicKey,
      privateKey: keyPair.secretKey,
    };
  }

  async x25519(privateKey: Uint8Array, publicKey: Uint8Array): Promise<Uint8Array> {
    // tweetnacl's scalarMult performs X25519
    // Wrap inputs in canonical Uint8Array for bundler compatibility
    return nacl.scalarMult(new Uint8Array(privateKey), new Uint8Array(publicKey));
  }

  async blake2b256(
    key: Uint8Array | null,
    personal: string,
    salt: string,
    data: Uint8Array
  ): Promise<Uint8Array> {
    // BLAKE2b personalization and salt are each 16 bytes
    const personalBytes = padString(personal, 16);
    const saltBytes = padString(salt, 16);

    // Wrap inputs/outputs in canonical Uint8Array for bundler compatibility
    const digest = blake2b(new Uint8Array(data), {
      dkLen: 32,
      key: key ? new Uint8Array(key) : undefined,
      personalization: personalBytes,
      salt: saltBytes,
    });
    return new Uint8Array(digest);
  }

  async blake2b512(
    key: Uint8Array | null,
    personal: string,
    salt: string,
    data: Uint8Array
  ): Promise<Uint8Array> {
    const personalBytes = padString(personal, 16);
    const saltBytes = padString(salt, 16);

    const digest = blake2b(new Uint8Array(data), {
      dkLen: 64,
      key: key ? new Uint8Array(key) : undefined,
      personalization: personalBytes,
      salt: saltBytes,
    });
    return new Uint8Array(digest);
  }

  async symmetricEncrypt(
    data: Uint8Array,
    key: Uint8Array,
    nonce: Uint8Array
  ): Promise<Uint8Array> {
    return nacl.secretbox(
      new Uint8Array(data),
      new Uint8Array(nonce),
      new Uint8Array(key)
    );
  }

  async symmetricDecrypt(
    data: Uint8Array,
    key: Uint8Array,
    nonce: Uint8Array
  ): Promise<Uint8Array> {
    const decrypted = nacl.secretbox.open(
      new Uint8Array(data),
      new Uint8Array(nonce),
      new Uint8Array(key)
    );
    if (decrypted === null) {
      throw new Error('Decryption failed: authentication tag mismatch');
    }
    return decrypted;
  }

  async randomBytes(length: number): Promise<Uint8Array> {
    return nacl.randomBytes(length);
  }
}

/**
 * Singleton instance of the default crypto provider
 */
export const defaultCryptoProvider = new DefaultCryptoProvider();
