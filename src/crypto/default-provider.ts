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
 *
 * @example
 * ```ts
 * import { DefaultCryptoProvider } from '@privatemessaging/ibex/crypto';
 *
 * // Instantiate the provider.
 * const crypto = new DefaultCryptoProvider();
 *
 * // Generate a key pair for each party.
 * const alice = await crypto.generateKeyPair();
 * const bob = await crypto.generateKeyPair();
 *
 * // Each party derives the same shared secret from their own private key
 * // and the other party's public key.
 * const aliceShared = await crypto.x25519(alice.privateKey, bob.publicKey);
 * const bobShared = await crypto.x25519(bob.privateKey, alice.publicKey);
 * // aliceShared and bobShared are byte-for-byte identical (32-byte secret).
 * ```
 */
export class DefaultCryptoProvider implements CryptoProvider {
  /**
   * Generate an X25519 key pair using NaCl's `box` key generation.
   *
   * The returned keys are raw, unencoded byte arrays. The private key must be
   * kept secret; the public key may be shared with other parties.
   *
   * @returns A promise resolving to a {@link KeyPair} containing a 32-byte
   *   `publicKey` ({@link Uint8Array}) and a 32-byte `privateKey`
   *   ({@link Uint8Array}).
   *
   * @example
   * ```ts
   * const crypto = new DefaultCryptoProvider();
   * const { publicKey, privateKey } = await crypto.generateKeyPair();
   * // publicKey.length === 32, privateKey.length === 32
   * ```
   */
  async generateKeyPair(): Promise<KeyPair> {
    const keyPair = nacl.box.keyPair();
    return {
      publicKey: keyPair.publicKey,
      privateKey: keyPair.secretKey,
    };
  }

  /**
   * Perform an X25519 Diffie-Hellman key exchange (scalar multiplication).
   *
   * Combines a local private key with a remote public key to derive a shared
   * secret. Given key pairs `(a, A)` and `(b, B)`, computing
   * `x25519(a, B)` yields the same secret as `x25519(b, A)`, allowing two
   * parties to agree on a secret over an insecure channel.
   *
   * @param privateKey - The local party's 32-byte private key
   *   ({@link Uint8Array}), typically `KeyPair.privateKey` from
   *   {@link DefaultCryptoProvider.generateKeyPair}.
   * @param publicKey - The remote party's 32-byte public key
   *   ({@link Uint8Array}).
   * @returns A promise resolving to the 32-byte shared secret
   *   ({@link Uint8Array}).
   *
   * @example
   * ```ts
   * const crypto = new DefaultCryptoProvider();
   * const alice = await crypto.generateKeyPair();
   * const bob = await crypto.generateKeyPair();
   *
   * // Both parties independently compute the same shared secret.
   * const sharedByAlice = await crypto.x25519(alice.privateKey, bob.publicKey);
   * const sharedByBob = await crypto.x25519(bob.privateKey, alice.publicKey);
   * // sharedByAlice and sharedByBob are equal (32-byte secret).
   * ```
   */
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
