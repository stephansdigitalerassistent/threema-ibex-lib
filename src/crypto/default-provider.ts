import type { CryptoProvider, KeyPair } from '../types/crypto.js';
import nacl from 'tweetnacl';
import { blake2b } from '@noble/hashes/blake2.js';
import { padString } from '../utils/bytes.js';

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

  /**
   * Compute a BLAKE2b hash truncated to 256 bits (32 bytes).
   *
   * Supports optional keying (for a MAC-like keyed hash) plus BLAKE2b's
   * personalization and salt parameters, which domain-separate otherwise
   * identical inputs. The `personal` and `salt` strings are UTF-8 encoded and
   * then padded or truncated to exactly 16 bytes each.
   *
   * @param key - Optional key material ({@link Uint8Array}) for a keyed hash,
   *   or `null` for an unkeyed digest.
   * @param personal - Personalization string; UTF-8 encoded and fit to 16
   *   bytes.
   * @param salt - Salt string; UTF-8 encoded and fit to 16 bytes.
   * @param data - The data to hash ({@link Uint8Array}).
   * @returns A promise resolving to the 32-byte digest ({@link Uint8Array}).
   *
   * @example
   * ```ts
   * const crypto = new DefaultCryptoProvider();
   * const data = new TextEncoder().encode('hello');
   *
   * // Unkeyed hash with personalization and salt.
   * const digest = await crypto.blake2b256(null, 'app.context', 'someSalt', data);
   * // digest.length === 32
   * ```
   */
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

  /**
   * Compute a BLAKE2b hash at its full 512-bit (64-byte) output length.
   *
   * Behaves identically to {@link DefaultCryptoProvider.blake2b256} but returns
   * the full digest. Supports optional keying plus BLAKE2b's personalization
   * and salt parameters; the `personal` and `salt` strings are UTF-8 encoded
   * and then padded or truncated to exactly 16 bytes each.
   *
   * @param key - Optional key material ({@link Uint8Array}) for a keyed hash,
   *   or `null` for an unkeyed digest.
   * @param personal - Personalization string; UTF-8 encoded and fit to 16
   *   bytes.
   * @param salt - Salt string; UTF-8 encoded and fit to 16 bytes.
   * @param data - The data to hash ({@link Uint8Array}).
   * @returns A promise resolving to the 64-byte digest ({@link Uint8Array}).
   *
   * @example
   * ```ts
   * const crypto = new DefaultCryptoProvider();
   * const data = new TextEncoder().encode('hello');
   *
   * // Keyed hash for a MAC-like construction.
   * const key = await crypto.randomBytes(32);
   * const digest = await crypto.blake2b512(key, 'app.context', 'someSalt', data);
   * // digest.length === 64
   * ```
   */
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

  /**
   * Encrypt data with XSalsa20-Poly1305 authenticated encryption (NaCl
   * `secretbox`).
   *
   * Produces ciphertext with a 16-byte Poly1305 authentication tag prepended,
   * guaranteeing both confidentiality and integrity. The same `nonce` must
   * never be reused with the same `key`; generate a fresh nonce per message
   * via {@link DefaultCryptoProvider.randomBytes}.
   *
   * @param data - The plaintext to encrypt ({@link Uint8Array}).
   * @param key - The 32-byte secret key ({@link Uint8Array}).
   * @param nonce - The 24-byte nonce ({@link Uint8Array}); must be unique per
   *   message under a given key.
   * @returns A promise resolving to the ciphertext ({@link Uint8Array}) with
   *   the authentication tag prepended.
   *
   * @example
   * ```ts
   * const crypto = new DefaultCryptoProvider();
   * const key = await crypto.randomBytes(32);
   * const nonce = await crypto.randomBytes(24);
   * const message = new TextEncoder().encode('secret');
   *
   * const ciphertext = await crypto.symmetricEncrypt(message, key, nonce);
   * // ciphertext is message.length + 16 bytes (tag prepended).
   * ```
   */
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

  /**
   * Decrypt and authenticate data produced by
   * {@link DefaultCryptoProvider.symmetricEncrypt} (NaCl `secretbox.open`).
   *
   * Verifies the prepended Poly1305 authentication tag before returning the
   * plaintext. If the ciphertext, key, or nonce has been tampered with or does
   * not match, authentication fails and an error is thrown rather than
   * returning corrupt data.
   *
   * @param data - The ciphertext ({@link Uint8Array}) including the 16-byte
   *   authentication tag.
   * @param key - The 32-byte secret key ({@link Uint8Array}) used to encrypt.
   * @param nonce - The 24-byte nonce ({@link Uint8Array}) used to encrypt.
   * @returns A promise resolving to the decrypted plaintext
   *   ({@link Uint8Array}).
   * @throws {Error} If authentication fails (tag mismatch).
   *
   * @example
   * ```ts
   * const crypto = new DefaultCryptoProvider();
   * const key = await crypto.randomBytes(32);
   * const nonce = await crypto.randomBytes(24);
   * const message = new TextEncoder().encode('secret');
   *
   * const ciphertext = await crypto.symmetricEncrypt(message, key, nonce);
   * const plaintext = await crypto.symmetricDecrypt(ciphertext, key, nonce);
   * // new TextDecoder().decode(plaintext) === 'secret'
   * ```
   */
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

  /**
   * Generate cryptographically secure random bytes.
   *
   * Backed by NaCl's CSPRNG, suitable for generating keys, nonces, and other
   * secret material.
   *
   * @param length - The number of random bytes to generate.
   * @returns A promise resolving to a {@link Uint8Array} of `length` random
   *   bytes.
   *
   * @example
   * ```ts
   * const crypto = new DefaultCryptoProvider();
   *
   * // Generate a 32-byte symmetric key and a 24-byte nonce.
   * const key = await crypto.randomBytes(32);
   * const nonce = await crypto.randomBytes(24);
   * // key.length === 32, nonce.length === 24
   * ```
   */
  async randomBytes(length: number): Promise<Uint8Array> {
    return nacl.randomBytes(length);
  }
}

/**
 * Singleton instance of the default crypto provider
 */
export const defaultCryptoProvider = new DefaultCryptoProvider();
