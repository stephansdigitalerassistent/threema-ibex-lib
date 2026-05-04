import type { CryptoProvider } from '../types/crypto.js';
import type { ResolvedIbexConfig } from '../types/common.js';
import { DEFAULT_CONFIG } from '../types/common.js';

/**
 * Error thrown when a ratchet operation fails
 */
export class RatchetError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RatchetError';
  }
}

/**
 * KDF Ratchet for forward secrecy.
 *
 * This class implements a chain of keys where each key is derived from the
 * previous one using a Key Derivation Function (KDF), specifically BLAKE2b-256.
 *
 * It ensures forward secrecy: if a message key or even a chain key is
 * compromised, past message keys cannot be recovered because the derivation
 * process is one-way.
 */
export class KDFRatchet {
  private _counter: number;
  private _currentChainKey: Uint8Array;
  private _config: ResolvedIbexConfig;

  /**
   * Create a new KDF ratchet.
   *
   * @param counter - Initial counter value (0-based)
   * @param initialChainKey - 32-byte initial chain key (K0)
   * @param config - Optional configuration overrides
   * @throws RatchetError if the initial chain key is not 32 bytes or counter is negative
   */
  constructor(
    counter: number,
    initialChainKey: Uint8Array,
    config?: Partial<ResolvedIbexConfig>
  ) {
    if (initialChainKey.length !== 32) {
      throw new RatchetError('Initial chain key must be 32 bytes');
    }
    if (counter < 0) {
      throw new RatchetError('Counter must be non-negative');
    }

    this._counter = counter;
    this._currentChainKey = new Uint8Array(initialChainKey);
    this._config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Current ratchet counter.
   * Increments each time the ratchet is turned. Represents the number of
   * messages processed by this ratchet.
   */
  get counter(): number {
    return this._counter;
  }

  /**
   * Current chain key (32 bytes).
   * This is used to derive the next chain key and the current message key.
   * Should be handled with care and zeroed out when no longer needed.
   */
  get currentChainKey(): Uint8Array {
    return new Uint8Array(this._currentChainKey);
  }

  /**
   * Derive the encryption key (message key) from the current chain key.
   *
   * This uses BLAKE2b-256 with a specific "encryption key" salt.
   *
   * @param crypto - Crypto provider for BLAKE2b
   * @returns 32-byte encryption key
   */
  async getCurrentEncryptionKey(crypto: CryptoProvider): Promise<Uint8Array> {
    return crypto.blake2b256(
      this._currentChainKey,
      this._config.kdfPersonal,
      this._config.kdfSaltEncryptionKey,
      new Uint8Array(0)
    );
  }

  /**
   * Turn the ratchet once, advancing to the next chain key.
   *
   * The old chain key is securely zeroed out after the new one is derived
   * to maintain forward secrecy.
   *
   * @param crypto - Crypto provider for BLAKE2b
   */
  async turn(crypto: CryptoProvider): Promise<void> {
    // Derive the new chain key using the "chain key" salt
    const newChainKey = await crypto.blake2b256(
      this._currentChainKey,
      this._config.kdfPersonal,
      this._config.kdfSaltChainKey,
      new Uint8Array(0)
    );

    // Zero out old key for forward secrecy - ensure it's wiped from memory
    this._currentChainKey.fill(0);
    this._currentChainKey = newChainKey;
    this._counter++;
  }

  /**
   * Turn the ratchet multiple times until it reaches the target counter.
   *
   * Useful for catching up when messages are received out of order or
   * some messages were lost.
   *
   * @param crypto - Crypto provider for BLAKE2b
   * @param targetCounter - The desired counter value to reach
   * @returns The number of turns performed
   * @throws RatchetError if the target is behind the current counter or the increment exceeds config limits
   */
  async turnUntil(crypto: CryptoProvider, targetCounter: number): Promise<number> {
    if (targetCounter < this._counter) {
      throw new RatchetError(
        `Cannot turn ratchet backwards: current=${this._counter}, target=${targetCounter}`
      );
    }

    const numTurns = targetCounter - this._counter;
    // Safety check to prevent infinite loops or DoS if a malicious counter is provided
    if (numTurns > this._config.maxCounterIncrement) {
      throw new RatchetError(
        `Counter increment too large: ${numTurns} > ${this._config.maxCounterIncrement}`
      );
    }

    // Repeatedly turn the ratchet until the counters match
    for (let i = 0; i < numTurns; i++) {
      await this.turn(crypto);
    }

    return numTurns;
  }

  /**
   * Create a copy of this ratchet (for persistence/testing)
   */
  clone(): KDFRatchet {
    return new KDFRatchet(this._counter, this._currentChainKey, this._config);
  }

  /**
   * Serialize the ratchet state for persistence
   */
  toJSON(): { counter: number; chainKey: number[] } {
    return {
      counter: this._counter,
      chainKey: Array.from(this._currentChainKey),
    };
  }

  /**
   * Restore a ratchet from serialized state
   */
  static fromJSON(
    data: { counter: number; chainKey: number[] },
    config?: Partial<ResolvedIbexConfig>
  ): KDFRatchet {
    return new KDFRatchet(
      data.counter,
      new Uint8Array(data.chainKey),
      config
    );
  }
}
