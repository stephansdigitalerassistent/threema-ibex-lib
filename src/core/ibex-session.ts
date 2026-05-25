import type { CryptoProvider } from '../types/crypto.js';
import type { ResolvedIbexConfig, Version, VersionRange } from '../types/common.js';
import type { SerializedIbexSession, SerializedRatchet } from '../types/storage.js';
import { IbexSessionState, resolveConfig, Version as V } from '../types/common.js';
import { KDFRatchet } from './kdf-ratchet.js';
import { IbexSessionId } from './session-id.js';
import { concat, zeroize } from '../utils/bytes.js';

/**
 * Error thrown for invalid Ibex session states
 */
export class IbexSessionError extends Error {
  /**
   * Creates a new IbexSessionError.
   *
   * @param message - The error message description.
   */
  constructor(message: string) {
    super(message);
    this.name = 'IbexSessionError';
  }
}

/**
 * Negotiated 4DH versions for local and remote parties.
 * Used to track which protocol version is being applied for outgoing and incoming messages.
 */
export interface IbexVersions {
  /** Protocol version used for local (outgoing) 4DH messages */
  local: Version;
  /** Protocol version used for remote (incoming) 4DH messages */
  remote: Version;
}

/**
 * Contact information required for establishing or maintaining an Ibex session.
 */
export interface Contact {
  /** Unique identifier for the contact (e.g., Threema ID) */
  identity: string;
  /** The contact's long-term X25519 public key */
  publicKey: Uint8Array;
}

/**
 * Identity store providing access to the local party's long-term identity keys.
 */
export interface IdentityStore {
  /** Unique identifier for the local party */
  identity: string;
  /** The local party's long-term X25519 public key */
  publicKey: Uint8Array;
  /** The local party's long-term X25519 private key. MUST be kept secure. */
  privateKey: Uint8Array;
}

/**
 * Ibex session for forward secrecy.
 *
 * Manages ECDH key exchange and KDF ratchets between two parties.
 * Provides double-ratchet-like forward secrecy using X25519 for Diffie-Hellman
 * and BLAKE2b for key derivation.
 *
 * ### Cryptographic Session Lifecycle & State Transitions
 *
 * The session progresses through several states depending on the exchange of ephemeral keys:
 *
 * 1. **Initiator Session Creation (`L20` - Local 2DH):**
 *    - The initiator calls {@link IbexSession.createAsInitiator}.
 *    - Initiator generates a local ephemeral X25519 keypair.
 *    - Performs ECDH over static-static and ephemeral-static key combinations to derive `myRatchet2DH`.
 *    - State is `L20` (has local 2DH outgoing ratchet, no incoming or 4DH ratchets).
 *    - Initiator transmits `IbexInit` to the responder.
 *
 * 2. **Responder Session Creation (`R24` - Remote 2DH + 4DH):**
 *    - The responder receives `IbexInit` and calls {@link IbexSession.createAsResponder}.
 *    - Responder generates its own ephemeral X25519 keypair.
 *    - Computes 2DH (for incoming) and full 4DH key agreements (static-static, ephemeral-static,
 *      static-ephemeral, ephemeral-ephemeral) to initialize `peerRatchet2DH`, `myRatchet4DH`, and `peerRatchet4DH`.
 *    - State is `R24` (ready to send 4DH, can still receive 2DH messages).
 *    - Responder transmits `IbexAccept` to the initiator.
 *
 * 3. **Initiator Accept Processing (`RL44` - Established 4DH):**
 *    - The initiator receives `IbexAccept` and calls {@link IbexSession.processAccept}.
 *    - Computes full 4DH agreements using the responder's ephemeral public key.
 *    - Initializes `myRatchet4DH` and `peerRatchet4DH`.
 *    - Discards `myRatchet2DH` and zeroizes the local ephemeral private key.
 *    - State becomes `RL44` (both parties on 4DH).
 *
 * 4. **Responder Handshake Completion (`RL44` - Established 4DH):**
 *    - When the responder receives the first 4DH message, it discards `peerRatchet2DH`.
 *    - State transitions from `R24` to `RL44`.
 *
 * 5. **State Summary:**
 *    - `L20`: Initiator post-init. Only has `myRatchet2DH`.
 *    - `R20`: Responder post-init, before accepting (unused/intermediate state). Only has `peerRatchet2DH`.
 *    - `R24`: Responder post-accept. Has `peerRatchet2DH`, `myRatchet4DH`, `peerRatchet4DH`.
 *    - `RL44`: Fully established. Has `myRatchet4DH` and `peerRatchet4DH`.
 */
export class IbexSession {
  private readonly _id: IbexSessionId;
  private readonly _myIdentity: string;
  private readonly _peerIdentity: string;
  private _myEphemeralPrivateKey: Uint8Array | null;
  private readonly _myEphemeralPublicKey: Uint8Array;
  private _current4DHVersions: IbexVersions | null;
  private _lastOutgoingMessageTimestamp: number;
  private _myRatchet2DH: KDFRatchet | null;
  private _myRatchet4DH: KDFRatchet | null;
  private _peerRatchet2DH: KDFRatchet | null;
  private _peerRatchet4DH: KDFRatchet | null;
  private readonly _config: ResolvedIbexConfig;

  /** Supported protocol version range: 1.0 to 1.2 */
  static readonly SUPPORTED_VERSION_MIN: Version = V.V1_0;
  static readonly SUPPORTED_VERSION_MAX: Version = V.V1_2;

  /**
   * Private constructor to instantiate an Ibex session.
   *
   * Library consumers should use factory methods:
   * - {@link IbexSession.createAsInitiator}
   * - {@link IbexSession.createAsResponder}
   * - {@link IbexSession.restore}
   *
   * @param id - Unique session identifier.
   * @param myIdentity - Local user's identity string.
   * @param peerIdentity - Remote user's identity string.
   * @param myEphemeralPrivateKey - Local ephemeral X25519 private key, or null if discarded.
   * @param myEphemeralPublicKey - Local ephemeral X25519 public key.
   * @param current4DHVersions - Currently negotiated protocol versions for 4DH communication.
   * @param lastOutgoingMessageTimestamp - Unix timestamp in milliseconds when the last message was sent.
   * @param myRatchet2DH - Outgoing 2DH KDF ratchet, if active.
   * @param myRatchet4DH - Outgoing 4DH KDF ratchet, if active.
   * @param peerRatchet2DH - Incoming 2DH KDF ratchet, if active.
   * @param peerRatchet4DH - Incoming 4DH KDF ratchet, if active.
   * @param config - The resolved session configuration settings.
   */
  private constructor(
    id: IbexSessionId,
    myIdentity: string,
    peerIdentity: string,
    myEphemeralPrivateKey: Uint8Array | null,
    myEphemeralPublicKey: Uint8Array,
    current4DHVersions: IbexVersions | null,
    lastOutgoingMessageTimestamp: number,
    myRatchet2DH: KDFRatchet | null,
    myRatchet4DH: KDFRatchet | null,
    peerRatchet2DH: KDFRatchet | null,
    peerRatchet4DH: KDFRatchet | null,
    config: ResolvedIbexConfig
  ) {
    this._id = id;
    this._myIdentity = myIdentity;
    this._peerIdentity = peerIdentity;
    this._myEphemeralPrivateKey = myEphemeralPrivateKey;
    this._myEphemeralPublicKey = myEphemeralPublicKey;
    this._current4DHVersions = current4DHVersions;
    this._lastOutgoingMessageTimestamp = lastOutgoingMessageTimestamp;
    this._myRatchet2DH = myRatchet2DH;
    this._myRatchet4DH = myRatchet4DH;
    this._peerRatchet2DH = peerRatchet2DH;
    this._peerRatchet4DH = peerRatchet4DH;
    this._config = config;
  }

  // Getters
  /**
   * Unique session identifier.
   */
  get id(): IbexSessionId {
    return this._id;
  }

  /**
   * Local identity identifier.
   */
  get myIdentity(): string {
    return this._myIdentity;
  }

  /**
   * Remote party's identity identifier.
   */
  get peerIdentity(): string {
    return this._peerIdentity;
  }

  /**
   * Local ephemeral public key used for this session.
   */
  get myEphemeralPublicKey(): Uint8Array {
    return new Uint8Array(this._myEphemeralPublicKey);
  }

  /**
   * Local ephemeral private key. Only available during session setup for the initiator.
   */
  get myEphemeralPrivateKey(): Uint8Array | null {
    return this._myEphemeralPrivateKey ? new Uint8Array(this._myEphemeralPrivateKey) : null;
  }

  /**
   * Currently negotiated 4DH versions, if established.
   */
  get current4DHVersions(): IbexVersions | null {
    return this._current4DHVersions;
  }

  /**
   * Timestamp of the last outgoing message sent in this session.
   */
  get lastOutgoingMessageTimestamp(): number {
    return this._lastOutgoingMessageTimestamp;
  }

  /**
   * Set the timestamp of the last outgoing message.
   */
  set lastOutgoingMessageTimestamp(value: number) {
    this._lastOutgoingMessageTimestamp = value;
  }

  /**
   * Outgoing 2DH ratchet (used before 4DH is established).
   */
  get myRatchet2DH(): KDFRatchet | null {
    return this._myRatchet2DH;
  }

  /**
   * Outgoing 4DH ratchet.
   */
  get myRatchet4DH(): KDFRatchet | null {
    return this._myRatchet4DH;
  }

  /**
   * Incoming 2DH ratchet (used before 4DH is established).
   */
  get peerRatchet2DH(): KDFRatchet | null {
    return this._peerRatchet2DH;
  }

  /**
   * Incoming 4DH ratchet.
   */
  get peerRatchet4DH(): KDFRatchet | null {
    return this._peerRatchet4DH;
  }

  /**
   * Session configuration.
   */
  get config(): ResolvedIbexConfig {
    return this._config;
  }

  /**
   * Get the current session state based on ratchet availability
   */
  get state(): IbexSessionState {
    const m2 = this._myRatchet2DH !== null;
    const m4 = this._myRatchet4DH !== null;
    const p2 = this._peerRatchet2DH !== null;
    const p4 = this._peerRatchet4DH !== null;

    if (!m2 && m4 && !p2 && p4) return IbexSessionState.RL44;
    if (!m2 && p2 && m4 && p4) return IbexSessionState.R24;
    if (m2 && !m4 && !p2 && !p4) return IbexSessionState.L20;
    if (!m2 && !m4 && p2 && !p4) return IbexSessionState.R20;

    throw new IbexSessionError(
      `Invalid session state: my2DH=${m2}, my4DH=${m4}, peer2DH=${p2}, peer4DH=${p4}`
    );
  }

  /**
   * Returns the protocol version range supported by this library implementation.
   *
   * @returns The supported VersionRange (min to max).
   */
  static getSupportedVersionRange(): VersionRange {
    return {
      min: IbexSession.SUPPORTED_VERSION_MIN,
      max: IbexSession.SUPPORTED_VERSION_MAX,
    };
  }

  /**
   * Creates a new Ibex session as the initiator.
   *
   * This initiates the handshake by generating a new session ID and local ephemeral keypair,
   * performing a 2DH key agreement, and creating the outgoing 2DH ratchet.
   * The session will start in the `L20` state.
   *
   * @param contact - The peer's identity and long-term public key.
   * @param identityStore - The local identity store containing long-term keys.
   * @param crypto - Cryptographic provider for X25519 and BLAKE2b operations.
   * @param config - Optional configuration parameter overrides.
   * @returns A Promise resolving to the initialized `IbexSession`.
   */
  static async createAsInitiator(
    contact: Contact,
    identityStore: IdentityStore,
    crypto: CryptoProvider,
    config?: Partial<ResolvedIbexConfig>
  ): Promise<IbexSession> {
    const resolvedConfig = resolveConfig(config);
    const sessionId = await IbexSessionId.generate(crypto);
    const ephemeralKeyPair = await crypto.generateKeyPair();

    // Derive 2DH root key
    const dhStaticStatic = await crypto.x25519(identityStore.privateKey, contact.publicKey);
    const dhEphemeralStatic = await crypto.x25519(ephemeralKeyPair.privateKey, contact.publicKey);

    const myRatchet2DH = await IbexSession.initKDF2DH(
      crypto,
      dhStaticStatic,
      dhEphemeralStatic,
      identityStore.identity,
      resolvedConfig
    );

    return new IbexSession(
      sessionId,
      identityStore.identity,
      contact.identity,
      ephemeralKeyPair.privateKey,
      ephemeralKeyPair.publicKey,
      null, // No 4DH versions yet
      0,
      myRatchet2DH,
      null,
      null,
      null,
      resolvedConfig
    );
  }

  /**
   * Creates a new Ibex session as the responder in response to an initiator's session invitation.
   *
   * This completes the handshake setup on the responder's side by:
   * 1. Negotiating the protocol version.
   * 2. Generating a local ephemeral X25519 keypair.
   * 3. Computing 2DH and full 4DH key agreements.
   * 4. Initializing incoming 2DH, outgoing 4DH, and incoming 4DH ratchets.
   *
   * The session starts in the `R24` state, prepared to decrypt incoming 2DH messages
   * and encrypt outgoing messages using the higher-security 4DH ratchet.
   *
   * @param sessionId - The session ID proposed by the initiator.
   * @param peerVersionRange - Supported protocol versions of the initiator.
   * @param peerEphemeralPublicKey - Ephemeral public key sent by the initiator.
   * @param contact - The peer's identity and long-term public key.
   * @param identityStore - The local identity store containing long-term keys.
   * @param crypto - Cryptographic provider for X25519 and BLAKE2b operations.
   * @param config - Optional configuration parameter overrides.
   * @returns A Promise resolving to the initialized `IbexSession`.
   * @throws {IbexSessionError} If the peer's ephemeral public key is malformed or if version negotiation fails.
   */
  static async createAsResponder(
    sessionId: IbexSessionId,
    peerVersionRange: VersionRange,
    peerEphemeralPublicKey: Uint8Array,
    contact: Contact,
    identityStore: IdentityStore,
    crypto: CryptoProvider,
    config?: Partial<ResolvedIbexConfig>
  ): Promise<IbexSession> {
    const resolvedConfig = resolveConfig(config);

    if (peerEphemeralPublicKey.length !== 32) {
      throw new IbexSessionError('Invalid peer ephemeral public key length');
    }

    const negotiatedVersion = IbexSession.negotiateVersion(
      IbexSession.getSupportedVersionRange(),
      peerVersionRange
    );

    // Generate our ephemeral key pair
    const ephemeralKeyPair = await crypto.generateKeyPair();

    // Compute DH values
    const dhStaticStatic = await crypto.x25519(identityStore.privateKey, contact.publicKey);
    const dhEphemeralStatic = await crypto.x25519(identityStore.privateKey, peerEphemeralPublicKey);
    const dhStaticEphemeral = await crypto.x25519(ephemeralKeyPair.privateKey, contact.publicKey);
    const dhEphemeralEphemeral = await crypto.x25519(
      ephemeralKeyPair.privateKey,
      peerEphemeralPublicKey
    );

    // Derive 2DH peer ratchet (for incoming messages from initiator)
    const peerRatchet2DH = await IbexSession.initKDF2DH(
      crypto,
      dhStaticStatic,
      dhEphemeralStatic,
      contact.identity,
      resolvedConfig
    );

    // Derive 4DH ratchets
    const { myRatchet4DH, peerRatchet4DH } = await IbexSession.initKDF4DH(
      crypto,
      dhStaticStatic,
      dhEphemeralStatic,
      dhStaticEphemeral,
      dhEphemeralEphemeral,
      identityStore.identity,
      contact.identity,
      resolvedConfig
    );

    return new IbexSession(
      sessionId,
      identityStore.identity,
      contact.identity,
      null, // Responder doesn't keep ephemeral private key
      ephemeralKeyPair.publicKey,
      { local: negotiatedVersion, remote: negotiatedVersion },
      0,
      null,
      myRatchet4DH,
      peerRatchet2DH,
      peerRatchet4DH,
      resolvedConfig
    );
  }

  /**
   * Processes an incoming Accept message from the responder to establish the session.
   *
   * This transitions the session from `L20` (Local 2DH) to `RL44` (Established 4DH) by:
   * 1. Negotiating the final protocol version.
   * 2. Performing a full 4DH key agreement using the responder's ephemeral public key.
   * 3. Initializing the outgoing and incoming 4DH ratchets.
   * 4. Discarding the temporary 2DH ratchet.
   * 5. Zeroizing and discarding the local ephemeral private key.
   *
   * @param peerVersionRange - The protocol version range supported by the responder.
   * @param peerEphemeralPublicKey - The responder's ephemeral X25519 public key.
   * @param contact - The responder's identity and long-term public key.
   * @param identityStore - The local identity store containing long-term keys.
   * @param crypto - Cryptographic provider for X25519 and BLAKE2b operations.
   * @throws {IbexSessionError} If the ephemeral private key was already discarded, the public key is invalid, or version negotiation fails.
   */
  async processAccept(
    peerVersionRange: VersionRange,
    peerEphemeralPublicKey: Uint8Array,
    contact: Contact,
    identityStore: IdentityStore,
    crypto: CryptoProvider
  ): Promise<void> {
    if (this._myEphemeralPrivateKey === null) {
      throw new IbexSessionError('Missing ephemeral private key - cannot process Accept');
    }

    if (peerEphemeralPublicKey.length !== 32) {
      throw new IbexSessionError('Invalid peer ephemeral public key length');
    }

    const negotiatedVersion = IbexSession.negotiateVersion(
      IbexSession.getSupportedVersionRange(),
      peerVersionRange
    );

    // Compute DH values
    const dhStaticStatic = await crypto.x25519(identityStore.privateKey, contact.publicKey);
    const dhEphemeralStatic = await crypto.x25519(this._myEphemeralPrivateKey, contact.publicKey);
    const dhStaticEphemeral = await crypto.x25519(identityStore.privateKey, peerEphemeralPublicKey);
    const dhEphemeralEphemeral = await crypto.x25519(
      this._myEphemeralPrivateKey,
      peerEphemeralPublicKey
    );

    // Derive 4DH ratchets
    const { myRatchet4DH, peerRatchet4DH } = await IbexSession.initKDF4DH(
      crypto,
      dhStaticStatic,
      dhEphemeralStatic,
      dhStaticEphemeral,
      dhEphemeralEphemeral,
      this._myIdentity,
      this._peerIdentity,
      this._config
    );

    // Update state
    this._myRatchet4DH = myRatchet4DH;
    this._peerRatchet4DH = peerRatchet4DH;
    this._current4DHVersions = { local: negotiatedVersion, remote: negotiatedVersion };

    // Discard 2DH ratchet and ephemeral private key
    this._myRatchet2DH = null;
    zeroize(this._myEphemeralPrivateKey);
    this._myEphemeralPrivateKey = null;
  }

  /**
   * Discards the responder's incoming 2DH ratchet.
   *
   * This completes the final transition to pure 4DH communication once the first
   * 4DH message is successfully processed, moving the state from `R24` to `RL44`.
   */
  discardPeerRatchet2DH(): void {
    this._peerRatchet2DH = null;
  }

  /**
   * Updates the protocol versions used for 4DH communication.
   *
   * @param versions - The negotiated local and remote protocol versions.
   */
  update4DHVersions(versions: IbexVersions): void {
    this._current4DHVersions = versions;
  }

  /**
   * Serializes the session state into a JSON-compatible object for persistent storage.
   *
   * @returns A serialized representation of the session, including active ratchets.
   */
  serialize(): SerializedIbexSession {
    return {
      id: this._id,
      myIdentity: this._myIdentity,
      peerIdentity: this._peerIdentity,
      myEphemeralPrivateKey: this._myEphemeralPrivateKey
        ? new Uint8Array(this._myEphemeralPrivateKey)
        : null,
      myEphemeralPublicKey: new Uint8Array(this._myEphemeralPublicKey),
      current4DHVersions: this._current4DHVersions,
      lastOutgoingMessageTimestamp: this._lastOutgoingMessageTimestamp,
      myRatchet2DH: this._myRatchet2DH ? this.serializeRatchet(this._myRatchet2DH) : null,
      myRatchet4DH: this._myRatchet4DH ? this.serializeRatchet(this._myRatchet4DH) : null,
      peerRatchet2DH: this._peerRatchet2DH ? this.serializeRatchet(this._peerRatchet2DH) : null,
      peerRatchet4DH: this._peerRatchet4DH ? this.serializeRatchet(this._peerRatchet4DH) : null,
    };
  }

  private serializeRatchet(ratchet: KDFRatchet): SerializedRatchet {
    return {
      counter: ratchet.counter,
      chainKey: ratchet.currentChainKey,
    };
  }

  /**
   * Restores an `IbexSession` from a serialized session state object retrieved from storage.
   *
   * Reconstructs the state machines for all active KDF ratchets and ensures internal state consistency.
   *
   * @param data - The serialized session data.
   * @param config - Optional configuration parameter overrides.
   * @returns The restored `IbexSession` instance.
   */
  static restore(
    data: SerializedIbexSession,
    config?: Partial<ResolvedIbexConfig>
  ): IbexSession {
    const resolvedConfig = resolveConfig(config);

    const deserializeRatchet = (r: SerializedRatchet | null): KDFRatchet | null => {
      if (!r) return null;
      return new KDFRatchet(r.counter, r.chainKey, resolvedConfig);
    };

    const session = new IbexSession(
      data.id,
      data.myIdentity,
      data.peerIdentity,
      data.myEphemeralPrivateKey,
      data.myEphemeralPublicKey,
      data.current4DHVersions,
      data.lastOutgoingMessageTimestamp,
      deserializeRatchet(data.myRatchet2DH),
      deserializeRatchet(data.myRatchet4DH),
      deserializeRatchet(data.peerRatchet2DH),
      deserializeRatchet(data.peerRatchet4DH),
      resolvedConfig
    );

    // Validate state consistency
    const state = session.state;
    if ((state === IbexSessionState.L20 || state === IbexSessionState.R20) && session._current4DHVersions) {
      // Clear 4DH versions in 2DH-only states
      session._current4DHVersions = null;
    }

    return session;
  }

  /**
   * Negotiate the protocol version to use between local and remote supported ranges.
   *
   * @param local - Local party's supported version range
   * @param remote - Remote party's supported version range
   * @returns The highest common version supported by both parties
   * @throws IbexSessionError if no common version exists or the range is invalid
   */
  private static negotiateVersion(local: VersionRange, remote: VersionRange): Version {
    // Handle legacy clients with no version range (default to 1.0)
    if (remote.min === 0 && remote.max === 0) {
      remote = { min: V.V1_0, max: V.V1_0 };
    }

    if (remote.max < remote.min) {
      throw new IbexSessionError(`Invalid version range: min=${remote.min}, max=${remote.max}`);
    }

    // Check for overlap between local and remote supported ranges
    if (remote.min > local.max || local.min > remote.max) {
      throw new IbexSessionError(
        `No common version: local=[${local.min},${local.max}], remote=[${remote.min},${remote.max}]`
      );
    }

    // Take minimum of maximum supported versions (highest common version)
    return Math.min(local.max, remote.max);
  }

  /**
   * Initialize a 2DH KDF ratchet.
   *
   * This is used for the initial forward security state before the full 4DH
   * handshake is completed.
   *
   * @param crypto - Crypto provider for BLAKE2b and X25519
   * @param dhStaticStatic - DH(localStatic, remoteStatic)
   * @param dhEphemeralStatic - DH(localEphemeral, remoteStatic)
   * @param identity - Identity string for salt derivation
   * @param config - Resolved configuration
   * @returns A new KDFRatchet initialized with derived K0
   */
  private static async initKDF2DH(
    crypto: CryptoProvider,
    dhStaticStatic: Uint8Array,
    dhEphemeralStatic: Uint8Array,
    identity: string,
    config: ResolvedIbexConfig
  ): Promise<KDFRatchet> {
    // Combine DH outputs: Static-Static and Ephemeral-Static
    const combined = concat(dhStaticStatic, dhEphemeralStatic);
    const salt = config.keSalt2DHPrefix + identity;

    // Derive K0 using BLAKE2b-256
    const k0 = await crypto.blake2b256(combined, config.kdfPersonal, salt, new Uint8Array(0));

    return new KDFRatchet(0, k0, config);
  }

  /**
   * Initialize 4DH KDF ratchets for both directions.
   *
   * The 4DH handshake combines four Diffie-Hellman outputs to ensure that the
   * resulting keys depend on both parties' static and ephemeral keys.
   *
   * @param crypto - Crypto provider
   * @param dhStaticStatic - DH(localStatic, remoteStatic)
   * @param dhEphemeralStatic - DH(localEphemeral, remoteStatic)
   * @param dhStaticEphemeral - DH(localStatic, remoteEphemeral)
   * @param dhEphemeralEphemeral - DH(localEphemeral, remoteEphemeral)
   * @param myIdentity - Local identity identifier for salt derivation
   * @param peerIdentity - Remote identity identifier for salt derivation
   * @param config - Resolved configuration
   * @returns Initialized outgoing and incoming 4DH ratchets
   */
  private static async initKDF4DH(
    crypto: CryptoProvider,
    dhStaticStatic: Uint8Array,
    dhEphemeralStatic: Uint8Array,
    dhStaticEphemeral: Uint8Array,
    dhEphemeralEphemeral: Uint8Array,
    myIdentity: string,
    peerIdentity: string,
    config: ResolvedIbexConfig
  ): Promise<{ myRatchet4DH: KDFRatchet; peerRatchet4DH: KDFRatchet }> {
    // Hash all 4 DH outputs together to create an intermediate master secret
    const combined = concat(
      dhStaticStatic,
      dhEphemeralStatic,
      dhStaticEphemeral,
      dhEphemeralEphemeral
    );
    // Use BLAKE2b-512 for the intermediate hash to preserve entropy
    const intermediateHash = await crypto.blake2b512(null, '', '', combined);

    // Derive per-identity keys (K0) for each direction
    const mySalt = config.keSalt4DHPrefix + myIdentity;
    const peerSalt = config.keSalt4DHPrefix + peerIdentity;

    const myK = await crypto.blake2b256(intermediateHash, config.kdfPersonal, mySalt, new Uint8Array(0));
    const peerK = await crypto.blake2b256(intermediateHash, config.kdfPersonal, peerSalt, new Uint8Array(0));

    return {
      myRatchet4DH: new KDFRatchet(0, myK, config),
      peerRatchet4DH: new KDFRatchet(0, peerK, config),
    };
  }

  toString(): string {
    return `IbexSession(id=${this._id.toHex().slice(0, 8)}..., state=${this.state}, versions=${
      this._current4DHVersions
        ? `${V.toString(this._current4DHVersions.local)}/${V.toString(this._current4DHVersions.remote)}`
        : 'none'
    })`;
  }
}
