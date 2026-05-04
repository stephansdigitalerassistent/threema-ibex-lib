import type { CryptoProvider } from '../types/crypto.js';
import type { IbexSessionStore } from '../types/storage.js';
import type { ResolvedIbexConfig } from '../types/common.js';
import {
  DHType,
  IbexMode,
  resolveConfig,
  Version,
} from '../types/common.js';
import type {
  IbexInit,
  IbexAccept,
  IbexReject,
  IbexTerminate,
  IbexMessage,
} from '../types/messages.js';
import {
  RejectCause,
  TerminateCause,
  createInit,
  createAccept,
  createReject,
  createTerminate,
  createMessage,
} from '../types/messages.js';
import { IbexSession, Contact, IdentityStore } from '../core/ibex-session.js';
import { IbexSessionId } from '../core/session-id.js';
import { CryptoConstants } from '../types/crypto.js';
import { zeroNonce } from '../utils/bytes.js';

/**
 * Result of decrypting an encapsulated message.
 */
export interface DecryptionResult {
  /** Decrypted plaintext (typically starts with a type byte followed by the message body) */
  plaintext: Uint8Array;
  /** The forward security mode (2DH or 4DH) that was used to encrypt this message */
  mode: IbexMode;
  /** The protocol version applied to this message */
  appliedVersion: Version;
  /** Information needed to commit the peer ratchet state after successful processing */
  ratchetId: RatchetIdentifier;
}

/**
 * Identifies which ratchet (session + identity + DH type) was used for decryption.
 * Used to advance the correct ratchet state in the session store.
 */
export interface RatchetIdentifier {
  /** The session identifier */
  sessionId: IbexSessionId;
  /** The identity of the peer who sent the message */
  peerIdentity: string;
  /** Whether 2DH or 4DH was used */
  dhType: DHType;
}

/**
 * Result of committing a peer ratchet's state.
 */
export type CommitResult =
  | { committed: true }
  | { committed: false; reason: 'session_not_found' | 'ratchet_not_found' };

/**
 * Result of encrypting a plaintext message.
 */
export interface EncryptionResult {
  /** The fully encrypted Ibex message, ready for transport */
  message: IbexMessage;
  /** The updated session state (must be persisted once the message is successfully sent) */
  session: IbexSession;
}

/**
 * Result of running the full encapsulation steps for a plaintext.
 * May involve multiple messages if a new session needs to be initiated.
 */
export interface EncapsulationResult {
  /**
   * Ordered list of messages to send to the peer.
   * If a new session is started, this will include an IbexInit message before the IbexMessage.
   */
  messages: (IbexInit | IbexMessage)[];
  /** The updated session state to persist after sending */
  session: IbexSession | null;
  /** The forward security mode used for the main message (2DH or 4DH) */
  mode: IbexMode;
}

/**
 * Callbacks for events emitted by the IbexProcessor.
 * Useful for logging, metrics, or triggering external logic (e.g., UI updates).
 */
export interface IbexProcessorEvents {
  /** Emitted when a new session is locally initiated */
  onSessionInitiated?(session: IbexSession, contact: Contact): void;
  /** Emitted when a session is successfully established as a responder (after receiving Init) */
  onSessionEstablishedAsResponder?(session: IbexSession, contact: Contact): void;
  /** Emitted when a session is successfully established as an initiator (after receiving Accept) */
  onSessionEstablishedAsInitiator?(session: IbexSession, contact: Contact): void;
  /** Emitted when a session is terminated (e.g., due to a Reject or Terminate message) */
  onSessionTerminated?(sessionId: IbexSessionId, contact: Contact, cause: TerminateCause): void;
  /** Emitted when messages were skipped because the peer's counter advanced faster than expected */
  onMessagesSkipped?(sessionId: IbexSessionId, contact: Contact, count: number): void;
  /** Emitted when the first 4DH message is successfully received in a session */
  onFirst4DHMessageReceived?(session: IbexSession, contact: Contact): void;
}

/**
 * Ibex Message Processor.
 *
 * This is the primary entry point for using the Ibex protocol. It coordinates
 * session management, encryption, and decryption, interacting with a session
 * store and a crypto provider.
 */
export class IbexProcessor {
  private readonly store: IbexSessionStore;
  private readonly crypto: CryptoProvider;
  private readonly config: ResolvedIbexConfig;
  private readonly events: IbexProcessorEvents;

  /**
   * Create a new IbexProcessor.
   *
   * @param options - Configuration options
   */
  constructor(options: {
    /** Store for persisting Ibex sessions */
    sessionStore: IbexSessionStore;
    /** Provider for cryptographic primitives (X25519, BLAKE2b, AEAD) */
    cryptoProvider: CryptoProvider;
    /** Optional protocol configuration overrides */
    config?: Partial<ResolvedIbexConfig>;
    /** Optional event handlers */
    events?: IbexProcessorEvents;
  }) {
    this.store = options.sessionStore;
    this.crypto = options.cryptoProvider;
    this.config = resolveConfig(options.config);
    this.events = options.events ?? {};
  }

  /**
   * Encapsulate a plaintext message for a contact.
   *
   * If no active session exists with the contact, a new session is initiated,
   * and an `IbexInit` message is prepended to the result.
   *
   * @param contact - Remote contact to send to
   * @param identityStore - Local identity store
   * @param plaintext - Data to encrypt
   * @returns The messages to send and the updated session state
   */
  async encapsulate(
    contact: Contact,
    identityStore: IdentityStore,
    plaintext: Uint8Array
  ): Promise<EncapsulationResult> {
    const messages: (IbexInit | IbexMessage)[] = [];

    // Attempt to retrieve the best existing session for this contact
    let session = await this.getBestSession(identityStore.identity, contact.identity);

    if (!session) {
      // No session found, initiate a new one
      session = await IbexSession.createAsInitiator(contact, identityStore, this.crypto, this.config);

      // Create the Init message to establish the session on the responder's side
      const init = createInit(
        session.id,
        IbexSession.getSupportedVersionRange(),
        session.myEphemeralPublicKey
      );
      messages.push(init);

      this.events.onSessionInitiated?.(session, contact);
    }

    // Encapsulate the actual plaintext within the session (either the new or existing one)
    const encrypted = await this.encapsulateInSession(session, plaintext);
    messages.push(encrypted.message);

    // Update session timestamp for LRU-like management
    session.lastOutgoingMessageTimestamp = Date.now();

    return {
      messages,
      session: encrypted.session,
      mode: encrypted.message.dhType === DHType.FOURDH
        ? IbexMode.FOURDH
        : IbexMode.TWODH,
    };
  }

  /**
   * Internal helper to encrypt a message using an active session.
   */
  private async encapsulateInSession(
    session: IbexSession,
    plaintext: Uint8Array
  ): Promise<EncryptionResult> {
    // Determine which ratchet to use: prefer 4DH if established, otherwise fall back to 2DH
    let ratchet = session.myRatchet4DH;
    let dhType = DHType.FOURDH;

    if (!ratchet) {
      ratchet = session.myRatchet2DH;
      dhType = DHType.TWODH;

      if (!ratchet) {
        throw new Error('No outgoing ratchet available in session');
      }
    }

    // Derive the encryption key for the current ratchet turn
    const encryptionKey = await ratchet.getCurrentEncryptionKey(this.crypto);
    const counter = ratchet.counter;
    // Advance the ratchet immediately after deriving the key
    await ratchet.turn(this.crypto);

    // Encrypt with a zero nonce. This is safe because every ratchet turn
    // derives a unique message key.
    const nonce = zeroNonce(CryptoConstants.NONCE_BYTES);
    const ciphertext = await this.crypto.symmetricEncrypt(plaintext, encryptionKey, nonce);

    // Determine protocol versions to include in the message header
    const versions = session.current4DHVersions;
    const offeredVersion = versions?.local ?? Version.V1_0;
    const appliedVersion = versions?.local ?? Version.V1_0;

    const message = createMessage(
      session.id,
      dhType,
      counter,
      offeredVersion,
      appliedVersion,
      ciphertext
    );

    return { message, session };
  }

  /**
   * Process an incoming Init message from a peer.
   *
   * @param contact - The peer sending the Init
   * @param identityStore - Local identity store
   * @param init - The Init message
   * @returns An Accept message to establish the session, or Terminate on failure
   */
  async processInit(
    contact: Contact,
    identityStore: IdentityStore,
    init: IbexInit
  ): Promise<IbexAccept | IbexTerminate> {
    // Check if a session with this ID already exists
    const existing = await this.store.get(
      identityStore.identity,
      contact.identity,
      init.sessionId
    );
    if (existing) {
      // Re-sending Init is allowed, but we don't need to re-process it if already established
      return createTerminate(init.sessionId, TerminateCause.UNKNOWN_SESSION);
    }

    // Delete any existing sessions that have 4DH established to avoid ambiguity,
    // but keep L20 (initiator-only) sessions as they might be part of a race condition.
    await this.store.deleteAllExcept(
      identityStore.identity,
      contact.identity,
      init.sessionId,
      true
    );

    try {
      // Create a new session as the responder
      const session = await IbexSession.createAsResponder(
        init.sessionId,
        init.versionRange,
        init.ephemeralPublicKey,
        contact,
        identityStore,
        this.crypto,
        this.config
      );

      session.lastOutgoingMessageTimestamp = Date.now();

      // Persist the newly created session
      await this.store.store(session.serialize());

      this.events.onSessionEstablishedAsResponder?.(session, contact);

      // Respond with Accept to complete the handshake
      return createAccept(
        init.sessionId,
        IbexSession.getSupportedVersionRange(),
        session.myEphemeralPublicKey
      );
    } catch {
      // Typically happens if version negotiation fails
      return createTerminate(init.sessionId, TerminateCause.DISABLED_BY_LOCAL);
    }
  }

  /**
   * Process an incoming Accept message (as initiator).
   *
   * @param contact - The peer sending the Accept
   * @param identityStore - Local identity store
   * @param accept - The Accept message
   */
  async processAccept(
    contact: Contact,
    identityStore: IdentityStore,
    accept: IbexAccept
  ): Promise<void> {
    const serialized = await this.store.get(
      identityStore.identity,
      contact.identity,
      accept.sessionId
    );

    if (!serialized) {
      throw new Error(`Session not found for Accept: ${accept.sessionId.toHex()}`);
    }

    const session = IbexSession.restore(serialized, this.config);

    // Complete the 4DH handshake using the peer's ephemeral key from the Accept message
    await session.processAccept(
      accept.versionRange,
      accept.ephemeralPublicKey,
      contact,
      identityStore,
      this.crypto
    );

    // Persist the upgraded (2DH -> 4DH) session
    await this.store.store(session.serialize());

    this.events.onSessionEstablishedAsInitiator?.(session, contact);
  }

  /**
   * Process an encapsulated incoming IbexMessage.
   *
   * This decodes and decrypts the message, advancing the peer's ratchet
   * state if necessary to match the message counter.
   *
   * @param contact - The peer sending the message
   * @param identityStore - Local identity store
   * @param message - The Ibex message
   * @returns DecryptionResult on success, or IbexReject on failure
   */
  async processMessage(
    contact: Contact,
    identityStore: IdentityStore,
    message: IbexMessage
  ): Promise<DecryptionResult | IbexReject> {
    const serialized = await this.store.get(
      identityStore.identity,
      contact.identity,
      message.sessionId
    );

    if (!serialized) {
      return createReject(
        message.sessionId,
        new Uint8Array(16),
        RejectCause.UNKNOWN_SESSION,
        message.groupIdentity
      );
    }

    const session = IbexSession.restore(serialized, this.config);

    // Select the correct incoming ratchet based on whether the message uses 2DH or 4DH
    const ratchet = message.dhType === DHType.TWODH
      ? session.peerRatchet2DH
      : session.peerRatchet4DH;

    if (!ratchet) {
      return createReject(
        message.sessionId,
        new Uint8Array(16),
        RejectCause.STATE_MISMATCH,
        message.groupIdentity
      );
    }

    // Fast-forward the ratchet if the peer's counter is ahead (indicates skipped messages)
    try {
      const numSkipped = await ratchet.turnUntil(this.crypto, message.counter);
      if (numSkipped > 0) {
        this.events.onMessagesSkipped?.(message.sessionId, contact, numSkipped);
      }
    } catch {
      // Likely counter moved backwards or increment too large
      return createReject(
        message.sessionId,
        new Uint8Array(16),
        RejectCause.STATE_MISMATCH,
        message.groupIdentity
      );
    }

    // Derive message key and decrypt ciphertext
    const encryptionKey = await ratchet.getCurrentEncryptionKey(this.crypto);
    const nonce = zeroNonce(CryptoConstants.NONCE_BYTES);

    let plaintext: Uint8Array;
    try {
      plaintext = await this.crypto.symmetricDecrypt(message.encryptedData, encryptionKey, nonce);
    } catch {
      // Decryption failed - could be wrong key or corrupted data
      return createReject(
        message.sessionId,
        new Uint8Array(16),
        RejectCause.STATE_MISMATCH,
        message.groupIdentity
      );
    }

    // Special event for the transition to 4DH communication
    if (message.dhType === DHType.FOURDH && ratchet.counter === 0) {
      this.events.onFirst4DHMessageReceived?.(session, contact);
    }

    // Once a 4DH message is received, the 2DH fallback is no longer needed
    if (message.dhType === DHType.FOURDH && session.peerRatchet2DH) {
      session.discardPeerRatchet2DH();
    }

    // Persist the session state. NOTE: The ratchet is NOT advanced yet.
    // It must be advanced via commitPeerRatchet once the app confirms processing.
    await this.store.store(session.serialize());

    const mode = message.dhType === DHType.FOURDH
      ? IbexMode.FOURDH
      : IbexMode.TWODH;

    return {
      plaintext,
      mode,
      appliedVersion: message.appliedVersion,
      ratchetId: {
        sessionId: message.sessionId,
        peerIdentity: contact.identity,
        dhType: message.dhType,
      },
    };
  }

  /**
   * Commit the peer ratchet after message processing is complete.
   *
   * Advancing the ratchet only AFTER processing ensures that if the app crashes
   * or fails to process a message, it can be retried with the same key.
   *
   * @param identityStore - Local identity store
   * @param ratchetId - Identifier for the ratchet to advance
   * @returns Result indicating whether the commit succeeded
   */
  async commitPeerRatchet(
    identityStore: IdentityStore,
    ratchetId: RatchetIdentifier
  ): Promise<CommitResult> {
    const serialized = await this.store.get(
      identityStore.identity,
      ratchetId.peerIdentity,
      ratchetId.sessionId
    );

    if (!serialized) {
      return { committed: false, reason: 'session_not_found' };
    }

    const session = IbexSession.restore(serialized, this.config);
    const ratchet = ratchetId.dhType === DHType.TWODH
      ? session.peerRatchet2DH
      : session.peerRatchet4DH;

    if (!ratchet) {
      return { committed: false, reason: 'ratchet_not_found' };
    }

    // Advance the ratchet to the next turn (consumes the current message key)
    await ratchet.turn(this.crypto);
    await this.store.store(session.serialize());
    return { committed: true };
  }

  /**
   * Process a Reject message
   */
  async processReject(
    identityStore: IdentityStore,
    contact: Contact,
    reject: IbexReject
  ): Promise<void> {
    // Delete the session
    await this.store.delete(
      identityStore.identity,
      contact.identity,
      reject.sessionId
    );

    this.events.onSessionTerminated?.(reject.sessionId, contact, TerminateCause.RESET);
  }

  /**
   * Process a Terminate message
   */
  async processTerminate(
    identityStore: IdentityStore,
    contact: Contact,
    terminate: IbexTerminate
  ): Promise<void> {
    await this.store.delete(
      identityStore.identity,
      contact.identity,
      terminate.sessionId
    );

    this.events.onSessionTerminated?.(terminate.sessionId, contact, terminate.cause);
  }

  /**
   * Clear and terminate all sessions with a contact
   */
  async clearAndTerminateAllSessions(
    identityStore: IdentityStore,
    contact: Contact,
    cause: TerminateCause
  ): Promise<IbexTerminate[]> {
    const sessions = await this.store.getAll(identityStore.identity, contact.identity);
    const terminates: IbexTerminate[] = [];

    for (const session of sessions) {
      terminates.push(createTerminate(session.id, cause));
      this.events.onSessionTerminated?.(session.id, contact, cause);
    }

    await this.store.deleteAll(identityStore.identity, contact.identity);

    return terminates;
  }

  /**
   * Get the best session for a contact
   */
  private async getBestSession(
    myIdentity: string,
    peerIdentity: string
  ): Promise<IbexSession | null> {
    const serialized = await this.store.getBest(myIdentity, peerIdentity);
    if (!serialized) {
      return null;
    }
    return IbexSession.restore(serialized, this.config);
  }
}
