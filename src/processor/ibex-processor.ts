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
/**
 * Result of committing a peer ratchet's state.
 *
 * Indicates whether the ratchet was successfully advanced or if it failed because
 * the session or ratchet could not be located.
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
 *
 * @example
 * ```ts
 * import { IbexProcessor } from '@privatemessaging/ibex';
 * import { MemoryIbexSessionStore } from '@privatemessaging/ibex';
 * import { defaultCryptoProvider } from '@privatemessaging/ibex/crypto';
 *
 * const processor = new IbexProcessor({
 *   sessionStore: new MemoryIbexSessionStore(),
 *   cryptoProvider: defaultCryptoProvider,
 * });
 * ```
 */
export class IbexProcessor {
  private readonly store: IbexSessionStore;
  private readonly crypto: CryptoProvider;
  private readonly config: ResolvedIbexConfig;
  private readonly events: IbexProcessorEvents;

  /**
   * Creates a new IbexProcessor instance.
   *
   * @param options - Configuration and dependency options.
   * @param options.sessionStore - Store for persisting and retrieving Ibex session states.
   * @param options.cryptoProvider - Provider for cryptographic operations (ECDH, hashing, encryption).
   * @param options.config - Optional protocol configuration settings overrides.
   * @param options.events - Optional callbacks for processor lifecycle events.
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
   * Encapsulates (encrypts) a plaintext message for a target contact, performing session establishment if needed.
   *
   * Cryptographic flow:
   * 1. Looks up the best existing session for the peer.
   * 2. If no session is found, initiates a new one using {@link IbexSession.createAsInitiator},
   *    and generates an `IbexInit` message prepended to the message queue.
   * 3. Encrypts the plaintext using the current active ratchet (prioritizing 4DH over 2DH)
   *    and advances the local outgoing ratchet.
   * 4. Updates the outgoing message timestamp.
   *
   * @param contact - The recipient's identity and long-term public key.
   * @param identityStore - Local identity store containing long-term identity keys.
   * @param plaintext - Raw bytes of the message to encrypt.
   * @returns A Promise resolving to the {@link EncapsulationResult} containing:
   *          - `messages`: Array of messages to send over the network (e.g., [Init, Message] or just [Message]).
   *          - `session`: The updated session object. The caller MUST persist this session state.
   *          - `mode`: The encryption mode applied (2DH or 4DH).
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
   * Processes an incoming session initiation request (`IbexInit`) from a peer contact.
   *
   * Cryptographic/Session flow:
   * 1. Verifies if a session with this ID already exists. If yes, rejects/ignores it with a `Terminate` message.
   * 2. Clears older sessions with this peer to prevent duplicate/stale state.
   * 3. Initializes a new responder session using {@link IbexSession.createAsResponder}.
   * 4. Persists the responder session in the session store.
   * 5. Returns an `IbexAccept` message to transmit back to the initiator.
   *
   * @param contact - The initiator's contact details.
   * @param identityStore - Local identity store containing long-term keys.
   * @param init - The incoming `IbexInit` message.
   * @returns A Promise resolving to an `IbexAccept` message on success (to be sent to the initiator),
   *          or an `IbexTerminate` message if session creation or version negotiation fails.
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
      // Re-sending Init is allowed (e.g. the peer missed our Accept); the
      // handshake must be idempotent, so re-send the Accept instead of
      // terminating the session the peer is about to use.
      return createAccept(
        init.sessionId,
        IbexSession.getSupportedVersionRange(),
        existing.myEphemeralPublicKey
      );
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
    } catch (e: any) {
      console.error('[Ibex] createAsResponder failed:', e);
      // Typically happens if version negotiation fails
      return createTerminate(init.sessionId, TerminateCause.DISABLED_BY_LOCAL);
    }
  }

  /**
   * Processes an incoming `IbexAccept` handshake response from a responder contact.
   *
   * Cryptographic/Session flow:
   * 1. Retrieves the matching session from storage.
   * 2. Computes the 4DH key agreements and transitions the session state to established 4DH (`RL44`).
   * 3. Persists the updated session in the session store.
   *
   * @param contact - The responder's contact details.
   * @param identityStore - Local identity store containing long-term keys.
   * @param accept - The incoming `IbexAccept` message.
   * @throws {Error} If no session with the corresponding session ID is found in the store.
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
   * Decrypts an incoming encrypted message (`IbexMessage`) using the appropriate session.
   *
   * Cryptographic/Session flow:
   * 1. Retrieves the session from storage.
   * 2. Selects the appropriate incoming ratchet (2DH or 4DH) based on the message type.
   * 3. Fast-forwards the ratchet state to match the message counter if messages were skipped.
   * 4. Derives the message decryption key and decrypts the ciphertext.
   * 5. Discards the peer's 2DH ratchet if the message is 4DH (completes responder transition to `RL44`).
   * 6. Persists the updated session state (note: the ratchet key is not advanced yet).
   *
   * **Important:** The recipient MUST call {@link IbexProcessor.commitPeerRatchet} after successfully
   * processing the message content to advance the ratchet state and prevent message key reuse.
   *
   * @param contact - The sender's contact details.
   * @param identityStore - Local identity store containing long-term keys.
   * @param message - The incoming `IbexMessage` to decrypt.
   * @returns A Promise resolving to a {@link DecryptionResult} containing the plaintext on success,
   *          or an `IbexReject` message to return to the sender if decryption or validation fails.
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
      console.error('[Ibex] STATE_MISMATCH: no ratchet found for dhType:', message.dhType);
      // Spec: on STATE_MISMATCH the session must be deleted so the peer's
      // follow-up Init can negotiate a fresh one.
      await this.store.delete(identityStore.identity, contact.identity, message.sessionId);
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
    } catch (e: any) {
      console.error('[Ibex] STATE_MISMATCH: turnUntil failed:', e.message || e);
      // Likely counter moved backwards or increment too large.
      // Spec: delete the session so it can be renegotiated.
      await this.store.delete(identityStore.identity, contact.identity, message.sessionId);
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
    } catch (e: any) {
      console.error('[Ibex] STATE_MISMATCH: symmetricDecrypt failed:', e.message || e);
      // Decryption failed - could be wrong key or corrupted data.
      // Spec: delete the session so it can be renegotiated.
      await this.store.delete(identityStore.identity, contact.identity, message.sessionId);
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
   * Commits the peer ratchet state by advancing it to the next ratchet turn.
   *
   * This is a critical post-decryption step. In the double-ratchet pattern, keys are
   * advanced and consumed immediately upon successful message processing. Delaying this
   * step until the application has fully processed the decrypted content ensures that
   * transient processing failures do not cause permanent message loss (allowing retries).
   *
   * @param identityStore - Local identity store containing long-term keys.
   * @param ratchetId - The identifier indicating which ratchet in which session to commit.
   * @returns A Promise resolving to a {@link CommitResult} indicating status of the operation.
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
   * Processes an incoming `IbexReject` message, terminating the associated session.
   *
   * Deletes the session from the session store and emits a session termination event.
   *
   * @param identityStore - Local identity store containing long-term keys.
   * @param contact - The peer who sent the reject message.
   * @param reject - The incoming `IbexReject` message.
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
   * Processes an incoming `IbexTerminate` message, terminating the associated session.
   *
   * Deletes the session from the session store and emits a session termination event.
   *
   * @param identityStore - Local identity store containing long-term keys.
   * @param contact - The peer who sent the terminate message.
   * @param terminate - The incoming `IbexTerminate` message.
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
   * Clears and terminates all active and historical sessions with a specific contact.
   *
   * This sends termination notices to the remote party and deletes all sessions
   * associated with the contact from local storage.
   *
   * @param identityStore - Local identity store containing long-term keys.
   * @param contact - The peer contact whose sessions should be cleared.
   * @param cause - The reason for terminating the sessions.
   * @returns A Promise resolving to an array of `IbexTerminate` messages to send to the contact.
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
