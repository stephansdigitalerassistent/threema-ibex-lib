import type { IbexSessionId } from '../core/session-id.js';
import { IbexSessionState } from './common.js';
import type { Version } from './common.js';

/**
 * Serialized state of a KDF ratchet.
 * Used for persisting the forward security state to a storage backend.
 */
export interface SerializedRatchet {
  /** The current ratchet counter value */
  counter: number;
  /** The 32-byte current chain key */
  chainKey: Uint8Array;
}

/**
 * Serialized state of a full Ibex session.
 * Contains all the information needed to restore an active session from storage.
 */
export interface SerializedIbexSession {
  /** The unique session identifier */
  id: IbexSessionId;
  /** Local identity identifier (e.g., Threema ID) */
  myIdentity: string;
  /** Remote party's identity identifier */
  peerIdentity: string;
  /**
   * The initiator's ephemeral private key.
   * This is only kept until an Accept message is received, then it's zeroed out.
   */
  myEphemeralPrivateKey: Uint8Array | null;
  /** The local party's ephemeral public key for this session */
  myEphemeralPublicKey: Uint8Array;
  /**
   * Currently negotiated 4DH protocol versions.
   * Null if the session is still in the 2DH initiation phase.
   */
  current4DHVersions: { local: Version; remote: Version } | null;
  /** Timestamp (ms) when the last outgoing message was sent */
  lastOutgoingMessageTimestamp: number;
  /** Serialized outgoing 2DH ratchet (if present) */
  myRatchet2DH: SerializedRatchet | null;
  /** Serialized outgoing 4DH ratchet (if present) */
  myRatchet4DH: SerializedRatchet | null;
  /** Serialized incoming 2DH ratchet (if present) */
  peerRatchet2DH: SerializedRatchet | null;
  /** Serialized incoming 4DH ratchet (if present) */
  peerRatchet4DH: SerializedRatchet | null;
}

/**
 * Interface for Ibex session storage backends.
 *
 * Implementations of this interface handle the persistence of Ibex sessions.
 * This allows the library to be used with various storage technologies such as
 * SQLite, IndexedDB, or simple in-memory maps.
 */
export interface IbexSessionStore {
  /**
   * Store or update a serialized Ibex session.
   *
   * @param session - The serialized session data to persist
   */
  store(session: SerializedIbexSession): Promise<void>;

  /**
   * Retrieve a specific Ibex session by its ID.
   *
   * @param myIdentity - Local party's identity
   * @param peerIdentity - Remote party's identity
   * @param sessionId - Unique session identifier
   * @returns The serialized session if found, or null
   */
  get(
    myIdentity: string,
    peerIdentity: string,
    sessionId: IbexSessionId
  ): Promise<SerializedIbexSession | null>;

  /**
   * Retrieve the "best" active session for a contact.
   *
   * Usually prefers sessions in the RL44 (full 4DH) state.
   *
   * @param myIdentity - Local party's identity
   * @param peerIdentity - Remote party's identity
   * @returns The best available session, or null
   */
  getBest(
    myIdentity: string,
    peerIdentity: string
  ): Promise<SerializedIbexSession | null>;

  /**
   * Retrieve all Ibex sessions associated with a specific contact.
   *
   * @param myIdentity - Local party's identity
   * @param peerIdentity - Remote party's identity
   * @returns An array of serialized sessions
   */
  getAll(
    myIdentity: string,
    peerIdentity: string
  ): Promise<SerializedIbexSession[]>;

  /**
   * Delete a specific Ibex session from storage.
   *
   * @param myIdentity - Local party's identity
   * @param peerIdentity - Remote party's identity
   * @param sessionId - Unique session identifier
   * @returns A promise that resolves to true if the session was found and deleted
   */
  delete(
    myIdentity: string,
    peerIdentity: string,
    sessionId: IbexSessionId
  ): Promise<boolean>;

  /**
   * Delete multiple sessions for a contact, optionally keeping specific ones.
   *
   * @param myIdentity - Local party's identity
   * @param peerIdentity - Remote party's identity
   * @param exceptSessionId - The ID of a session that should NOT be deleted
   * @param keepL20Sessions - Whether to preserve initiator-only (L20) sessions
   * @returns A promise that resolves to the number of sessions deleted
   */
  deleteAllExcept(
    myIdentity: string,
    peerIdentity: string,
    exceptSessionId: IbexSessionId,
    keepL20Sessions: boolean
  ): Promise<number>;

  /**
   * Delete all Ibex sessions for a specific contact.
   *
   * @param myIdentity - Local party's identity
   * @param peerIdentity - Remote party's identity
   * @returns A promise that resolves to the number of sessions deleted
   */
  deleteAll(myIdentity: string, peerIdentity: string): Promise<number>;
}

/**
 * Determine session state from ratchet availability
 */
export function getSessionState(session: SerializedIbexSession): IbexSessionState {
  const { myRatchet2DH, myRatchet4DH, peerRatchet2DH, peerRatchet4DH } = session;

  if (!myRatchet2DH && myRatchet4DH && !peerRatchet2DH && peerRatchet4DH) {
    return IbexSessionState.RL44;
  }
  if (!myRatchet2DH && peerRatchet2DH && myRatchet4DH && peerRatchet4DH) {
    return IbexSessionState.R24;
  }
  if (myRatchet2DH && !myRatchet4DH && !peerRatchet2DH && !peerRatchet4DH) {
    return IbexSessionState.L20;
  }
  if (!myRatchet2DH && !myRatchet4DH && peerRatchet2DH && !peerRatchet4DH) {
    return IbexSessionState.R20;
  }

  throw new Error(
    `Invalid session state: my2DH=${!!myRatchet2DH}, my4DH=${!!myRatchet4DH}, ` +
      `peer2DH=${!!peerRatchet2DH}, peer4DH=${!!peerRatchet4DH}`
  );
}
