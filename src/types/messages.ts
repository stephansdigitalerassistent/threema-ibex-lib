import type { IbexSessionId } from '../core/session-id.js';
import type { DHType, Version, VersionRange } from './common.js';

/**
 * Ibex control message types.
 */
export enum IbexMessageType {
  /** Initiate a new session */
  INIT = 'init',
  /** Accept a session initiation */
  ACCEPT = 'accept',
  /** Reject an encrypted message */
  REJECT = 'reject',
  /** Terminate an active session */
  TERMINATE = 'terminate',
  /** An encapsulated encrypted message */
  MESSAGE = 'message',
}

/**
 * Reason for rejecting an incoming Ibex message.
 */
export enum RejectCause {
  /** The session ID specified in the message header is unknown to the receiver */
  UNKNOWN_SESSION = 1,
  /** The session is in a state that does not allow the requested operation (e.g., 4DH message before handshake complete) */
  STATE_MISMATCH = 2,
}

/**
 * Reason for terminating an Ibex session.
 */
export enum TerminateCause {
  /** The session is being manually reset by the local user */
  RESET = 1,
  /** The receiver of a message does not recognize the session ID */
  UNKNOWN_SESSION = 2,
  /** The local party has disabled Ibex forward secrecy for this contact */
  DISABLED_BY_LOCAL = 3,
  /** The remote party has disabled Ibex forward secrecy */
  DISABLED_BY_REMOTE = 4,
}

/**
 * Base interface for all Ibex protocol messages.
 */
export interface IbexMessageBase {
  /** The specific type of this Ibex message */
  type: IbexMessageType;
  /** The unique session identifier */
  sessionId: IbexSessionId;
}

/**
 * Init message: Sent by the initiator to propose a new forward-secure session.
 */
export interface IbexInit extends IbexMessageBase {
  type: IbexMessageType.INIT;
  /** The range of protocol versions the initiator supports */
  versionRange: VersionRange;
  /** The initiator's ephemeral X25519 public key (32 bytes) */
  ephemeralPublicKey: Uint8Array;
}

/**
 * Accept message: Sent by the responder to accept a session initiation.
 * Completes the first half of the 4DH handshake.
 */
export interface IbexAccept extends IbexMessageBase {
  type: IbexMessageType.ACCEPT;
  /** The range of protocol versions the responder supports */
  versionRange: VersionRange;
  /** The responder's ephemeral X25519 public key (32 bytes) */
  ephemeralPublicKey: Uint8Array;
}

/**
 * Reject message: Sent when an encapsulated message cannot be decrypted or processed.
 */
export interface IbexReject extends IbexMessageBase {
  type: IbexMessageType.REJECT;
  /** The identifier of the message that was rejected */
  rejectedMessageId: Uint8Array;
  /** The reason why the message was rejected */
  cause: RejectCause;
  /** Optional group identity if the rejected message was a group message */
  groupIdentity?: GroupIdentity;
}

/**
 * Terminate message: Sent to signal that a session is being closed.
 */
export interface IbexTerminate extends IbexMessageBase {
  type: IbexMessageType.TERMINATE;
  /** The reason why the session is being terminated */
  cause: TerminateCause;
}

/**
 * IbexMessage: Encapsulates an encrypted payload with forward security.
 */
export interface IbexMessage extends IbexMessageBase {
  type: IbexMessageType.MESSAGE;
  /** Whether 2DH or 4DH was used for encryption */
  dhType: DHType;
  /** The ratchet counter (increments for every message) */
  counter: number;
  /** The maximum protocol version the sender supports */
  offeredVersion: Version;
  /** The protocol version actually applied to this message */
  appliedVersion: Version;
  /** Optional group identity if this is a group message */
  groupIdentity?: GroupIdentity;
  /** The AEAD-encrypted message payload */
  encryptedData: Uint8Array;
}

/**
 * Group identity for group messages
 */
export interface GroupIdentity {
  /** Group creator's identity */
  creatorIdentity: string;
  /** Group ID */
  groupId: Uint8Array;
}

/**
 * Union type for all Ibex messages
 */
export type IbexControlMessage = IbexInit | IbexAccept | IbexReject | IbexTerminate | IbexMessage;

/**
 * Create an Init message
 */
export function createInit(
  sessionId: IbexSessionId,
  versionRange: VersionRange,
  ephemeralPublicKey: Uint8Array
): IbexInit {
  return {
    type: IbexMessageType.INIT,
    sessionId,
    versionRange,
    ephemeralPublicKey: new Uint8Array(ephemeralPublicKey),
  };
}

/**
 * Create an Accept message
 */
export function createAccept(
  sessionId: IbexSessionId,
  versionRange: VersionRange,
  ephemeralPublicKey: Uint8Array
): IbexAccept {
  return {
    type: IbexMessageType.ACCEPT,
    sessionId,
    versionRange,
    ephemeralPublicKey: new Uint8Array(ephemeralPublicKey),
  };
}

/**
 * Create a Reject message
 */
export function createReject(
  sessionId: IbexSessionId,
  rejectedMessageId: Uint8Array,
  cause: RejectCause,
  groupIdentity?: GroupIdentity
): IbexReject {
  return {
    type: IbexMessageType.REJECT,
    sessionId,
    rejectedMessageId: new Uint8Array(rejectedMessageId),
    cause,
    groupIdentity,
  };
}

/**
 * Create a Terminate message
 */
export function createTerminate(
  sessionId: IbexSessionId,
  cause: TerminateCause
): IbexTerminate {
  return {
    type: IbexMessageType.TERMINATE,
    sessionId,
    cause,
  };
}

/**
 * Create an encapsulated Message
 */
export function createMessage(
  sessionId: IbexSessionId,
  dhType: DHType,
  counter: number,
  offeredVersion: Version,
  appliedVersion: Version,
  encryptedData: Uint8Array,
  groupIdentity?: GroupIdentity
): IbexMessage {
  return {
    type: IbexMessageType.MESSAGE,
    sessionId,
    dhType,
    counter,
    offeredVersion,
    appliedVersion,
    encryptedData: new Uint8Array(encryptedData),
    groupIdentity,
  };
}
