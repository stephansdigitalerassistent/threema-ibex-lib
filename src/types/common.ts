/**
 * Protocol version encoding: major version in high byte, minor in low byte.
 * e.g., 0x0100 = 1.0, 0x0101 = 1.1, 0x0102 = 1.2.
 */
export type Version = number;

/**
 * Utility functions for protocol versions.
 */
export const Version = {
  /** Unspecified version (0.0) */
  UNSPECIFIED: 0,
  /** Version 1.0 */
  V1_0: 0x0100,
  /** Version 1.1 */
  V1_1: 0x0101,
  /** Version 1.2 */
  V1_2: 0x0102,

  /** Extract major version byte */
  major(v: Version): number {
    return (v >> 8) & 0xff;
  },

  /** Extract minor version byte */
  minor(v: Version): number {
    return v & 0xff;
  },

  /** Create version from major and minor components */
  create(major: number, minor: number): Version {
    return ((major & 0xff) << 8) | (minor & 0xff);
  },

  /** Format version as string (e.g., "1.2") */
  toString(v: Version): string {
    return `${Version.major(v)}.${Version.minor(v)}`;
  },
} as const;

/**
 * A range of supported protocol versions.
 */
export interface VersionRange {
  /** Minimum supported version (inclusive) */
  min: Version;
  /** Maximum supported version (inclusive) */
  max: Version;
}

/**
 * Diffie-Hellman type indicating which ratchet handshake was used.
 */
export enum DHType {
  /** 2-element Diffie-Hellman (initial fallback) */
  TWODH = 1,
  /** 4-element Diffie-Hellman (full forward secrecy) */
  FOURDH = 2,
}

/**
 * Ibex encryption mode used for a specific message.
 */
export enum IbexMode {
  /** No encryption / Plaintext (should not be used for Ibex messages) */
  NONE = 0,
  /** Encrypted using the 2DH ratchet */
  TWODH = 1,
  /** Encrypted using the 4DH ratchet */
  FOURDH = 2,
}

/**
 * Ibex session states representing the progression of the handshake.
 */
export enum IbexSessionState {
  /** Locally initiated, outgoing 2DH available. Waiting for Accept from peer. */
  L20 = 'L20',
  /** Remotely initiated, incoming 2DH available. Responder has sent Accept but hasn't received first 4DH message. */
  R20 = 'R20',
  /** Remotely initiated, incoming 2DH available and outgoing 4DH available. Peer hasn't yet transitioned to 4DH. */
  R24 = 'R24',
  /** Full 4DH established in both directions. Fallback 2DH ratchets have been discarded. */
  RL44 = 'RL44',
}

/**
 * Configuration for Ibex protocol constants
 * All values have Threema-compatible defaults
 */
export interface IbexConfig {
  /** KDF personalization string (default: "3ma-e2e") */
  kdfPersonal?: string;
  /** Salt for deriving chain keys (default: "kdf-ck") */
  kdfSaltChainKey?: string;
  /** Salt for deriving encryption keys (default: "kdf-aek") */
  kdfSaltEncryptionKey?: string;
  /** Prefix for 2DH key exchange salt (default: "ke-2dh-") */
  keSalt2DHPrefix?: string;
  /** Prefix for 4DH key exchange salt (default: "ke-4dh-") */
  keSalt4DHPrefix?: string;
  /** Maximum ratchet turns allowed in one operation (default: 25000) */
  maxCounterIncrement?: number;
}

/**
 * Resolved configuration with all defaults applied
 */
export interface ResolvedIbexConfig {
  kdfPersonal: string;
  kdfSaltChainKey: string;
  kdfSaltEncryptionKey: string;
  keSalt2DHPrefix: string;
  keSalt4DHPrefix: string;
  maxCounterIncrement: number;
}

/**
 * Default Threema-compatible configuration values
 */
export const DEFAULT_CONFIG: ResolvedIbexConfig = {
  kdfPersonal: '3ma-e2e',
  kdfSaltChainKey: 'kdf-ck',
  kdfSaltEncryptionKey: 'kdf-aek',
  keSalt2DHPrefix: 'ke-2dh-',
  keSalt4DHPrefix: 'ke-4dh-',
  maxCounterIncrement: 25000,
};

/**
 * Resolve partial config to full config with defaults
 */
export function resolveConfig(config?: IbexConfig): ResolvedIbexConfig {
  return {
    ...DEFAULT_CONFIG,
    ...config,
  };
}
