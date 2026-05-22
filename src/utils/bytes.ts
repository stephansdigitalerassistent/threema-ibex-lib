/**
 * Concatenate multiple Uint8Arrays into a single array
 */
export function concat(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/**
 * Convert a string to UTF-8 bytes
 */
export function stringToBytes(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

/**
 * Convert bytes to a string (UTF-8)
 */
export function bytesToString(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

/**
 * Convert bytes to hex string
 *
 * @example
 * ```ts
 * import { bytesToHex } from '@privatemessaging/ibex';
 *
 * const hex = bytesToHex(new Uint8Array([1, 2, 3])); // '010203'
 * ```
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Convert hex string to bytes
 *
 * @example
 * ```ts
 * import { hexToBytes } from '@privatemessaging/ibex';
 *
 * const bytes = hexToBytes('010203'); // Uint8Array [ 1, 2, 3 ]
 * ```
 */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error('Invalid hex string length');
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Compare two Uint8Arrays for equality (constant-time)
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/**
 * Securely zero out a Uint8Array
 */
export function zeroize(arr: Uint8Array): void {
  arr.fill(0);
}

/**
 * Create a zero-filled nonce of the specified length
 */
export function zeroNonce(length: number): Uint8Array {
  return new Uint8Array(length);
}
