import type { IbexSessionId } from '../core/session-id.js';
import type { IbexSessionStore, SerializedIbexSession } from '../types/storage.js';
import { IbexSessionState } from '../types/common.js';
import { getSessionState } from '../types/storage.js';

/**
 * In-memory Ibex session store
 *
 * Useful for testing and simple applications.
 * Data is lost when the process exits.
 */
export class MemoryIbexSessionStore implements IbexSessionStore {
  private sessions = new Map<string, SerializedIbexSession>();

  private makeKey(myIdentity: string, peerIdentity: string, sessionId: IbexSessionId): string {
    return `${myIdentity}:${peerIdentity}:${sessionId.toHex()}`;
  }

  private makePeerKey(myIdentity: string, peerIdentity: string): string {
    return `${myIdentity}:${peerIdentity}`;
  }

  async store(session: SerializedIbexSession): Promise<void> {
    const key = this.makeKey(session.myIdentity, session.peerIdentity, session.id);
    this.sessions.set(key, { ...session });
  }

  async get(
    myIdentity: string,
    peerIdentity: string,
    sessionId: IbexSessionId
  ): Promise<SerializedIbexSession | null> {
    const key = this.makeKey(myIdentity, peerIdentity, sessionId);
    const session = this.sessions.get(key);
    return session ? { ...session } : null;
  }

  async getBest(
    myIdentity: string,
    peerIdentity: string
  ): Promise<SerializedIbexSession | null> {
    const allSessions = await this.getAll(myIdentity, peerIdentity);
    if (allSessions.length === 0) {
      return null;
    }

    // Prefer sessions in RL44 state, then sort by session ID (hex comparison)
    const rl44Sessions = allSessions.filter((s) => {
      try {
        return getSessionState(s) === IbexSessionState.RL44;
      } catch {
        return false;
      }
    });

    const candidates = rl44Sessions.length > 0 ? rl44Sessions : allSessions;

    // Sort by session ID (lowest first)
    candidates.sort((a, b) => a.id.toHex().localeCompare(b.id.toHex()));

    return { ...candidates[0] };
  }

  async getAll(
    myIdentity: string,
    peerIdentity: string
  ): Promise<SerializedIbexSession[]> {
    const prefix = this.makePeerKey(myIdentity, peerIdentity);
    const result: SerializedIbexSession[] = [];

    for (const [key, session] of this.sessions) {
      if (key.startsWith(prefix + ':')) {
        result.push({ ...session });
      }
    }

    return result;
  }

  async delete(
    myIdentity: string,
    peerIdentity: string,
    sessionId: IbexSessionId
  ): Promise<boolean> {
    const key = this.makeKey(myIdentity, peerIdentity, sessionId);
    return this.sessions.delete(key);
  }

  async deleteAllExcept(
    myIdentity: string,
    peerIdentity: string,
    exceptSessionId: IbexSessionId,
    keepL20Sessions: boolean
  ): Promise<number> {
    const allSessions = await this.getAll(myIdentity, peerIdentity);
    let deleted = 0;

    for (const session of allSessions) {
      if (session.id.equals(exceptSessionId)) {
        continue;
      }

      if (keepL20Sessions) {
        try {
          if (getSessionState(session) === IbexSessionState.L20) {
            continue;
          }
        } catch {
          // Invalid state, delete it
        }
      }

      const key = this.makeKey(myIdentity, peerIdentity, session.id);
      if (this.sessions.delete(key)) {
        deleted++;
      }
    }

    return deleted;
  }

  async deleteAll(myIdentity: string, peerIdentity: string): Promise<number> {
    const allSessions = await this.getAll(myIdentity, peerIdentity);
    let deleted = 0;

    for (const session of allSessions) {
      const key = this.makeKey(myIdentity, peerIdentity, session.id);
      if (this.sessions.delete(key)) {
        deleted++;
      }
    }

    return deleted;
  }

  /**
   * Clear all sessions (for testing)
   */
  clear(): void {
    this.sessions.clear();
  }

  /**
   * Get total number of sessions (for testing)
   */
  get size(): number {
    return this.sessions.size;
  }
}
