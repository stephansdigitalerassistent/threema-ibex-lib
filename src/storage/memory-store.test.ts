import { describe, it, expect, beforeEach } from 'vitest';
import { MemoryIbexSessionStore } from './memory-store.js';
import { IbexSessionId } from '../core/session-id.js';
import { IbexSessionState } from '../types/common.js';
import type { SerializedIbexSession } from '../types/storage.js';

describe('MemoryIbexSessionStore', () => {
  let store: MemoryIbexSessionStore;

  beforeEach(() => {
    store = new MemoryIbexSessionStore();
  });

  const myId = 'my-identity';
  const peerId = 'peer-identity';

  // Helper to create a dummy serialized session
  function createMockSession(
    sessionIdHex: string,
    state: IbexSessionState,
    myIdentity = myId,
    peerIdentity = peerId
  ): SerializedIbexSession {
    const id = IbexSessionId.fromHex(sessionIdHex);
    const mockRatchet = { counter: 0, chainKey: new Uint8Array(32) };

    let myRatchet2DH = null;
    let myRatchet4DH = null;
    let peerRatchet2DH = null;
    let peerRatchet4DH = null;

    if (state === IbexSessionState.RL44) {
      myRatchet4DH = mockRatchet;
      peerRatchet4DH = mockRatchet;
    } else if (state === IbexSessionState.R24) {
      peerRatchet2DH = mockRatchet;
      myRatchet4DH = mockRatchet;
      peerRatchet4DH = mockRatchet;
    } else if (state === IbexSessionState.L20) {
      myRatchet2DH = mockRatchet;
    } else {
      peerRatchet2DH = mockRatchet;
    }

    return {
      id,
      myIdentity,
      peerIdentity,
      myEphemeralPrivateKey: null,
      myEphemeralPublicKey: new Uint8Array(32),
      current4DHVersions: null,
      lastOutgoingMessageTimestamp: Date.now(),
      myRatchet2DH,
      myRatchet4DH,
      peerRatchet2DH,
      peerRatchet4DH,
    };
  }

  describe('store and get', () => {
    it('should store and retrieve a session', async () => {
      const session = createMockSession('0102030405060708090a0b0c0d0e0f10', IbexSessionState.RL44);
      await store.store(session);

      expect(store.size).toBe(1);

      const retrieved = await store.get(myId, peerId, session.id);
      expect(retrieved).not.toBeNull();
      expect(retrieved?.id.equals(session.id)).toBe(true);
      expect(retrieved?.myIdentity).toBe(myId);
      expect(retrieved?.peerIdentity).toBe(peerId);
      
      // Ensure it returned a copy
      expect(retrieved).not.toBe(session);
    });

    it('should return null when retrieving non-existent session', async () => {
      const nonExistentId = IbexSessionId.fromHex('0102030405060708090a0b0c0d0e0f10');
      const retrieved = await store.get(myId, peerId, nonExistentId);
      expect(retrieved).toBeNull();
    });
  });

  describe('getAll', () => {
    it('should retrieve all sessions for a specific contact and ignore others', async () => {
      const session1 = createMockSession('0102030405060708090a0b0c0d0e0f10', IbexSessionState.RL44);
      const session2 = createMockSession('0202030405060708090a0b0c0d0e0f10', IbexSessionState.L20);
      const sessionOther = createMockSession('0302030405060708090a0b0c0d0e0f10', IbexSessionState.RL44, 'other-my', 'other-peer');

      await store.store(session1);
      await store.store(session2);
      await store.store(sessionOther);

      expect(store.size).toBe(3);

      const all = await store.getAll(myId, peerId);
      expect(all.length).toBe(2);
      expect(all.some(s => s.id.equals(session1.id))).toBe(true);
      expect(all.some(s => s.id.equals(session2.id))).toBe(true);
    });
  });

  describe('getBest', () => {
    it('should return null when no sessions exist', async () => {
      const best = await store.getBest(myId, peerId);
      expect(best).toBeNull();
    });

    it('should prefer RL44 sessions over other states', async () => {
      const sessionL20 = createMockSession('0202030405060708090a0b0c0d0e0f10', IbexSessionState.L20);
      const sessionRL44 = createMockSession('0102030405060708090a0b0c0d0e0f10', IbexSessionState.RL44);
      
      await store.store(sessionL20);
      await store.store(sessionRL44);

      const best = await store.getBest(myId, peerId);
      expect(best).not.toBeNull();
      expect(best?.id.equals(sessionRL44.id)).toBe(true);
    });

    it('should fall back to non-RL44 sessions if no RL44 sessions exist', async () => {
      const sessionL20 = createMockSession('0102030405060708090a0b0c0d0e0f10', IbexSessionState.L20);
      
      await store.store(sessionL20);

      const best = await store.getBest(myId, peerId);
      expect(best).not.toBeNull();
      expect(best?.id.equals(sessionL20.id)).toBe(true);
    });

    it('should sort sessions by ID (hex comparison) and return lowest if state is same', async () => {
      const sessionRL44_2 = createMockSession('0202030405060708090a0b0c0d0e0f10', IbexSessionState.RL44);
      const sessionRL44_1 = createMockSession('0102030405060708090a0b0c0d0e0f10', IbexSessionState.RL44);
      
      await store.store(sessionRL44_2);
      await store.store(sessionRL44_1);

      const best = await store.getBest(myId, peerId);
      expect(best).not.toBeNull();
      expect(best?.id.equals(sessionRL44_1.id)).toBe(true);
    });

    it('should sort fallback sessions by ID (hex comparison) and return lowest', async () => {
      const sessionL20_2 = createMockSession('0202030405060708090a0b0c0d0e0f10', IbexSessionState.L20);
      const sessionL20_1 = createMockSession('0102030405060708090a0b0c0d0e0f10', IbexSessionState.L20);

      await store.store(sessionL20_2);
      await store.store(sessionL20_1);

      const best = await store.getBest(myId, peerId);
      expect(best).not.toBeNull();
      expect(best?.id.equals(sessionL20_1.id)).toBe(true);
    });
  });

  describe('delete', () => {
    it('should delete a specific session and return true', async () => {
      const session = createMockSession('0102030405060708090a0b0c0d0e0f10', IbexSessionState.RL44);
      await store.store(session);

      const deleted = await store.delete(myId, peerId, session.id);
      expect(deleted).toBe(true);
      expect(store.size).toBe(0);
    });

    it('should return false if session to delete is not found', async () => {
      const nonExistentId = IbexSessionId.fromHex('0102030405060708090a0b0c0d0e0f10');
      const deleted = await store.delete(myId, peerId, nonExistentId);
      expect(deleted).toBe(false);
    });
  });

  describe('deleteAllExcept', () => {
    it('should delete all sessions for a contact except specified session, preserving L20 if requested', async () => {
      const sessionKeep = createMockSession('0102030405060708090a0b0c0d0e0f10', IbexSessionState.RL44);
      const sessionDeleteRL44 = createMockSession('0202030405060708090a0b0c0d0e0f10', IbexSessionState.RL44);
      const sessionKeepL20 = createMockSession('0302030405060708090a0b0c0d0e0f10', IbexSessionState.L20);
      const sessionOtherContact = createMockSession('0402030405060708090a0b0c0d0e0f10', IbexSessionState.RL44, 'other-my', 'other-peer');

      await store.store(sessionKeep);
      await store.store(sessionDeleteRL44);
      await store.store(sessionKeepL20);
      await store.store(sessionOtherContact);

      // Keep keepL20Sessions = true
      const deletedCount = await store.deleteAllExcept(myId, peerId, sessionKeep.id, true);
      expect(deletedCount).toBe(1); // Only sessionDeleteRL44 should be deleted
      
      expect(await store.get(myId, peerId, sessionKeep.id)).not.toBeNull();
      expect(await store.get(myId, peerId, sessionDeleteRL44.id)).toBeNull();
      expect(await store.get(myId, peerId, sessionKeepL20.id)).not.toBeNull();
      expect(await store.get('other-my', 'other-peer', sessionOtherContact.id)).not.toBeNull();
    });

    it('should delete L20 sessions too if keepL20Sessions is false', async () => {
      const sessionKeep = createMockSession('0102030405060708090a0b0c0d0e0f10', IbexSessionState.RL44);
      const sessionL20 = createMockSession('0202030405060708090a0b0c0d0e0f10', IbexSessionState.L20);

      await store.store(sessionKeep);
      await store.store(sessionL20);

      const deletedCount = await store.deleteAllExcept(myId, peerId, sessionKeep.id, false);
      expect(deletedCount).toBe(1); // sessionL20 deleted
      expect(await store.get(myId, peerId, sessionL20.id)).toBeNull();
    });

    it('should delete invalid state sessions', async () => {
      const sessionKeep = createMockSession('0102030405060708090a0b0c0d0e0f10', IbexSessionState.RL44);
      const sessionInvalid = createMockSession('0202030405060708090a0b0c0d0e0f10', IbexSessionState.RL44);
      // Make it invalid by clearing ratchets (so getSessionState will throw)
      sessionInvalid.myRatchet2DH = null;
      sessionInvalid.myRatchet4DH = null;
      sessionInvalid.peerRatchet2DH = null;
      sessionInvalid.peerRatchet4DH = null;

      await store.store(sessionKeep);
      await store.store(sessionInvalid);

      const deletedCount = await store.deleteAllExcept(myId, peerId, sessionKeep.id, true);
      expect(deletedCount).toBe(1); // sessionInvalid deleted because it is invalid and not keeped
      expect(await store.get(myId, peerId, sessionInvalid.id)).toBeNull();
    });
  });

  describe('deleteAll', () => {
    it('should delete all sessions for a specific contact and return count', async () => {
      const session1 = createMockSession('0102030405060708090a0b0c0d0e0f10', IbexSessionState.RL44);
      const session2 = createMockSession('0202030405060708090a0b0c0d0e0f10', IbexSessionState.L20);
      const sessionOther = createMockSession('0302030405060708090a0b0c0d0e0f10', IbexSessionState.RL44, 'other-my', 'other-peer');

      await store.store(session1);
      await store.store(session2);
      await store.store(sessionOther);

      const deletedCount = await store.deleteAll(myId, peerId);
      expect(deletedCount).toBe(2);
      expect(store.size).toBe(1);
      expect(await store.get(myId, peerId, session1.id)).toBeNull();
      expect(await store.get(myId, peerId, session2.id)).toBeNull();
      expect(await store.get('other-my', 'other-peer', sessionOther.id)).not.toBeNull();
    });
  });

  describe('clear', () => {
    it('should clear all stored sessions', async () => {
      const session1 = createMockSession('0102030405060708090a0b0c0d0e0f10', IbexSessionState.RL44);
      const session2 = createMockSession('0202030405060708090a0b0c0d0e0f10', IbexSessionState.L20);

      await store.store(session1);
      await store.store(session2);
      expect(store.size).toBe(2);

      store.clear();
      expect(store.size).toBe(0);
    });
  });
});
