import { describe, it, expect, beforeEach } from 'vitest';
import { IbexProcessor, DecryptionResult } from './ibex-processor.js';
import { DefaultCryptoProvider } from '../crypto/default-provider.js';
import { MemoryIbexSessionStore } from '../storage/memory-store.js';
import { Contact, IdentityStore } from '../core/ibex-session.js';
import { IbexMessageType, TerminateCause, RejectCause } from '../types/messages.js';
import { IbexMode, DHType } from '../types/common.js';
import type { IbexInit, IbexAccept, IbexMessage } from '../types/messages.js';

describe('IbexProcessor', () => {
  let crypto: DefaultCryptoProvider;
  let aliceStore: MemoryIbexSessionStore;
  let bobStore: MemoryIbexSessionStore;
  let aliceProcessor: IbexProcessor;
  let bobProcessor: IbexProcessor;
  let alice: IdentityStore;
  let bob: IdentityStore;
  let aliceContact: Contact;
  let bobContact: Contact;

  beforeEach(async () => {
    crypto = new DefaultCryptoProvider();
    aliceStore = new MemoryIbexSessionStore();
    bobStore = new MemoryIbexSessionStore();

    // Generate key pairs
    const aliceKeys = await crypto.generateKeyPair();
    const bobKeys = await crypto.generateKeyPair();

    alice = {
      identity: 'ALICE123',
      publicKey: aliceKeys.publicKey,
      privateKey: aliceKeys.privateKey,
    };

    bob = {
      identity: 'BOB12345',
      publicKey: bobKeys.publicKey,
      privateKey: bobKeys.privateKey,
    };

    aliceContact = { identity: alice.identity, publicKey: alice.publicKey };
    bobContact = { identity: bob.identity, publicKey: bob.publicKey };

    aliceProcessor = new IbexProcessor({
      sessionStore: aliceStore,
      cryptoProvider: crypto,
    });

    bobProcessor = new IbexProcessor({
      sessionStore: bobStore,
      cryptoProvider: crypto,
    });
  });

  describe('encapsulate', () => {
    it('should create Init and Message for new session', async () => {
      const plaintext = new TextEncoder().encode('Hello, Bob!');

      const result = await aliceProcessor.encapsulate(bobContact, alice, plaintext);

      expect(result.messages.length).toBe(2);
      expect(result.messages[0].type).toBe(IbexMessageType.INIT);
      expect(result.messages[1].type).toBe(IbexMessageType.MESSAGE);
      expect(result.mode).toBe(IbexMode.TWODH); // First message is 2DH
      expect(result.session).not.toBeNull();
    });

    it('should use existing session for subsequent messages', async () => {
      const plaintext = new TextEncoder().encode('Hello!');

      // First message creates session
      const result1 = await aliceProcessor.encapsulate(bobContact, alice, plaintext);
      expect(result1.messages.length).toBe(2);

      // Store the session
      await aliceStore.store(result1.session!.serialize());

      // Second message uses existing session
      const result2 = await aliceProcessor.encapsulate(bobContact, alice, plaintext);
      expect(result2.messages.length).toBe(1);
      expect(result2.messages[0].type).toBe(IbexMessageType.MESSAGE);
    });
  });

  describe('processInit', () => {
    it('should respond with Accept', async () => {
      // Alice sends Init
      const result = await aliceProcessor.encapsulate(bobContact, alice, new Uint8Array([1]));
      const init = result.messages[0] as IbexInit;

      // Bob processes Init
      const response = await bobProcessor.processInit(aliceContact, bob, init);

      expect(response.type).toBe(IbexMessageType.ACCEPT);
      expect((response as IbexAccept).sessionId.equals(init.sessionId)).toBe(true);
    });

    it('should re-send the same Accept for duplicate Init', async () => {
      // Alice sends Init
      const result = await aliceProcessor.encapsulate(bobContact, alice, new Uint8Array([1]));
      const init = result.messages[0] as IbexInit;

      // Bob processes Init first time
      const first = await bobProcessor.processInit(aliceContact, bob, init);

      // Bob processes same Init again (e.g. Alice missed the Accept)
      const response = await bobProcessor.processInit(aliceContact, bob, init);

      expect(response.type).toBe(IbexMessageType.ACCEPT);
      expect((response as IbexAccept).sessionId.equals(init.sessionId)).toBe(true);
      expect((response as IbexAccept).ephemeralPublicKey).toEqual(
        (first as IbexAccept).ephemeralPublicKey
      );
    });
  });

  describe('processAccept', () => {
    it('should complete handshake', async () => {
      // Alice sends Init
      const result = await aliceProcessor.encapsulate(bobContact, alice, new Uint8Array([1]));
      const init = result.messages[0] as IbexInit;
      await aliceStore.store(result.session!.serialize());

      // Bob responds with Accept
      const accept = await bobProcessor.processInit(aliceContact, bob, init) as IbexAccept;

      // Alice processes Accept
      await aliceProcessor.processAccept(bobContact, alice, accept);

      // Verify session is in RL44 state
      const aliceSession = await aliceStore.getBest(alice.identity, bob.identity);
      expect(aliceSession).not.toBeNull();
      expect(aliceSession!.myRatchet4DH).not.toBeNull();
      expect(aliceSession!.peerRatchet4DH).not.toBeNull();
    });
  });

  describe('full message exchange', () => {
    async function setupSessions() {
      // Alice sends Init + Message
      const result = await aliceProcessor.encapsulate(bobContact, alice, new Uint8Array([1]));
      const init = result.messages[0] as IbexInit;
      await aliceStore.store(result.session!.serialize());

      // Bob responds with Accept
      const accept = await bobProcessor.processInit(aliceContact, bob, init) as IbexAccept;

      // Alice processes Accept
      await aliceProcessor.processAccept(bobContact, alice, accept);
    }

    it('should encrypt and decrypt 2DH message (before Accept)', async () => {
      // Alice sends Init + Message
      const plaintext = new TextEncoder().encode('Hello, Bob!');
      const result = await aliceProcessor.encapsulate(bobContact, alice, plaintext);
      const init = result.messages[0] as IbexInit;
      const message = result.messages[1] as IbexMessage;
      await aliceStore.store(result.session!.serialize());

      // Bob processes Init
      await bobProcessor.processInit(aliceContact, bob, init);

      // Bob decrypts message
      const decrypted = await bobProcessor.processMessage(
        aliceContact,
        bob,
        message
      ) as DecryptionResult;

      expect(decrypted.plaintext).toEqual(plaintext);
      expect(decrypted.mode).toBe(IbexMode.TWODH);
    });

    it('should encrypt and decrypt 4DH message (after Accept)', async () => {
      await setupSessions();

      // Alice sends 4DH message
      const plaintext = new TextEncoder().encode('Secret message!');
      const result = await aliceProcessor.encapsulate(bobContact, alice, plaintext);

      expect(result.messages.length).toBe(1);
      const message = result.messages[0] as IbexMessage;
      expect(message.dhType).toBe(DHType.FOURDH);

      await aliceStore.store(result.session!.serialize());

      // Bob decrypts
      const decrypted = await bobProcessor.processMessage(
        aliceContact,
        bob,
        message
      ) as DecryptionResult;

      expect(decrypted.plaintext).toEqual(plaintext);
      expect(decrypted.mode).toBe(IbexMode.FOURDH);
    });

    it('should handle multiple messages correctly', async () => {
      await setupSessions();

      // Alice sends multiple messages
      for (let i = 0; i < 5; i++) {
        const plaintext = new TextEncoder().encode(`Message ${i}`);
        const result = await aliceProcessor.encapsulate(bobContact, alice, plaintext);
        await aliceStore.store(result.session!.serialize());

        const message = result.messages[0] as IbexMessage;

        const decrypted = await bobProcessor.processMessage(
          aliceContact,
          bob,
          message
        ) as DecryptionResult;

        // Commit ratchet
        const commitResult = await bobProcessor.commitPeerRatchet(bob, decrypted.ratchetId);
        expect(commitResult.committed).toBe(true);

        expect(new TextDecoder().decode(decrypted.plaintext)).toBe(`Message ${i}`);
      }
    });
  });

  describe('commitPeerRatchet', () => {
    it('should return session_not_found when session does not exist', async () => {
      const { IbexSessionId } = await import('../core/session-id.js');
      const fakeSessionId = await IbexSessionId.generate(crypto);
      const fakeRatchetId = {
        sessionId: fakeSessionId,
        peerIdentity: 'UNKNOWN1',
        dhType: DHType.FOURDH,
      };

      const result = await aliceProcessor.commitPeerRatchet(alice, fakeRatchetId);

      expect(result.committed).toBe(false);
      if (!result.committed) {
        expect(result.reason).toBe('session_not_found');
      }
    });

    it('should return ratchet_not_found when session exists but ratchet is missing', async () => {
      // Create a session (L20 state - only has myRatchet2DH, no peer ratchets)
      const encapResult = await aliceProcessor.encapsulate(bobContact, alice, new Uint8Array([1]));
      await aliceStore.store(encapResult.session!.serialize());

      // Try to commit a peer ratchet that doesn't exist (session is L20, has no peerRatchet4DH)
      const fakeRatchetId = {
        sessionId: encapResult.session!.id,
        peerIdentity: bob.identity,
        dhType: DHType.FOURDH, // No 4DH peer ratchet in L20 state
      };

      const result = await aliceProcessor.commitPeerRatchet(alice, fakeRatchetId);

      expect(result.committed).toBe(false);
      if (!result.committed) {
        expect(result.reason).toBe('ratchet_not_found');
      }
    });

    it('should successfully commit ratchet after decryption', async () => {
      // Full setup: Alice sends, Bob responds with Accept
      const encapResult = await aliceProcessor.encapsulate(bobContact, alice, new Uint8Array([1]));
      const init = encapResult.messages[0] as IbexInit;
      await aliceStore.store(encapResult.session!.serialize());

      await bobProcessor.processInit(aliceContact, bob, init);

      // Alice sends another message
      const plaintext = new TextEncoder().encode('Test message');
      const result2 = await aliceProcessor.encapsulate(bobContact, alice, plaintext);
      await aliceStore.store(result2.session!.serialize());
      const message = result2.messages[0] as IbexMessage;

      // Bob decrypts
      const decrypted = await bobProcessor.processMessage(aliceContact, bob, message) as DecryptionResult;

      // Commit should succeed
      const commitResult = await bobProcessor.commitPeerRatchet(bob, decrypted.ratchetId);
      expect(commitResult.committed).toBe(true);
    });
  });

  describe('processReject', () => {
    it('should delete session on reject', async () => {
      // Create a session
      const result = await aliceProcessor.encapsulate(bobContact, alice, new Uint8Array([1]));
      await aliceStore.store(result.session!.serialize());

      expect(aliceStore.size).toBe(1);

      // Process reject
      const reject = {
        type: IbexMessageType.REJECT as const,
        sessionId: result.session!.id,
        rejectedMessageId: new Uint8Array(16),
        cause: RejectCause.UNKNOWN_SESSION,
      };

      await aliceProcessor.processReject(alice, bobContact, reject);

      expect(aliceStore.size).toBe(0);
    });
  });

  describe('processTerminate', () => {
    it('should delete session on terminate', async () => {
      // Create a session
      const result = await aliceProcessor.encapsulate(bobContact, alice, new Uint8Array([1]));
      await aliceStore.store(result.session!.serialize());

      expect(aliceStore.size).toBe(1);

      // Process terminate
      const terminate = {
        type: IbexMessageType.TERMINATE as const,
        sessionId: result.session!.id,
        cause: TerminateCause.RESET,
      };

      await aliceProcessor.processTerminate(alice, bobContact, terminate);

      expect(aliceStore.size).toBe(0);
    });
  });

  describe('clearAndTerminateAllSessions', () => {
    it('should clear all sessions and return terminates', async () => {
      // Create a session
      const result = await aliceProcessor.encapsulate(bobContact, alice, new Uint8Array([1]));
      await aliceStore.store(result.session!.serialize());

      expect(aliceStore.size).toBe(1);

      // Clear all
      const terminates = await aliceProcessor.clearAndTerminateAllSessions(
        alice,
        bobContact,
        TerminateCause.RESET
      );

      expect(terminates.length).toBe(1);
      expect(aliceStore.size).toBe(0);
      expect(terminates[0].type).toBe(IbexMessageType.TERMINATE);
      expect(terminates[0].cause).toBe(TerminateCause.RESET);
    });
  });

  describe('events', () => {
    it('should emit session events', async () => {
      let initiated = false;
      let establishedResponder = false;
      let establishedInitiator = false;

      const aliceWithEvents = new IbexProcessor({
        sessionStore: aliceStore,
        cryptoProvider: crypto,
        events: {
          onSessionInitiated: () => { initiated = true; },
          onSessionEstablishedAsInitiator: () => { establishedInitiator = true; },
        },
      });

      const bobWithEvents = new IbexProcessor({
        sessionStore: bobStore,
        cryptoProvider: crypto,
        events: {
          onSessionEstablishedAsResponder: () => { establishedResponder = true; },
        },
      });

      // Alice initiates
      const result = await aliceWithEvents.encapsulate(bobContact, alice, new Uint8Array([1]));
      expect(initiated).toBe(true);

      await aliceStore.store(result.session!.serialize());
      const init = result.messages[0] as IbexInit;

      // Bob responds
      const accept = await bobWithEvents.processInit(aliceContact, bob, init) as IbexAccept;
      expect(establishedResponder).toBe(true);

      // Alice completes
      await aliceWithEvents.processAccept(bobContact, alice, accept);
      expect(establishedInitiator).toBe(true);
    });
  });
});
