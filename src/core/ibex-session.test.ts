import { describe, it, expect, beforeEach } from 'vitest';
import { IbexSession, Contact, IdentityStore, IbexSessionError } from './ibex-session.js';
import { DefaultCryptoProvider } from '../crypto/default-provider.js';
import { IbexSessionState } from '../types/common.js';

describe('IbexSession', () => {
  let crypto: DefaultCryptoProvider;
  let alice: IdentityStore;
  let bob: IdentityStore;
  let aliceContact: Contact;
  let bobContact: Contact;

  beforeEach(async () => {
    crypto = new DefaultCryptoProvider();

    // Generate key pairs for Alice and Bob
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

    aliceContact = {
      identity: alice.identity,
      publicKey: alice.publicKey,
    };

    bobContact = {
      identity: bob.identity,
      publicKey: bob.publicKey,
    };
  });

  describe('createAsInitiator', () => {
    it('should create session in L20 state', async () => {
      const session = await IbexSession.createAsInitiator(bobContact, alice, crypto);

      expect(session.state).toBe(IbexSessionState.L20);
      expect(session.myIdentity).toBe(alice.identity);
      expect(session.peerIdentity).toBe(bob.identity);
      expect(session.myEphemeralPrivateKey).not.toBeNull();
      expect(session.myEphemeralPublicKey.length).toBe(32);
      expect(session.myRatchet2DH).not.toBeNull();
      expect(session.myRatchet4DH).toBeNull();
      expect(session.peerRatchet2DH).toBeNull();
      expect(session.peerRatchet4DH).toBeNull();
      expect(session.current4DHVersions).toBeNull();
    });
  });

  describe('createAsResponder', () => {
    it('should create session in R24 state', async () => {
      // Alice initiates
      const aliceSession = await IbexSession.createAsInitiator(bobContact, alice, crypto);

      // Bob responds
      const bobSession = await IbexSession.createAsResponder(
        aliceSession.id,
        IbexSession.getSupportedVersionRange(),
        aliceSession.myEphemeralPublicKey,
        aliceContact,
        bob,
        crypto
      );

      expect(bobSession.state).toBe(IbexSessionState.R24);
      expect(bobSession.myIdentity).toBe(bob.identity);
      expect(bobSession.peerIdentity).toBe(alice.identity);
      expect(bobSession.myEphemeralPrivateKey).toBeNull(); // Responder discards private key
      expect(bobSession.peerRatchet2DH).not.toBeNull(); // For incoming 2DH messages
      expect(bobSession.myRatchet4DH).not.toBeNull();
      expect(bobSession.peerRatchet4DH).not.toBeNull();
      expect(bobSession.current4DHVersions).not.toBeNull();
    });

    it('should reject invalid ephemeral key length', async () => {
      const aliceSession = await IbexSession.createAsInitiator(bobContact, alice, crypto);

      await expect(
        IbexSession.createAsResponder(
          aliceSession.id,
          IbexSession.getSupportedVersionRange(),
          new Uint8Array(16), // Wrong length
          aliceContact,
          bob,
          crypto
        )
      ).rejects.toThrow('Invalid peer ephemeral public key length');
    });
  });

  describe('processAccept', () => {
    it('should transition initiator to RL44 state', async () => {
      // Alice initiates
      const aliceSession = await IbexSession.createAsInitiator(bobContact, alice, crypto);
      expect(aliceSession.state).toBe(IbexSessionState.L20);

      // Bob responds
      const bobSession = await IbexSession.createAsResponder(
        aliceSession.id,
        IbexSession.getSupportedVersionRange(),
        aliceSession.myEphemeralPublicKey,
        aliceContact,
        bob,
        crypto
      );

      // Alice processes accept
      await aliceSession.processAccept(
        IbexSession.getSupportedVersionRange(),
        bobSession.myEphemeralPublicKey,
        bobContact,
        alice,
        crypto
      );

      expect(aliceSession.state).toBe(IbexSessionState.RL44);
      expect(aliceSession.myEphemeralPrivateKey).toBeNull(); // Discarded
      expect(aliceSession.myRatchet2DH).toBeNull(); // Discarded
      expect(aliceSession.myRatchet4DH).not.toBeNull();
      expect(aliceSession.peerRatchet4DH).not.toBeNull();
      expect(aliceSession.current4DHVersions).not.toBeNull();
    });

    it('should reject if ephemeral private key is missing', async () => {
      // Alice initiates
      const aliceSession = await IbexSession.createAsInitiator(bobContact, alice, crypto);

      // Bob responds
      const bobSession = await IbexSession.createAsResponder(
        aliceSession.id,
        IbexSession.getSupportedVersionRange(),
        aliceSession.myEphemeralPublicKey,
        aliceContact,
        bob,
        crypto
      );

      // Alice processes accept
      await aliceSession.processAccept(
        IbexSession.getSupportedVersionRange(),
        bobSession.myEphemeralPublicKey,
        bobContact,
        alice,
        crypto
      );

      // Try to process accept again - should fail
      await expect(
        aliceSession.processAccept(
          IbexSession.getSupportedVersionRange(),
          bobSession.myEphemeralPublicKey,
          bobContact,
          alice,
          crypto
        )
      ).rejects.toThrow('Missing ephemeral private key');
    });
  });

  describe('full handshake', () => {
    it('should derive same encryption keys for both parties', async () => {
      // Alice initiates
      const aliceSession = await IbexSession.createAsInitiator(bobContact, alice, crypto);

      // Bob responds
      const bobSession = await IbexSession.createAsResponder(
        aliceSession.id,
        IbexSession.getSupportedVersionRange(),
        aliceSession.myEphemeralPublicKey,
        aliceContact,
        bob,
        crypto
      );

      // Alice processes accept
      await aliceSession.processAccept(
        IbexSession.getSupportedVersionRange(),
        bobSession.myEphemeralPublicKey,
        bobContact,
        alice,
        crypto
      );

      // Both should be in RL44/R24 state
      expect(aliceSession.state).toBe(IbexSessionState.RL44);
      expect(bobSession.state).toBe(IbexSessionState.R24);

      // Alice's outgoing 4DH key should match Bob's incoming 4DH key
      const aliceOutKey = await aliceSession.myRatchet4DH!.getCurrentEncryptionKey(crypto);
      const bobInKey = await bobSession.peerRatchet4DH!.getCurrentEncryptionKey(crypto);

      expect(aliceOutKey).toEqual(bobInKey);

      // Bob's outgoing 4DH key should match Alice's incoming 4DH key
      const bobOutKey = await bobSession.myRatchet4DH!.getCurrentEncryptionKey(crypto);
      const aliceInKey = await aliceSession.peerRatchet4DH!.getCurrentEncryptionKey(crypto);

      expect(bobOutKey).toEqual(aliceInKey);
    });

    it('should derive matching 2DH keys before Accept', async () => {
      // Alice initiates
      const aliceSession = await IbexSession.createAsInitiator(bobContact, alice, crypto);

      // Bob responds
      const bobSession = await IbexSession.createAsResponder(
        aliceSession.id,
        IbexSession.getSupportedVersionRange(),
        aliceSession.myEphemeralPublicKey,
        aliceContact,
        bob,
        crypto
      );

      // Alice's outgoing 2DH should match Bob's incoming 2DH
      const aliceOut2DH = await aliceSession.myRatchet2DH!.getCurrentEncryptionKey(crypto);
      const bobIn2DH = await bobSession.peerRatchet2DH!.getCurrentEncryptionKey(crypto);

      expect(aliceOut2DH).toEqual(bobIn2DH);
    });
  });

  describe('serialization', () => {
    it('should serialize and restore L20 session', async () => {
      const session = await IbexSession.createAsInitiator(bobContact, alice, crypto);

      const serialized = session.serialize();
      const restored = IbexSession.restore(serialized);

      expect(restored.id.equals(session.id)).toBe(true);
      expect(restored.myIdentity).toBe(session.myIdentity);
      expect(restored.peerIdentity).toBe(session.peerIdentity);
      expect(restored.state).toBe(IbexSessionState.L20);
    });

    it('should serialize and restore RL44 session', async () => {
      // Complete handshake
      const aliceSession = await IbexSession.createAsInitiator(bobContact, alice, crypto);
      const bobSession = await IbexSession.createAsResponder(
        aliceSession.id,
        IbexSession.getSupportedVersionRange(),
        aliceSession.myEphemeralPublicKey,
        aliceContact,
        bob,
        crypto
      );
      await aliceSession.processAccept(
        IbexSession.getSupportedVersionRange(),
        bobSession.myEphemeralPublicKey,
        bobContact,
        alice,
        crypto
      );

      const serialized = aliceSession.serialize();
      const restored = IbexSession.restore(serialized);

      expect(restored.state).toBe(IbexSessionState.RL44);
      expect(restored.current4DHVersions).toEqual(aliceSession.current4DHVersions);

      // Verify ratchet keys match
      const originalKey = await aliceSession.myRatchet4DH!.getCurrentEncryptionKey(crypto);
      const restoredKey = await restored.myRatchet4DH!.getCurrentEncryptionKey(crypto);
      expect(originalKey).toEqual(restoredKey);
    });
  });

  describe('discardPeerRatchet2DH', () => {
    it('should discard peer 2DH ratchet after first 4DH message', async () => {
      // Bob is in R24 state
      const aliceSession = await IbexSession.createAsInitiator(bobContact, alice, crypto);
      const bobSession = await IbexSession.createAsResponder(
        aliceSession.id,
        IbexSession.getSupportedVersionRange(),
        aliceSession.myEphemeralPublicKey,
        aliceContact,
        bob,
        crypto
      );

      expect(bobSession.state).toBe(IbexSessionState.R24);
      expect(bobSession.peerRatchet2DH).not.toBeNull();

      bobSession.discardPeerRatchet2DH();

      expect(bobSession.peerRatchet2DH).toBeNull();
      expect(bobSession.state).toBe(IbexSessionState.RL44);
    });
  });

  describe('custom config', () => {
    it('should use custom salt prefixes', async () => {
      const customConfig = {
        keSalt2DHPrefix: 'custom-2dh-',
        keSalt4DHPrefix: 'custom-4dh-',
      };

      const sessionDefault = await IbexSession.createAsInitiator(bobContact, alice, crypto);
      const sessionCustom = await IbexSession.createAsInitiator(bobContact, alice, crypto, customConfig);

      // Different configs should produce different ratchet keys
      const keyDefault = await sessionDefault.myRatchet2DH!.getCurrentEncryptionKey(crypto);
      const keyCustom = await sessionCustom.myRatchet2DH!.getCurrentEncryptionKey(crypto);

      expect(keyDefault).not.toEqual(keyCustom);
    });
  });
});

describe('IbexSessionError', () => {
  it('should correctly assign the message, set its name property, and preserve prototype chain', () => {
    const message = 'Test error message';
    const error = new IbexSessionError(message);

    expect(error.message).toBe(message);
    expect(error.name).toBe('IbexSessionError');
    expect(error instanceof Error).toBe(true);
    expect(error instanceof IbexSessionError).toBe(true);
  });
});

