import { EnvelopeClient, SecureBuffer, asMasterKey } from '@de-otio/crypto-envelope';
import { describe, expect, it } from 'vitest';
import { UnlockFailed, WrongRecoveryKey } from '../../src/errors.js';
import { InMemoryStorage } from '../../src/storage/in-memory.js';
import { RECOVERY_KEY_BYTES, RecoveryKeyTier } from '../../src/tiers/recovery-key.js';
import type { WrappedKey } from '../../src/types.js';

function randomMasterKey() {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return asMasterKey(SecureBuffer.from(bytes));
}

describe('RecoveryKeyTier.generate / fromRecoveryKey', () => {
  it('generates a 32-byte recovery key and a recovery-key tier', () => {
    const { tier, recoveryKey } = RecoveryKeyTier.generate();
    expect(tier.kind).toBe('recovery-key');
    expect(recoveryKey).toBeInstanceOf(Uint8Array);
    expect(recoveryKey.length).toBe(RECOVERY_KEY_BYTES);
  });

  it('generates independent keys per call (high entropy)', () => {
    const a = RecoveryKeyTier.generate().recoveryKey;
    const b = RecoveryKeyTier.generate().recoveryKey;
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });

  it('rejects a recovery key that is not exactly 32 bytes', () => {
    expect(() => RecoveryKeyTier.fromRecoveryKey(new Uint8Array(16))).toThrow(/32-byte/);
    expect(() => RecoveryKeyTier.fromRecoveryKey(new Uint8Array(33))).toThrow(/32-byte/);
  });

  it('does not retain the caller-supplied array (copies into a SecureBuffer)', async () => {
    const key = new Uint8Array(RECOVERY_KEY_BYTES).fill(7);
    const tier = RecoveryKeyTier.fromRecoveryKey(key);
    // Mutating the caller's array after construction must not affect the tier.
    key.fill(0);
    const master = randomMasterKey();
    const wrapped = await tier.wrap(master);
    // Unwrap with the ORIGINAL (all-7s) key still works.
    const recovered = await tier.unwrap(wrapped, {
      kind: 'recovery-key',
      recoveryKey: new Uint8Array(RECOVERY_KEY_BYTES).fill(7),
    });
    expect(Buffer.from(recovered.buffer).equals(Buffer.from(master.buffer))).toBe(true);
  });
});

describe('RecoveryKeyTier round-trip', () => {
  it('wraps a master + unwraps it under the same recovery key (no kdfParams)', async () => {
    const { tier, recoveryKey } = RecoveryKeyTier.generate();
    const master = randomMasterKey();
    const wrapped = await tier.wrap(master);

    expect(wrapped.tier).toBe('recovery-key');
    expect(wrapped.v).toBe(1);
    expect(wrapped.kdfParams).toBeUndefined();
    expect(wrapped.envelope.length).toBeGreaterThan(0);

    const recovered = await tier.unwrap(wrapped, { kind: 'recovery-key', recoveryKey });
    expect(Buffer.from(recovered.buffer).equals(Buffer.from(master.buffer))).toBe(true);
  });

  it('unwraps on a SEPARATE tier instance built from the key (the new-device path)', async () => {
    const { tier: deviceA, recoveryKey } = RecoveryKeyTier.generate();
    const master = randomMasterKey();
    const wrapped = await deviceA.wrap(master);

    // Device B has only the recovery key the user typed back in.
    const deviceB = RecoveryKeyTier.fromRecoveryKey(recoveryKey);
    const recovered = await deviceB.unwrap(wrapped, { kind: 'recovery-key', recoveryKey });
    expect(Buffer.from(recovered.buffer).equals(Buffer.from(master.buffer))).toBe(true);
  });

  it('rejects a different recovery key at unwrap with WrongRecoveryKey', async () => {
    const { tier } = RecoveryKeyTier.generate();
    const wrapped = await tier.wrap(randomMasterKey());
    const wrongKey = new Uint8Array(RECOVERY_KEY_BYTES).fill(1);
    await expect(
      tier.unwrap(wrapped, { kind: 'recovery-key', recoveryKey: wrongKey }),
    ).rejects.toBeInstanceOf(WrongRecoveryKey);
  });

  it('fresh nonce per wrap — two wraps of the same master differ but both unwrap', async () => {
    const { tier, recoveryKey } = RecoveryKeyTier.generate();
    const master = randomMasterKey();
    const a = await tier.wrap(master);
    const b = await tier.wrap(master);
    expect(Buffer.from(a.envelope).equals(Buffer.from(b.envelope))).toBe(false);

    const ra = await tier.unwrap(a, { kind: 'recovery-key', recoveryKey });
    const rb = await tier.unwrap(b, { kind: 'recovery-key', recoveryKey });
    expect(Buffer.from(ra.buffer).equals(Buffer.from(master.buffer))).toBe(true);
    expect(Buffer.from(rb.buffer).equals(Buffer.from(master.buffer))).toBe(true);
  });

  it('rejects unwrap with a wrong input.kind', async () => {
    const { tier } = RecoveryKeyTier.generate();
    const wrapped = await tier.wrap(randomMasterKey());
    await expect(tier.unwrap(wrapped, { kind: 'ssh-agent' })).rejects.toThrow(/recovery-key/);
  });

  it('rejects unwrap with a malformed recovery key in the input', async () => {
    const { tier } = RecoveryKeyTier.generate();
    const wrapped = await tier.wrap(randomMasterKey());
    await expect(
      tier.unwrap(wrapped, { kind: 'recovery-key', recoveryKey: new Uint8Array(8) }),
    ).rejects.toThrow(/32-byte/);
  });

  it('rejects unwrap on a tier-mismatched wrapped key', async () => {
    const { tier, recoveryKey } = RecoveryKeyTier.generate();
    const bogus: WrappedKey = {
      v: 1,
      tier: 'maximum',
      envelope: new Uint8Array(32),
      ts: new Date().toISOString(),
    };
    await expect(tier.unwrap(bogus, { kind: 'recovery-key', recoveryKey })).rejects.toThrow(
      /tier 'maximum'/,
    );
  });

  it('dispose() is idempotent', () => {
    const { tier } = RecoveryKeyTier.generate();
    expect(() => {
      tier.dispose();
      tier.dispose();
    }).not.toThrow();
  });

  // Authentic envelope under the CORRECT key, but the inner payload is not a
  // 32-byte `{ master: base64 }` — i.e. something other than RecoveryKeyTier
  // produced it. Decryption succeeds (right key) but the payload shape is
  // rejected. Guards the defensive checks in decryptMasterUnderKek.
  async function envelopeWithPayload(
    recoveryKey: Uint8Array,
    payload: Record<string, unknown>,
  ): Promise<Uint8Array> {
    const kek = asMasterKey(SecureBuffer.from(new Uint8Array(recoveryKey)));
    const client = new EnvelopeClient({ masterKey: kek });
    try {
      return await client.encrypt(payload);
    } finally {
      client.dispose();
    }
  }

  it('rejects an authentic envelope whose payload is missing the master string', async () => {
    const recoveryKey = new Uint8Array(RECOVERY_KEY_BYTES).fill(9);
    const envelope = await envelopeWithPayload(recoveryKey, { notMaster: 1 });
    const tier = RecoveryKeyTier.fromRecoveryKey(recoveryKey);
    await expect(
      tier.unwrap(
        { v: 1, tier: 'recovery-key', envelope, ts: '' },
        { kind: 'recovery-key', recoveryKey },
      ),
    ).rejects.toBeInstanceOf(WrongRecoveryKey);
  });

  it('rejects an authentic envelope whose master is not 32 bytes', async () => {
    const recoveryKey = new Uint8Array(RECOVERY_KEY_BYTES).fill(9);
    const shortMaster = Buffer.from(new Uint8Array(8)).toString('base64');
    const envelope = await envelopeWithPayload(recoveryKey, { master: shortMaster });
    const tier = RecoveryKeyTier.fromRecoveryKey(recoveryKey);
    await expect(
      tier.unwrap(
        { v: 1, tier: 'recovery-key', envelope, ts: '' },
        { kind: 'recovery-key', recoveryKey },
      ),
    ).rejects.toBeInstanceOf(WrongRecoveryKey);
  });
});

describe('RecoveryKeyTier known-answer vector (cross-language freeze)', () => {
  // A FIXED recovery key + a FIXED wrapped envelope, generated once by this
  // implementation and frozen here. The Dart port MUST decrypt this exact
  // envelope under this exact key to the exact master. Decrypt is deterministic
  // (the AEAD nonce and blob-id are embedded in the envelope and AAD-bound), so
  // pinning the ciphertext is a stable cross-language contract. The envelope is
  // crypto-envelope's v2 CBOR wire format (the `CKB` / 0x434b42 magic prefix).
  // If this test ever fails after a dependency bump, the wrapped-key wire
  // format changed — coordinate a versioned migration, do not silently update.
  const RECOVERY_KEY_HEX = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
  const MASTER_HEX = '2020212223242526272829ff2b2c2d2e2f303132333435363738393a3b3c3d3e';
  const ENVELOPE_HEX =
    '434b42a46176026269647818625f37304b796648564170633333706d4573546c647935366274737818323032362d30362d32305430383a33393a35332e3235395a63656e63a462637458612fe34550a4c0c41a6103cd677169d47fa97627e3c678ab1d4d6c58f0b8b99ac47d643631ffcb13e59d74d9f8472e9da00992c6d03db9ef0ce365a492118747def314efd0ca654150dc690ba07bd47356cb738d87aed2759ab62beeb648f35650b263616c67725843686143686132302d506f6c7931333035636b69646764656661756c7466636f6d6d69745820475339b3826c1136f722b2f9be4d2eccf42ae9a653829d44e8b7b1e4c8304cf6';

  it('decrypts the frozen envelope to the frozen master', async () => {
    const tier = RecoveryKeyTier.fromRecoveryKey(hexToBytes(RECOVERY_KEY_HEX));
    const recovered = await tier.unwrap(
      {
        v: 1,
        tier: 'recovery-key',
        envelope: hexToBytes(ENVELOPE_HEX),
        ts: '2026-06-20T08:39:53.262Z', // informational; not consulted by unwrap
      },
      { kind: 'recovery-key', recoveryKey: hexToBytes(RECOVERY_KEY_HEX) },
    );
    expect(Buffer.from(recovered.buffer).toString('hex')).toBe(MASTER_HEX);
  });

  it('rejects the frozen envelope under a one-bit-flipped recovery key', async () => {
    const flipped = hexToBytes(RECOVERY_KEY_HEX);
    flipped[0] = (flipped[0] ?? 0) ^ 0x01;
    const tier = RecoveryKeyTier.fromRecoveryKey(flipped);
    await expect(
      tier.unwrap(
        { v: 1, tier: 'recovery-key', envelope: hexToBytes(ENVELOPE_HEX), ts: '' },
        { kind: 'recovery-key', recoveryKey: flipped },
      ),
    ).rejects.toBeInstanceOf(WrongRecoveryKey);
  });
});

describe('InMemoryStorage integration with RecoveryKeyTier', () => {
  it('persists and retrieves a wrapped master', async () => {
    const storage = new InMemoryStorage();
    const { tier, recoveryKey } = RecoveryKeyTier.generate();
    const wrapped = await tier.wrap(randomMasterKey());
    await storage.put('keyring', wrapped);

    const roundTripped = await storage.get('keyring');
    expect(roundTripped?.tier).toBe('recovery-key');
    if (!roundTripped) throw new Error('round-tripped wrapped key was null');

    const recovered = await tier.unwrap(roundTripped, { kind: 'recovery-key', recoveryKey });
    expect(recovered.length).toBe(32);
  });
});

// ── helpers ──────────────────────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
