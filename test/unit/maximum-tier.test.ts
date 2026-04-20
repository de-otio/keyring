import { SecureBuffer, asMasterKey } from '@de-otio/crypto-envelope';
import { describe, expect, it } from 'vitest';
import { WrongPassphrase } from '../../src/errors.js';
import { InMemoryStorage } from '../../src/storage/in-memory.js';
import { MaximumTier } from '../../src/tiers/maximum.js';
import type { WrappedKey } from '../../src/types.js';

// Argon2id at t=3, m=64 MiB takes ~2-3s on noble uninstrumented; under
// v8 coverage instrumentation it can exceed 10s per derivation. Bump
// the timeout for every test that exercises the real parameters.
// Tests that can use weakened params do so.
const ARGON2_TIMEOUT = { timeout: 60_000 };

function randomMasterKey() {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return asMasterKey(SecureBuffer.from(bytes));
}

describe('MaximumTier.fromPassphrase', () => {
  it('rejects an empty passphrase', () => {
    expect(() => MaximumTier.fromPassphrase('')).toThrow(/non-empty/);
  });

  it('rejects under-floor Argon2id parameters', () => {
    expect(() => MaximumTier.fromPassphrase('x', { m: 1024 })).toThrow(/too weak/);
    expect(() => MaximumTier.fromPassphrase('x', { t: 0 })).toThrow(/too weak/);
    expect(() => MaximumTier.fromPassphrase('x', { p: 0 })).toThrow(/too weak/);
  });

  it('accepts valid parameters at the floor', () => {
    const tier = MaximumTier.fromPassphrase('x', { t: 1, m: 8192, p: 1 });
    expect(tier.kind).toBe('maximum');
    expect(tier.params).toEqual({ t: 1, m: 8192, p: 1 });
  });

  it('uses OWASP 2023 second-tier defaults when params omitted', () => {
    const tier = MaximumTier.fromPassphrase('x');
    expect(tier.params).toEqual({ t: 3, m: 65_536, p: 1 });
  });
});

// Use weakened params for round-trip tests — faster, still exercises the
// full KDF + envelope round-trip.
const FAST_PARAMS = { t: 1, m: 8192, p: 1 };

describe('MaximumTier round-trip', ARGON2_TIMEOUT, () => {
  it('wraps a master + unwraps it under the same passphrase', async () => {
    const tier = MaximumTier.fromPassphrase('hunter2', FAST_PARAMS);
    const master = randomMasterKey();
    const wrapped = await tier.wrap(master);
    expect(wrapped.tier).toBe('maximum');
    expect(wrapped.v).toBe(1);
    expect(wrapped.kdfParams?.algorithm).toBe('argon2id');

    const recovered = await tier.unwrap(wrapped, { kind: 'passphrase', passphrase: 'hunter2' });
    expect(Buffer.from(recovered.buffer).equals(Buffer.from(master.buffer))).toBe(true);
  });

  it('rejects a different passphrase at unwrap', async () => {
    const tier = MaximumTier.fromPassphrase('hunter2', FAST_PARAMS);
    const master = randomMasterKey();
    const wrapped = await tier.wrap(master);

    await expect(
      tier.unwrap(wrapped, { kind: 'passphrase', passphrase: 'wrong' }),
    ).rejects.toBeInstanceOf(WrongPassphrase);
  });

  it('unwraps under a separately-constructed tier with matching passphrase', async () => {
    const a = MaximumTier.fromPassphrase('secret', FAST_PARAMS);
    const b = MaximumTier.fromPassphrase('DOES NOT MATTER for unwrap', FAST_PARAMS);
    // The held passphrase is only used for wrap; unwrap reads from input.
    const master = randomMasterKey();
    const wrapped = await a.wrap(master);
    const recovered = await b.unwrap(wrapped, { kind: 'passphrase', passphrase: 'secret' });
    expect(Buffer.from(recovered.buffer).equals(Buffer.from(master.buffer))).toBe(true);
  });

  it(
    'fresh salt per wrap — two wraps produce different envelopes',
    { timeout: 120_000 },
    async () => {
      const tier = MaximumTier.fromPassphrase('pw', FAST_PARAMS);
      const master = randomMasterKey();
      const a = await tier.wrap(master);
      const b = await tier.wrap(master);
      expect(Buffer.from(a.envelope).equals(Buffer.from(b.envelope))).toBe(false);
      // Both unwrap successfully.
      const ra = await tier.unwrap(a, { kind: 'passphrase', passphrase: 'pw' });
      const rb = await tier.unwrap(b, { kind: 'passphrase', passphrase: 'pw' });
      expect(Buffer.from(ra.buffer).equals(Buffer.from(rb.buffer))).toBe(true);
    },
  );

  it('rejects unwrap with wrong input.kind', async () => {
    const tier = MaximumTier.fromPassphrase('pw', FAST_PARAMS);
    const wrapped = await tier.wrap(randomMasterKey());
    await expect(tier.unwrap(wrapped, { kind: 'ssh-agent' })).rejects.toThrow(/passphrase/);
  });

  it('rejects unwrap on a tier-mismatched wrapped key', async () => {
    const tier = MaximumTier.fromPassphrase('pw', FAST_PARAMS);
    const bogus: WrappedKey = {
      v: 1,
      tier: 'standard',
      envelope: new Uint8Array(32),
      ts: new Date().toISOString(),
    };
    await expect(tier.unwrap(bogus, { kind: 'passphrase', passphrase: 'pw' })).rejects.toThrow(
      /tier 'standard'/,
    );
  });
});

describe('InMemoryStorage integration with MaximumTier', ARGON2_TIMEOUT, () => {
  it('persists and retrieves a wrapped master', async () => {
    const storage = new InMemoryStorage();
    const tier = MaximumTier.fromPassphrase('pw', FAST_PARAMS);
    const wrapped = await tier.wrap(randomMasterKey());
    await storage.put('personal', wrapped);

    const roundTripped = await storage.get('personal');
    expect(roundTripped).not.toBeNull();
    expect(roundTripped?.tier).toBe('maximum');

    if (!roundTripped) throw new Error('round-tripped wrapped key was null');
    const recovered = await tier.unwrap(roundTripped, {
      kind: 'passphrase',
      passphrase: 'pw',
    });
    expect(recovered.length).toBe(32);
  });
});
