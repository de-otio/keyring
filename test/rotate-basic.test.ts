import { SecureBuffer, asMasterKey } from '@de-otio/crypto-envelope';
import type { AnyEnvelope, MasterKey } from '@de-otio/crypto-envelope';
import { beforeEach, describe, expect, it, vi } from 'vitest';

// Mock crypto-envelope's `rewrapEnvelope` so the orchestrator can be
// exercised with a simple passthrough. The real primitive is covered
// in the crypto-envelope repo; here we just need `rotate()` to hand
// an envelope in and get one back without performing AEAD work.
vi.mock('@de-otio/crypto-envelope', async () => {
  const actual = await vi.importActual<typeof import('@de-otio/crypto-envelope')>(
    '@de-otio/crypto-envelope',
  );
  return {
    ...actual,
    rewrapEnvelope: vi.fn(
      (env: AnyEnvelope, _old: MasterKey, _new: MasterKey): AnyEnvelope =>
        // Deep clone so tests can assert the original envelope is not mutated.
        JSON.parse(JSON.stringify(env)) as AnyEnvelope,
    ),
  };
});

import { NotUnlocked } from '../src/errors.js';
import { KeyRing } from '../src/keyring.js';
import { InMemoryStorage } from '../src/storage/in-memory.js';
import { MaximumTier } from '../src/tiers/maximum.js';
import type { KeyRingEvent } from '../src/types.js';
import { fakeEnumerator, fakeEnvelope } from './helpers/fake-enumerator.js';

const FAST_PARAMS = { t: 1, m: 8192, p: 1 };
const ARGON2_TIMEOUT = { timeout: 30_000 };

function randomMasterKey(): MasterKey {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return asMasterKey(SecureBuffer.from(bytes));
}

async function unlockedRing() {
  const storage = new InMemoryStorage();
  const tier = MaximumTier.fromPassphrase('secret', FAST_PARAMS);
  const ring = new KeyRing({ tier, storage });
  await ring.setup(randomMasterKey());
  await ring.unlockWithPassphrase('secret');
  return { ring, tier, storage };
}

function envelopes(count: number): AnyEnvelope[] {
  return Array.from({ length: count }, (_, i) => fakeEnvelope(`b_${String(i).padStart(4, '0')}`));
}

describe('KeyRing.rotate (Phase G basic)', ARGON2_TIMEOUT, () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('throws NotUnlocked when the ring is locked', async () => {
    const storage = new InMemoryStorage();
    const tier = MaximumTier.fromPassphrase('x', FAST_PARAMS);
    const ring = new KeyRing({ tier, storage });
    await ring.setup(randomMasterKey());
    // deliberately NOT unlocked
    const enumerator = fakeEnumerator({ envelopes: envelopes(1) });
    await expect(ring.rotate(tier, enumerator)).rejects.toBeInstanceOf(NotUnlocked);
  });

  it('happy path: rotates every envelope and reports no outstanding old-master requirement', async () => {
    const { ring, tier } = await unlockedRing();
    const events: KeyRingEvent[] = [];
    const ring2 = ring; // alias to avoid shadowing in the sink closure

    // Replace the ring with one that has an events sink so we can assert
    // the lifecycle events fired in the right order.
    const storage2 = new InMemoryStorage();
    const tier2 = MaximumTier.fromPassphrase('secret', FAST_PARAMS);
    const withEvents = new KeyRing({
      tier: tier2,
      storage: storage2,
      events: { emit: (e) => events.push(e) },
    });
    await withEvents.setup(randomMasterKey());
    await withEvents.unlockWithPassphrase('secret');

    const envs = envelopes(10);
    const enumerator = fakeEnumerator({ envelopes: envs });
    const result = await withEvents.rotate(tier2, enumerator);

    expect(result.rotated).toBe(10);
    expect(result.skipped).toBe(0);
    expect(result.failed).toEqual([]);
    expect(result.oldMasterStillRequired).toBe(false);
    expect(result.lastPersistedId).toBe('b_0009');
    expect(result.newMaster).toBeDefined();
    expect(result.newMaster?.length).toBe(32);
    expect(enumerator.persisted).toHaveLength(10);

    // Event ordering: rotate-start → blob-rewrapped × 10 → rotate-complete.
    expect(events[0]?.kind).toBe('rotate-start');
    expect(events.at(-1)?.kind).toBe('rotate-complete');
    const rewrapEvents = events.filter((e) => e.kind === 'blob-rewrapped');
    expect(rewrapEvents).toHaveLength(10);

    // Silence the unused-ring warning — setup ran on `ring2` too.
    expect(ring2.isUnlocked).toBe(true);
  });

  it('aborts mid-run and reports partial progress with oldMasterStillRequired=true', async () => {
    const { ring, tier } = await unlockedRing();
    const controller = new AbortController();
    const envs = envelopes(10);

    let completed = 0;
    const enumerator = fakeEnumerator({
      envelopes: envs,
      persistDelayMs: 1, // ensures persist actually awaits, so abort can land between tasks
      onPersistSettled: ({ failed }) => {
        if (!failed) {
          completed++;
          if (completed === 5) {
            // Fire abort after the 5th persist resolves. The next
            // enumerate-tick or batch-drain will observe it.
            controller.abort();
          }
        }
      },
    });

    const result = await ring.rotate(tier, enumerator, {
      signal: controller.signal,
      batchSize: 1, // serial — makes the "≤ 5" bound tight
    });

    expect(result.rotated).toBeGreaterThan(0);
    expect(result.rotated).toBeLessThanOrEqual(5);
    expect(result.oldMasterStillRequired).toBe(true);
    // lastPersistedId is set to the last successful persist's id.
    expect(result.lastPersistedId).not.toBeNull();
    const lastIdNumeric = Number(result.lastPersistedId?.slice(2));
    expect(lastIdNumeric).toBeLessThanOrEqual(4); // index 4 is the 5th envelope
  });

  it('records persist rejections into failed[] with retriable=true and keeps going', async () => {
    const { ring, tier } = await unlockedRing();
    const envs = envelopes(10);
    const badId = envs[3]?.id;
    if (!badId) throw new Error('test setup invariant');

    const enumerator = fakeEnumerator({
      envelopes: envs,
      persistRejects: (id) => id === badId,
      persistError: new Error('fake disk full'),
    });

    const result = await ring.rotate(tier, enumerator);

    expect(result.rotated).toBe(9);
    expect(result.failed).toHaveLength(1);
    expect(result.failed[0]?.id).toBe(badId);
    expect(result.failed[0]?.retriable).toBe(true);
    expect(result.failed[0]?.error.message).toMatch(/disk full/);
    expect(result.oldMasterStillRequired).toBe(true);
    // lastPersistedId should be the last envelope that actually persisted
    // (the list is processed in order with batchSize default; but 9
    // out of 10 succeeded and the last id is the last envelope).
    expect(result.lastPersistedId).toBe('b_0009');
  });

  it('resumes from lastPersistedId after an abort, finishing the remaining envelopes', async () => {
    const { ring, tier } = await unlockedRing();
    const envs = envelopes(10);

    // First run — abort after 4 successful persists.
    const c1 = new AbortController();
    let completed = 0;
    const e1 = fakeEnumerator({
      envelopes: envs,
      persistDelayMs: 1,
      onPersistSettled: ({ failed }) => {
        if (!failed) {
          completed++;
          if (completed === 4) c1.abort();
        }
      },
    });
    const r1 = await ring.rotate(tier, e1, { signal: c1.signal, batchSize: 1 });
    expect(r1.oldMasterStillRequired).toBe(true);
    expect(r1.rotated).toBeLessThanOrEqual(4);
    expect(r1.lastPersistedId).not.toBeNull();

    // Second run — resume from the cursor on a fresh enumerator over the
    // SAME envelopes (a real consumer would enumerate the same storage).
    const e2 = fakeEnumerator({ envelopes: envs });
    const opts: Parameters<typeof ring.rotate>[2] = {};
    if (r1.lastPersistedId !== null) opts.startAfter = r1.lastPersistedId;
    const r2 = await ring.rotate(tier, e2, opts);

    const totalRotated = r1.rotated + r2.rotated;
    expect(totalRotated).toBe(10);
    expect(r2.failed).toEqual([]);
    expect(r2.oldMasterStillRequired).toBe(false);
    expect(r2.lastPersistedId).toBe('b_0009');
  });
});
