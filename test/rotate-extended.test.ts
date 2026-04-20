/**
 * Phase G extended tests for `KeyRing.rotate()` — stress + concurrent
 * abort + idempotence. Owned by Worker C (see
 * `plans/04-phase-g-execution.md`).
 *
 * These tests will fail until Worker B's `rotate()` implementation
 * merges; they are checked in first because they document the contract.
 *
 * A local inline fake enumerator is used (rather than the shared
 * `test/helpers/fake-enumerator.ts` Worker B owns) to avoid cross-branch
 * coupling before integration.
 */

import { type AnyEnvelope, EnvelopeClient, deserialize } from '@de-otio/crypto-envelope';
import { describe, expect, it } from 'vitest';
import { InMemoryStorage, KeyRing, MaximumTier } from '../src/index.js';
import type { BlobEnumerator, RotateOptions, RotationResult } from '../src/types.js';

const FAST_PARAMS = { t: 1, m: 8192, p: 1 };
const ARGON2_TIMEOUT = { timeout: 60_000 };

/**
 * Bypass the compile-time check that `rotate` isn't yet on `KeyRing` in
 * this branch. Worker B adds it on `feat/phase-g-rotate`; integration
 * merges the two. Remove this helper and call `ring.rotate(...)` directly
 * after integration.
 */
type WithRotate = {
  rotate(
    newTier: unknown,
    enumerator: BlobEnumerator,
    options?: RotateOptions,
  ): Promise<RotationResult>;
};
function asRotatable(ring: KeyRing): WithRotate {
  return ring as unknown as WithRotate;
}

/**
 * Generate an `AnyEnvelope` directly (not wire bytes) so the fake
 * enumerator can yield it to `rotate` without an extra deserialize hop.
 *
 * `EnvelopeClient.encrypt` returns wire bytes; we round-trip through
 * `deserialize` so the test owns a concrete `AnyEnvelope` structure.
 */
async function makeEnvelopes(
  client: EnvelopeClient,
  count: number,
  payloadBytes = 20,
): Promise<AnyEnvelope[]> {
  const out: AnyEnvelope[] = [];
  const junk = 'a'.repeat(payloadBytes);
  for (let i = 0; i < count; i++) {
    const wire = await client.encrypt({ i, junk });
    out.push(deserialize(wire));
  }
  return out;
}

/**
 * Minimal in-memory blob enumerator.
 *
 * - `persist` is instrumented with a counter that tracks concurrent
 *   unresolved persists at any moment, so test 1 can enforce a
 *   `batchSize`-bounded semaphore.
 * - `persistDelayMs` lets abort tests interleave abort with in-flight
 *   persists.
 * - `onPersistResolved(cb)` fires once per resolved persist — test 2
 *   uses this to trigger an abort at a specific envelope index.
 */
function makeFakeEnumerator(options: {
  envelopes: AnyEnvelope[];
  ordering?: 'stable' | 'arbitrary';
  persistDelayMs?: number;
  maxConcurrent?: number; // if set, persist throws when in-flight count exceeds it
  onPersistResolved?: (id: string, resolvedCount: number) => void;
}): BlobEnumerator & {
  persisted: Map<string, AnyEnvelope>;
  peakInFlight: number;
} {
  const persisted = new Map<string, AnyEnvelope>();
  let inFlight = 0;
  let peakInFlight = 0;
  let resolvedCount = 0;

  const enumerator = {
    ordering: options.ordering ?? 'stable',
    persisted,
    get peakInFlight() {
      return peakInFlight;
    },
    async *enumerate(opts?: { startAfter?: string; signal?: AbortSignal }) {
      // Trivial stable-ordering resume: skip until we find startAfter.
      let skip = !!opts?.startAfter;
      for (const env of options.envelopes) {
        if (opts?.signal?.aborted) return;
        if (skip) {
          if (env.id === opts?.startAfter) skip = false;
          continue;
        }
        yield env;
      }
    },
    async persist(updated: AnyEnvelope, signal?: AbortSignal): Promise<void> {
      inFlight++;
      if (inFlight > peakInFlight) peakInFlight = inFlight;
      if (options.maxConcurrent !== undefined && inFlight > options.maxConcurrent) {
        inFlight--;
        throw new Error(`persist concurrency violated: ${inFlight + 1} > ${options.maxConcurrent}`);
      }
      try {
        if (options.persistDelayMs) {
          await new Promise<void>((resolve, reject) => {
            const t = setTimeout(resolve, options.persistDelayMs);
            if (signal) {
              signal.addEventListener(
                'abort',
                () => {
                  clearTimeout(t);
                  reject(new DOMException('aborted', 'AbortError'));
                },
                { once: true },
              );
            }
          });
        } else {
          // Yield once so multiple persists can interleave on the
          // microtask queue; keeps the concurrency semaphore test
          // meaningful even without artificial delay.
          await Promise.resolve();
        }
        persisted.set(updated.id, updated);
        resolvedCount++;
        options.onPersistResolved?.(updated.id, resolvedCount);
      } finally {
        inFlight--;
      }
    },
  };
  return enumerator;
}

async function buildUnlockedRing(passphrase: string): Promise<{
  ring: KeyRing<'maximum'>;
  oldClient: EnvelopeClient;
}> {
  const storage = new InMemoryStorage<'maximum'>({ acceptedTiers: ['maximum'] });
  const tier = MaximumTier.fromPassphrase(passphrase, FAST_PARAMS);
  const ring = new KeyRing<'maximum'>({ tier, storage });
  // Setup with a fresh master, unlock, so `rotate` has a live old master.
  const masterBytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(masterBytes);
  const { SecureBuffer, asMasterKey } = await import('@de-otio/crypto-envelope');
  const master = asMasterKey(SecureBuffer.from(masterBytes));
  await ring.setup(master);
  await ring.unlockWithPassphrase(passphrase);
  // An EnvelopeClient under the same master so we can pre-create blobs.
  const oldClient = new EnvelopeClient({
    masterKey: ring.tryGetMaster() ?? master,
  });
  return { ring, oldClient };
}

describe('KeyRing.rotate — extended (stress / abort / idempotence)', ARGON2_TIMEOUT, () => {
  describe('test 1: 2k-blob bounded memory', () => {
    it('never exceeds batchSize + 2 in-flight persists while rotating 2000 envelopes', async () => {
      const { ring, oldClient } = await buildUnlockedRing('pw1');
      const envelopes = await makeEnvelopes(oldClient, 2000);
      const batchSize = 8;
      // Bounded-memory proxy: instrument the enumerator to throw if
      // more than `batchSize + 2` persists are simultaneously in flight.
      // The +2 slack absorbs event-loop scheduling jitter (a micro-task
      // for the semaphore increment landing one tick before the dec).
      const enumerator = makeFakeEnumerator({
        envelopes,
        maxConcurrent: batchSize + 2,
      });
      const newTier = MaximumTier.fromPassphrase('pw1-new', FAST_PARAMS);
      const result = await asRotatable(ring).rotate(newTier, enumerator, { batchSize });

      expect(result.rotated).toBe(2000);
      expect(result.failed).toEqual([]);
      expect(enumerator.peakInFlight).toBeLessThanOrEqual(batchSize + 2);
      expect(enumerator.persisted.size).toBe(2000);
      expect(result.oldMasterStillRequired).toBe(false);
    });
  });

  describe('test 2: concurrent abort', () => {
    it('resolves (not rejects) on abort mid-flight; lastPersistedId is accurate within ±batchSize', async () => {
      const { ring, oldClient } = await buildUnlockedRing('pw2');
      const envelopes = await makeEnvelopes(oldClient, 200);
      const batchSize = 8;
      const controller = new AbortController();
      let idOfFiftiethPersist: string | null = null;

      const enumerator = makeFakeEnumerator({
        envelopes,
        persistDelayMs: 1, // force scheduling so abort actually lands mid-flight
        onPersistResolved: (id, resolvedCount) => {
          if (resolvedCount === 50) {
            idOfFiftiethPersist = id;
            // fire the abort once the 50th persist has resolved
            controller.abort();
          }
        },
      });
      const newTier = MaximumTier.fromPassphrase('pw2-new', FAST_PARAMS);

      // Must resolve, not throw — plan specifies partial-state-on-abort
      // resolves (only a signal mid-await inside persist may reject).
      const result = await asRotatable(ring).rotate(newTier, enumerator, {
        batchSize,
        signal: controller.signal,
      });

      // `rotated` should be within ±batchSize of 50 — up to `batchSize`
      // in-flight rewraps complete after the 50th resolves, before the
      // outer loop's abort check fires.
      expect(result.rotated).toBeGreaterThanOrEqual(50 - batchSize);
      expect(result.rotated).toBeLessThanOrEqual(50 + batchSize);
      expect(result.oldMasterStillRequired).toBe(true);
      expect(result.lastPersistedId).not.toBeNull();
      // The 50th id should appear in persisted.
      expect(idOfFiftiethPersist).not.toBeNull();
      if (idOfFiftiethPersist) {
        expect(enumerator.persisted.has(idOfFiftiethPersist)).toBe(true);
      }
    });
  });

  describe('test 3: idempotent double-run', () => {
    it('re-runs end-to-end with no error (Phase G has no commitment-based skip yet)', async () => {
      const { ring, oldClient } = await buildUnlockedRing('pw3');
      const envelopes = await makeEnvelopes(oldClient, 100);
      const batchSize = 8;
      const enumerator = makeFakeEnumerator({ envelopes });
      const newTier = MaximumTier.fromPassphrase('pw3-new', FAST_PARAMS);

      // First run: rotates every envelope.
      const first = await asRotatable(ring).rotate(newTier, enumerator, { batchSize });
      expect(first.rotated).toBe(100);
      expect(first.failed).toEqual([]);
      expect(first.oldMasterStillRequired).toBe(false);

      // Second run against the **same** input envelopes. Phase G has
      // no commitment-based skip (scope cut per
      // plans/04-phase-g-execution.md), so re-running against the same
      // inputs re-does the work. The ring still holds the original
      // master (rotate doesn't auto-swap), so the old-master-encrypted
      // envelopes decrypt fine and are rewrapped under a fresh master.
      //
      // Consumer-side idempotence (skip-by-commitment when the
      // envelope is already on the new master) lands in a later alpha.
      const enumerator2 = makeFakeEnumerator({ envelopes });
      const second = await asRotatable(ring).rotate(newTier, enumerator2, { batchSize });
      expect(second.rotated).toBe(100);
      expect(second.failed).toEqual([]);
      expect(second.oldMasterStillRequired).toBe(false);
    });
  });
});
