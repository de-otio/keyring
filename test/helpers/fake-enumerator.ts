import type { AnyEnvelope } from '@de-otio/crypto-envelope';
import type { BlobEnumerator } from '../../src/types.js';

/**
 * Minimal in-memory fake of {@link BlobEnumerator} for the rotate tests.
 *
 * Holds a list of envelopes, yields them through an async generator, and
 * records every `persist` call for assertion. Configurable hooks let a test
 * inject a per-envelope persist rejection or an artificial delay so that
 * the library's bounded concurrency and abort behaviour can be exercised.
 *
 * Intentionally tiny — Worker C reuses the same helper for extended tests.
 */
export interface FakeEnumeratorOptions {
  /** Envelopes yielded by `enumerate`, in the order supplied. */
  envelopes: readonly AnyEnvelope[];
  /**
   * Per-envelope-id predicate: return `true` to make `persist` reject with
   * the supplied {@link FakeEnumeratorOptions.persistError} for that id.
   * Defaults to rejecting nothing.
   */
  persistRejects?: (id: string) => boolean;
  /** Error thrown by `persist` when `persistRejects` returns true. */
  persistError?: Error;
  /** `'stable'` (default) enables `startAfter`-based resume; `'arbitrary'`
   *  disables it (enumerate ignores `startAfter`). */
  ordering?: 'stable' | 'arbitrary';
  /** Optional async delay applied inside `persist` so tests can observe
   *  bounded-concurrency behaviour without real I/O. */
  persistDelayMs?: number;
  /**
   * Fires after each individual `persist` settles (success or failure).
   * Tests use this to count completed persists and trigger an abort after
   * a specific index.
   */
  onPersistSettled?: (args: { id: string; index: number; failed: boolean }) => void;
}

export interface FakeEnumerator extends BlobEnumerator {
  /** Envelopes that `persist` resolved for, in the order they resolved. */
  readonly persisted: ReadonlyArray<AnyEnvelope>;
}

/**
 * Build a {@link FakeEnumerator} for a rotate test.
 *
 * `enumerate` honours `startAfter` (stable ordering only) by skipping all
 * envelopes up to and **including** the matching id — mirroring the
 * documented resume-cursor semantics of {@link BlobEnumerator} (cursor
 * points at the last successfully-persisted id; next run picks up after).
 *
 * `persist` pushes into the `persisted` array on success so tests can
 * assert how many rewraps actually landed. Order of `persisted` reflects
 * the order `persist` resolved, not the order `enumerate` yielded — with
 * `batchSize > 1` these can diverge.
 */
export function fakeEnumerator(options: FakeEnumeratorOptions): FakeEnumerator {
  const {
    envelopes,
    persistRejects = () => false,
    persistError = new Error('fake-enumerator: persist rejected'),
    ordering = 'stable',
    persistDelayMs = 0,
    onPersistSettled,
  } = options;

  const persisted: AnyEnvelope[] = [];
  let persistCallIndex = 0;

  const enumerator: FakeEnumerator = {
    ordering,
    get persisted() {
      return persisted;
    },
    async *enumerate(enumerateOptions?: { startAfter?: string; signal?: AbortSignal }) {
      let skipping = false;
      let skipUntilFound = false;
      if (ordering === 'stable' && enumerateOptions?.startAfter !== undefined) {
        skipping = true;
        skipUntilFound = true;
      }
      for (const env of envelopes) {
        if (enumerateOptions?.signal?.aborted) return;
        if (skipping) {
          if (skipUntilFound && env.id === enumerateOptions?.startAfter) {
            skipping = false;
            // Cursor points at the last-persisted id → the NEXT envelope
            // is where we resume. So continue past this one too.
            continue;
          }
          continue;
        }
        yield env;
      }
    },
    async persist(updated, signal) {
      const myIndex = persistCallIndex++;
      if (persistDelayMs > 0) {
        await new Promise<void>((resolve, reject) => {
          const t = setTimeout(resolve, persistDelayMs);
          if (signal) {
            const onAbort = () => {
              clearTimeout(t);
              reject(
                Object.assign(new Error('fake-enumerator: persist aborted'), {
                  name: 'AbortError',
                }),
              );
            };
            if (signal.aborted) {
              onAbort();
            } else {
              signal.addEventListener('abort', onAbort, { once: true });
            }
          }
        });
      }
      if (persistRejects(updated.id)) {
        onPersistSettled?.({ id: updated.id, index: myIndex, failed: true });
        throw persistError;
      }
      persisted.push(updated);
      onPersistSettled?.({ id: updated.id, index: myIndex, failed: false });
    },
  };

  return enumerator;
}

/**
 * Build a deterministic v1-shaped envelope for tests. The bytes are not
 * real ciphertext — the rewrap primitive is mocked in the rotate tests.
 *
 * Exposed here so Worker C can reuse the same id scheme.
 */
export function fakeEnvelope(
  id: string,
  algorithm: 'XChaCha20-Poly1305' = 'XChaCha20-Poly1305',
): AnyEnvelope {
  return {
    v: 1,
    id,
    ts: '2026-04-19T00:00:00.000Z',
    enc: {
      alg: algorithm,
      kid: 'test-kid',
      ct: 'AAAAAAAAAAAAAAAAAAAAAA==',
      'ct.len': 16,
      commit: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
    },
  };
}
