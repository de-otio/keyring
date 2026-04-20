import { randomBytes } from 'node:crypto';
import type { AnyEnvelope, MasterKey } from '@de-otio/crypto-envelope';
import { SecureBuffer, asMasterKey, rewrapEnvelope } from '@de-otio/crypto-envelope';
import { AlreadyUnlocked, NotUnlocked, TierStorageMismatch } from './errors.js';
import type {
  BlobEnumerator,
  EventSink,
  KeyStorage,
  RotateOptions,
  RotationResult,
  Tier,
  TierKind,
  UnlockInput,
  WrappedKey,
} from './types.js';

/**
 * Default slot name for the personal master. Reserved; callers cannot
 * use it as a project-key name.
 */
const PERSONAL_SLOT = '__personal';

export interface KeyRingOptions<K extends TierKind> {
  tier: Tier<K>;
  storage: KeyStorage<K>;
  /** Slot name under which the personal master is stored. Defaults to
   *  the reserved `__personal` slot; override for multi-tenancy within
   *  a single storage. */
  slot?: string;
  /** Optional sink for key-lifecycle events. SOC 2 CC6.1 / CC7.2
   *  consumers pipe these into their audit log; the library does not
   *  persist them. */
  events?: EventSink;
}

/**
 * Minimal `KeyRing` — manages a single master key, wrapped by one tier,
 * persisted in one storage backend.
 *
 * Phase B scope: `setup(master)` (wrap + persist), `unlock(input)`
 * (fetch + unwrap), `withMaster(fn)` (scoped access), `lock()` (zero),
 * `delete()` (Art. 17 crypto-shredding).
 *
 * Project keys, rotation, events, `MessageCounter` integration, and
 * audit-event `EventSink` are later phases (F, G) in the plan.
 *
 * ## Capability check
 *
 * The constructor enforces that `storage` accepts the `tier`'s kind —
 * the TypeScript generic `K` carries the check at compile time; the
 * runtime `TierStorageMismatch` throw is a belt-and-braces for
 * consumers that evade narrowing.
 */
export class KeyRing<K extends TierKind = TierKind> {
  private readonly tier: Tier<K>;
  private readonly storage: KeyStorage<K>;
  private readonly slot: string;
  private readonly events: EventSink | undefined;
  private master: MasterKey | null = null;
  private lastUnlockInputKind: UnlockInput['kind'] | null = null;

  constructor(options: KeyRingOptions<K>) {
    if (!options.storage.acceptedTiers.includes(options.tier.kind)) {
      throw new TierStorageMismatch(options.tier.kind, options.storage.platform);
    }
    this.tier = options.tier;
    this.storage = options.storage;
    this.slot = options.slot ?? PERSONAL_SLOT;
    this.events = options.events;
  }

  get isUnlocked(): boolean {
    return this.master !== null;
  }

  /** Return the stored wrapped key, or `null` if the ring has not been
   *  set up yet. Does not unwrap. */
  async getWrapped(): Promise<WrappedKey | null> {
    return this.storage.get(this.slot);
  }

  /**
   * First-time setup: wrap the supplied master via the tier and persist
   * it. Throws if a wrapped key already exists at this slot — use
   * {@link rotate} (future phase) or {@link delete} + re-setup instead
   * of silently overwriting.
   */
  async setup(master: MasterKey): Promise<void> {
    const existing = await this.storage.get(this.slot);
    if (existing) {
      throw new Error(
        `slot '${this.slot}' already has a wrapped master; call delete() first or use rotate() when that lands`,
      );
    }
    const wrapped = await this.tier.wrap(master);
    await this.storage.put(this.slot, wrapped);
  }

  /**
   * Unlock the ring: fetch the wrapped key, ask the tier to unwrap it,
   * hold the result for {@link withMaster} / {@link tryGetMaster}.
   *
   * Idempotent on matching input: calling `unlock` with the same kind
   * while already unlocked is a no-op. Mismatched input (different
   * kind) throws {@link AlreadyUnlocked} — call {@link lock} first if
   * you want to re-unlock.
   */
  async unlock(input: UnlockInput): Promise<void> {
    if (this.master) {
      if (this.lastUnlockInputKind === input.kind) {
        return;
      }
      throw new AlreadyUnlocked(
        `ring already unlocked with kind '${this.lastUnlockInputKind}'; call lock() before unlocking with kind '${input.kind}'`,
      );
    }
    const wrapped = await this.storage.get(this.slot);
    if (!wrapped) {
      throw new Error(`slot '${this.slot}' is empty; call setup(master) first`);
    }
    this.master = await this.tier.unwrap(wrapped, input);
    this.lastUnlockInputKind = input.kind;
  }

  /** Sugar: unlock using a passphrase. Shortcut for MaximumTier. */
  async unlockWithPassphrase(passphrase: string): Promise<void> {
    await this.unlock({ kind: 'passphrase', passphrase });
  }

  /** Sugar: unlock via ssh-agent. Shortcut for StandardTier (Phase C). */
  async unlockWithSshAgent(): Promise<void> {
    await this.unlock({ kind: 'ssh-agent' });
  }

  /** Sugar: unlock with an SSH private key PEM. Shortcut for StandardTier. */
  async unlockWithSshKey(privateKeyPem: string, passphrase?: string): Promise<void> {
    await this.unlock(
      passphrase
        ? { kind: 'ssh-key', privateKeyPem, passphrase }
        : { kind: 'ssh-key', privateKeyPem },
    );
  }

  /**
   * Scoped access to the master. The master is valid inside the
   * callback; after the promise resolves or rejects the master is not
   * re-locked automatically — use {@link lock} when you're done with
   * the ring. The method exists so callers don't need a throwing
   * getter.
   */
  async withMaster<T>(fn: (master: MasterKey) => Promise<T>): Promise<T> {
    if (!this.master) {
      throw new NotUnlocked('KeyRing.withMaster called before unlock()');
    }
    return fn(this.master);
  }

  /** Non-throwing accessor. Returns null if the ring is locked. */
  tryGetMaster(): MasterKey | null {
    return this.master;
  }

  /** Zero the in-memory master. The wrapped form stays in storage.
   *  Idempotent. */
  async lock(): Promise<void> {
    if (this.master) {
      this.master.dispose();
      this.master = null;
      this.lastUnlockInputKind = null;
    }
  }

  /**
   * Crypto-shredding affordance (GDPR Art. 17): delete the wrapped key
   * from storage AND zero the in-memory master. After this, every
   * envelope encrypted under this master is permanently unreadable.
   */
  async delete(): Promise<void> {
    await this.lock();
    await this.storage.delete(this.slot);
  }

  /**
   * Rotate every envelope yielded by `enumerator` from the current
   * master to a freshly-generated new master.
   *
   * ## Semantics
   *
   * 1. Requires the ring to be unlocked (the current master is the
   *    `oldMaster` handed to `rewrapEnvelope`). Throws {@link NotUnlocked}
   *    otherwise.
   * 2. Generates a fresh 32-byte random master via
   *    `crypto.randomBytes(32)` and brands it as a `MasterKey`.
   * 3. Iterates the enumerator; for each envelope calls
   *    `rewrapEnvelope(env, oldMaster, newMaster)` and then
   *    `enumerator.persist(rewrapped, signal)`.
   * 4. Honours bounded concurrency via a small semaphore
   *    (`batchSize`, default 8). Never holds more than `batchSize`
   *    in-flight rewrap/persist tasks in memory at any time.
   * 5. Returns a {@link RotationResult} including `newMaster`. The
   *    caller is responsible for:
   *      - calling `newTier.wrap(newMaster)` + `storage.put(slot, ...)` to
   *        persist the new wrapped master, **only** after checking
   *        `oldMasterStillRequired === false`, and
   *      - calling `newMaster.dispose()` to zero its bytes when done.
   *
   * ## `newTier` argument
   *
   * `newTier` is accepted to match the type signature (from
   * `types.ts`) and document intent: the caller has already decided
   * which tier the new master should land under. `rotate()` itself
   * does **not** swap `this.tier` nor write to storage — that is
   * consumer-driven (see plan-04 §"Interface contracts", the
   * explicit-consumer-control resolution). A future phase may auto-
   * swap storage using `newTier`; right now it is reserved.
   *
   * ## Abort
   *
   * `options.signal` is checked between each rewrap; if it fires, the
   * method resolves with a partial result and `oldMasterStillRequired:
   * true`. The signal is forwarded to `enumerate()` and `persist()` so
   * consumer code can react. If `persist()` rejects with an
   * `AbortError` mid-await, the rejection flows out through the
   * `failed[]` list with `retriable: true`.
   *
   * ## Failure modes
   *
   * - `rewrapEnvelope` throws (tampered or decrypt-fail) → the entry
   *   lands in `failed[]` with `retriable: false`.
   * - `persist` rejects → the entry lands in `failed[]` with
   *   `retriable: true`.
   *
   * In either case rotation continues with the remaining envelopes;
   * the caller retries failures via `startAfter: lastPersistedId`.
   *
   * ## **Not safe inside an MV3 service worker.**
   *
   * Service workers terminate after 30 seconds of idle, which can kill
   * a rotation mid-flight. Drive rotation from a persistent extension
   * page instead. A `rotateBatch` primitive for worker-driven
   * cursor-paginated rotation may land in v0.2.
   *
   * @param newTier Reserved; see "`newTier` argument" above.
   * @param enumerator Caller-supplied iterator + persister; only the
   *   consumer knows their blob layout.
   * @param options Concurrency, resume cursor, abort signal.
   */
  async rotate(
    _newTier: Tier<K>,
    enumerator: BlobEnumerator,
    options?: RotateOptions,
  ): Promise<RotationResult> {
    if (!this.master) {
      throw new NotUnlocked('KeyRing.rotate called before unlock()');
    }
    const oldMaster = this.master;

    const batchSize = options?.batchSize ?? 8;
    if (!Number.isInteger(batchSize) || batchSize < 1) {
      throw new Error(`KeyRing.rotate: batchSize must be a positive integer, got ${batchSize}`);
    }

    const signal = options?.signal;

    // Fresh new master for the rewrap target. SecureBuffer copies the
    // plaintext and zeroes our transient buffer below.
    const newMasterBytes = randomBytes(32);
    let newMaster: MasterKey;
    try {
      newMaster = asMasterKey(SecureBuffer.from(newMasterBytes));
    } finally {
      newMasterBytes.fill(0);
    }

    const result: {
      rotated: number;
      skipped: number;
      failed: Array<{ id: string; error: Error; retriable: boolean }>;
      lastPersistedId: string | null;
      oldMasterStillRequired: boolean;
    } = {
      rotated: 0,
      skipped: 0,
      failed: [],
      lastPersistedId: null,
      oldMasterStillRequired: false,
    };

    const nowIso = () => new Date().toISOString();

    this.events?.emit({
      kind: 'rotate-start',
      oldFingerprint: '',
      newFingerprint: '',
      ts: nowIso(),
    });

    // Bounded-concurrency semaphore: Set<Promise> of in-flight tasks.
    // Before starting a new task, if the set is at `batchSize`,
    // await Promise.race to let at least one slot free up. Each task
    // removes itself from the set on settle (via .finally). This gives
    // FIFO-ish persist ordering without any extra dependency.
    const inflight = new Set<Promise<void>>();

    const enumerateOpts: { startAfter?: string; signal?: AbortSignal } = {};
    if (options?.startAfter !== undefined) enumerateOpts.startAfter = options.startAfter;
    if (signal !== undefined) enumerateOpts.signal = signal;

    /**
     * Process a single envelope. Never rejects — all errors are
     * captured into `result.failed` with the right `retriable` flag.
     * Runs sequentially to completion: rewrap → persist → bookkeep.
     */
    const processOne = async (env: AnyEnvelope, myIndex: number): Promise<void> => {
      let rewrapped: AnyEnvelope;
      try {
        rewrapped = rewrapEnvelope(env, oldMaster, newMaster);
      } catch (e) {
        result.failed.push({
          id: env.id,
          error: e instanceof Error ? e : new Error(String(e)),
          retriable: false,
        });
        return;
      }

      try {
        await enumerator.persist(rewrapped, signal);
      } catch (e) {
        result.failed.push({
          id: env.id,
          error: e instanceof Error ? e : new Error(String(e)),
          retriable: true,
        });
        return;
      }

      result.rotated++;
      result.lastPersistedId = env.id;
      this.events?.emit({
        kind: 'blob-rewrapped',
        id: env.id,
        index: myIndex,
        total: null,
        ts: nowIso(),
      });
    };

    let index = 0;
    try {
      for await (const env of enumerator.enumerate(enumerateOpts)) {
        if (signal?.aborted) break;

        let abortedDuringDrain = false;
        while (inflight.size >= batchSize) {
          // Race returns with the first settled task; that task's
          // .finally handler (attached below) has already removed it
          // from the set.
          await Promise.race(inflight);
          if (signal?.aborted) {
            abortedDuringDrain = true;
            break;
          }
        }
        if (abortedDuringDrain) break;

        const myIndex = index++;
        const task = processOne(env, myIndex);
        inflight.add(task);
        task.finally(() => inflight.delete(task));
      }

      // Drain — wait for every in-flight task to settle before we
      // finalise the result. `processOne` never rejects, but
      // allSettled is the defensive choice.
      await Promise.allSettled(inflight);
    } finally {
      if (signal?.aborted || result.failed.length > 0) {
        result.oldMasterStillRequired = true;
      }

      this.events?.emit({
        kind: 'rotate-complete',
        result: {
          rotated: result.rotated,
          skipped: result.skipped,
          oldMasterStillRequired: result.oldMasterStillRequired,
        },
        ts: nowIso(),
      });
    }

    return {
      rotated: result.rotated,
      skipped: result.skipped,
      failed: result.failed,
      lastPersistedId: result.lastPersistedId,
      oldMasterStillRequired: result.oldMasterStillRequired,
      newMaster,
    };
  }
}
