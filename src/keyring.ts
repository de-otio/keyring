import type { MasterKey } from '@de-otio/crypto-envelope';
import { AlreadyUnlocked, NotUnlocked, TierStorageMismatch } from './errors.js';
import type { KeyStorage, Tier, TierKind, UnlockInput, WrappedKey } from './types.js';

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
  private master: MasterKey | null = null;
  private lastUnlockInputKind: UnlockInput['kind'] | null = null;

  constructor(options: KeyRingOptions<K>) {
    if (!options.storage.acceptedTiers.includes(options.tier.kind)) {
      throw new TierStorageMismatch(options.tier.kind, options.storage.platform);
    }
    this.tier = options.tier;
    this.storage = options.storage;
    this.slot = options.slot ?? PERSONAL_SLOT;
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
}
