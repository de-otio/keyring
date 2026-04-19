import type { KeyStorage, TierKind, WrappedKey } from '../types.js';

/**
 * In-process, non-persistent key storage. Suitable for tests, ephemeral
 * CLI workflows, and the "unlock once, use in this process" pattern.
 *
 * **Not persistent.** Every process restart starts with an empty store.
 * Do not use for long-lived user-facing applications.
 *
 * **Not concurrency-safe across workers.** Each instance is isolated;
 * sharing state between Node Worker threads requires a separate
 * transport.
 */
export class InMemoryStorage<K extends TierKind = TierKind> implements KeyStorage<K> {
  readonly platform: 'node' | 'browser' | 'webext' = 'node';
  readonly acceptedTiers: readonly K[];
  private readonly _slots = new Map<string, WrappedKey>();

  constructor(options: { acceptedTiers?: readonly K[] } = {}) {
    // Default: accept both tier kinds. Callers generic-narrow the class
    // to restrict at the type level; the runtime check is a belt-and-
    // braces for consumers that evade TypeScript.
    this.acceptedTiers =
      options.acceptedTiers ?? (['standard', 'maximum'] as unknown as readonly K[]);
  }

  async put(slot: string, wrapped: WrappedKey): Promise<void> {
    this._slots.set(slot, wrapped);
  }

  async get(slot: string): Promise<WrappedKey | null> {
    return this._slots.get(slot) ?? null;
  }

  async delete(slot: string): Promise<void> {
    this._slots.delete(slot);
  }

  async list(): Promise<string[]> {
    return Array.from(this._slots.keys());
  }

  /** Test helper: wipe all slots. Not part of the public `KeyStorage` API. */
  clear(): void {
    this._slots.clear();
  }
}
