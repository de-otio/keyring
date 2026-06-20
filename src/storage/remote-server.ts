import type { KeyStorage, TierKind, WrappedKey } from '../types.js';
import { deserializeWrappedKey, serializeWrappedKey } from './wrapped-key-codec.js';

/**
 * The HTTP (or other) transport a {@link RemoteServerStorage} delegates to. The
 * **consuming application** implements this against its own server — endpoints,
 * authentication (bearer token / cookie), retries, and the mapping from a
 * keyring `slot` to whatever the server addresses (a path, a row, a settings
 * namespace) all live here, NOT in this library. Keeping it abstract is what
 * lets `@de-otio/keyring` ship a server-backed store without taking a
 * dependency on any particular API shape.
 *
 * The `blob` is the **opaque** serialised {@link WrappedKey} string. It is
 * ciphertext-only from the server's perspective: the server stores and returns
 * it verbatim and learns nothing (server-blind). Implementations MUST NOT
 * parse, transform, or truncate it.
 */
export interface RemoteBlobTransport {
  /** Return the stored blob for `slot`, or `null` if there is none. */
  fetchBlob(slot: string): Promise<string | null>;
  /** Store (create or overwrite) the opaque blob for `slot`. */
  storeBlob(slot: string, blob: string): Promise<void>;
  /** Remove the blob for `slot`. Idempotent: removing an absent slot resolves. */
  removeBlob(slot: string): Promise<void>;
  /** List the slot names the server currently holds for this principal. */
  listSlots(): Promise<string[]>;
}

export interface RemoteServerStorageOptions<K extends TierKind> {
  /**
   * Tier kinds this store will accept. **Defaults to `['recovery-key']`** — and
   * that default is a security decision, not a placeholder: a server-held
   * wrapped master must be sealed under a *high-entropy* key. A passphrase-
   * (`maximum`) or SSH-passphrase-derived (`standard`) master sitting on a
   * server is offline-grindable; the `recovery-key` tier's 32-byte key is not.
   * Override only if you have a deliberate reason and understand that exposure.
   */
  acceptedTiers?: readonly K[];
  /** Reported `platform`. Defaults to `'node'` (the codec uses Node base64). A
   *  browser/webext consumer can override the label, but note the shared codec
   *  is Node-`Buffer`-based; a pure-browser build needs its own codec. */
  platform?: 'node' | 'browser' | 'webext';
}

/**
 * `KeyStorage` backed by a remote, **server-blind** blob store. The wrapped
 * master is serialised (opaque ciphertext) and handed to an injected
 * {@link RemoteBlobTransport}; the server holds bytes it cannot open.
 *
 * Pairs with the `recovery-key` tier for the canonical use case: a settings/
 * messaging keystore that syncs the wrapped DEK across a user's devices through
 * the same server-blind channel as the encrypted data itself, with **no
 * server-side key escrow**.
 */
export class RemoteServerStorage<K extends TierKind = 'recovery-key'> implements KeyStorage<K> {
  readonly platform: 'node' | 'browser' | 'webext';
  readonly acceptedTiers: readonly K[];
  private readonly transport: RemoteBlobTransport;

  constructor(transport: RemoteBlobTransport, options?: RemoteServerStorageOptions<K>) {
    this.transport = transport;
    this.acceptedTiers = options?.acceptedTiers ?? (['recovery-key'] as unknown as readonly K[]);
    this.platform = options?.platform ?? 'node';
  }

  async put(slot: string, wrapped: WrappedKey): Promise<void> {
    assertNonEmptySlot(slot);
    // Boundary guard: refuse to push a tier this store does not accept (the
    // default refuses grindable passphrase/SSH masters), independent of any
    // KeyRing-construction check. A server must never receive a low-entropy-
    // wrapped master.
    if (!(this.acceptedTiers as readonly TierKind[]).includes(wrapped.tier)) {
      throw new Error(
        `RemoteServerStorage refuses tier '${wrapped.tier}': accepted tiers are [${this.acceptedTiers.join(
          ', ',
        )}]. Storing a low-entropy-wrapped master on a server is offline-grindable.`,
      );
    }
    await this.transport.storeBlob(slot, serializeWrappedKey(wrapped));
  }

  async get(slot: string): Promise<WrappedKey | null> {
    assertNonEmptySlot(slot);
    const blob = await this.transport.fetchBlob(slot);
    if (blob === null) return null;
    return deserializeWrappedKey(blob);
  }

  async delete(slot: string): Promise<void> {
    assertNonEmptySlot(slot);
    await this.transport.removeBlob(slot);
  }

  async list(): Promise<string[]> {
    return this.transport.listSlots();
  }
}

function assertNonEmptySlot(slot: string): void {
  if (typeof slot !== 'string' || slot.length === 0) {
    throw new Error('RemoteServerStorage: slot must be a non-empty string');
  }
}
