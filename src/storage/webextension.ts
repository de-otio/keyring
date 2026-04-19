import type { KeyStorage, WrappedKey } from '../types.js';

/**
 * Minimal WebExtension `chrome.storage` surface. Declared locally so
 * callers don't need `@types/chrome` installed just to use this library.
 * Both Chrome (MV3) and Firefox expose this shape; `browser.storage` on
 * older Firefox can be polyfilled via `webextension-polyfill`.
 */
export interface WebExtensionStorageArea {
  get(keys: string | string[] | null): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(keys: string | string[]): Promise<void>;
}

/**
 * WebExtension-backed `KeyStorage`. Persists wrapped keys in
 * `chrome.storage.local` (default) or `chrome.storage.session`, depending
 * on the caller's configured persistence. Only `'standard'` (SSH-wrapped)
 * tiers are accepted — passphrase-derived masters ({@link MaximumTier})
 * must not live in browser storage; browsers lack the memory-hygiene
 * primitives (`mlock`, `madvise(MADV_DONTDUMP)`) available on Node via
 * `sodium-native`, so passphrase-derived material in WebExtension
 * storage would weaken the threat model.
 *
 * ## Keying
 *
 * Slots live under a configurable `prefix` (default `'keyring:'`) so
 * callers can share a `chrome.storage.local` with unrelated data. `list()`
 * enumerates only keys with the prefix, never the full storage area.
 *
 * ## Persistence
 *
 * - `'local'`: Chrome `chrome.storage.local`; persists across browser
 *   restarts; ~10MB quota. Suitable for wrapped keys that should survive
 *   the session.
 * - `'session'`: Chrome `chrome.storage.session` (MV3-only); cleared when
 *   the browser closes. Suitable for "unlock once per session" flows.
 *
 * ## Crypto-shredding
 *
 * `delete(slot)` calls `chrome.storage.*.remove(key)`. Chrome/Firefox
 * don't expose block-level erasure guarantees — bytes may persist in
 * free profile-disk space until filesystem reuse. Per the library's
 * framing: erasure is satisfied at the envelope layer, not the storage
 * layer.
 */
export class WebExtensionStorage implements KeyStorage<'standard'> {
  readonly platform = 'webext' as const;
  readonly acceptedTiers: readonly 'standard'[] = ['standard'];
  readonly prefix: string;
  readonly persistence: 'local' | 'session';
  private readonly area: WebExtensionStorageArea;

  constructor(
    options: {
      /** Storage area. Defaults to `chrome.storage.local` (or
       *  `chrome.storage.session` when `persistence === 'session'`) if
       *  the global `chrome.storage` is present. Tests inject a mock. */
      storageArea?: WebExtensionStorageArea;
      /** `'local'` survives browser restarts; `'session'` clears on browser
       *  close. Default: `'local'`. Ignored when `storageArea` is supplied. */
      persistence?: 'local' | 'session';
      /** Key namespace so this storage can share a `chrome.storage.local`
       *  with other extension data. Default: `'keyring:'`. Trailing `:` is
       *  added if missing. */
      prefix?: string;
    } = {},
  ) {
    this.persistence = options.persistence ?? 'local';
    this.prefix = normalisePrefix(options.prefix ?? 'keyring:');
    const injected = options.storageArea;
    if (injected) {
      this.area = injected;
    } else {
      const detected = detectArea(this.persistence);
      if (!detected) {
        throw new Error(
          'WebExtensionStorage: chrome.storage not found; pass `storageArea` explicitly or run in an MV3 extension context',
        );
      }
      this.area = detected;
    }
  }

  async put(slot: string, wrapped: WrappedKey): Promise<void> {
    assertValidSlotName(slot);
    await this.area.set({ [this.keyFor(slot)]: toSerialisable(wrapped) });
  }

  async get(slot: string): Promise<WrappedKey | null> {
    assertValidSlotName(slot);
    const key = this.keyFor(slot);
    const obj = await this.area.get(key);
    const raw = obj[key];
    if (raw === undefined || raw === null) return null;
    return fromSerialisable(raw);
  }

  async delete(slot: string): Promise<void> {
    assertValidSlotName(slot);
    await this.area.remove(this.keyFor(slot));
  }

  async list(): Promise<string[]> {
    const all = await this.area.get(null);
    const out: string[] = [];
    for (const key of Object.keys(all)) {
      if (key.startsWith(this.prefix)) {
        out.push(key.slice(this.prefix.length));
      }
    }
    return out;
  }

  private keyFor(slot: string): string {
    return this.prefix + slot;
  }
}

// ── storage area detection ─────────────────────────────────────────────

function detectArea(persistence: 'local' | 'session'): WebExtensionStorageArea | null {
  const g = globalThis as unknown as {
    chrome?: { storage?: Record<string, WebExtensionStorageArea | undefined> };
    browser?: { storage?: Record<string, WebExtensionStorageArea | undefined> };
  };
  const storage = g.chrome?.storage ?? g.browser?.storage;
  const area = storage?.[persistence];
  return area ?? null;
}

function normalisePrefix(p: string): string {
  if (p.length === 0) return 'keyring:';
  return p.endsWith(':') ? p : `${p}:`;
}

// ── slot-name validation ──────────────────────────────────────────────

const SLOT_NAME_PATTERN = /^[A-Za-z0-9._-]{1,128}$/;

function assertValidSlotName(slot: string): void {
  if (!SLOT_NAME_PATTERN.test(slot) || slot === '.' || slot === '..') {
    throw new Error(
      `invalid slot name '${slot}': must match ${SLOT_NAME_PATTERN} (letters, digits, '.', '_', '-'; 1–128 chars; not '.' or '..')`,
    );
  }
}

// ── serialisation ──────────────────────────────────────────────────────

interface SerialisedWrappedKey {
  v: 1;
  tier: string;
  envelope: string;
  kdfParams?: {
    algorithm: string;
    t?: number;
    m?: number;
    p?: number;
    iterations?: number;
    salt: string;
  };
  sshFingerprint?: string;
  ts: string;
}

function bytesToBase64(u8: Uint8Array): string {
  // btoa/atob are globals in Node 20+ and every modern browser.
  let s = '';
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i] ?? 0);
  return btoa(s);
}

function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}

function toSerialisable(w: WrappedKey): SerialisedWrappedKey {
  const out: SerialisedWrappedKey = {
    v: w.v,
    tier: w.tier,
    envelope: bytesToBase64(w.envelope),
    ts: w.ts,
  };
  if (w.kdfParams) {
    if (w.kdfParams.algorithm === 'argon2id') {
      out.kdfParams = {
        algorithm: 'argon2id',
        t: w.kdfParams.t,
        m: w.kdfParams.m,
        p: w.kdfParams.p,
        salt: bytesToBase64(w.kdfParams.salt),
      };
    } else {
      out.kdfParams = {
        algorithm: 'pbkdf2-sha256',
        iterations: w.kdfParams.iterations,
        salt: bytesToBase64(w.kdfParams.salt),
      };
    }
  }
  if (w.sshFingerprint) {
    out.sshFingerprint = w.sshFingerprint;
  }
  return out;
}

function fromSerialisable(raw: unknown): WrappedKey {
  if (typeof raw !== 'object' || raw === null) {
    throw new Error('WebExtensionStorage: stored value is not an object');
  }
  const parsed = raw as SerialisedWrappedKey;
  if (parsed.v !== 1) {
    throw new Error(`unsupported wrapped-key wire version: ${parsed.v}`);
  }
  if (parsed.tier !== 'standard' && parsed.tier !== 'maximum') {
    throw new Error(`unsupported tier kind: ${parsed.tier}`);
  }
  const wrapped: WrappedKey = {
    v: 1,
    tier: parsed.tier,
    envelope: base64ToBytes(parsed.envelope),
    ts: parsed.ts,
  };
  if (parsed.kdfParams) {
    const saltBytes = base64ToBytes(parsed.kdfParams.salt);
    if (parsed.kdfParams.algorithm === 'argon2id') {
      wrapped.kdfParams = {
        algorithm: 'argon2id',
        t: parsed.kdfParams.t ?? 0,
        m: parsed.kdfParams.m ?? 0,
        p: parsed.kdfParams.p ?? 0,
        salt: saltBytes,
      };
    } else if (parsed.kdfParams.algorithm === 'pbkdf2-sha256') {
      wrapped.kdfParams = {
        algorithm: 'pbkdf2-sha256',
        iterations: parsed.kdfParams.iterations ?? 0,
        salt: saltBytes,
      };
    } else {
      throw new Error(`unsupported KDF algorithm: ${parsed.kdfParams.algorithm}`);
    }
  }
  if (parsed.sshFingerprint) {
    wrapped.sshFingerprint = parsed.sshFingerprint;
  }
  return wrapped;
}
