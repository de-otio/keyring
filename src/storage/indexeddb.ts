import type { KeyStorage, WrappedKey } from '../types.js';

/**
 * IndexedDB-backed `KeyStorage` for browser contexts (service workers,
 * web pages, extension background pages). Only `'standard'` (SSH-wrapped)
 * tiers are accepted — passphrase-derived masters
 * ({@link MaximumTier}) must not live in browser storage; browsers
 * lack `mlock`/`madvise` primitives available on Node via
 * `sodium-native`, so passphrase-derived material in IndexedDB would
 * weaken the threat model.
 *
 * ## Database layout
 *
 * Single object store per `dbName`; the `storeName` option lets callers
 * partition when they share a DB with non-keyring content. Keys are
 * slot names; values are {@link WrappedKey}-shaped records stored via
 * IndexedDB's structured-clone algorithm (so `Uint8Array` round-trips
 * natively — no base64).
 *
 * ## Optional runtime dep
 *
 * `idb` wraps IndexedDB's callback API in promises. It ships a tiny
 * (~1.5KB gzipped) bundle and is lazy-loaded on first use; failure
 * throws a helpful error rather than a cryptic `Cannot find module`.
 *
 * ## Crypto-shredding
 *
 * `delete(slot)` calls `objectStore.delete(key)`. Browsers don't expose
 * block-level erasure — bytes may persist in profile-disk free space
 * until the browser's storage layer compacts. Per the library's
 * framing: erasure is satisfied at the envelope layer, not the storage
 * layer.
 */
export class IndexedDbStorage implements KeyStorage<'standard'> {
  readonly platform = 'browser' as const;
  readonly acceptedTiers: readonly 'standard'[] = ['standard'];
  readonly dbName: string;
  readonly storeName: string;
  readonly version: number;

  constructor(options: { dbName: string; storeName?: string; version?: number }) {
    if (!options.dbName || typeof options.dbName !== 'string') {
      throw new Error('IndexedDbStorage: `dbName` option is required');
    }
    this.dbName = options.dbName;
    this.storeName = options.storeName ?? 'wrapped-keys';
    this.version = options.version ?? 1;
  }

  async put(slot: string, wrapped: WrappedKey): Promise<void> {
    assertValidSlotName(slot);
    const db = await this.openDb();
    try {
      await db.put(this.storeName, serialiseRecord(wrapped), slot);
    } finally {
      db.close();
    }
  }

  async get(slot: string): Promise<WrappedKey | null> {
    assertValidSlotName(slot);
    const db = await this.openDb();
    try {
      const raw = await db.get(this.storeName, slot);
      if (raw === undefined || raw === null) return null;
      return deserialiseRecord(raw);
    } finally {
      db.close();
    }
  }

  async delete(slot: string): Promise<void> {
    assertValidSlotName(slot);
    const db = await this.openDb();
    try {
      await db.delete(this.storeName, slot);
    } finally {
      db.close();
    }
  }

  async list(): Promise<string[]> {
    const db = await this.openDb();
    try {
      const keys = await db.getAllKeys(this.storeName);
      return keys.map((k) => String(k));
    } finally {
      db.close();
    }
  }

  private async openDb(): Promise<DbHandle> {
    const { openDB } = await loadIdb();
    return openDB(this.dbName, this.version, {
      upgrade: (db) => {
        if (!db.objectStoreNames.contains(this.storeName)) {
          db.createObjectStore(this.storeName);
        }
      },
    });
  }
}

// ── lazy-load handling ─────────────────────────────────────────────────

interface DbHandle {
  put(storeName: string, value: unknown, key?: IDBValidKey): Promise<IDBValidKey>;
  get(storeName: string, key: IDBValidKey): Promise<unknown>;
  delete(storeName: string, key: IDBValidKey): Promise<void>;
  getAllKeys(storeName: string): Promise<IDBValidKey[]>;
  close(): void;
}

interface IdbModule {
  openDB(
    name: string,
    version: number,
    options: {
      upgrade: (db: {
        objectStoreNames: { contains: (s: string) => boolean };
        createObjectStore: (s: string) => unknown;
      }) => void;
    },
  ): Promise<DbHandle>;
}

let cachedIdb: IdbModule | null = null;
let cachedErr: Error | null = null;

async function loadIdb(): Promise<IdbModule> {
  if (cachedIdb) return cachedIdb;
  if (cachedErr) throw cachedErr;
  try {
    cachedIdb = (await import('idb')) as unknown as IdbModule;
    return cachedIdb;
  } catch (cause) {
    cachedErr = new Error(
      'IndexedDbStorage: the optional `idb` package could not be loaded. Install it as a peer dependency (`npm i idb`) to use IndexedDB-backed storage in browser contexts.',
      { cause },
    );
    throw cachedErr;
  }
}

/** Internal: reset the module cache. Not part of the public API —
 *  exposed for tests that need to re-drive the load path. */
export function _resetIdbCache(): void {
  cachedIdb = null;
  cachedErr = null;
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

interface StoredRecord {
  v: 1;
  tier: string;
  envelope: Uint8Array;
  kdfParams?: {
    algorithm: string;
    t?: number;
    m?: number;
    p?: number;
    iterations?: number;
    salt: Uint8Array;
  };
  sshFingerprint?: string;
  ts: string;
}

function serialiseRecord(w: WrappedKey): StoredRecord {
  const out: StoredRecord = {
    v: w.v,
    tier: w.tier,
    envelope: w.envelope,
    ts: w.ts,
  };
  if (w.kdfParams) {
    if (w.kdfParams.algorithm === 'argon2id') {
      out.kdfParams = {
        algorithm: 'argon2id',
        t: w.kdfParams.t,
        m: w.kdfParams.m,
        p: w.kdfParams.p,
        salt: w.kdfParams.salt,
      };
    } else {
      out.kdfParams = {
        algorithm: 'pbkdf2-sha256',
        iterations: w.kdfParams.iterations,
        salt: w.kdfParams.salt,
      };
    }
  }
  if (w.sshFingerprint) {
    out.sshFingerprint = w.sshFingerprint;
  }
  return out;
}

function deserialiseRecord(raw: unknown): WrappedKey {
  if (typeof raw !== 'object' || raw === null) {
    throw new Error('IndexedDbStorage: stored record is not an object');
  }
  const parsed = raw as StoredRecord;
  if (parsed.v !== 1) {
    throw new Error(`unsupported wrapped-key wire version: ${parsed.v}`);
  }
  if (parsed.tier !== 'standard' && parsed.tier !== 'maximum') {
    throw new Error(`unsupported tier kind: ${parsed.tier}`);
  }
  const wrapped: WrappedKey = {
    v: 1,
    tier: parsed.tier,
    envelope: coerceBytes(parsed.envelope),
    ts: parsed.ts,
  };
  if (parsed.kdfParams) {
    const saltBytes = coerceBytes(parsed.kdfParams.salt);
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

function coerceBytes(v: unknown): Uint8Array {
  if (v instanceof Uint8Array) return v;
  if (v instanceof ArrayBuffer) return new Uint8Array(v);
  // Some stores (fakes / old browsers) may coerce to Array<number> or
  // { 0: x, 1: y, ... } under structured-clone edge cases.
  if (Array.isArray(v)) return new Uint8Array(v);
  throw new Error('IndexedDbStorage: expected Uint8Array for binary field');
}
