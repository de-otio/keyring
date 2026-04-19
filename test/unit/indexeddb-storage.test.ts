import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { WrappedKey } from '../../src/types.js';

/**
 * Unit tests for IndexedDbStorage. `idb` (and by transitive dep, the
 * browser-only `indexedDB` global) is mocked — we substitute an
 * in-memory fake that implements just the surface our SUT calls. The
 * real IndexedDB round-trip is covered by the Playwright smoke test
 * (deferred until a browser test project is wired, Phase E3).
 */

// Per-test in-memory fake. `stores` is a Map<dbName, Map<storeName, Map<key, value>>>.
const stores = new Map<string, Map<string, Map<string, unknown>>>();

vi.mock('idb', () => {
  class FakeDb {
    constructor(
      private readonly dbName: string,
      private readonly version: number,
    ) {}
    get objectStoreNames() {
      const db = stores.get(this.dbName);
      return {
        contains: (s: string) => db?.has(s) ?? false,
      };
    }
    createObjectStore(storeName: string) {
      let db = stores.get(this.dbName);
      if (!db) {
        db = new Map();
        stores.set(this.dbName, db);
      }
      if (!db.has(storeName)) db.set(storeName, new Map());
      return {};
    }
    async put(storeName: string, value: unknown, key: string) {
      const store = stores.get(this.dbName)?.get(storeName);
      if (!store) throw new Error(`store ${storeName} missing in fake`);
      // Structured-clone approximation: copy the envelope Uint8Array so
      // callers holding the original can mutate it without the fake
      // seeing changes.
      store.set(key, clonePlain(value));
      return key;
    }
    async get(storeName: string, key: string) {
      return stores.get(this.dbName)?.get(storeName)?.get(key);
    }
    async delete(storeName: string, key: string) {
      stores.get(this.dbName)?.get(storeName)?.delete(key);
    }
    async getAllKeys(storeName: string) {
      return Array.from(stores.get(this.dbName)?.get(storeName)?.keys() ?? []);
    }
    close() {
      /* noop for fake */
    }
  }

  async function openDB(
    dbName: string,
    version: number,
    options: { upgrade: (db: FakeDb) => void },
  ) {
    const db = new FakeDb(dbName, version);
    if (!stores.has(dbName)) {
      stores.set(dbName, new Map());
      options.upgrade(db);
    } else {
      // Still run upgrade so callers adding new stores land them.
      options.upgrade(db);
    }
    return db;
  }

  return { openDB };
});

function clonePlain(v: unknown): unknown {
  if (v instanceof Uint8Array) return new Uint8Array(v);
  if (v === null || typeof v !== 'object') return v;
  const out: Record<string, unknown> = {};
  for (const [k, val] of Object.entries(v)) out[k] = clonePlain(val);
  return out;
}

const { IndexedDbStorage, _resetIdbCache } = await import('../../src/storage/indexeddb.js');

function wrappedFixture(overrides?: Partial<WrappedKey>): WrappedKey {
  const base: WrappedKey = {
    v: 1,
    tier: 'standard',
    envelope: new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd]),
    sshFingerprint: 'SHA256:abc',
    ts: '2026-04-19T10:00:00.000Z',
  };
  return { ...base, ...overrides };
}

describe('IndexedDbStorage (mocked idb)', () => {
  beforeEach(() => {
    stores.clear();
    _resetIdbCache();
  });

  it('throws when dbName is missing', () => {
    expect(() => new IndexedDbStorage({ dbName: '' })).toThrow(/dbName/);
  });

  it('round-trips put + get', async () => {
    const s = new IndexedDbStorage({ dbName: 'test-db' });
    const w = wrappedFixture();
    await s.put('slot1', w);
    const got = await s.get('slot1');
    expect(got).not.toBeNull();
    expect(got?.tier).toBe('standard');
    expect(Array.from(got?.envelope ?? [])).toEqual([0xaa, 0xbb, 0xcc, 0xdd]);
    expect(got?.sshFingerprint).toBe('SHA256:abc');
  });

  it('returns null for a missing slot', async () => {
    const s = new IndexedDbStorage({ dbName: 'test-db' });
    expect(await s.get('never')).toBeNull();
  });

  it('overwrites on second put', async () => {
    const s = new IndexedDbStorage({ dbName: 'test-db' });
    await s.put('slot', wrappedFixture({ sshFingerprint: 'SHA256:first' }));
    await s.put('slot', wrappedFixture({ sshFingerprint: 'SHA256:second' }));
    const got = await s.get('slot');
    expect(got?.sshFingerprint).toBe('SHA256:second');
  });

  it('delete removes the slot', async () => {
    const s = new IndexedDbStorage({ dbName: 'test-db' });
    await s.put('slot', wrappedFixture());
    await s.delete('slot');
    expect(await s.get('slot')).toBeNull();
  });

  it('delete on a missing slot is idempotent', async () => {
    const s = new IndexedDbStorage({ dbName: 'test-db' });
    await expect(s.delete('never')).resolves.not.toThrow();
  });

  it('list returns all stored slot names', async () => {
    const s = new IndexedDbStorage({ dbName: 'test-db' });
    await s.put('alice', wrappedFixture());
    await s.put('bob', wrappedFixture());
    expect((await s.list()).sort()).toEqual(['alice', 'bob']);
  });

  it('isolates different DBs', async () => {
    const a = new IndexedDbStorage({ dbName: 'db-a' });
    const b = new IndexedDbStorage({ dbName: 'db-b' });
    await a.put('alice', wrappedFixture());
    await b.put('bob', wrappedFixture());
    expect(await a.list()).toEqual(['alice']);
    expect(await b.list()).toEqual(['bob']);
  });

  it('isolates different storeNames within one DB', async () => {
    const a = new IndexedDbStorage({ dbName: 'shared', storeName: 'store-a' });
    const b = new IndexedDbStorage({ dbName: 'shared', storeName: 'store-b' });
    await a.put('alice', wrappedFixture());
    await b.put('bob', wrappedFixture());
    expect(await a.list()).toEqual(['alice']);
    expect(await b.list()).toEqual(['bob']);
  });

  it('persists argon2id kdfParams through round-trip', async () => {
    const s = new IndexedDbStorage({ dbName: 'test-db' });
    const w: WrappedKey = {
      v: 1,
      tier: 'maximum',
      envelope: new Uint8Array([1, 2, 3]),
      kdfParams: {
        algorithm: 'argon2id',
        t: 3,
        m: 65_536,
        p: 1,
        salt: new Uint8Array(16).fill(0x42),
      },
      ts: 'now',
    };
    await s.put('k', w);
    const got = await s.get('k');
    if (got?.kdfParams?.algorithm !== 'argon2id') {
      expect.fail('expected argon2id kdfParams round-trip');
    }
    expect(got.kdfParams.t).toBe(3);
    expect(got.kdfParams.m).toBe(65_536);
    expect(got.kdfParams.p).toBe(1);
    expect(Array.from(got.kdfParams.salt)).toEqual(Array.from(new Uint8Array(16).fill(0x42)));
  });

  it('persists pbkdf2-sha256 kdfParams through round-trip', async () => {
    const s = new IndexedDbStorage({ dbName: 'test-db' });
    const w: WrappedKey = {
      v: 1,
      tier: 'maximum',
      envelope: new Uint8Array([1]),
      kdfParams: {
        algorithm: 'pbkdf2-sha256',
        iterations: 1_000_000,
        salt: new Uint8Array(8).fill(0xee),
      },
      ts: 'now',
    };
    await s.put('k', w);
    const got = await s.get('k');
    if (got?.kdfParams?.algorithm !== 'pbkdf2-sha256') {
      expect.fail('expected pbkdf2-sha256 kdfParams round-trip');
    }
    expect(got.kdfParams.iterations).toBe(1_000_000);
  });

  it('rejects slot names containing path-traversal', async () => {
    const s = new IndexedDbStorage({ dbName: 'test-db' });
    await expect(s.put('../evil', wrappedFixture())).rejects.toThrow(/invalid slot name/);
    await expect(s.put('.', wrappedFixture())).rejects.toThrow(/invalid slot name/);
    await expect(s.put('with space', wrappedFixture())).rejects.toThrow(/invalid slot name/);
  });

  it('rejects a stored value with unsupported wire version', async () => {
    const s = new IndexedDbStorage({ dbName: 'test-db' });
    await s.put('slot', wrappedFixture());
    // Bypass the SUT to poke a bad record directly into the fake store.
    const store = stores.get('test-db')?.get('wrapped-keys');
    store?.set('bad', { v: 99, tier: 'standard', envelope: new Uint8Array([1]), ts: 'x' });
    await expect(s.get('bad')).rejects.toThrow(/wire version/);
  });

  it('rejects a stored value with unknown tier kind', async () => {
    const s = new IndexedDbStorage({ dbName: 'test-db' });
    await s.put('slot', wrappedFixture());
    const store = stores.get('test-db')?.get('wrapped-keys');
    store?.set('bad', { v: 1, tier: 'enhanced', envelope: new Uint8Array([1]), ts: 'x' });
    await expect(s.get('bad')).rejects.toThrow(/tier kind/);
  });

  it('rejects a stored value that is not an object', async () => {
    const s = new IndexedDbStorage({ dbName: 'test-db' });
    await s.put('slot', wrappedFixture());
    const store = stores.get('test-db')?.get('wrapped-keys');
    store?.set('bad', 'not an object');
    await expect(s.get('bad')).rejects.toThrow(/not an object/);
  });

  it('rejects a stored kdfParams with unsupported algorithm', async () => {
    const s = new IndexedDbStorage({ dbName: 'test-db' });
    await s.put('slot', wrappedFixture());
    const store = stores.get('test-db')?.get('wrapped-keys');
    store?.set('bad', {
      v: 1,
      tier: 'maximum',
      envelope: new Uint8Array([1]),
      ts: 'x',
      kdfParams: { algorithm: 'scrypt', salt: new Uint8Array([1]) },
    });
    await expect(s.get('bad')).rejects.toThrow(/KDF algorithm/);
  });

  it('declares the browser platform', () => {
    const s = new IndexedDbStorage({ dbName: 'test-db' });
    expect(s.platform).toBe('browser');
  });

  it('accepts only standard tier', () => {
    const s = new IndexedDbStorage({ dbName: 'test-db' });
    expect(s.acceptedTiers).toEqual(['standard']);
  });

  it('coerces ArrayBuffer-shaped envelope back to Uint8Array on deserialise', async () => {
    const s = new IndexedDbStorage({ dbName: 'test-db' });
    await s.put('slot', wrappedFixture());
    const store = stores.get('test-db')?.get('wrapped-keys');
    // Simulate an older storage engine that returned ArrayBuffer rather
    // than Uint8Array from structured clone.
    const buf = new Uint8Array([9, 9, 9]).buffer;
    store?.set('ab', {
      v: 1,
      tier: 'standard',
      envelope: buf,
      ts: 'x',
    });
    const got = await s.get('ab');
    expect(Array.from(got?.envelope ?? [])).toEqual([9, 9, 9]);
  });
});

describe('IndexedDbStorage — module-load failure', () => {
  afterEach(() => {
    vi.doUnmock('idb');
  });

  it('wraps a load failure in a helpful error', async () => {
    vi.resetModules();
    vi.doMock('idb', () => {
      throw new Error('simulated idb missing');
    });
    const { IndexedDbStorage: Fresh, _resetIdbCache: reset } = await import(
      /* @vite-ignore */ '../../src/storage/indexeddb.js'
    );
    reset();
    const s = new Fresh({ dbName: 'test-db' });
    await expect(s.put('slot', wrappedFixture())).rejects.toThrow(/idb/);
  });
});
