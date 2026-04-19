import { beforeEach, describe, expect, it } from 'vitest';
import {
  WebExtensionStorage,
  type WebExtensionStorageArea,
} from '../../src/storage/webextension.js';
import type { WrappedKey } from '../../src/types.js';

/**
 * Unit tests for WebExtensionStorage. `chrome.storage` is not present in
 * Node — tests inject a `WebExtensionStorageArea` fake that implements
 * the same surface. The real MV3 round-trip is covered by the Playwright
 * smoke test (deferred until a browser test project is wired, Phase E3).
 */

class FakeStorageArea implements WebExtensionStorageArea {
  readonly store = new Map<string, unknown>();

  async get(keys: string | string[] | null): Promise<Record<string, unknown>> {
    if (keys === null) return Object.fromEntries(this.store);
    const keyArr = Array.isArray(keys) ? keys : [keys];
    const out: Record<string, unknown> = {};
    for (const k of keyArr) {
      if (this.store.has(k)) out[k] = this.store.get(k);
    }
    return out;
  }
  async set(items: Record<string, unknown>): Promise<void> {
    for (const [k, v] of Object.entries(items)) this.store.set(k, v);
  }
  async remove(keys: string | string[]): Promise<void> {
    const keyArr = Array.isArray(keys) ? keys : [keys];
    for (const k of keyArr) this.store.delete(k);
  }
}

function wrappedFixture(overrides?: Partial<WrappedKey>): WrappedKey {
  const base: WrappedKey = {
    v: 1,
    tier: 'standard',
    envelope: new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd]),
    sshFingerprint: 'SHA256:abcdef',
    ts: '2026-04-19T10:00:00.000Z',
  };
  return { ...base, ...overrides };
}

describe('WebExtensionStorage', () => {
  let area: FakeStorageArea;
  let storage: WebExtensionStorage;

  beforeEach(() => {
    area = new FakeStorageArea();
    storage = new WebExtensionStorage({ storageArea: area });
  });

  it('throws when no storageArea and no chrome.storage global', () => {
    // globalThis has no `chrome` in Node — defaults to detect mode.
    expect(() => new WebExtensionStorage()).toThrow(/chrome\.storage/);
  });

  it('round-trips put + get', async () => {
    const w = wrappedFixture();
    await storage.put('slot1', w);
    const got = await storage.get('slot1');
    expect(got).not.toBeNull();
    expect(got?.tier).toBe('standard');
    expect(Array.from(got?.envelope ?? [])).toEqual([0xaa, 0xbb, 0xcc, 0xdd]);
    expect(got?.sshFingerprint).toBe('SHA256:abcdef');
  });

  it('returns null for a missing slot', async () => {
    expect(await storage.get('never')).toBeNull();
  });

  it('overwrites on second put', async () => {
    await storage.put('slot', wrappedFixture({ tier: 'standard' }));
    await storage.put('slot', wrappedFixture({ sshFingerprint: 'SHA256:changed' }));
    const got = await storage.get('slot');
    expect(got?.sshFingerprint).toBe('SHA256:changed');
  });

  it('delete removes the slot', async () => {
    await storage.put('slot', wrappedFixture());
    await storage.delete('slot');
    expect(await storage.get('slot')).toBeNull();
  });

  it('delete on a missing slot is idempotent', async () => {
    await expect(storage.delete('never')).resolves.not.toThrow();
  });

  it('list enumerates only this storage`s prefix, skipping foreign keys', async () => {
    // Outside-prefix key (set by some other extension feature).
    await area.set({ 'unrelated-app:state': { x: 1 } });
    await storage.put('alice', wrappedFixture());
    await storage.put('bob', wrappedFixture({ tier: 'standard' }));
    expect((await storage.list()).sort()).toEqual(['alice', 'bob']);
  });

  it('different prefixes isolate their slots', async () => {
    const a = new WebExtensionStorage({ storageArea: area, prefix: 'a:' });
    const b = new WebExtensionStorage({ storageArea: area, prefix: 'b:' });
    await a.put('alice', wrappedFixture());
    await b.put('bob', wrappedFixture());
    expect(await a.list()).toEqual(['alice']);
    expect(await b.list()).toEqual(['bob']);
  });

  it('normalises prefix by appending trailing colon when missing', async () => {
    const s = new WebExtensionStorage({ storageArea: area, prefix: 'chaoskb' });
    expect(s.prefix).toBe('chaoskb:');
  });

  it('falls back to `keyring:` when prefix is empty string', () => {
    const s = new WebExtensionStorage({ storageArea: area, prefix: '' });
    expect(s.prefix).toBe('keyring:');
  });

  it('defaults persistence to local', () => {
    expect(storage.persistence).toBe('local');
  });

  it('honours session persistence setting', () => {
    const s = new WebExtensionStorage({ storageArea: area, persistence: 'session' });
    expect(s.persistence).toBe('session');
  });

  it('rejects slot names containing path-traversal', async () => {
    await expect(storage.put('../evil', wrappedFixture())).rejects.toThrow(/invalid slot name/);
    await expect(storage.put('.', wrappedFixture())).rejects.toThrow(/invalid slot name/);
    await expect(storage.put('..', wrappedFixture())).rejects.toThrow(/invalid slot name/);
    await expect(storage.put('with space', wrappedFixture())).rejects.toThrow(/invalid slot name/);
    await expect(storage.get('../evil')).rejects.toThrow(/invalid slot name/);
    await expect(storage.delete('../evil')).rejects.toThrow(/invalid slot name/);
  });

  it('persists argon2id kdfParams through round-trip', async () => {
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
    await storage.put('k', w);
    const got = await storage.get('k');
    expect(got?.kdfParams?.algorithm).toBe('argon2id');
    if (got?.kdfParams?.algorithm === 'argon2id') {
      expect(got.kdfParams.t).toBe(3);
      expect(got.kdfParams.m).toBe(65_536);
      expect(got.kdfParams.p).toBe(1);
      expect(Array.from(got.kdfParams.salt)).toEqual(Array.from(new Uint8Array(16).fill(0x42)));
    }
  });

  it('persists pbkdf2-sha256 kdfParams through round-trip', async () => {
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
    await storage.put('k', w);
    const got = await storage.get('k');
    if (got?.kdfParams?.algorithm !== 'pbkdf2-sha256') {
      expect.fail('expected pbkdf2-sha256 kdfParams round-trip');
    }
    expect(got.kdfParams.iterations).toBe(1_000_000);
  });

  it('rejects a stored value with unsupported wire version', async () => {
    await area.set({ 'keyring:bad': { v: 99, tier: 'standard', envelope: 'AA==', ts: 'x' } });
    await expect(storage.get('bad')).rejects.toThrow(/wire version/);
  });

  it('rejects a stored value with unknown tier kind', async () => {
    await area.set({
      'keyring:bad': { v: 1, tier: 'enhanced', envelope: 'AA==', ts: 'x' },
    });
    await expect(storage.get('bad')).rejects.toThrow(/tier kind/);
  });

  it('rejects a stored value that is not an object', async () => {
    await area.set({ 'keyring:bad': 'not an object' });
    await expect(storage.get('bad')).rejects.toThrow(/not an object/);
  });

  it('rejects a stored kdfParams with unsupported algorithm', async () => {
    await area.set({
      'keyring:bad': {
        v: 1,
        tier: 'maximum',
        envelope: 'AA==',
        ts: 'x',
        kdfParams: { algorithm: 'scrypt', salt: 'AA==' },
      },
    });
    await expect(storage.get('bad')).rejects.toThrow(/KDF algorithm/);
  });

  it('declares the webext platform', () => {
    expect(storage.platform).toBe('webext');
  });

  it('accepts only standard tier', () => {
    expect(storage.acceptedTiers).toEqual(['standard']);
  });

  it('detects chrome.storage via globalThis.chrome', () => {
    const g = globalThis as unknown as Record<string, unknown>;
    const had = 'chrome' in g;
    const original = g.chrome;
    try {
      g.chrome = { storage: { local: area } };
      const s = new WebExtensionStorage({});
      expect(s.platform).toBe('webext');
    } finally {
      if (had) g.chrome = original;
      else Reflect.deleteProperty(g, 'chrome');
    }
  });

  it('detects browser.storage via globalThis.browser (Firefox pre-polyfill)', () => {
    const g = globalThis as unknown as Record<string, unknown>;
    const had = 'browser' in g;
    const original = g.browser;
    try {
      g.browser = { storage: { local: area } };
      const s = new WebExtensionStorage({});
      expect(s.platform).toBe('webext');
    } finally {
      if (had) g.browser = original;
      else Reflect.deleteProperty(g, 'browser');
    }
  });
});
