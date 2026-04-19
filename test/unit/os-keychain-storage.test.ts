import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { WrappedKey } from '../../src/types.js';

/**
 * Unit tests for OsKeychainStorage — `@napi-rs/keyring` is mocked so
 * these tests run on every CI runner, including headless Linux ones
 * without libsecret. The real-keychain integration tests are in the
 * nightly workflow (not yet wired — Phase J).
 */

// Per-test mocked state. `vi.mock` hoists so the `mock` module shape
// must be a function; implementations are installed inside `beforeEach`.
const store = new Map<string, string>();

vi.mock('@napi-rs/keyring', () => {
  class AsyncEntry {
    private readonly key: string;
    constructor(service: string, account: string) {
      this.key = `${service}::${account}`;
    }
    async setPassword(password: string): Promise<void> {
      store.set(this.key, password);
    }
    async getPassword(): Promise<string | null> {
      return store.get(this.key) ?? null;
    }
    async deletePassword(): Promise<boolean> {
      const existed = store.has(this.key);
      store.delete(this.key);
      return existed;
    }
  }
  async function findCredentialsAsync(service: string) {
    const prefix = `${service}::`;
    const out: { account: string; password: string }[] = [];
    for (const [key, password] of store) {
      if (key.startsWith(prefix)) {
        out.push({ account: key.slice(prefix.length), password });
      }
    }
    return out;
  }
  return { AsyncEntry, findCredentialsAsync, Entry: AsyncEntry };
});

// Import AFTER the mock is hoisted, so the SUT sees the mock.
const { OsKeychainStorage, _resetKeyringCache } = await import('../../src/storage/os-keychain.js');

function wrappedFixture(overrides?: Partial<WrappedKey>): WrappedKey {
  const base: WrappedKey = {
    v: 1,
    tier: 'maximum',
    envelope: new Uint8Array([0xaa, 0xbb, 0xcc]),
    kdfParams: {
      algorithm: 'argon2id',
      t: 3,
      m: 65_536,
      p: 1,
      salt: new Uint8Array(16).fill(0x42),
    },
    ts: '2026-04-19T10:00:00.000Z',
  };
  return { ...base, ...overrides };
}

describe('OsKeychainStorage (mocked @napi-rs/keyring)', () => {
  beforeEach(() => {
    store.clear();
    _resetKeyringCache();
  });

  it('throws when service option is missing', () => {
    expect(() => new OsKeychainStorage({ service: '' })).toThrow(/service/);
  });

  it('round-trips put + get', async () => {
    const s = new OsKeychainStorage({ service: 'test-service' });
    const w = wrappedFixture();
    await s.put('slot1', w);
    const got = await s.get('slot1');
    expect(got).not.toBeNull();
    expect(got?.tier).toBe('maximum');
    expect(Buffer.from(got?.envelope ?? []).equals(Buffer.from(w.envelope))).toBe(true);
  });

  it('returns null for a missing slot', async () => {
    const s = new OsKeychainStorage({ service: 'test-service' });
    expect(await s.get('never')).toBeNull();
  });

  it('overwrites on second put', async () => {
    const s = new OsKeychainStorage({ service: 'svc' });
    await s.put('slot', wrappedFixture({ tier: 'standard' }));
    await s.put('slot', wrappedFixture({ tier: 'maximum' }));
    const got = await s.get('slot');
    expect(got?.tier).toBe('maximum');
  });

  it('delete removes the slot', async () => {
    const s = new OsKeychainStorage({ service: 'svc' });
    await s.put('slot', wrappedFixture());
    await s.delete('slot');
    expect(await s.get('slot')).toBeNull();
  });

  it('delete on a missing slot is idempotent', async () => {
    const s = new OsKeychainStorage({ service: 'svc' });
    await expect(s.delete('never')).resolves.not.toThrow();
  });

  it('list returns accounts for the service only', async () => {
    const a = new OsKeychainStorage({ service: 'svc-a' });
    const b = new OsKeychainStorage({ service: 'svc-b' });
    await a.put('alice', wrappedFixture());
    await a.put('bob', wrappedFixture({ tier: 'standard' }));
    await b.put('charlie', wrappedFixture());

    expect((await a.list()).sort()).toEqual(['alice', 'bob']);
    expect(await b.list()).toEqual(['charlie']);
  });

  it('persists sshFingerprint through round-trip', async () => {
    const s = new OsKeychainStorage({ service: 'svc' });
    await s.put('k', {
      v: 1,
      tier: 'standard',
      envelope: new Uint8Array([1, 2]),
      sshFingerprint: 'SHA256:abc',
      ts: 'now',
    });
    expect((await s.get('k'))?.sshFingerprint).toBe('SHA256:abc');
  });

  it('persists pbkdf2-sha256 KDF params through round-trip', async () => {
    const s = new OsKeychainStorage({ service: 'svc' });
    const w: WrappedKey = {
      v: 1,
      tier: 'maximum',
      envelope: new Uint8Array([1]),
      kdfParams: {
        algorithm: 'pbkdf2-sha256',
        iterations: 1_000_000,
        salt: new Uint8Array(16).fill(0xee),
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

  it('rejects a stored value with unsupported wire version', async () => {
    const { AsyncEntry } = await import('@napi-rs/keyring');
    const entry = new AsyncEntry('svc', 'bad');
    await entry.setPassword(JSON.stringify({ v: 99, tier: 'maximum' }));

    const s = new OsKeychainStorage({ service: 'svc' });
    await expect(s.get('bad')).rejects.toThrow(/wire version/);
  });

  it('rejects a stored value with unknown tier kind', async () => {
    const { AsyncEntry } = await import('@napi-rs/keyring');
    const entry = new AsyncEntry('svc', 'bad');
    await entry.setPassword(JSON.stringify({ v: 1, tier: 'enhanced', envelope: 'AA==', ts: 'x' }));

    const s = new OsKeychainStorage({ service: 'svc' });
    await expect(s.get('bad')).rejects.toThrow(/tier kind/);
  });

  it('default acceptedTiers is both standard and maximum', () => {
    const s = new OsKeychainStorage({ service: 'svc' });
    expect([...s.acceptedTiers].sort()).toEqual(['maximum', 'standard']);
  });
});

describe('OsKeychainStorage — module-load failure', () => {
  it('wraps a load failure in OsKeychainUnavailable', async () => {
    // Force the @napi-rs/keyring mock to throw at module load time.
    // `vi.resetModules()` + re-import SUT re-runs its lazy load path
    // under the thrower-mock. Because the SUT is re-imported, its
    // `OsKeychainUnavailable` class is a distinct object identity from
    // the one imported at the top of this file — assert by shape
    // (`code`) rather than `instanceof`.
    vi.resetModules();
    vi.doMock('@napi-rs/keyring', () => {
      throw new Error('simulated prebuild missing');
    });
    const { OsKeychainStorage: FreshStorage } = await import(
      /* @vite-ignore */ '../../src/storage/os-keychain.js'
    );
    const s = new FreshStorage({ service: 'svc' });
    await expect(s.put('slot', wrappedFixture())).rejects.toMatchObject({
      code: 'OS_KEYCHAIN_UNAVAILABLE',
    });
    vi.doUnmock('@napi-rs/keyring');
  });
});
