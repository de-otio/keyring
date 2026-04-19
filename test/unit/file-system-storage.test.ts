import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { FileSystemStorage } from '../../src/storage/file-system.js';
import type { WrappedKey } from '../../src/types.js';

function wrappedFixture(overrides?: Partial<WrappedKey>): WrappedKey {
  const base: WrappedKey = {
    v: 1,
    tier: 'maximum',
    envelope: new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd]),
    kdfParams: {
      algorithm: 'argon2id',
      t: 3,
      m: 65_536,
      p: 1,
      salt: new Uint8Array(16).fill(0x42),
    },
    ts: '2026-04-19T09:00:00.000Z',
  };
  return { ...base, ...overrides };
}

describe('FileSystemStorage', () => {
  let root: string;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), 'keyring-fs-test-'));
  });
  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  describe('happy path', () => {
    it('round-trips put + get', async () => {
      const s = new FileSystemStorage({ root });
      const w = wrappedFixture();
      await s.put('slot', w);

      const got = await s.get('slot');
      expect(got).not.toBeNull();
      expect(got?.v).toBe(1);
      expect(got?.tier).toBe('maximum');
      expect(got?.ts).toBe(w.ts);
      expect(Buffer.from(got?.envelope ?? []).equals(Buffer.from(w.envelope))).toBe(true);
      if (got?.kdfParams?.algorithm === 'argon2id') {
        expect(got.kdfParams.t).toBe(3);
        expect(got.kdfParams.m).toBe(65_536);
        expect(got.kdfParams.p).toBe(1);
        expect(Buffer.from(got.kdfParams.salt).equals(Buffer.from(w.kdfParams!.salt))).toBe(true);
      } else {
        expect.fail('expected argon2id kdfParams');
      }
    });

    it('returns null for missing slot', async () => {
      const s = new FileSystemStorage({ root });
      expect(await s.get('nope')).toBeNull();
    });

    it('list is empty on empty storage', async () => {
      const s = new FileSystemStorage({ root });
      expect(await s.list()).toEqual([]);
    });

    it('list returns all slot names', async () => {
      const s = new FileSystemStorage({ root });
      await s.put('alice', wrappedFixture());
      await s.put('bob', wrappedFixture({ tier: 'standard' }));
      const names = await s.list();
      expect(names.sort()).toEqual(['alice', 'bob']);
    });

    it('delete removes the slot file', async () => {
      const s = new FileSystemStorage({ root });
      await s.put('slot', wrappedFixture());
      await s.delete('slot');
      expect(await s.get('slot')).toBeNull();
    });

    it('delete on missing slot is a no-op', async () => {
      const s = new FileSystemStorage({ root });
      await expect(s.delete('never')).resolves.not.toThrow();
    });

    it('persists sshFingerprint through round-trip', async () => {
      const s = new FileSystemStorage({ root });
      const w = wrappedFixture({
        tier: 'standard',
        kdfParams: undefined,
        sshFingerprint: 'SHA256:abc123',
      });
      await s.put('ssh', w);
      const got = await s.get('ssh');
      expect(got?.sshFingerprint).toBe('SHA256:abc123');
    });
  });

  describe('security posture', () => {
    it('writes files with 0600 permissions', async () => {
      const s = new FileSystemStorage({ root });
      await s.put('slot', wrappedFixture());
      const info = await stat(join(root, 'slot'));
      // Mask off file-type bits; compare only the permission bits.
      expect((info.mode & 0o777).toString(8)).toBe('600');
    });

    it('creates the root directory with 0700 permissions (when it did not exist)', async () => {
      const nested = join(root, 'deep', 'nested');
      const s = new FileSystemStorage({ root: nested });
      await s.put('slot', wrappedFixture());
      const info = await stat(nested);
      expect((info.mode & 0o777).toString(8)).toBe('700');
    });
  });

  describe('slot-name validation', () => {
    it.each([
      'a/b',
      '..',
      '../escape',
      'with space',
      'with/../slash',
      '',
      'x'.repeat(129),
      '\u0000null',
    ])('rejects %j as a slot name', async (bad) => {
      const s = new FileSystemStorage({ root });
      await expect(s.put(bad, wrappedFixture())).rejects.toThrow(/invalid slot name/);
    });

    it.each(['a', 'personal', 'key_1', 'alice-bob', 'x.y', 'K_e.y-1'])(
      'accepts %j as a slot name',
      async (good) => {
        const s = new FileSystemStorage({ root });
        await expect(s.put(good, wrappedFixture())).resolves.not.toThrow();
      },
    );
  });

  describe('serialisation stability', () => {
    it('persists as valid JSON with base64-encoded binary fields', async () => {
      const s = new FileSystemStorage({ root });
      await s.put('slot', wrappedFixture());
      const raw = await readFile(join(root, 'slot'), 'utf8');
      const parsed = JSON.parse(raw);
      expect(parsed.v).toBe(1);
      expect(parsed.tier).toBe('maximum');
      expect(typeof parsed.envelope).toBe('string');
      expect(typeof parsed.kdfParams.salt).toBe('string');
    });

    it('rejects a stored file with unsupported wire version', async () => {
      const s = new FileSystemStorage({ root });
      const { writeFile } = await import('node:fs/promises');
      await writeFile(
        join(root, 'bad'),
        JSON.stringify({ v: 99, tier: 'maximum', envelope: '', ts: '' }),
      );
      await expect(s.get('bad')).rejects.toThrow(/wire version/);
    });

    it('rejects a stored file with unknown tier kind', async () => {
      const s = new FileSystemStorage({ root });
      const { writeFile } = await import('node:fs/promises');
      await writeFile(
        join(root, 'bad'),
        JSON.stringify({ v: 1, tier: 'enhanced', envelope: 'AA==', ts: '' }),
      );
      await expect(s.get('bad')).rejects.toThrow(/tier kind/);
    });
  });
});
