import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SecureBuffer, asMasterKey } from '@de-otio/crypto-envelope';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { TofuMismatch, TofuPinFileTampered } from '../../src/errors.js';
import { KnownKeys } from '../../src/known-keys.js';

function newMaster() {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return asMasterKey(SecureBuffer.from(bytes));
}

describe('KnownKeys (TOFU with B6 MAC fix)', () => {
  let root: string;
  let filePath: string;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), 'keyring-tofu-'));
    filePath = join(root, 'known_keys.json');
  });
  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it('pins a new key and retrieves it', async () => {
    const k = new KnownKeys({ filePath, masterKey: newMaster() });
    await k.pin('github:alice', 'SHA256:AAA', 'ssh-ed25519 AAAA', 'github');
    const got = await k.get('github:alice');
    expect(got?.fingerprint).toBe('SHA256:AAA');
    expect(got?.source).toBe('github');
  });

  it('returns null for unseen identifier', async () => {
    const k = new KnownKeys({ filePath, masterKey: newMaster() });
    expect(await k.get('never')).toBeNull();
  });

  it('check returns new / match / mismatch', async () => {
    const k = new KnownKeys({ filePath, masterKey: newMaster() });
    expect(await k.check('id', 'SHA256:X')).toBe('new');
    await k.pin('id', 'SHA256:X', 'pubkey', 'source');
    expect(await k.check('id', 'SHA256:X')).toBe('match');
    expect(await k.check('id', 'SHA256:Y')).toBe('mismatch');
  });

  it('pin twice with same fingerprint updates verifiedAt', async () => {
    const k = new KnownKeys({ filePath, masterKey: newMaster() });
    await k.pin('id', 'SHA256:X', 'pub', 'src');
    const before = (await k.get('id'))?.verifiedAt;
    await new Promise((r) => setTimeout(r, 5));
    await k.pin('id', 'SHA256:X', 'pub', 'src');
    const after = (await k.get('id'))?.verifiedAt;
    expect(after).not.toBe(before);
  });

  it('pin twice with different fingerprint throws TofuMismatch', async () => {
    const k = new KnownKeys({ filePath, masterKey: newMaster() });
    await k.pin('id', 'SHA256:X', 'pub', 'src');
    await expect(k.pin('id', 'SHA256:Y', 'pub2', 'src2')).rejects.toBeInstanceOf(TofuMismatch);
  });

  it('update replaces an existing pin without throwing', async () => {
    const k = new KnownKeys({ filePath, masterKey: newMaster() });
    await k.pin('id', 'SHA256:X', 'pubX', 'github');
    const firstSeen = (await k.get('id'))?.firstSeen;
    await k.update('id', 'SHA256:Y', 'pubY', 'github');
    const got = await k.get('id');
    expect(got?.fingerprint).toBe('SHA256:Y');
    expect(got?.firstSeen).toBe(firstSeen); // preserved
  });

  it('list returns all identifiers', async () => {
    const k = new KnownKeys({ filePath, masterKey: newMaster() });
    await k.pin('a', 'SHA256:1', 'p1', 's1');
    await k.pin('b', 'SHA256:2', 'p2', 's2');
    const ids = await k.list();
    expect(ids.sort()).toEqual(['a', 'b']);
  });

  describe('B6 MAC integrity', () => {
    it('rejects a pin file with tampered fingerprint bytes', async () => {
      const master = newMaster();
      const k = new KnownKeys({ filePath, masterKey: master });
      await k.pin('id', 'SHA256:X', 'pub', 'src');

      // Tamper: flip a byte in the fingerprint without updating the MAC.
      const raw = await readFile(filePath, 'utf8');
      const tampered = raw.replace('SHA256:X', 'SHA256:Y');
      await writeFile(filePath, tampered);

      // Use a fresh KnownKeys with the same master — the re-computed
      // MAC differs from the stored one.
      const k2 = new KnownKeys({ filePath, masterKey: master });
      await expect(k2.get('id')).rejects.toBeInstanceOf(TofuPinFileTampered);
    });

    it('rejects a pin file written under a different master', async () => {
      const k = new KnownKeys({ filePath, masterKey: newMaster() });
      await k.pin('id', 'SHA256:X', 'pub', 'src');

      // A different master derives a different MAC key → verify fails.
      const k2 = new KnownKeys({ filePath, masterKey: newMaster() });
      await expect(k2.get('id')).rejects.toBeInstanceOf(TofuPinFileTampered);
    });

    it('rejects a malformed pin file', async () => {
      await writeFile(filePath, 'not json at all');
      const k = new KnownKeys({ filePath, masterKey: newMaster() });
      await expect(k.get('anything')).rejects.toBeInstanceOf(TofuPinFileTampered);
    });

    it('rejects a pin file with missing MAC field', async () => {
      await writeFile(filePath, JSON.stringify({ v: 1, pins: {} }));
      const k = new KnownKeys({ filePath, masterKey: newMaster() });
      await expect(k.get('x')).rejects.toBeInstanceOf(TofuPinFileTampered);
    });

    it('rejects an unsupported file version', async () => {
      await writeFile(filePath, JSON.stringify({ v: 2, pins: {}, mac: 'deadbeef' }));
      const k = new KnownKeys({ filePath, masterKey: newMaster() });
      await expect(k.get('x')).rejects.toBeInstanceOf(TofuPinFileTampered);
    });
  });

  describe('file hygiene', () => {
    it('creates the parent directory', async () => {
      const nested = join(root, 'sub', 'sub2', 'known_keys.json');
      const k = new KnownKeys({ filePath: nested, masterKey: newMaster() });
      await k.pin('id', 'SHA256:X', 'pub', 'src');
      const raw = await readFile(nested, 'utf8');
      expect(raw).toContain('SHA256:X');
    });
  });
});
