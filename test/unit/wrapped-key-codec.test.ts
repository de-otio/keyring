import { describe, expect, it } from 'vitest';
import {
  type SerialisedWrappedKey,
  deserializeWrappedKey,
  serializeWrappedKey,
} from '../../src/storage/wrapped-key-codec.js';
import type { WrappedKey } from '../../src/types.js';

const TS = '2026-06-20T00:00:00.000Z';

describe('wrapped-key-codec round-trip', () => {
  it('round-trips a recovery-key wrapped key (no kdfParams)', () => {
    const w: WrappedKey = {
      v: 1,
      tier: 'recovery-key',
      envelope: new Uint8Array([1, 2, 3, 250, 0, 255]),
      ts: TS,
    };
    const back = deserializeWrappedKey(serializeWrappedKey(w));
    expect(back.tier).toBe('recovery-key');
    expect(back.kdfParams).toBeUndefined();
    expect(Array.from(back.envelope)).toEqual([1, 2, 3, 250, 0, 255]);
    expect(back.ts).toBe(TS);
  });

  it('round-trips a maximum (argon2id) wrapped key with kdfParams', () => {
    const w: WrappedKey = {
      v: 1,
      tier: 'maximum',
      envelope: new Uint8Array([9, 9, 9]),
      kdfParams: { algorithm: 'argon2id', t: 3, m: 65_536, p: 1, salt: new Uint8Array([7, 7]) },
      ts: TS,
    };
    const back = deserializeWrappedKey(serializeWrappedKey(w));
    expect(back.kdfParams).toEqual({
      algorithm: 'argon2id',
      t: 3,
      m: 65_536,
      p: 1,
      salt: new Uint8Array([7, 7]),
    });
  });

  it('round-trips a maximum (pbkdf2-sha256) wrapped key with kdfParams', () => {
    const w: WrappedKey = {
      v: 1,
      tier: 'maximum',
      envelope: new Uint8Array([4, 5, 6]),
      kdfParams: { algorithm: 'pbkdf2-sha256', iterations: 1_000_000, salt: new Uint8Array([3, 3]) },
      ts: TS,
    };
    const back = deserializeWrappedKey(serializeWrappedKey(w));
    expect(back.kdfParams).toEqual({
      algorithm: 'pbkdf2-sha256',
      iterations: 1_000_000,
      salt: new Uint8Array([3, 3]),
    });
  });

  it('round-trips a standard wrapped key with sshFingerprint', () => {
    const w: WrappedKey = {
      v: 1,
      tier: 'standard',
      envelope: new Uint8Array([5]),
      sshFingerprint: 'SHA256:abc',
      ts: TS,
    };
    const back = deserializeWrappedKey(serializeWrappedKey(w));
    expect(back.sshFingerprint).toBe('SHA256:abc');
  });

  it('rejects an unknown wire version', () => {
    const bad = JSON.stringify({ v: 2, tier: 'recovery-key', envelope: '', ts: TS });
    expect(() => deserializeWrappedKey(bad)).toThrow(/wire version: 2/);
  });

  it('rejects an unknown tier kind', () => {
    const bad = JSON.stringify({ v: 1, tier: 'enhanced', envelope: '', ts: TS });
    expect(() => deserializeWrappedKey(bad)).toThrow(/unsupported tier kind: enhanced/);
  });

  it('rejects an unknown KDF algorithm', () => {
    const bad = JSON.stringify({
      v: 1,
      tier: 'maximum',
      envelope: '',
      ts: TS,
      kdfParams: { algorithm: 'scrypt', salt: '' },
    });
    expect(() => deserializeWrappedKey(bad)).toThrow(/unsupported KDF algorithm.*scrypt/);
  });
});

describe('wrapped-key-codec frozen serialization (cross-language freeze)', () => {
  // The exact JSON a recovery-key WrappedKey serialises to. The Dart port must
  // produce byte-identical output for these inputs. serializeWrappedKey is
  // deterministic (no randomness), so this is a stable contract.
  it('serialises a recovery-key wrapped key to the frozen JSON shape', () => {
    const w: WrappedKey = {
      v: 1,
      tier: 'recovery-key',
      envelope: new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
      ts: TS,
    };
    expect(serializeWrappedKey(w)).toBe(
      `{"v":1,"tier":"recovery-key","envelope":"3q2+7w==","ts":"${TS}"}`,
    );
  });

  it('field order is v, tier, envelope, ts (kdfParams/sshFingerprint omitted when absent)', () => {
    const w: WrappedKey = { v: 1, tier: 'recovery-key', envelope: new Uint8Array(), ts: TS };
    const parsed = JSON.parse(serializeWrappedKey(w)) as SerialisedWrappedKey;
    expect(Object.keys(parsed)).toEqual(['v', 'tier', 'envelope', 'ts']);
  });
});
