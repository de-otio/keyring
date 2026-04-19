import { SecureBuffer, asMasterKey } from '@de-otio/crypto-envelope';
import type { MasterKey } from '@de-otio/crypto-envelope';
import { beforeAll, describe, expect, it } from 'vitest';
import { ReservedSlotName, UnlockFailed } from '../../src/errors.js';
import {
  RESERVED_PROJECT_NAMES,
  type WrappedProjectKey,
  createProjectKey,
  unwrapProjectKey,
} from '../../src/project-keys.js';

/**
 * Integration-style tests — `createProjectKey` / `unwrapProjectKey`
 * round-trips use a real 32-byte master built directly via
 * `asMasterKey(SecureBuffer.from(bytes))` rather than going through
 * Argon2id, which would dominate CI runtime for tests that don't need
 * to exercise the passphrase-derivation path.
 */

function randomMasterKey(): MasterKey {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return asMasterKey(SecureBuffer.from(bytes));
}

let master: MasterKey;
let master2: MasterKey;

beforeAll(() => {
  master = randomMasterKey();
  master2 = randomMasterKey();
});

describe('createProjectKey / unwrapProjectKey', () => {
  it('round-trips a fresh project key under the same master and name', async () => {
    const { projectKey, wrapped } = await createProjectKey(master, 'alpha');
    try {
      expect(wrapped.projectName).toBe('alpha');
      expect(wrapped.wrappedKey).toBeInstanceOf(Uint8Array);
      expect(wrapped.wrappedKey.length).toBeGreaterThan(0);

      const recovered = await unwrapProjectKey(master, wrapped);
      try {
        expect(Array.from(recovered.buffer)).toEqual(Array.from(projectKey.buffer));
      } finally {
        recovered.dispose();
      }
    } finally {
      projectKey.dispose();
    }
  });

  it('produces different wrapped bytes each call (fresh random key)', async () => {
    const a = await createProjectKey(master, 'alpha');
    const b = await createProjectKey(master, 'alpha');
    try {
      expect(Array.from(a.projectKey.buffer)).not.toEqual(Array.from(b.projectKey.buffer));
      expect(Buffer.from(a.wrapped.wrappedKey).equals(Buffer.from(b.wrapped.wrappedKey))).toBe(
        false,
      );
    } finally {
      a.projectKey.dispose();
      b.projectKey.dispose();
    }
  });

  it('rejects the reserved `__personal` name at wrap time', async () => {
    await expect(createProjectKey(master, '__personal')).rejects.toBeInstanceOf(ReservedSlotName);
  });

  it('rejects the reserved `__personal` name at unwrap time', async () => {
    // Fabricate a wrapped object with the reserved name — normally unreachable.
    const fake: WrappedProjectKey = {
      projectName: '__personal',
      wrappedKey: new Uint8Array([1, 2, 3]),
      ts: 'now',
    };
    await expect(unwrapProjectKey(master, fake)).rejects.toBeInstanceOf(ReservedSlotName);
  });

  it('rejects an empty project name', async () => {
    await expect(createProjectKey(master, '')).rejects.toThrow(/invalid project name/);
  });

  it('rejects project names with path-traversal or special chars', async () => {
    await expect(createProjectKey(master, '../evil')).rejects.toThrow(/invalid project name/);
    await expect(createProjectKey(master, 'with space')).rejects.toThrow(/invalid project name/);
    await expect(createProjectKey(master, 'a/b')).rejects.toThrow(/invalid project name/);
  });

  it('rejects project names longer than 128 chars', async () => {
    const tooLong = 'a'.repeat(129);
    await expect(createProjectKey(master, tooLong)).rejects.toThrow(/invalid project name/);
  });

  it('refuses to unwrap when the project name does not match (S1 fix)', async () => {
    const { projectKey, wrapped } = await createProjectKey(master, 'alpha');
    try {
      // Tamper with the stored project name — the envelope's kid was bound
      // to 'alpha' at wrap time, so a reader claiming this wrapped bundle
      // belongs to 'beta' must be refused.
      const tampered: WrappedProjectKey = { ...wrapped, projectName: 'beta' };
      await expect(unwrapProjectKey(master, tampered)).rejects.toThrow(/kid/);
    } finally {
      projectKey.dispose();
    }
  });

  it('refuses to unwrap under a different master (different envelope AAD)', async () => {
    const { projectKey, wrapped } = await createProjectKey(master, 'alpha');
    try {
      await expect(unwrapProjectKey(master2, wrapped)).rejects.toBeInstanceOf(UnlockFailed);
    } finally {
      projectKey.dispose();
    }
  });

  it('refuses to unwrap when the envelope bytes are tampered', async () => {
    const { projectKey, wrapped } = await createProjectKey(master, 'alpha');
    try {
      const tampered: WrappedProjectKey = {
        ...wrapped,
        wrappedKey: Uint8Array.from(wrapped.wrappedKey).map((b, i) =>
          i === 100 ? (b ^ 0xff) & 0xff : b,
        ),
      };
      await expect(unwrapProjectKey(master, tampered)).rejects.toThrow();
    } finally {
      projectKey.dispose();
    }
  });

  it('binds both project name AND master — cross-master-same-name swap fails', async () => {
    const { projectKey: key1, wrapped: w1 } = await createProjectKey(master, 'alpha');
    const { projectKey: key2, wrapped: w2 } = await createProjectKey(master2, 'alpha');
    try {
      // w1 was wrapped under `master`, w2 under `master2`. Trying to open
      // w2 with `master` fails AEAD; trying to open w1 with `master2`
      // also fails AEAD. This is the defence-in-depth on top of kid binding.
      await expect(unwrapProjectKey(master, w2)).rejects.toBeInstanceOf(UnlockFailed);
      await expect(unwrapProjectKey(master2, w1)).rejects.toBeInstanceOf(UnlockFailed);
    } finally {
      key1.dispose();
      key2.dispose();
    }
  });

  it('includes __personal in the reserved set', () => {
    expect(RESERVED_PROJECT_NAMES.has('__personal')).toBe(true);
  });

  it('allows ordinary alphanumeric / dot / dash / underscore names', async () => {
    for (const name of ['alpha', 'alpha.beta', 'alpha-beta', 'alpha_beta', 'a1', '_prefix']) {
      const { projectKey, wrapped } = await createProjectKey(master, name);
      try {
        const recovered = await unwrapProjectKey(master, wrapped);
        try {
          expect(Array.from(recovered.buffer)).toEqual(Array.from(projectKey.buffer));
        } finally {
          recovered.dispose();
        }
      } finally {
        projectKey.dispose();
      }
    }
  });
});
