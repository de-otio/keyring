import { SecureBuffer, asMasterKey } from '@de-otio/crypto-envelope';
import { describe, expect, it } from 'vitest';
import {
  AlreadyUnlocked,
  NotUnlocked,
  TierStorageMismatch,
  WrongPassphrase,
} from '../../src/errors.js';
import { KeyRing } from '../../src/keyring.js';
import { InMemoryStorage } from '../../src/storage/in-memory.js';
import { MaximumTier } from '../../src/tiers/maximum.js';

const FAST_PARAMS = { t: 1, m: 8192, p: 1 };
const ARGON2_TIMEOUT = { timeout: 30_000 };

function randomMasterKey() {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return asMasterKey(SecureBuffer.from(bytes));
}

describe('KeyRing (Phase B minimal surface)', ARGON2_TIMEOUT, () => {
  describe('capability check', () => {
    it('throws TierStorageMismatch when storage refuses the tier kind', () => {
      const tier = MaximumTier.fromPassphrase('x', FAST_PARAMS);
      const standardOnly = new InMemoryStorage<'standard'>({ acceptedTiers: ['standard'] });
      // deliberately evade the type-level check to exercise the runtime fallback
      expect(
        () =>
          new (KeyRing as unknown as new (opts: unknown) => unknown)({
            tier,
            storage: standardOnly,
          }),
      ).toThrow(TierStorageMismatch);
    });
  });

  describe('setup → unlock → use → lock round-trip', () => {
    it('sets up, unlocks, gives scoped access to the master, then locks', async () => {
      const storage = new InMemoryStorage();
      const tier = MaximumTier.fromPassphrase('secret', FAST_PARAMS);
      const ring = new KeyRing({ tier, storage });
      const master = randomMasterKey();

      await ring.setup(master);
      expect(ring.isUnlocked).toBe(false); // setup does not unlock

      await ring.unlockWithPassphrase('secret');
      expect(ring.isUnlocked).toBe(true);

      const recoveredLen = await ring.withMaster(async (m) => m.length);
      expect(recoveredLen).toBe(32);

      await ring.lock();
      expect(ring.isUnlocked).toBe(false);
    });

    it('setup fails when the slot already has a wrapped key', async () => {
      const storage = new InMemoryStorage();
      const tier = MaximumTier.fromPassphrase('secret', FAST_PARAMS);
      const ring = new KeyRing({ tier, storage });
      await ring.setup(randomMasterKey());
      await expect(ring.setup(randomMasterKey())).rejects.toThrow(/already has/);
    });

    it('rejects a wrong passphrase with WrongPassphrase', async () => {
      const storage = new InMemoryStorage();
      const tier = MaximumTier.fromPassphrase('correct', FAST_PARAMS);
      const ring = new KeyRing({ tier, storage });
      await ring.setup(randomMasterKey());
      await expect(ring.unlockWithPassphrase('wrong')).rejects.toBeInstanceOf(WrongPassphrase);
    });

    it('withMaster before unlock throws NotUnlocked', async () => {
      const ring = new KeyRing({
        tier: MaximumTier.fromPassphrase('x', FAST_PARAMS),
        storage: new InMemoryStorage(),
      });
      await expect(ring.withMaster(async () => 1)).rejects.toBeInstanceOf(NotUnlocked);
    });

    it('tryGetMaster returns null before unlock, the master after', async () => {
      const storage = new InMemoryStorage();
      const tier = MaximumTier.fromPassphrase('pw', FAST_PARAMS);
      const ring = new KeyRing({ tier, storage });
      await ring.setup(randomMasterKey());
      expect(ring.tryGetMaster()).toBeNull();
      await ring.unlockWithPassphrase('pw');
      expect(ring.tryGetMaster()).not.toBeNull();
    });

    it('unlock on empty storage throws', async () => {
      const ring = new KeyRing({
        tier: MaximumTier.fromPassphrase('x', FAST_PARAMS),
        storage: new InMemoryStorage(),
      });
      await expect(ring.unlockWithPassphrase('x')).rejects.toThrow(/empty/);
    });
  });

  describe('idempotence + re-unlock policy', () => {
    it('repeated unlock with matching kind is a no-op', async () => {
      const storage = new InMemoryStorage();
      const tier = MaximumTier.fromPassphrase('pw', FAST_PARAMS);
      const ring = new KeyRing({ tier, storage });
      await ring.setup(randomMasterKey());
      await ring.unlockWithPassphrase('pw');
      await expect(ring.unlockWithPassphrase('pw')).resolves.not.toThrow();
      expect(ring.isUnlocked).toBe(true);
    });

    it('unlock with a different kind while already unlocked throws AlreadyUnlocked', async () => {
      const storage = new InMemoryStorage();
      const tier = MaximumTier.fromPassphrase('pw', FAST_PARAMS);
      const ring = new KeyRing({ tier, storage });
      await ring.setup(randomMasterKey());
      await ring.unlockWithPassphrase('pw');
      await expect(ring.unlock({ kind: 'ssh-agent' })).rejects.toBeInstanceOf(AlreadyUnlocked);
    });

    it('lock is idempotent', async () => {
      const storage = new InMemoryStorage();
      const tier = MaximumTier.fromPassphrase('pw', FAST_PARAMS);
      const ring = new KeyRing({ tier, storage });
      await ring.setup(randomMasterKey());
      await ring.unlockWithPassphrase('pw');
      await ring.lock();
      await expect(ring.lock()).resolves.not.toThrow();
      expect(ring.isUnlocked).toBe(false);
    });
  });

  describe('delete (crypto-shredding)', () => {
    it('removes the wrapped key from storage and locks the ring', async () => {
      const storage = new InMemoryStorage();
      const tier = MaximumTier.fromPassphrase('pw', FAST_PARAMS);
      const ring = new KeyRing({ tier, storage });
      await ring.setup(randomMasterKey());
      await ring.unlockWithPassphrase('pw');
      await ring.delete();

      expect(ring.isUnlocked).toBe(false);
      expect(await storage.get('__personal')).toBeNull();
      // After delete, re-unlock fails because the slot is empty.
      await expect(ring.unlockWithPassphrase('pw')).rejects.toThrow(/empty/);
    });
  });

  describe('custom slot names', () => {
    it('respects the `slot` option for multi-tenant storage', async () => {
      const storage = new InMemoryStorage();
      const tier = MaximumTier.fromPassphrase('pw', FAST_PARAMS);
      const ringA = new KeyRing({ tier, storage, slot: 'tenant-a' });
      const ringB = new KeyRing({ tier, storage, slot: 'tenant-b' });
      await ringA.setup(randomMasterKey());
      await ringB.setup(randomMasterKey());
      const slots = await storage.list();
      expect(slots.sort()).toEqual(['tenant-a', 'tenant-b']);
    });
  });
});
