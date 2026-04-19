import { describe, expect, it } from 'vitest';
import {
  KeyRingError,
  NotUnlocked,
  ProjectKeyNotFound,
  TierStorageMismatch,
  UnsupportedSshKeyType,
  WrongPassphrase,
} from '../src/index.js';

// Phase A scaffolding smoke test. Phase B onwards has dedicated test
// files for each runtime class.

describe('public surface smoke', () => {
  it('exposes the error hierarchy with stable codes', () => {
    const err = new WrongPassphrase('test');
    expect(err).toBeInstanceOf(KeyRingError);
    expect(err.code).toBe('WRONG_PASSPHRASE');
  });

  it('distinguishes NotUnlocked from other unlock errors', () => {
    const nu = new NotUnlocked('ring not unlocked');
    expect(nu.code).toBe('NOT_UNLOCKED');
    expect(nu).toBeInstanceOf(KeyRingError);
  });

  it('ProjectKeyNotFound carries the slot name', () => {
    const err = new ProjectKeyNotFound('my-project');
    expect(err.name).toBe('ProjectKeyNotFound');
    expect(err.slotName).toBe('my-project');
    expect(err.code).toBe('PROJECT_KEY_NOT_FOUND');
    expect(err.message).toContain('my-project');
  });

  it('TierStorageMismatch captures both ends of the capability mismatch', () => {
    const err = new TierStorageMismatch('maximum', 'webext');
    expect(err.code).toBe('TIER_STORAGE_MISMATCH');
    expect(err.tierKind).toBe('maximum');
    expect(err.storagePlatform).toBe('webext');
  });

  it('UnsupportedSshKeyType names the key type', () => {
    const err = new UnsupportedSshKeyType('ecdsa-sha2-nistp256');
    expect(err.keyType).toBe('ecdsa-sha2-nistp256');
    expect(err.message).toMatch(/v0\.1|Ed25519|RSA/);
  });
});
