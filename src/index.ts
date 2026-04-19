/**
 * `@de-otio/keyring` — key-lifecycle layer on top of `@de-otio/crypto-envelope`.
 *
 * Pre-alpha. Public API under construction. Phase B scope shipped:
 * `MaximumTier`, `InMemoryStorage`, `FileSystemStorage`, minimal
 * `KeyRing`. Phase C adds `StandardTier` (SSH wrap); Phase D adds
 * `OsKeychainStorage`; Phase E adds browser storage; Phase F adds
 * project keys + invite.
 */

// Public types — stable surface (Phase A)
export type {
  AnyEnvelope,
  BlobEnumerator,
  EventSink,
  ISecureBuffer,
  KdfParamsSnapshot,
  KeyRingEvent,
  KeyStorage,
  MasterKey,
  RotateOptions,
  RotationPolicy,
  RotationResult,
  Tier,
  TierKind,
  UnlockInput,
  WrappedKey,
} from './types.js';

// Error classes — stable surface (Phase A)
export {
  AlreadyUnlocked,
  InvalidSshKey,
  InviteSmallOrderPoint,
  KeyRingError,
  NotUnlocked,
  OsKeychainUnavailable,
  ProjectKeyNotFound,
  ReservedSlotName,
  RotationPartialFailure,
  SshAgentRefused,
  TierStorageMismatch,
  TofuMismatch,
  TofuPinFileTampered,
  UnlockFailed,
  UnsupportedSshKeyType,
  WrongPassphrase,
} from './errors.js';

// Phase B runtime
export { KeyRing, type KeyRingOptions } from './keyring.js';
export { MaximumTier, type Argon2idParams } from './tiers/maximum.js';
export { InMemoryStorage } from './storage/in-memory.js';
export { FileSystemStorage } from './storage/file-system.js';

// Phase C runtime
export { StandardTier } from './tiers/standard.js';
export {
  parseSshPublicKey,
  sshFingerprint,
  ed25519ToX25519PublicKey,
  ed25519ToX25519SecretKey,
  type SshPublicKey,
  type SshKeyType,
} from './ssh/keys.js';
export {
  KnownKeys,
  sha256Fingerprint,
  type CheckPinResult,
  type KnownKeysOptions,
  type PinnedKey,
} from './known-keys.js';

// Runtime classes not yet implemented — stubs until their phase lands.
// Each throws at construction so accidental early use fails loudly.

class NotImplementedError extends Error {
  constructor(name: string, phase: string) {
    super(`${name} is not yet implemented (landing in Phase ${phase}); see plans/01-extraction.md`);
    this.name = 'NotImplementedError';
  }
}

// Phase D stub
export class OsKeychainStorage {
  constructor(_options?: unknown) {
    throw new NotImplementedError('OsKeychainStorage', 'D');
  }
}

// Phase G stub (was listed as G in the plan after scope cut)
export function rotateMaster(
  _oldMaster: unknown,
  _newMaster: unknown,
  _enumerator: unknown,
  _options?: unknown,
): never {
  throw new NotImplementedError('rotateMaster', 'G (deferred to keyring 0.2)');
}
