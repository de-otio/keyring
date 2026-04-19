/**
 * `@de-otio/keyring` — key-lifecycle layer on top of `@de-otio/crypto-envelope`.
 *
 * Pre-alpha. Phase B: MaximumTier + fs/in-memory storage + minimal
 * KeyRing. Phase C: StandardTier + SSH + TOFU. Phase D:
 * OsKeychainStorage. Phase E: browser storage. Phase F: project keys
 * + invite.
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
  ed25519ToX25519PublicKey,
  ed25519ToX25519SecretKey,
  parseSshPublicKey,
  sshFingerprint,
  type SshKeyType,
  type SshPublicKey,
} from './ssh/keys.js';
export {
  KnownKeys,
  sha256Fingerprint,
  type CheckPinResult,
  type KnownKeysOptions,
  type PinnedKey,
} from './known-keys.js';

// Phase D runtime
export { OsKeychainStorage } from './storage/os-keychain.js';

// Phase E runtime — browser storage backends. Safe to import in Node;
// constructors that need browser globals (`chrome.storage`, `indexedDB`)
// throw at construction time there. Exporting here lets consumers
// bundling their own browser code reach them via the single
// `@de-otio/keyring` entry.
export {
  WebExtensionStorage,
  type WebExtensionStorageArea,
} from './storage/webextension.js';
export { IndexedDbStorage } from './storage/indexeddb.js';

// Runtime classes not yet implemented — stubs until their phase lands.
// Each throws at construction so accidental early use fails loudly.

class NotImplementedError extends Error {
  constructor(name: string, phase: string) {
    super(`${name} is not yet implemented (landing in Phase ${phase}); see plans/01-extraction.md`);
    this.name = 'NotImplementedError';
  }
}

// Phase G stub (deferred to keyring 0.2).
export function rotateMaster(
  _oldMaster: unknown,
  _newMaster: unknown,
  _enumerator: unknown,
  _options?: unknown,
): never {
  throw new NotImplementedError('rotateMaster', 'G (deferred to keyring 0.2)');
}
