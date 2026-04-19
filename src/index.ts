/**
 * `@de-otio/keyring` — key-lifecycle layer on top of `@de-otio/crypto-envelope`.
 *
 * **Pre-alpha.** Public API under construction; runtime classes stubbed until
 * Phase B+ lands. Only types and error classes are stable enough to import
 * today. See `plans/01-extraction.md` for the roadmap.
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

// Runtime classes — stubs until Phase B+
// Each throws at construction so accidental early use fails loudly.

class NotImplementedError extends Error {
  constructor(name: string, phase: string) {
    super(`${name} is not yet implemented (landing in Phase ${phase}); see plans/01-extraction.md`);
    this.name = 'NotImplementedError';
  }
}

export class KeyRing {
  constructor(_options: unknown) {
    throw new NotImplementedError('KeyRing', 'G');
  }
}

export class StandardTier {
  static fromSshAgent(): never {
    throw new NotImplementedError('StandardTier.fromSshAgent', 'C');
  }
  static fromSshKey(_pem: string, _passphrase?: string): never {
    throw new NotImplementedError('StandardTier.fromSshKey', 'C');
  }
}

export class MaximumTier {
  static fromPassphrase(_params?: unknown): never {
    throw new NotImplementedError('MaximumTier.fromPassphrase', 'B');
  }
}

export class OsKeychainStorage {
  constructor(_options?: unknown) {
    throw new NotImplementedError('OsKeychainStorage', 'D');
  }
}

export class FileSystemStorage {
  constructor(_options?: unknown) {
    throw new NotImplementedError('FileSystemStorage', 'B');
  }
}

export class InMemoryStorage {
  constructor() {
    throw new NotImplementedError('InMemoryStorage', 'B');
  }
}

/** Placeholder for `rotateMaster`; real implementation lands in Phase G. */
export function rotateMaster(
  _oldMaster: unknown,
  _newMaster: unknown,
  _enumerator: unknown,
  _options?: unknown,
): never {
  throw new NotImplementedError('rotateMaster', 'G');
}
