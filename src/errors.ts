import type { RotationResult } from './types.js';

/**
 * Base class for all keyring errors. Consumers can `catch (e: unknown)` +
 * `if (e instanceof KeyRingError)` to distinguish library errors from
 * crypto-envelope errors (which flow through unwrapped; see plan §5).
 *
 * Each subclass has a stable `code` for exhaustive handling:
 *
 * ```ts
 * try {
 *   await ring.unlockWithPassphrase(pw);
 * } catch (e) {
 *   if (e instanceof WrongPassphrase) return retry();
 *   if (e instanceof KeyRingError) return fatal(e.code);
 *   throw e;  // not ours
 * }
 * ```
 */
export abstract class KeyRingError extends Error {
  abstract readonly code: string;

  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = this.constructor.name;
  }
}

/** `ring.withMaster` / `tryGetMaster` called before `unlock()`. */
export class NotUnlocked extends KeyRingError {
  readonly code = 'NOT_UNLOCKED';
}

/** Generic unlock failure. Subclassed for specific causes. Explicit `string`
 *  annotation (rather than letting TS narrow to the literal) lets subclasses
 *  override with their own code literals. */
export class UnlockFailed extends KeyRingError {
  readonly code: string = 'UNLOCK_FAILED';
}

/** Passphrase did not match the wrapped master. Separate subclass so
 *  consumers can count retry attempts without misclassifying e.g.
 *  corrupted-wrapped-key errors. */
export class WrongPassphrase extends UnlockFailed {
  override readonly code = 'WRONG_PASSPHRASE';
}

/** ssh-agent refused to sign (agent locked, key not loaded, agent not
 *  running). */
export class SshAgentRefused extends UnlockFailed {
  override readonly code = 'SSH_AGENT_REFUSED';
}

/** SSH private key could not be parsed, or passphrase unlocks the key but
 *  not the keyring slot. */
export class InvalidSshKey extends UnlockFailed {
  override readonly code = 'INVALID_SSH_KEY';
}

/** `getProjectKey` or `deleteProjectKey` for a name that is not registered.
 *  Use `tryGetProjectKey` if null is acceptable. */
export class ProjectKeyNotFound extends KeyRingError {
  readonly code = 'PROJECT_KEY_NOT_FOUND';
  // `slotName`, not `name` — the latter is `Error.name`, overriding it would
  // break stack-trace formatting.
  constructor(public readonly slotName: string) {
    super(`project key not found: ${slotName}`);
  }
}

/** `createProjectKey('__personal')` or any other reserved slot name. */
export class ReservedSlotName extends KeyRingError {
  readonly code = 'RESERVED_SLOT_NAME';
  constructor(public readonly slotName: string) {
    super(`slot name is reserved: ${slotName}`);
  }
}

/** `rotate` returned a result with `failed.length > 0`. Thrown only when the
 *  caller passes `throwOnPartialFailure: true`; otherwise the result is
 *  returned normally. */
export class RotationPartialFailure extends KeyRingError {
  readonly code = 'ROTATION_PARTIAL_FAILURE';
  constructor(public readonly result: RotationResult) {
    super(
      `rotation partial failure: ${result.rotated} rotated, ${result.failed.length} failed, old master still required`,
    );
  }
}

/** TOFU pin file's on-disk value for an SSH key's fingerprint differs from
 *  the observed public key. Attack, or legitimate key rotation the user has
 *  not yet acknowledged. */
export class TofuMismatch extends KeyRingError {
  readonly code = 'TOFU_MISMATCH';
  constructor(
    public readonly fingerprint: string,
    public readonly pinnedAt: string,
  ) {
    super(`TOFU pin mismatch for ${fingerprint} (pinned ${pinnedAt})`);
  }
}

/** Runtime fallback for the compile-time capability check — consumer
 *  bypassed TypeScript narrowing and passed an incompatible tier+storage
 *  pair to `KeyRing`. */
export class TierStorageMismatch extends KeyRingError {
  readonly code = 'TIER_STORAGE_MISMATCH';
  constructor(
    public readonly tierKind: string,
    public readonly storagePlatform: string,
  ) {
    super(
      `tier '${tierKind}' cannot be stored on '${storagePlatform}' storage — passphrase-derived masters must not land in WebExtension or IndexedDB storage`,
    );
  }
}

/** TOFU pin file's integrity MAC does not verify — filesystem-write
 *  attacker tampered with pins, or file was truncated/corrupted. Plan §3
 *  B6 fix. */
export class TofuPinFileTampered extends KeyRingError {
  readonly code = 'TOFU_PIN_FILE_TAMPERED';
}

/** Invite-flow ECDH shared secret is all-zero — attacker-supplied small-order
 *  ephemeral pubkey. Plan §3 B4 fix; reject rather than proceed. */
export class InviteSmallOrderPoint extends KeyRingError {
  readonly code = 'INVITE_SMALL_ORDER_POINT';
}

/** `unlock(input)` called on an already-unlocked ring with a *different*
 *  input than the previous successful unlock. Plan §15 decision 5.
 *  Matching re-unlock is a no-op; mismatch requires explicit `lock()` first. */
export class AlreadyUnlocked extends KeyRingError {
  readonly code = 'ALREADY_UNLOCKED';
}

/** `@napi-rs/keyring` is the OS-keychain backend; platforms without
 *  prebuild binaries (BSD, Alpine musl) get this error from `OsKeychainStorage`
 *  operations. Fallback: `FileSystemStorage` with appropriate permissions. */
export class OsKeychainUnavailable extends KeyRingError {
  readonly code = 'OS_KEYCHAIN_UNAVAILABLE';
}

/** ECDSA SSH key passed to StandardTier — v0.1 supports Ed25519 + RSA only.
 *  ECDSA is v0.2 scope. */
export class UnsupportedSshKeyType extends KeyRingError {
  readonly code = 'UNSUPPORTED_SSH_KEY_TYPE';
  constructor(public readonly keyType: string) {
    super(
      `SSH key type '${keyType}' is not supported in v0.1 (Ed25519 and RSA only); ECDSA support is scheduled for v0.2`,
    );
  }
}
