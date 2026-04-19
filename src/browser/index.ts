/**
 * `@de-otio/keyring/browser` — browser-only entry point.
 *
 * Resolved via `package.json` `exports.browser` condition in bundlers (Vite,
 * esbuild, webpack 5, Rollup) and by explicit subpath import
 * (`import { ... } from '@de-otio/keyring/browser'`) in code that needs to
 * opt out of the Node path.
 *
 * **Pre-alpha.** Stubbed until Phase E lands browser storage backends.
 */

// Shared stable surface
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
} from '../types.js';

export {
  AlreadyUnlocked,
  InvalidSshKey,
  InviteSmallOrderPoint,
  KeyRingError,
  NotUnlocked,
  ProjectKeyNotFound,
  ReservedSlotName,
  RotationPartialFailure,
  TierStorageMismatch,
  TofuMismatch,
  TofuPinFileTampered,
  UnlockFailed,
  UnsupportedSshKeyType,
  WrongPassphrase,
} from '../errors.js';

class NotImplementedError extends Error {
  constructor(name: string, phase: string) {
    super(`${name} is not yet implemented (landing in Phase ${phase}); see plans/01-extraction.md`);
    this.name = 'NotImplementedError';
  }
}

/**
 * High-level constructor for the browser-extension use-case (chaoskb plugin +
 * trellis). Requires explicit `insecureMemory: true` acknowledgement because
 * `SecureBufferBrowser` cannot mlock; see plan §7 + design-review Q1.
 */
export class KeyRing {
  constructor(_options: { insecureMemory: true } & Record<string, unknown>) {
    throw new NotImplementedError('KeyRing (browser)', 'E');
  }

  static forBrowserExtension(_options: { insecureMemory: true; service?: string }): never {
    throw new NotImplementedError('KeyRing.forBrowserExtension', 'E');
  }
}

export class StandardTier {
  static fromSshKey(_pem: string, _passphrase?: string): never {
    throw new NotImplementedError('StandardTier.fromSshKey (browser)', 'C');
  }
}

/** **Compile-time note:** this class is intentionally `KeyStorage<'standard'>`
 *  only. Passing a `MaximumTier` to a `KeyRing` constructed with this storage
 *  is a TypeScript error — passphrase-derived masters must not land in
 *  WebExtension storage (plan §7). */
export class WebExtensionStorage {
  constructor(_options?: { persistence?: 'local' | 'session' }) {
    throw new NotImplementedError('WebExtensionStorage', 'E');
  }
}

/** Same capability restriction as `WebExtensionStorage` — IndexedDB entries
 *  are accessible to every same-origin XSS; passphrase-derived masters must
 *  not land here. */
export class IndexedDbStorage {
  constructor(_options?: { dbName?: string }) {
    throw new NotImplementedError('IndexedDbStorage', 'E');
  }
}
