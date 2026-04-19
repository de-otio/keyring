/**
 * `@de-otio/keyring/browser` — browser-only entry point.
 *
 * Resolved via `package.json` `exports.browser` condition in bundlers (Vite,
 * esbuild, webpack 5, Rollup) and by explicit subpath import
 * (`import { ... } from '@de-otio/keyring/browser'`) in code that needs to
 * opt out of the Node path.
 *
 * Phase E: browser storage backends (`WebExtensionStorage`,
 * `IndexedDbStorage`). Phase F: project keys + invite flow. Phase G:
 * rotation orchestration.
 *
 * `StandardTier` and `KeyRing` are not re-exported here — they require
 * `node:crypto` + `sodium-native`. A browser fork using Web Crypto is
 * deferred to a future phase; browser consumers that need to unwrap
 * keys (rather than just persist them) should bundle the Node entry
 * under a bundler that polyfills Node built-ins, or run the KeyRing in
 * a service worker that speaks to the browser UI over a message port.
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

// Phase E runtime — browser storage backends
export {
  WebExtensionStorage,
  type WebExtensionStorageArea,
} from '../storage/webextension.js';
export { IndexedDbStorage } from '../storage/indexeddb.js';
