import { OsKeychainUnavailable } from '../errors.js';
import type { KeyStorage, TierKind, WrappedKey } from '../types.js';
import { deserializeWrappedKey, serializeWrappedKey } from './wrapped-key-codec.js';

/**
 * OS-keychain-backed `KeyStorage`. Wrapped-key bytes are stored as
 * base64-encoded JSON inside the OS keychain's "password" field under a
 * caller-supplied service name.
 *
 * Platform backing:
 * - **macOS:** Keychain Services (via Security.framework)
 * - **Windows:** Credential Manager (via `wincred`)
 * - **Linux:** libsecret (via dbus; needs `gnome-keyring` or `kwallet`
 *   running). Headless servers may not have a secret-service daemon —
 *   in that case construct a `FileSystemStorage` with `0o700` root as
 *   a fallback.
 *
 * ## Dependency
 *
 * `@napi-rs/keyring` is an **optional** runtime dependency. Prebuild
 * binaries ship for the common platforms; Alpine musl, BSD, and ARM32
 * may lack a prebuild. The module is loaded lazily on the first
 * `put` / `get` / `delete` / `list` call; failure throws
 * {@link OsKeychainUnavailable} with guidance to fall back to
 * `FileSystemStorage`.
 *
 * ## GDPR Art. 17 / crypto-shredding
 *
 * `delete(slot)` removes the entry from the OS keychain. Keychain
 * compaction behaviour is OS-dependent (macOS keychain.db, Windows
 * Credential Manager, libsecret backends) — bytes may persist in
 * free space until the keychain compacts. Per the library's honest
 * framing: erasure is satisfied at the envelope layer, not the
 * storage layer.
 */
export class OsKeychainStorage<K extends TierKind = TierKind> implements KeyStorage<K> {
  readonly platform: 'node' | 'browser' | 'webext' = 'node';
  readonly acceptedTiers: readonly K[];
  readonly service: string;

  constructor(options: { service: string; acceptedTiers?: readonly K[] }) {
    if (!options.service || typeof options.service !== 'string') {
      throw new Error('OsKeychainStorage: `service` option is required');
    }
    this.service = options.service;
    this.acceptedTiers =
      options.acceptedTiers ?? (['standard', 'maximum'] as unknown as readonly K[]);
  }

  async put(slot: string, wrapped: WrappedKey): Promise<void> {
    const mod = await loadKeyring();
    const entry = new mod.AsyncEntry(this.service, slot);
    await entry.setPassword(serializeWrappedKey(wrapped));
  }

  async get(slot: string): Promise<WrappedKey | null> {
    const mod = await loadKeyring();
    const entry = new mod.AsyncEntry(this.service, slot);
    const raw = await entry.getPassword();
    if (raw === null || raw === undefined) return null;
    return deserializeWrappedKey(raw);
  }

  async delete(slot: string): Promise<void> {
    const mod = await loadKeyring();
    const entry = new mod.AsyncEntry(this.service, slot);
    // `deletePassword` returns `true` if deleted, `false` if absent. We
    // treat both as success — delete is idempotent per the KeyStorage
    // contract.
    try {
      await entry.deletePassword();
    } catch (err) {
      // Some backends (libsecret on headless CI) throw on missing
      // entries rather than returning false. Swallow the not-found case;
      // re-throw everything else.
      if (!isNotFoundError(err)) throw err;
    }
  }

  async list(): Promise<string[]> {
    const mod = await loadKeyring();
    const creds = await mod.findCredentialsAsync(this.service);
    return creds.map((c) => c.account);
  }
}

// ── lazy-load handling ─────────────────────────────────────────────────

type KeyringModule = typeof import('@napi-rs/keyring');

let cachedModule: KeyringModule | null = null;
let cachedError: Error | null = null;

async function loadKeyring(): Promise<KeyringModule> {
  if (cachedModule) return cachedModule;
  if (cachedError) throw cachedError;
  try {
    cachedModule = await import('@napi-rs/keyring');
    return cachedModule;
  } catch (cause) {
    cachedError = new OsKeychainUnavailable(
      `@napi-rs/keyring could not be loaded on ${process.platform}-${process.arch}. Prebuild binaries ship for darwin / win32 / linux-gnu only. Fall back to FileSystemStorage (with a 0o700 root directory) for unsupported platforms.`,
      { cause },
    );
    throw cachedError;
  }
}

/** Internal: reset the module cache. Not part of the public API —
 *  exposed for tests that need to re-drive the load path. */
export function _resetKeyringCache(): void {
  cachedModule = null;
  cachedError = null;
}

function isNotFoundError(err: unknown): boolean {
  if (!err || typeof err !== 'object') return false;
  const msg = (err as { message?: string }).message ?? '';
  // libsecret: "No matching secret found in the secret service";
  // wincred: "Element not found";
  // macOS Keychain: "The specified item could not be found in the keychain".
  return (
    /not found/i.test(msg) ||
    /no matching/i.test(msg) ||
    /no entry found/i.test(msg) ||
    /does not exist/i.test(msg)
  );
}
