import { OsKeychainUnavailable } from '../errors.js';
import type { KeyStorage, TierKind, WrappedKey } from '../types.js';

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
    await entry.setPassword(serialise(wrapped));
  }

  async get(slot: string): Promise<WrappedKey | null> {
    const mod = await loadKeyring();
    const entry = new mod.AsyncEntry(this.service, slot);
    const raw = await entry.getPassword();
    if (raw === null || raw === undefined) return null;
    return deserialise(raw);
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

// ── serialisation ──────────────────────────────────────────────────────

interface Serialised {
  v: 1;
  tier: string;
  envelope: string;
  kdfParams?: {
    algorithm: string;
    t?: number;
    m?: number;
    p?: number;
    iterations?: number;
    salt: string;
  };
  sshFingerprint?: string;
  ts: string;
}

function serialise(w: WrappedKey): string {
  const out: Serialised = {
    v: w.v,
    tier: w.tier,
    envelope: Buffer.from(w.envelope).toString('base64'),
    ts: w.ts,
  };
  if (w.kdfParams) {
    if (w.kdfParams.algorithm === 'argon2id') {
      out.kdfParams = {
        algorithm: 'argon2id',
        t: w.kdfParams.t,
        m: w.kdfParams.m,
        p: w.kdfParams.p,
        salt: Buffer.from(w.kdfParams.salt).toString('base64'),
      };
    } else {
      out.kdfParams = {
        algorithm: 'pbkdf2-sha256',
        iterations: w.kdfParams.iterations,
        salt: Buffer.from(w.kdfParams.salt).toString('base64'),
      };
    }
  }
  if (w.sshFingerprint) {
    out.sshFingerprint = w.sshFingerprint;
  }
  return JSON.stringify(out);
}

function deserialise(raw: string): WrappedKey {
  const parsed = JSON.parse(raw) as Serialised;
  if (parsed.v !== 1) {
    throw new Error(`unsupported wrapped-key wire version: ${parsed.v}`);
  }
  if (parsed.tier !== 'standard' && parsed.tier !== 'maximum') {
    throw new Error(`unsupported tier kind: ${parsed.tier}`);
  }
  const wrapped: WrappedKey = {
    v: 1,
    tier: parsed.tier,
    envelope: new Uint8Array(Buffer.from(parsed.envelope, 'base64')),
    ts: parsed.ts,
  };
  if (parsed.kdfParams) {
    const saltBytes = new Uint8Array(Buffer.from(parsed.kdfParams.salt, 'base64'));
    if (parsed.kdfParams.algorithm === 'argon2id') {
      wrapped.kdfParams = {
        algorithm: 'argon2id',
        t: parsed.kdfParams.t ?? 0,
        m: parsed.kdfParams.m ?? 0,
        p: parsed.kdfParams.p ?? 0,
        salt: saltBytes,
      };
    } else if (parsed.kdfParams.algorithm === 'pbkdf2-sha256') {
      wrapped.kdfParams = {
        algorithm: 'pbkdf2-sha256',
        iterations: parsed.kdfParams.iterations ?? 0,
        salt: saltBytes,
      };
    } else {
      throw new Error(`unsupported KDF algorithm: ${parsed.kdfParams.algorithm}`);
    }
  }
  if (parsed.sshFingerprint) {
    wrapped.sshFingerprint = parsed.sshFingerprint;
  }
  return wrapped;
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
