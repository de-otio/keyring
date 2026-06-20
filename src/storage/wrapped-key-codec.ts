import type { TierKind, WrappedKey } from '../types.js';

/**
 * Canonical JSON serialisation of a {@link WrappedKey} for the **Node** storage
 * backends (filesystem, OS keychain, remote server). Binary fields are
 * base64-encoded via Node `Buffer`. This is the single source of truth for the
 * wrapped-key-on-the-wire shape those backends share — the browser backends
 * (`WebExtensionStorage`, `IndexedDbStorage`) keep an object-form variant
 * because `chrome.storage`/IndexedDB store structured objects, not strings, and
 * cannot use `Buffer`.
 *
 * Wire version is `1`. The shape is frozen during alpha per plan §9; a change
 * here is a coordinated wire-format migration, not a silent edit (a `recovery-
 * key` wrapped key produced by one release must deserialise in the next).
 */
export interface SerialisedWrappedKey {
  v: 1;
  tier: string;
  /** base64 of the crypto-envelope envelope bytes. */
  envelope: string;
  /** Present only for KDF-based tiers (`maximum`). Absent for `standard`
   *  (SSH) and `recovery-key` (high-entropy KEK, no KDF). */
  kdfParams?: {
    algorithm: string;
    t?: number;
    m?: number;
    p?: number;
    iterations?: number;
    salt: string; // base64
  };
  /** `standard` (SSH) tier only. */
  sshFingerprint?: string;
  ts: string;
}

/** Tier kinds this codec knows how to round-trip. Kept in sync with
 *  {@link TierKind}; a new tier must be added here deliberately. */
const KNOWN_TIERS: ReadonlySet<TierKind> = new Set<TierKind>([
  'standard',
  'maximum',
  'recovery-key',
]);

/** Serialise a {@link WrappedKey} to the canonical JSON string. */
export function serializeWrappedKey(w: WrappedKey): string {
  const out: SerialisedWrappedKey = {
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

/** Parse the canonical JSON string back into a {@link WrappedKey}. Throws on
 *  an unknown wire version, unknown tier, or unknown KDF algorithm. */
export function deserializeWrappedKey(json: string): WrappedKey {
  const parsed = JSON.parse(json) as SerialisedWrappedKey;
  if (parsed.v !== 1) {
    throw new Error(`unsupported wrapped-key wire version: ${parsed.v}`);
  }
  if (!KNOWN_TIERS.has(parsed.tier as TierKind)) {
    throw new Error(`unsupported tier kind: ${parsed.tier}`);
  }
  const wrapped: WrappedKey = {
    v: 1,
    tier: parsed.tier as TierKind,
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
      throw new Error(`unsupported KDF algorithm in wrapped key: ${parsed.kdfParams.algorithm}`);
    }
  }
  if (parsed.sshFingerprint) {
    wrapped.sshFingerprint = parsed.sshFingerprint;
  }
  return wrapped;
}
