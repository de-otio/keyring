import type { AnyEnvelope, ISecureBuffer, MasterKey } from '@de-otio/crypto-envelope';

// ── Tier model ─────────────────────────────────────────────────────────────

/**
 * Tier kind — how a master key is wrapped for storage.
 *
 * - `'standard'`: SSH-key-wrapped (Ed25519 via `crypto_box_seal`, RSA via
 *   RSA-OAEP KEM+DEM). Inherits strength of the user's SSH key passphrase.
 * - `'maximum'`: Argon2id-passphrase-derived master. Library-enforced KDF
 *   parameter floors. No recovery.
 *
 * `'enhanced'` (BIP39 mnemonic) from chaoskb is dropped.
 */
export type TierKind = 'standard' | 'maximum';

/** How a master is wrapped for storage. Generic in its `TierKind` so that
 *  capability-typed `KeyStorage<K>` can refuse mismatched tiers at compile
 *  time (see design-review B14). */
export interface Tier<K extends TierKind = TierKind> {
  readonly kind: K;
  wrap(master: MasterKey): Promise<WrappedKey>;
  unwrap(wrapped: WrappedKey, input: UnlockInput): Promise<MasterKey>;
}

// ── Storage ────────────────────────────────────────────────────────────────

/**
 * A storage backend for wrapped keys. Generic in the tier set it accepts:
 * browser backends (`WebExtensionStorage`, `IndexedDbStorage`) are
 * `KeyStorage<'standard'>` only — passing a `MaximumTier` to a
 * `KeyRing<'standard'>` constructor is a compile-time error.
 *
 * Runtime fallback: the `KeyRing` constructor also performs a runtime
 * capability check and throws `TierStorageMismatch` for consumers that evade
 * the type system.
 */
export interface KeyStorage<K extends TierKind = TierKind> {
  readonly platform: 'node' | 'browser' | 'webext';
  /** Which tier kinds this storage accepts at runtime. Compile-time narrowing
   *  via the `K` parameter is the primary enforcement. */
  readonly acceptedTiers: readonly K[];
  put(slot: string, wrapped: WrappedKey): Promise<void>;
  get(slot: string): Promise<WrappedKey | null>;
  /** GDPR Art. 17 affordance — crypto-shredding at the storage layer.
   *  **Honest framing:** Art. 17 is satisfied at the envelope layer (existing
   *  ciphertext remains but permanently unreadable), not the storage layer;
   *  per-backend residue is documented per implementation. */
  delete(slot: string): Promise<void>;
  list(): Promise<string[]>;
}

// ── Wrapped key wire format (frozen per plan §9) ──────────────────────────

/** On-disk wrapped-key shape. v1 wire format — mutable between minors during
 *  alpha per plan §9. */
export interface WrappedKey {
  v: 1;
  tier: TierKind;
  /** crypto-envelope envelope bytes (wrapping the 32-byte master). */
  envelope: Uint8Array;
  /** MaximumTier only: Argon2id/PBKDF2 parameters used to derive the master. */
  kdfParams?: KdfParamsSnapshot;
  /** StandardTier only: SSH key fingerprint that can unwrap this. */
  sshFingerprint?: string;
  /** ISO 8601 timestamp set at wrap time. Not cryptographically significant;
   *  informational. */
  ts: string;
}

export type KdfParamsSnapshot =
  | {
      algorithm: 'argon2id';
      /** time cost */
      t: number;
      /** memory cost in KiB */
      m: number;
      /** parallelism */
      p: number;
      salt: Uint8Array;
    }
  | {
      algorithm: 'pbkdf2-sha256';
      iterations: number;
      salt: Uint8Array;
    };

// ── Unlock input ──────────────────────────────────────────────────────────

/**
 * Low-level unlock input. Most callers use the sugar methods on `KeyRing`
 * (`unlockWithPassphrase`, `unlockWithSshAgent`, `unlockWithSshKey`).
 *
 * `kind` is the discriminant; TypeScript narrows via switch-on-kind.
 */
export type UnlockInput =
  | { kind: 'passphrase'; passphrase: string }
  | { kind: 'ssh-agent' }
  | { kind: 'ssh-key'; privateKeyPem: string; passphrase?: string };

// ── Rotation ──────────────────────────────────────────────────────────────

/**
 * Consumer-supplied enumerator for `rotateMaster`. The library orchestrates
 * rewrap; the consumer owns storage — only the consumer knows the blob layout.
 *
 * **Ordering contract:** `'stable'` enables resumable rotation via the
 * `startAfter` cursor; `'arbitrary'` disables resume (rotate must restart
 * from the beginning on interrupt).
 */
export interface BlobEnumerator {
  readonly ordering: 'stable' | 'arbitrary';
  /** Yield every envelope to rewrap. Optional `startAfter` resumes after a
   *  partial run; optional `signal` propagates abort. */
  enumerate(options?: {
    startAfter?: string;
    signal?: AbortSignal;
  }): AsyncIterable<AnyEnvelope>;
  /** Consumer persists the rewrapped envelope. Library does not retry on
   *  rejection — consumer's `persist` should be idempotent. */
  persist(updated: AnyEnvelope, signal?: AbortSignal): Promise<void>;
}

export interface RotateOptions {
  /** Bounded concurrency. Library never holds more than `batchSize`
   *  unpersisted rewrapped envelopes in memory. Default: 8. */
  batchSize?: number;
  /** Resume cursor from a previous `rotate` call's `lastPersistedId`. Only
   *  valid when the enumerator's `ordering` is `'stable'`. */
  startAfter?: string;
  signal?: AbortSignal;
}

export interface RotationResult {
  /** Envelopes successfully rewrapped under the new master and persisted. */
  rotated: number;
  /** Envelopes already on the new master at enumeration time (idempotent
   *  re-run). */
  skipped: number;
  /** Envelopes that failed to rewrap or persist. Consumer can retry by
   *  re-invoking `rotate` with `startAfter: lastPersistedId`. */
  failed: ReadonlyArray<{
    id: string;
    error: Error;
    /** True if the error looks transient (network, disk contention); false
     *  if the envelope itself is unrecoverable (decrypt-failed, tampered). */
    retriable: boolean;
  }>;
  /** Last envelope id for which `persist` resolved successfully. Null if no
   *  persist completed. Feed back as `startAfter` on the next call. */
  lastPersistedId: string | null;
  /** `true` when `failed.length > 0` or `signal` aborted. Consumer must
   *  retain the old wrapped master until this is `false`. */
  oldMasterStillRequired: boolean;
}

// ── Rotation policy / threshold events ────────────────────────────────────

export interface RotationPolicy {
  /** Emit `soft-threshold` event when counter crosses this value. Suggested:
   *  2²⁴ (16M messages) for AES-256-GCM. */
  softThreshold: number;
  /** Emit `hard-threshold` event when counter crosses this value. Keyring
   *  does **not** force rotation — consumer decides; but crypto-envelope's
   *  `EnvelopeClient` will refuse encrypt at its own hard cap (2³² for
   *  AES-GCM). */
  hardThreshold: number;
}

// ── Events ────────────────────────────────────────────────────────────────

/**
 * Key-lifecycle events. Optional `EventSink` on `KeyRing` constructor emits
 * these for SOC 2 CC6.1 / CC7.2 consumers; keyring does **not** own an audit
 * log. Consumers persist wherever their audit pipeline lives.
 */
export type KeyRingEvent =
  | { kind: 'unlocked'; slot: string; tier: TierKind; ts: string }
  | { kind: 'locked'; slot: string; ts: string }
  | { kind: 'create-project'; name: string; ts: string }
  | { kind: 'delete'; slot: string; ts: string }
  | { kind: 'rotate-start'; oldFingerprint: string; newFingerprint: string; ts: string }
  | { kind: 'blob-rewrapped'; id: string; index: number; total: number | null; ts: string }
  | {
      kind: 'rotate-complete';
      result: Pick<RotationResult, 'rotated' | 'skipped' | 'oldMasterStillRequired'>;
      ts: string;
    }
  | { kind: 'soft-threshold'; fingerprint: string; counter: number; threshold: number; ts: string }
  | { kind: 'hard-threshold'; fingerprint: string; counter: number; threshold: number; ts: string }
  | {
      kind: 'unlock-failed';
      slot: string;
      reason: 'wrong-passphrase' | 'agent-refused' | 'invalid-key';
      ts: string;
    };

export interface EventSink {
  emit(event: KeyRingEvent): void;
}

// ── Re-exports from crypto-envelope for ergonomics ─────────────────────────

export type { AnyEnvelope, ISecureBuffer, MasterKey };
