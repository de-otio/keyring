/**
 * Ambient type shim for `@de-otio/crypto-envelope`.
 *
 * Keyring's runtime depends on crypto-envelope v0.2 (`MasterKey` branded type,
 * `AnyEnvelope`, `MessageCounter`, `rewrapEnvelope`, etc.), which does not
 * exist on npm yet. This shim declares the subset keyring needs so that
 * `npm run typecheck` passes during Phase A scaffolding.
 *
 * **Remove this file** once `@de-otio/crypto-envelope@0.2.0-alpha.1` publishes
 * and the peer-dep resolves to real type definitions.
 */
declare module '@de-otio/crypto-envelope' {
  /** Memory-locked buffer (libsodium `sodium_malloc` / `sodium_memzero` in Node;
   *  pluggable in browsers per crypto-envelope plan-02 §5). */
  export interface ISecureBuffer {
    readonly buffer: Uint8Array;
    readonly length: number;
    readonly isDisposed: boolean;
    dispose(): void;
  }

  /** Concrete SecureBuffer impl class. Node path uses sodium-native; browser
   *  path uses plain `Uint8Array` + zero-on-dispose (strict-by-default, see
   *  keyring plan §7). */
  export class SecureBuffer implements ISecureBuffer {
    readonly buffer: Uint8Array;
    readonly length: number;
    readonly isDisposed: boolean;
    static from(bytes: Uint8Array): SecureBuffer;
    static alloc(length: number): SecureBuffer;
    dispose(): void;
    [Symbol.dispose](): void;
  }

  /** Branded master-key type — crypto-envelope plan-02 B8 fix. Prevents
   *  passing a passphrase-derived master directly to an AEAD primitive
   *  without going through HKDF. */
  export type MasterKey = SecureBuffer & { readonly __brand: 'MasterKey' };

  /** Supported AEAD algorithms. v0.2 adds AES-256-GCM alongside XChaCha20-Poly1305. */
  export type Algorithm = 'XChaCha20-Poly1305' | 'AES-256-GCM';

  export interface EnvelopeV1 {
    v: 1;
    id: string;
    ts: string;
    enc: {
      alg: Algorithm;
      kid: string;
      ct: string;
      'ct.len': number;
      commit: string;
    };
  }

  export interface EnvelopeV2 {
    v: 2;
    id: string;
    ts: string;
    enc: {
      alg: Algorithm;
      kid: string;
      ct: Uint8Array;
      commit: Uint8Array;
    };
  }

  export type AnyEnvelope = EnvelopeV1 | EnvelopeV2;

  /** Per-master counter used by the AES-GCM 2³² hard-cap. Keyring watches
   *  the counter to trigger rotation policy thresholds. Consumers provide
   *  persistent implementations (e.g. SQLite, DynamoDB) when running across
   *  process boundaries. */
  export interface MessageCounter {
    increment(keyFingerprint: Uint8Array): Promise<number>;
    current(keyFingerprint: Uint8Array): Promise<number>;
  }

  export interface EnvelopeClientOptions {
    masterKey: MasterKey;
    algorithm?: Algorithm;
    messageCounter?: MessageCounter;
  }

  export class EnvelopeClient {
    constructor(options: EnvelopeClientOptions);
    encrypt(payload: Record<string, unknown>, kid?: string): Promise<AnyEnvelope>;
    decrypt(envelope: AnyEnvelope): Promise<Record<string, unknown>>;
    [Symbol.dispose](): void;
  }

  /** Re-encrypt one blob under a new master. Keyring builds `rotateMaster`
   *  orchestration on top of this primitive. Idempotent: rewrapping a blob
   *  already under `newMaster` is a no-op. */
  export function rewrapEnvelope(
    envelope: AnyEnvelope,
    oldMaster: MasterKey,
    newMaster: MasterKey,
  ): AnyEnvelope;

  /** Derive a 32-byte master from a passphrase via Argon2id (default) or
   *  PBKDF2-SHA256 (fallback for WebCrypto-only runtimes). */
  export type PassphraseKdfParams =
    | { algorithm: 'argon2id'; t: number; m: number; p: number }
    | { algorithm: 'pbkdf2-sha256'; iterations: number };

  export function deriveMasterKeyFromPassphrase(
    passphrase: string,
    salt: Uint8Array,
    params: PassphraseKdfParams,
    options?: { signal?: AbortSignal },
  ): Promise<MasterKey>;
}
