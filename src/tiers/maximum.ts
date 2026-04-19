import {
  EnvelopeClient,
  SecureBuffer,
  asMasterKey,
  deriveMasterKeyFromPassphrase,
} from '@de-otio/crypto-envelope';
import type { ISecureBuffer, MasterKey } from '@de-otio/crypto-envelope';
import { UnlockFailed, WrongPassphrase } from '../errors.js';
import type { Tier, UnlockInput, WrappedKey } from '../types.js';

/**
 * KDF parameters for {@link MaximumTier}. Defaults follow OWASP 2023
 * second-tier Argon2id recommendations:
 * - `t` (time cost): 3 iterations
 * - `m` (memory cost): 65 536 KiB (64 MiB)
 * - `p` (parallelism): 1
 *
 * Callers who deliberately want different parameters (e.g. a lower-memory
 * phone build) can override, but dropping below these floors is not
 * recommended.
 */
export interface Argon2idParams {
  t: number;
  m: number;
  p: number;
}

const DEFAULT_ARGON2ID: Argon2idParams = { t: 3, m: 65_536, p: 1 };
const SALT_LENGTH = 16;

/**
 * Maximum tier — master key wrapped under a passphrase-derived KEK via
 * Argon2id + `@de-otio/crypto-envelope`'s envelope. The wrapped form
 * stores `(encrypted_master_envelope, salt, argon2id_params)`; the
 * passphrase is required at every unlock.
 *
 * ## Design
 *
 * A fresh KEK is derived on every wrap (fresh salt). The 32-byte master
 * is then encrypted under the KEK as a `{ master: base64 }` payload via
 * `EnvelopeClient`. On unwrap, the passphrase re-derives the KEK using
 * the stored salt; decryption failure under the KEK surfaces as
 * {@link WrongPassphrase}.
 *
 * ## Passphrase lifetime
 *
 * The tier instance holds the passphrase string for its lifetime
 * (required for `wrap`). JavaScript strings cannot be zeroed, so callers
 * should keep tier lifetimes short and dispose the tier as soon as the
 * wrap step completes.
 *
 * For unwrap, the passphrase is supplied via {@link UnlockInput} — the
 * tier's held passphrase is not consulted on the unwrap path (so a
 * passphrase-change flow can create two `MaximumTier` instances: the
 * new one wraps under the new passphrase; the old one is not needed
 * except for bookkeeping).
 */
export class MaximumTier implements Tier<'maximum'> {
  readonly kind = 'maximum' as const;
  private readonly passphrase: string;
  readonly params: Argon2idParams;

  private constructor(passphrase: string, params: Argon2idParams) {
    this.passphrase = passphrase;
    this.params = params;
  }

  /**
   * Construct a `MaximumTier` bound to a passphrase.
   *
   * The passphrase is held on the instance for use during {@link wrap}.
   * See the class JSDoc for the lifetime caveat.
   */
  static fromPassphrase(passphrase: string, params?: Partial<Argon2idParams>): MaximumTier {
    if (typeof passphrase !== 'string' || passphrase.length === 0) {
      throw new Error('MaximumTier.fromPassphrase: passphrase must be a non-empty string');
    }
    const resolved: Argon2idParams = { ...DEFAULT_ARGON2ID, ...params };
    if (resolved.t < 1 || resolved.m < 8192 || resolved.p < 1) {
      throw new Error(
        `MaximumTier: Argon2id parameters too weak (t=${resolved.t}, m=${resolved.m}, p=${resolved.p}); minimum acceptable is t=1, m=8192 (8 MiB), p=1. Defaults are OWASP 2023 second-tier (t=3, m=64 MiB, p=1).`,
      );
    }
    return new MaximumTier(passphrase, resolved);
  }

  async wrap(master: MasterKey): Promise<WrappedKey> {
    const salt = randomSalt();
    const kek = await deriveMasterKeyFromPassphrase(this.passphrase, salt, {
      algorithm: 'argon2id',
    });
    try {
      const envelope = await encryptMasterUnderKek(kek, master);
      return {
        v: 1,
        tier: 'maximum',
        envelope,
        kdfParams: {
          algorithm: 'argon2id',
          t: this.params.t,
          m: this.params.m,
          p: this.params.p,
          salt,
        },
        ts: new Date().toISOString(),
      };
    } finally {
      kek.dispose();
    }
  }

  async unwrap(wrapped: WrappedKey, input: UnlockInput): Promise<MasterKey> {
    if (wrapped.tier !== 'maximum') {
      throw new UnlockFailed(`MaximumTier.unwrap called on tier '${wrapped.tier}' wrapped key`);
    }
    if (input.kind !== 'passphrase') {
      throw new UnlockFailed(
        `MaximumTier.unwrap requires UnlockInput.kind='passphrase', got '${input.kind}'`,
      );
    }
    if (!wrapped.kdfParams || wrapped.kdfParams.algorithm !== 'argon2id') {
      throw new Error(
        'MaximumTier.unwrap: wrapped key is missing argon2id kdfParams; was this wrapped by MaximumTier?',
      );
    }

    const kek = await deriveMasterKeyFromPassphrase(input.passphrase, wrapped.kdfParams.salt, {
      algorithm: 'argon2id',
    });
    try {
      return await decryptMasterUnderKek(kek, wrapped.envelope);
    } catch (cause) {
      // Any decrypt-path failure under the KEK most likely means wrong
      // passphrase. We cannot disambiguate that from genuine envelope
      // tampering without additional side-channels; WrongPassphrase is
      // the user-facing label either way.
      throw new WrongPassphrase(
        'passphrase did not decrypt the wrapped master (either wrong passphrase or tampered wrapped-key)',
        { cause },
      );
    } finally {
      kek.dispose();
    }
  }
}

// ── internals ──────────────────────────────────────────────────────────

function randomSalt(): Uint8Array {
  const out = new Uint8Array(SALT_LENGTH);
  globalThis.crypto.getRandomValues(out);
  return out;
}

async function encryptMasterUnderKek(kek: MasterKey, master: ISecureBuffer): Promise<Uint8Array> {
  const client = new EnvelopeClient({ masterKey: kek });
  try {
    const masterB64 = Buffer.from(master.buffer).toString('base64');
    return await client.encrypt({ master: masterB64 });
  } finally {
    client.dispose();
  }
}

async function decryptMasterUnderKek(kek: MasterKey, envelope: Uint8Array): Promise<MasterKey> {
  const client = new EnvelopeClient({ masterKey: kek });
  try {
    const payload = (await client.decrypt(envelope)) as { master?: unknown };
    if (typeof payload.master !== 'string') {
      throw new Error('wrapped envelope did not contain the expected { master: string } payload');
    }
    const masterBytes = Buffer.from(payload.master, 'base64');
    if (masterBytes.length !== 32) {
      throw new Error(`wrapped master must be 32 bytes, got ${masterBytes.length}`);
    }
    return asMasterKey(SecureBuffer.from(masterBytes));
  } finally {
    client.dispose();
  }
}
