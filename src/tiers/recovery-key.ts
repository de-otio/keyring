import { EnvelopeClient, SecureBuffer, asMasterKey } from '@de-otio/crypto-envelope';
import type { ISecureBuffer, MasterKey } from '@de-otio/crypto-envelope';
import { UnlockFailed, WrongRecoveryKey } from '../errors.js';
import type { Tier, UnlockInput, WrappedKey } from '../types.js';

/** A recovery key is exactly 32 bytes of high-entropy randomness. */
export const RECOVERY_KEY_BYTES = 32;

/**
 * Recovery-key tier — master key wrapped under a **generated, high-entropy
 * 32-byte recovery key** used directly as the key-encryption key (KEK).
 *
 * ## Why no Argon2id / no salt
 *
 * Unlike {@link MaximumTier} (low-entropy passphrase ⇒ memory-hard KDF + salt),
 * the recovery key is full-entropy, so a password-stretching KDF buys nothing.
 * The KEK derivation that *does* happen is inside
 * `@de-otio/crypto-envelope`'s `EnvelopeClient`: it HKDF-SHA256-expands the
 * 32-byte master key into domain-separated content and key-commitment subkeys
 * (`crypto-envelope/v1/content` / `…/commit`). So the wrapped form is just
 * `(envelope)` — there are no `kdfParams` to store, and the wire format is
 * therefore trivially portable to other languages.
 *
 * ## Threat model fit
 *
 * Intended for **server-held** wrapped masters (e.g. a server-blind settings
 * keystore): a passphrase-wrapped master sitting on a server is offline-
 * grindable; a 32-byte-recovery-key-wrapped master is not.
 *
 * ## Recovery-key lifetime
 *
 * The tier holds a private copy of the recovery key (for {@link wrap}). Call
 * {@link dispose} once wrapping is done to zero it. `unwrap` reads the key from
 * its {@link UnlockInput} and does **not** consult the held copy, so a fresh
 * device can unwrap by constructing a tier via {@link fromRecoveryKey} (or any
 * tier instance) and passing the key through `unwrap`.
 */
export class RecoveryKeyTier implements Tier<'recovery-key'> {
  readonly kind = 'recovery-key' as const;
  private readonly recoveryKey: ISecureBuffer;

  private constructor(recoveryKey: ISecureBuffer) {
    this.recoveryKey = recoveryKey;
  }

  /**
   * Mint a fresh random recovery key and a tier bound to it.
   *
   * Returns the raw recovery-key bytes so the caller can display/encode it for
   * the user ("write this down"). The returned `Uint8Array` is the caller's to
   * own and zero; the tier keeps its own independent copy for {@link wrap}.
   */
  static generate(): { tier: RecoveryKeyTier; recoveryKey: Uint8Array } {
    const bytes = new Uint8Array(RECOVERY_KEY_BYTES);
    globalThis.crypto.getRandomValues(bytes);
    return { tier: RecoveryKeyTier.fromRecoveryKey(bytes), recoveryKey: bytes };
  }

  /**
   * Construct a tier bound to an existing recovery key (e.g. one the user just
   * typed back in on a new device). The tier copies the bytes into a
   * {@link SecureBuffer}; the caller's input array is not retained.
   */
  static fromRecoveryKey(recoveryKey: Uint8Array): RecoveryKeyTier {
    assertRecoveryKeyShape(recoveryKey, 'RecoveryKeyTier.fromRecoveryKey');
    return new RecoveryKeyTier(SecureBuffer.from(new Uint8Array(recoveryKey)));
  }

  async wrap(master: MasterKey): Promise<WrappedKey> {
    const kek = asMasterKey(SecureBuffer.from(new Uint8Array(this.recoveryKey.buffer)));
    try {
      const envelope = await encryptMasterUnderKek(kek, master);
      return {
        v: 1,
        tier: 'recovery-key',
        envelope,
        // No kdfParams: the recovery key is the KEK directly (see class JSDoc).
        ts: new Date().toISOString(),
      };
    } finally {
      kek.dispose();
    }
  }

  async unwrap(wrapped: WrappedKey, input: UnlockInput): Promise<MasterKey> {
    if (wrapped.tier !== 'recovery-key') {
      throw new UnlockFailed(`RecoveryKeyTier.unwrap called on tier '${wrapped.tier}' wrapped key`);
    }
    if (input.kind !== 'recovery-key') {
      throw new UnlockFailed(
        `RecoveryKeyTier.unwrap requires UnlockInput.kind='recovery-key', got '${input.kind}'`,
      );
    }
    assertRecoveryKeyShape(input.recoveryKey, 'RecoveryKeyTier.unwrap');

    const kek = asMasterKey(SecureBuffer.from(new Uint8Array(input.recoveryKey)));
    try {
      return await decryptMasterUnderKek(kek, wrapped.envelope);
    } catch (cause) {
      // Any decrypt-path failure under the KEK most likely means a wrong
      // recovery key; we cannot disambiguate that from a tampered wrapped key
      // without side-channels. WrongRecoveryKey is the user-facing label.
      throw new WrongRecoveryKey(
        'recovery key did not decrypt the wrapped master (wrong key or tampered wrapped-key)',
        { cause },
      );
    } finally {
      kek.dispose();
    }
  }

  /** Zero the held recovery-key copy. Idempotent. */
  dispose(): void {
    this.recoveryKey.dispose();
  }
}

// ── internals ──────────────────────────────────────────────────────────

function assertRecoveryKeyShape(key: Uint8Array, where: string): void {
  if (!(key instanceof Uint8Array) || key.length !== RECOVERY_KEY_BYTES) {
    throw new UnlockFailed(
      `${where}: recovery key must be a ${RECOVERY_KEY_BYTES}-byte Uint8Array, got ${
        key instanceof Uint8Array ? `${key.length} bytes` : typeof key
      }`,
    );
  }
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
