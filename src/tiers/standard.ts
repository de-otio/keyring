import * as crypto from 'node:crypto';
import {
  EnvelopeClient,
  SecureBuffer,
  asMasterKey,
  canonicalJson,
  deserialize,
} from '@de-otio/crypto-envelope';
import type { MasterKey } from '@de-otio/crypto-envelope';
import sodium from 'sodium-native';
import { InvalidSshKey, SshAgentRefused, UnlockFailed, UnsupportedSshKeyType } from '../errors.js';
import {
  type SshPublicKey,
  ed25519ToX25519PublicKey,
  ed25519ToX25519SecretKey,
  parseSshPublicKey,
  sshFingerprint,
} from '../ssh/keys.js';
import type { Tier, UnlockInput, WrappedKey } from '../types.js';

const RSA_MIN_BITS = 2048;

/**
 * Standard tier — master key wrapped under an SSH key.
 *
 * ## Ed25519 path
 *
 * Wrap: `crypto_box_seal` to an X25519 recipient derived from the SSH
 * Ed25519 public key. Unwrap: `crypto_box_seal_open` with the X25519
 * secret derived from the SSH Ed25519 secret.
 *
 * ## RSA path
 *
 * Hybrid KEM+DEM: a fresh 32-byte KEK is encrypted to the RSA public
 * key via RSA-OAEP-SHA256; the master is encrypted under the KEK via
 * `EnvelopeClient` (XChaCha20-Poly1305 + HMAC commitment).
 *
 * ### Security fix — B2 (non-empty AAD)
 *
 * The chaoskb predecessor encrypted the master under the KEK with an
 * **empty** AAD (`new Uint8Array(0)`). This allowed an attacker with
 * two RSA-wrapped blobs under the same SSH key to swap their AEAD
 * portions without detection — the AEAD did not bind the wrapping
 * context. The design review flagged this as a **Critical** finding.
 *
 * Fix: `EnvelopeClient` is instantiated with a `kid` bound to the
 * SSH key fingerprint + a wrap-context constant. The envelope's own
 * AAD binds `alg, id, kid, v` per RFC 8785 canonical JSON, so the
 * fingerprint + context are cryptographically bound to the ciphertext.
 * Substitution across two different RSA-wrapped blobs fails AEAD at
 * decrypt time.
 *
 * The wire format changes from chaoskb's v0 (raw KEM+DEM concatenation
 * with empty AAD) to keyring's v1 (KEM + an EnvelopeClient v1 JSON
 * envelope serialised with bound AAD). Chaoskb Phase H's legacy
 * decoder handles pre-v1 wrappings.
 */
export class StandardTier implements Tier<'standard'> {
  readonly kind = 'standard' as const;
  private readonly source: StandardTierSource;

  private constructor(source: StandardTierSource) {
    this.source = source;
  }

  /**
   * Create a `StandardTier` from an OpenSSH public key string (the
   * one-line `ssh-ed25519 AAAAC3...` form). Used for wrapping. For
   * unwrapping, supply the private key via `UnlockInput.kind ===
   * 'ssh-key'`.
   */
  static fromSshKey(publicKeyString: string): StandardTier {
    const pub = parseSshPublicKey(publicKeyString);
    return new StandardTier({ kind: 'ssh-pubkey', publicKey: pub });
  }

  /** Pubkey fingerprint held by this tier — exposed so callers can
   *  persist it alongside the wrapped key for display + TOFU. */
  get fingerprint(): string {
    return this.source.publicKey.fingerprint;
  }

  async wrap(master: MasterKey): Promise<WrappedKey> {
    const pub = this.source.publicKey;
    if (pub.type === 'ed25519') {
      return this.wrapEd25519(master, pub);
    }
    if (pub.type === 'rsa') {
      return this.wrapRsa(master, pub);
    }
    throw new UnsupportedSshKeyType(pub.type);
  }

  async unwrap(wrapped: WrappedKey, input: UnlockInput): Promise<MasterKey> {
    if (wrapped.tier !== 'standard') {
      throw new UnlockFailed(`StandardTier.unwrap called on tier '${wrapped.tier}' wrapped key`);
    }
    if (input.kind !== 'ssh-key') {
      throw new UnlockFailed(
        `StandardTier.unwrap requires kind='ssh-key', got '${input.kind}'. ssh-agent integration is a Phase C2 item; use an on-disk SSH private key for now.`,
      );
    }
    if (input.kind === 'ssh-key' && input.passphrase !== undefined) {
      // PEM decryption is handled by `crypto.createPrivateKey({ key, passphrase })`
      // on the Node path below.
    }

    const sshPriv = this.parsePrivateKey(input.privateKeyPem, input.passphrase);
    if (sshPriv.type === 'ed25519') {
      return this.unwrapEd25519(wrapped, sshPriv);
    }
    return this.unwrapRsa(wrapped, sshPriv);
  }

  // ── Ed25519 wrap / unwrap ────────────────────────────────────────────

  private wrapEd25519(master: MasterKey, pub: SshPublicKey): WrappedKey {
    const x25519Pk = ed25519ToX25519PublicKey(pub.publicKeyBytes);
    const sealed = Buffer.alloc(master.length + sodium.crypto_box_SEALBYTES);
    sodium.crypto_box_seal(sealed, Buffer.from(master.buffer), Buffer.from(x25519Pk));
    return {
      v: 1,
      tier: 'standard',
      envelope: new Uint8Array(sealed),
      sshFingerprint: pub.fingerprint,
      ts: new Date().toISOString(),
    };
  }

  private unwrapEd25519(wrapped: WrappedKey, priv: ParsedEd25519Private): MasterKey {
    // SecureBuffer-backed X25519 secret (B5 fix).
    const x25519Sk = ed25519ToX25519SecretKey(priv.secretKey);
    const x25519Pk = ed25519ToX25519PublicKey(priv.publicKey);
    const plaintext = Buffer.alloc(wrapped.envelope.length - sodium.crypto_box_SEALBYTES);
    try {
      // sodium-native's crypto_box_seal_open returns `boolean` — `false`
      // on authentication failure. Must check the return value; ignoring
      // it leaves `plaintext` full of uninitialised/garbage bytes that
      // we would otherwise return as if they were the recovered master.
      const ok = sodium.crypto_box_seal_open(
        plaintext,
        Buffer.from(wrapped.envelope),
        Buffer.from(x25519Pk),
        x25519Sk.buffer,
      );
      if (!ok) {
        throw new UnlockFailed('ssh ed25519 sealed-box open failed (wrong key or tampered blob)');
      }
      return asMasterKey(SecureBuffer.from(plaintext));
    } catch (cause) {
      if (cause instanceof UnlockFailed) throw cause;
      throw new UnlockFailed('ssh ed25519 sealed-box open failed (wrong key or tampered blob)', {
        cause,
      });
    } finally {
      x25519Sk.dispose();
      plaintext.fill(0);
      priv.secretKey.fill(0);
    }
  }

  // ── RSA wrap / unwrap (with B2 AAD fix) ──────────────────────────────

  private async wrapRsa(master: MasterKey, pub: SshPublicKey): Promise<WrappedKey> {
    const rsaPubKey = rsaPublicKeyBytesToKeyObject(pub.publicKeyBytes);
    // Node's `asymmetricKeySize` is in bytes when set; absence means we
    // fall back to reading the modulus length from the parsed SSH wire
    // format. Refuse under 2048 bits regardless.
    const sizeBytes = rsaKeySizeBytes(rsaPubKey, pub.publicKeyBytes);
    if (sizeBytes * 8 < RSA_MIN_BITS) {
      throw new InvalidSshKey(`RSA key too small: ${sizeBytes * 8} bits (minimum ${RSA_MIN_BITS})`);
    }

    // KEM: generate fresh KEK, encrypt with RSA-OAEP-SHA256.
    const kek = crypto.randomBytes(32);
    const wrappedKek = crypto.publicEncrypt(
      {
        key: rsaPubKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      kek,
    );

    // DEM: encrypt master under KEK via EnvelopeClient. The envelope's
    // own AAD binds `alg, id, kid, v` — we bind the SSH fingerprint
    // into `kid` so a ciphertext from fingerprint-A cannot be
    // presented as wrapped under fingerprint-B (B2 security fix).
    const kid = buildWrapKid(pub.fingerprint);
    let envelopeBytes: Uint8Array;
    const kekBuf = SecureBuffer.from(kek);
    try {
      const client = new EnvelopeClient({ masterKey: asMasterKey(kekBuf), kid });
      try {
        const masterB64 = Buffer.from(master.buffer).toString('base64');
        envelopeBytes = await client.encrypt({ master: masterB64 });
      } finally {
        client.dispose();
      }
    } finally {
      kek.fill(0);
      kekBuf.dispose();
    }

    // Wire format: [4-byte wrappedKek length][wrappedKek][envelopeBytes]
    const out = Buffer.alloc(4 + wrappedKek.length + envelopeBytes.length);
    let offset = 0;
    out.writeUInt32BE(wrappedKek.length, offset);
    offset += 4;
    wrappedKek.copy(out, offset);
    offset += wrappedKek.length;
    Buffer.from(envelopeBytes).copy(out, offset);

    return {
      v: 1,
      tier: 'standard',
      envelope: new Uint8Array(out),
      sshFingerprint: pub.fingerprint,
      ts: new Date().toISOString(),
    };
  }

  private async unwrapRsa(wrapped: WrappedKey, priv: ParsedRsaPrivate): Promise<MasterKey> {
    const buf = Buffer.from(wrapped.envelope);
    if (buf.length < 4) {
      throw new UnlockFailed('RSA-wrapped blob is too short');
    }
    const wrappedKekLen = buf.readUInt32BE(0);
    if (wrappedKekLen <= 0 || 4 + wrappedKekLen > buf.length) {
      throw new UnlockFailed('RSA-wrapped blob has invalid KEK length');
    }
    const wrappedKek = buf.subarray(4, 4 + wrappedKekLen);
    const envelopeBytes = buf.subarray(4 + wrappedKekLen);

    // KEM: decrypt the KEK.
    let kekBytes: Buffer;
    try {
      kekBytes = crypto.privateDecrypt(
        {
          key: priv.key,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha256',
        },
        wrappedKek,
      );
    } catch (cause) {
      throw new UnlockFailed('RSA-OAEP decrypt of the wrapping key failed', { cause });
    }

    if (kekBytes.length !== 32) {
      kekBytes.fill(0);
      throw new UnlockFailed(`wrapped KEK must be 32 bytes, got ${kekBytes.length}`);
    }

    // DEM: decrypt master under KEK. B2 fix — verify the envelope's own
    // kid (bound into its AAD at encrypt time) matches what we would
    // have computed from the stored sshFingerprint. Catches an attacker
    // who tampers with `wrapped.sshFingerprint`: the envelope-layer
    // decrypt uses the envelope's baked-in kid, so the fingerprint in
    // the wrapped-key metadata and the one bound to the ciphertext must
    // agree or we refuse to decrypt.
    if (!wrapped.sshFingerprint) {
      kekBytes.fill(0);
      throw new UnlockFailed('RSA-wrapped blob is missing sshFingerprint (required for AAD bind)');
    }
    const expectedKid = buildWrapKid(wrapped.sshFingerprint);
    let storedKid: string;
    try {
      const env = deserialize(envelopeBytes);
      storedKid = env.enc.kid;
    } catch (cause) {
      kekBytes.fill(0);
      throw new UnlockFailed('RSA-wrapped envelope bytes did not parse', { cause });
    }
    if (storedKid !== expectedKid) {
      kekBytes.fill(0);
      throw new UnlockFailed(
        'RSA-wrapped envelope kid does not match stored SSH fingerprint — metadata tampered with',
      );
    }

    const kekSb = SecureBuffer.from(kekBytes);
    try {
      const client = new EnvelopeClient({ masterKey: asMasterKey(kekSb), kid: expectedKid });
      try {
        const payload = (await client.decrypt(envelopeBytes)) as { master?: unknown };
        if (typeof payload.master !== 'string') {
          throw new UnlockFailed('wrapped envelope missing {master: string} payload');
        }
        const masterBytes = Buffer.from(payload.master, 'base64');
        if (masterBytes.length !== 32) {
          throw new UnlockFailed(`unwrapped master must be 32 bytes, got ${masterBytes.length}`);
        }
        return asMasterKey(SecureBuffer.from(masterBytes));
      } finally {
        client.dispose();
      }
    } catch (cause) {
      if (cause instanceof UnlockFailed) throw cause;
      throw new UnlockFailed('RSA-wrapped envelope AEAD decrypt failed', { cause });
    } finally {
      kekBytes.fill(0);
      kekSb.dispose();
    }
  }

  // ── Private key parsing ──────────────────────────────────────────────

  private parsePrivateKey(
    pem: string,
    passphrase?: string,
  ): ParsedEd25519Private | ParsedRsaPrivate {
    let keyObject: crypto.KeyObject;
    try {
      keyObject = crypto.createPrivateKey(passphrase ? { key: pem, passphrase } : pem);
    } catch (cause) {
      throw new InvalidSshKey('failed to parse SSH private key (wrong passphrase or format?)', {
        cause,
      });
    }

    if (keyObject.asymmetricKeyType === 'ed25519') {
      const jwk = keyObject.export({ format: 'jwk' }) as { x?: string; d?: string };
      if (!jwk.x || !jwk.d) {
        throw new InvalidSshKey('Ed25519 JWK missing x or d');
      }
      const publicKey = Buffer.from(base64urlToBase64(jwk.x), 'base64');
      const seed = Buffer.from(base64urlToBase64(jwk.d), 'base64');
      if (publicKey.length !== 32 || seed.length !== 32) {
        throw new InvalidSshKey('Ed25519 JWK fields must be 32 bytes each');
      }
      // OpenSSH ed25519 secret is 64 bytes: [seed || public]. libsodium
      // expects this concatenated form.
      const secretKey = Buffer.alloc(64);
      seed.copy(secretKey, 0);
      publicKey.copy(secretKey, 32);
      seed.fill(0);
      return {
        type: 'ed25519',
        publicKey: new Uint8Array(publicKey),
        secretKey: new Uint8Array(secretKey),
      };
    }

    if (keyObject.asymmetricKeyType === 'rsa') {
      return { type: 'rsa', key: keyObject };
    }

    throw new UnsupportedSshKeyType(keyObject.asymmetricKeyType ?? 'unknown');
  }
}

// ── internals ──────────────────────────────────────────────────────────

interface StandardTierSource {
  kind: 'ssh-pubkey';
  publicKey: SshPublicKey;
}

interface ParsedEd25519Private {
  type: 'ed25519';
  publicKey: Uint8Array;
  secretKey: Uint8Array; // 64-byte libsodium form [seed || public]
}

interface ParsedRsaPrivate {
  type: 'rsa';
  key: crypto.KeyObject;
}

/**
 * Construct the `kid` string bound into the envelope's AAD for a
 * StandardTier RSA wrap. The SSH fingerprint is the stable, unique
 * identifier for the wrapping public key; the wrap-context constant
 * keeps this binding separate from any other envelope kid taxonomy.
 *
 * Canonical JSON output ensures byte-stable encoding even if the
 * fingerprint contains fields re-orderable in other JSON producers.
 */
function buildWrapKid(fingerprint: string): string {
  return canonicalJson({
    ctx: 'keyring/v1/standard/rsa-kemdem',
    fp: fingerprint,
  });
}

function rsaKeySizeBytes(keyObject: crypto.KeyObject, rsaBytes: Uint8Array): number {
  const declared = (keyObject as unknown as { asymmetricKeySize?: number }).asymmetricKeySize;
  if (typeof declared === 'number' && declared > 0) return declared;
  // Fall back to reading the modulus length from the parsed SSH wire
  // format: `[4 byte eLen | e | 4 byte nLen | n]`. Strip any leading
  // sign byte (SSH wire format uses two's-complement big-endian, so
  // high-bit moduli get prefixed with 0x00).
  const buf = Buffer.from(rsaBytes);
  const eLen = buf.readUInt32BE(0);
  const nLen = buf.readUInt32BE(4 + eLen);
  const n = buf.subarray(4 + eLen + 4, 4 + eLen + 4 + nLen);
  return stripLeadingZero(n).length;
}

function rsaPublicKeyBytesToKeyObject(rsaBytes: Uint8Array): crypto.KeyObject {
  const buf = Buffer.from(rsaBytes);
  let offset = 0;
  const eLen = buf.readUInt32BE(offset);
  offset += 4;
  const e = buf.subarray(offset, offset + eLen);
  offset += eLen;
  const nLen = buf.readUInt32BE(offset);
  offset += 4;
  const n = buf.subarray(offset, offset + nLen);
  const jwk = {
    kty: 'RSA',
    n: bufferToBase64Url(stripLeadingZero(n)),
    e: bufferToBase64Url(stripLeadingZero(e)),
  };
  return crypto.createPublicKey({ key: jwk, format: 'jwk' });
}

function stripLeadingZero(buf: Buffer): Buffer {
  if (buf[0] === 0 && buf.length > 1) {
    return buf.subarray(1);
  }
  return buf;
}

function bufferToBase64Url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlToBase64(b64url: string): string {
  return b64url.replace(/-/g, '+').replace(/_/g, '/');
}

/** Exposed for tests: fingerprint of the wrapped key (present on every
 *  StandardTier-produced `WrappedKey`). */
export { sshFingerprint };
