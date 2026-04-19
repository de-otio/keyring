import { createHash } from 'node:crypto';
import { SecureBuffer } from '@de-otio/crypto-envelope';
import type { ISecureBuffer } from '@de-otio/crypto-envelope';
import sodium from 'sodium-native';
import { UnsupportedSshKeyType } from '../errors.js';

/**
 * SSH key handling — OpenSSH authorized_keys wire-format parsing and
 * Ed25519 ↔ X25519 conversions for `StandardTier`'s wrap/unwrap
 * operations.
 *
 * **Node-only.** Uses `sodium-native` for the curve-point conversions,
 * matching chaoskb's existing behaviour. A pure-JS noble-based variant
 * can land in a future phase if browser SSH use-cases emerge.
 */

export type SshKeyType = 'ed25519' | 'rsa';

export interface SshPublicKey {
  readonly type: SshKeyType;
  /** Wire-format public key bytes. For Ed25519: the 32-byte public key.
   *  For RSA: the SSH wire format `[exp_len|exp|mod_len|mod]`. */
  readonly publicKeyBytes: Uint8Array;
  /** SHA-256 fingerprint (`SHA256:<base64-no-pad>`) matching OpenSSH's
   *  `ssh-keygen -lf -E sha256`. */
  readonly fingerprint: string;
  readonly comment?: string;
}

/**
 * Parse an OpenSSH public key from `authorized_keys` / `.pub` file
 * format: `<key-type> <base64-blob> [comment]`.
 *
 * Supports `ssh-ed25519` and `ssh-rsa`. ECDSA keys (`ecdsa-sha2-*`)
 * throw `UnsupportedSshKeyType` — ECDSA support is a v0.2 scope item.
 */
export function parseSshPublicKey(keyString: string): SshPublicKey {
  const trimmed = keyString.trim();
  const parts = trimmed.split(/\s+/);
  if (parts.length < 2) {
    throw new Error('invalid SSH public key format: expected "<type> <base64> [comment]"');
  }
  const typeStr = parts[0] as string;
  const base64Blob = parts[1] as string;
  const comment = parts.length > 2 ? parts.slice(2).join(' ') : undefined;

  let type: SshKeyType;
  if (typeStr === 'ssh-ed25519') {
    type = 'ed25519';
  } else if (typeStr === 'ssh-rsa') {
    type = 'rsa';
  } else {
    throw new UnsupportedSshKeyType(typeStr);
  }

  const blob = Buffer.from(base64Blob, 'base64');
  const publicKeyBytes = extractPublicKeyFromBlob(blob, type);
  const fingerprint = sshFingerprint(blob);

  const out: SshPublicKey = { type, publicKeyBytes, fingerprint };
  return comment !== undefined ? { ...out, comment } : out;
}

/** Compute SHA-256 fingerprint matching OpenSSH's `-E sha256` format.
 *  Input: the SSH wire-format pubkey blob (base64-decoded from the
 *  `authorized_keys` line). */
export function sshFingerprint(blob: Uint8Array): string {
  const hash = createHash('sha256').update(blob).digest();
  return `SHA256:${hash.toString('base64').replace(/=+$/, '')}`;
}

// ── SSH wire-format parsing ────────────────────────────────────────────

function extractPublicKeyFromBlob(blob: Buffer, type: SshKeyType): Uint8Array {
  let offset = 0;
  const readString = (): Buffer => {
    if (offset + 4 > blob.length) {
      throw new Error('SSH key blob: unexpected end of data reading length');
    }
    const len = blob.readUInt32BE(offset);
    offset += 4;
    if (offset + len > blob.length) {
      throw new Error('SSH key blob: unexpected end of data reading string');
    }
    const data = blob.subarray(offset, offset + len);
    offset += len;
    return data;
  };

  const typeField = readString().toString('ascii');

  if (type === 'ed25519') {
    if (typeField !== 'ssh-ed25519') {
      throw new Error(`SSH key type mismatch: expected ssh-ed25519, got ${typeField}`);
    }
    const pubkey = readString();
    if (pubkey.length !== 32) {
      throw new Error(`Ed25519 public key must be 32 bytes, got ${pubkey.length}`);
    }
    return new Uint8Array(pubkey);
  }

  // RSA
  if (typeField !== 'ssh-rsa') {
    throw new Error(`SSH key type mismatch: expected ssh-rsa, got ${typeField}`);
  }
  const exponent = readString();
  const modulus = readString();
  // Preserve SSH wire format `[exp_len | exp | mod_len | mod]` so
  // StandardTier can reconstruct the Node `KeyObject` from the stored
  // bytes.
  const result = Buffer.alloc(4 + exponent.length + 4 + modulus.length);
  let pos = 0;
  result.writeUInt32BE(exponent.length, pos);
  pos += 4;
  exponent.copy(result, pos);
  pos += exponent.length;
  result.writeUInt32BE(modulus.length, pos);
  pos += 4;
  modulus.copy(result, pos);
  return new Uint8Array(result);
}

// ── Ed25519 ↔ X25519 conversions ───────────────────────────────────────

/**
 * Convert an Ed25519 public key to the corresponding X25519 (Curve25519)
 * public key, using libsodium's birational map. Used by `StandardTier`
 * to derive a sealed-box recipient from an SSH public key.
 */
export function ed25519ToX25519PublicKey(ed25519PublicKey: Uint8Array): Uint8Array {
  if (ed25519PublicKey.length !== 32) {
    throw new Error(`Ed25519 public key must be 32 bytes, got ${ed25519PublicKey.length}`);
  }
  const out = Buffer.alloc(sodium.crypto_box_PUBLICKEYBYTES);
  sodium.crypto_sign_ed25519_pk_to_curve25519(out, Buffer.from(ed25519PublicKey));
  return new Uint8Array(out);
}

/**
 * Convert an Ed25519 secret key to the corresponding X25519 secret key.
 *
 * **Security fix B5 (design-review):** returns a `SecureBuffer` rather
 * than a plain `Uint8Array`. The chaoskb predecessor returned a plain
 * `Uint8Array` that was never zeroed; callers had the responsibility
 * but didn't always take it (invite flow, standard-tier unwrap). The
 * `SecureBuffer` makes zeroing the caller's contract via `dispose()` /
 * `using`, and the internal sodium allocation is mlock'd.
 *
 * The input `ed25519SecretKey` buffer is zeroed after the conversion.
 */
export function ed25519ToX25519SecretKey(ed25519SecretKey: Uint8Array): ISecureBuffer {
  if (ed25519SecretKey.length !== 64) {
    throw new Error(`Ed25519 secret key must be 64 bytes, got ${ed25519SecretKey.length}`);
  }
  // Use a temporary sodium buffer for the conversion output; copy into
  // SecureBuffer (which mlocks + auto-zeros on dispose) then zero the
  // temporary. The input caller-supplied buffer is also zeroed.
  const tmp = Buffer.alloc(sodium.crypto_box_SECRETKEYBYTES);
  const inBuf = Buffer.from(ed25519SecretKey);
  try {
    sodium.crypto_sign_ed25519_sk_to_curve25519(tmp, inBuf);
    return SecureBuffer.from(tmp);
  } finally {
    sodium.sodium_memzero(tmp);
    sodium.sodium_memzero(inBuf);
    // The caller may still hold a reference to the original
    // Uint8Array; zero it defensively even though the handoff to inBuf
    // is a copy.
    if (ed25519SecretKey.buffer !== inBuf.buffer) {
      ed25519SecretKey.fill(0);
    }
  }
}
