// StandardTier prototype via age + ed25519→X25519 conversion.
//
// Compare against chaoskb/src/crypto/tiers/standard.ts (215 LOC).
//
// IMPORTANT WIRE-FORMAT CAVEAT (see report §wire-format):
// `age-encryption` v0.3.0 (the only maintained TS port of age) does NOT
// implement the SSH recipient stanza ("ssh-ed25519" / "ssh-rsa"). The Go
// `age` CLI does. Two paths exist for keyring:
//
//   (a) Implement a custom Recipient/Identity that emits the SSH stanza
//       per https://age-encryption.org/v1 §§"ssh-ed25519 recipient" /
//       "ssh-rsa recipient". Cost: ~150 LOC (ed25519) + ~100 LOC (rsa).
//       Benefit: `age -R authorized_keys` interop with the Go CLI.
//
//   (b) Convert the SSH ed25519 pubkey to an X25519 recipient at the
//       boundary (mirrors the `ssh-to-age` tool) and use age's built-in
//       X25519 recipient. Cost: ~30 LOC of wire decoding + 1 noble call.
//       Drawback: NOT wire-compat with Go age's SSH recipient — the
//       wrapped output decrypts only with the matching X25519 identity,
//       not with `age -i ~/.ssh/id_ed25519`.
//
// This spike implements (b) — that's the cheapest path and exercises the
// real integration surface. (a) is quantified separately in the report.
// RSA is left out of the spike entirely; under both paths it requires
// non-trivial OpenSSH-RSA decoding plus RSAES-OAEP framing, which is
// either implemented as a custom Recipient (a) or replaced wholesale by
// "ask the user to convert to ed25519" (b).

import { Encrypter, Decrypter, identityToRecipient } from "age-encryption";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bech32 } from "@scure/base";

/** Decode the OpenSSH `ssh-ed25519 AAAAC3... [comment]` text format. */
function parseSshEd25519PublicKey(line: string): Uint8Array {
  const parts = line.trim().split(/\s+/);
  if (parts.length < 2 || parts[0] !== "ssh-ed25519") {
    throw new Error("only ssh-ed25519 supported in this spike");
  }
  const blob = Uint8Array.from(atob(parts[1]), (c) => c.charCodeAt(0));
  // OpenSSH wire: string("ssh-ed25519") || string(32-byte pubkey)
  // Each `string` is uint32-be length || bytes.
  const dv = new DataView(blob.buffer, blob.byteOffset, blob.byteLength);
  const algLen = dv.getUint32(0);
  const algName = new TextDecoder().decode(blob.subarray(4, 4 + algLen));
  if (algName !== "ssh-ed25519") throw new Error("blob alg mismatch");
  const keyOffset = 4 + algLen;
  const keyLen = dv.getUint32(keyOffset);
  if (keyLen !== 32) throw new Error("ed25519 pubkey must be 32 bytes");
  return blob.subarray(keyOffset + 4, keyOffset + 4 + keyLen);
}

/** Convert an OpenSSH ssh-ed25519 public key line into an age `age1...` recipient. */
export function sshEd25519ToAgeRecipient(sshPubKey: string): string {
  const edPub = parseSshEd25519PublicKey(sshPubKey);
  // ed25519.utils.toMontgomery does the standard birational map, with the
  // sign-bit handling needed to match libsodium's
  // crypto_sign_ed25519_pk_to_curve25519. (Same map age uses for its
  // ssh-ed25519 recipient.)
  const xPub = ed25519.utils.toMontgomery(edPub);
  return bech32.encodeFromBytes("age", xPub);
}

/**
 * Convert an OpenSSH ed25519 secret seed (32 bytes) into an
 * AGE-SECRET-KEY-1... identity string.
 *
 * NOTE: this expects the raw ed25519 seed, not the OpenSSH PEM. Parsing
 * the OpenSSH PEM (with its bcrypt-pbkdf-protected secret-section) is
 * exactly what `sshpk` does and is out of scope for the spike. In the
 * real keyring, this comes from ssh-agent (which never exposes the
 * secret) or from a parsed PEM via sshpk.
 */
export function sshEd25519SeedToAgeIdentity(seed32: Uint8Array): string {
  if (seed32.length !== 32) throw new Error("ed25519 seed must be 32 bytes");
  const xPriv = ed25519.utils.toMontgomerySecret(seed32);
  return bech32.encodeFromBytes("AGE-SECRET-KEY-", xPriv).toUpperCase();
}

/**
 * Wrap a master key under an SSH ed25519 public key.
 * Returns age-format ciphertext bytes.
 */
export async function wrapWithSshKey(
  master: Uint8Array,
  sshPubKey: string,
): Promise<Uint8Array> {
  if (master.length === 0) throw new Error("master must be non-empty");
  const recipient = sshEd25519ToAgeRecipient(sshPubKey);
  // Round-trip through identityToRecipient is unnecessary; recipient is
  // already an age1... string. Sanity-check the bech32:
  if (!recipient.startsWith("age1")) throw new Error("recipient encoding bug");
  const e = new Encrypter();
  e.addRecipient(recipient);
  return e.encrypt(master);
}

/** Decrypt counterpart for wrapWithSshKey, given the raw ed25519 seed. */
export async function unwrapWithSshKey(
  wrapped: Uint8Array,
  sshSeed32: Uint8Array,
): Promise<Uint8Array> {
  const identity = sshEd25519SeedToAgeIdentity(sshSeed32);
  const d = new Decrypter();
  d.addIdentity(identity);
  return d.decrypt(wrapped);
}

// Internal helper kept exported for the test suite.
export const _internal = {
  parseSshEd25519PublicKey,
  sshEd25519ToAgeRecipient,
  sshEd25519SeedToAgeIdentity,
  // Alias for clarity in tests:
  identityToRecipient,
};
