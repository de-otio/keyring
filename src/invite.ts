import { Decrypter, Encrypter } from 'age-encryption';

/**
 * Invite flow — wrap a project key (or any 32-byte key) for a specific
 * recipient via the age file-encryption library.
 *
 * ## Why age (rather than custom ECDH)?
 *
 * The chaoskb predecessor rolled its own invite crypto (ephemeral X25519 +
 * HKDF + XChaCha20-Poly1305 + padding). The design review flagged two
 * findings:
 *
 * - **B4 (Medium)** — no small-order X25519 point check. An attacker who
 *   controlled the recipient's public key could send a low-order point
 *   and force the shared secret to a known fixed value (all-zero or
 *   otherwise). `sodium.crypto_scalarmult` doesn't reject low-order
 *   points explicitly; the chaoskb code accepted the zero secret silently
 *   and derived a key from it.
 * - **Previously-unflagged empty-AAD** — the AEAD tag was computed with
 *   `new Uint8Array(0)` as AAD. Swapping the nonce+ciphertext+tag across
 *   two invites from the same sender→recipient would decrypt cleanly,
 *   because the AEAD didn't bind any surrounding context.
 *
 * Both findings are **eliminated by delegating to age**:
 *
 * - `@noble/curves` (age's X25519 implementation) rejects low-order peer
 *   inputs at the scalar-mult layer — B4 is handled at the library
 *   boundary, not at the call site.
 * - age's header MAC binds every recipient stanza into the file-key
 *   derivation (RFC 9580-style AEAD header). Swapping stanzas produces
 *   a header MAC failure. Swapping ciphertext bodies produces a payload
 *   AEAD tag failure (age uses ChaCha20-Poly1305 with per-chunk
 *   binding).
 *
 * Both replacements come for free — age is a ~9KB gzipped dependency
 * already used across the Go ecosystem and vetted by FiloSottile's
 * `typage` library (which ships the TypeScript port).
 *
 * ## API
 *
 * - `invite(projectKey, inviteePubKey)` → the age-encrypted bytes that
 *   the sender hands to the invitee (over a side channel or via an
 *   invite URL).
 * - `acceptInvite(wrapped, myIdentity)` → recovers the project key.
 *
 * Callers supply recipient keys as age public-key strings (`age1...`)
 * and identities as age secret-key strings (`AGE-SECRET-KEY-1...`). Use
 * `generateX25519Identity` / `identityToRecipient` from `age-encryption`
 * to mint new keys.
 *
 * ## Challenge state
 *
 * This module does **not** manage challenge state (the "what project
 * does this invite authorize, and has it been used yet?" question).
 * That is the consumer's concern — chaoskb stores pending invites in
 * DynamoDB; trellis doesn't use project keys. See plan §15.6 for the
 * design decision rationale.
 */

/**
 * Encrypt a 32-byte key (typically a project key from
 * {@link createProjectKey}) for a single recipient.
 *
 * @param projectKey - The raw key bytes to wrap. Typically 32 bytes, but
 *   age supports arbitrary plaintext — the caller decides the semantics.
 * @param inviteePubKey - The recipient's age public key, e.g.
 *   `"age1kqa..."`. Generate via `identityToRecipient(secretKey)`.
 * @returns The age ciphertext bytes, ready to transmit.
 */
export async function invite(projectKey: Uint8Array, inviteePubKey: string): Promise<Uint8Array> {
  const enc = new Encrypter();
  enc.addRecipient(inviteePubKey);
  return enc.encrypt(projectKey);
}

/**
 * Decrypt an invite blob with the recipient's identity.
 *
 * @param wrapped - The age ciphertext bytes produced by {@link invite}.
 * @param myIdentity - The recipient's age secret key, e.g.
 *   `"AGE-SECRET-KEY-1..."`.
 * @returns The original raw key bytes.
 * @throws If the blob was encrypted for a different recipient, was
 *   tampered with, or is otherwise malformed. age throws with a
 *   descriptive message; the caller can wrap these in a keyring-specific
 *   error if needed.
 */
export async function acceptInvite(wrapped: Uint8Array, myIdentity: string): Promise<Uint8Array> {
  const dec = new Decrypter();
  dec.addIdentity(myIdentity);
  return dec.decrypt(wrapped);
}

// Re-export age's key-generation helpers so consumers can mint identities
// and recipients without a separate `age-encryption` import.
export {
  generateIdentity,
  generateX25519Identity,
  identityToRecipient,
} from 'age-encryption';
