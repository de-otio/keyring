// Invite prototype via age X25519 recipient.
//
// Compare against chaoskb/src/crypto/invite.ts (172 LOC).
// chaoskb hand-rolls X25519 KEM framing, with these issues:
//   - B4: missing small-order / contributory check on attacker-supplied
//         ephemeral pubkey
//   - B5: ed25519ToX25519SecretKey returns plain Uint8Array (unzeroed)
// age's X25519 recipient implementation handles small-order points correctly
// (rejects all-zero shared secret) and uses HKDF as required by the spec.
//
// Public surface (mirrors keyring §5 invite flow):
//   newInviteeIdentity()  -> { identity, recipient }   // invitee generates
//   createInvite(projectKey, inviteeRecipient) -> Uint8Array
//   acceptInvite(wrapped, myIdentity)          -> Uint8Array (the project key)
//
// Note: this maps to "invitee already has an X25519 keypair" — the chaoskb
// flow that converts an ed25519 SSH key to X25519 is *not* in scope for the
// spike (see §5 of the report; under age-adoption invitees use AGE-SECRET-KEY-1
// or `ssh-to-age` at the boundary).

import {
  Encrypter,
  Decrypter,
  generateX25519Identity,
  identityToRecipient,
} from "age-encryption";

export interface InviteeKeypair {
  /** AGE-SECRET-KEY-1... — keep secret. Hand to acceptInvite. */
  identity: string;
  /** age1... — share with inviter. */
  recipient: string;
}

export async function newInviteeIdentity(): Promise<InviteeKeypair> {
  const identity = await generateX25519Identity();
  const recipient = await identityToRecipient(identity);
  return { identity, recipient };
}

export async function createInvite(
  projectKey: Uint8Array,
  inviteeRecipient: string,
): Promise<Uint8Array> {
  if (projectKey.length === 0) throw new Error("projectKey must be non-empty");
  if (!inviteeRecipient.startsWith("age1")) {
    throw new Error("inviteeRecipient must be an age1... string");
  }
  const e = new Encrypter();
  e.addRecipient(inviteeRecipient);
  return e.encrypt(projectKey);
}

export async function acceptInvite(
  wrapped: Uint8Array,
  myIdentity: string,
): Promise<Uint8Array> {
  if (!myIdentity.startsWith("AGE-SECRET-KEY-1")) {
    throw new Error("identity must be an AGE-SECRET-KEY-1... string");
  }
  const d = new Decrypter();
  d.addIdentity(myIdentity);
  return d.decrypt(wrapped);
}
