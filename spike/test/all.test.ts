// Spike round-trip tests. Run with `npx tsx --test test/all.test.ts`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519.js";

import { wrapWithPassphrase, unwrapWithPassphrase } from "../age-passphrase-tier.ts";
import { newInviteeIdentity, createInvite, acceptInvite } from "../age-invite.ts";
import {
  wrapWithSshKey,
  unwrapWithSshKey,
  sshEd25519ToAgeRecipient,
  sshEd25519SeedToAgeIdentity,
  _internal,
} from "../age-ssh-tier.ts";

test("passphrase tier: round-trip", async () => {
  const master = randomBytes(32);
  const wrapped = await wrapWithPassphrase(master, "correct horse battery staple", { scryptLogN: 10 });
  const out = await unwrapWithPassphrase(wrapped, "correct horse battery staple");
  assert.deepEqual(out, new Uint8Array(master));
});

test("passphrase tier: wrong passphrase rejects", async () => {
  const master = randomBytes(32);
  const wrapped = await wrapWithPassphrase(master, "right", { scryptLogN: 10 });
  await assert.rejects(() => unwrapWithPassphrase(wrapped, "wrong"));
});

test("invite: round-trip", async () => {
  const projectKey = randomBytes(32);
  const invitee = await newInviteeIdentity();
  const invite = await createInvite(projectKey, invitee.recipient);
  const out = await acceptInvite(invite, invitee.identity);
  assert.deepEqual(out, new Uint8Array(projectKey));
});

test("invite: wrong identity rejects", async () => {
  const projectKey = randomBytes(32);
  const a = await newInviteeIdentity();
  const b = await newInviteeIdentity();
  const invite = await createInvite(projectKey, a.recipient);
  await assert.rejects(() => acceptInvite(invite, b.identity));
});

test("ssh tier: ed25519 round-trip", async () => {
  // Generate an ed25519 keypair the way OpenSSH would have:
  const seed = ed25519.utils.randomSecretKey();
  const pub = ed25519.getPublicKey(seed);
  // Reconstruct the OpenSSH text format ourselves: string(alg) || string(pub).
  const algBytes = new TextEncoder().encode("ssh-ed25519");
  const blob = new Uint8Array(4 + algBytes.length + 4 + pub.length);
  const dv = new DataView(blob.buffer);
  dv.setUint32(0, algBytes.length);
  blob.set(algBytes, 4);
  dv.setUint32(4 + algBytes.length, pub.length);
  blob.set(pub, 4 + algBytes.length + 4);
  const b64 = Buffer.from(blob).toString("base64");
  const sshLine = `ssh-ed25519 ${b64} test@spike`;

  const master = randomBytes(32);
  const wrapped = await wrapWithSshKey(master, sshLine);
  const out = await unwrapWithSshKey(wrapped, seed);
  assert.deepEqual(out, new Uint8Array(master));
});

test("ssh tier: pubkey-to-recipient is deterministic and bech32-valid", async () => {
  const seed = new Uint8Array(32).fill(7);
  const pub = ed25519.getPublicKey(seed);
  const algBytes = new TextEncoder().encode("ssh-ed25519");
  const blob = new Uint8Array(4 + algBytes.length + 4 + pub.length);
  const dv = new DataView(blob.buffer);
  dv.setUint32(0, algBytes.length);
  blob.set(algBytes, 4);
  dv.setUint32(4 + algBytes.length, pub.length);
  blob.set(pub, 4 + algBytes.length + 4);
  const sshLine = `ssh-ed25519 ${Buffer.from(blob).toString("base64")}`;

  const r1 = sshEd25519ToAgeRecipient(sshLine);
  const r2 = sshEd25519ToAgeRecipient(sshLine);
  assert.equal(r1, r2);
  assert.match(r1, /^age1[a-z0-9]+$/);

  // Cross-check: deriving the identity from the seed and converting it to a
  // recipient via age's own identityToRecipient must match.
  const id = sshEd25519SeedToAgeIdentity(seed);
  const r3 = await _internal.identityToRecipient(id);
  assert.equal(r1, r3);
});

test("ssh tier: rejects ssh-rsa (not in spike scope)", () => {
  assert.throws(() => sshEd25519ToAgeRecipient("ssh-rsa AAAA..."));
});
