import { beforeAll, describe, expect, it } from 'vitest';
import {
  acceptInvite,
  generateX25519Identity,
  identityToRecipient,
  invite,
} from '../../src/invite.js';

/**
 * Unit tests for the age-delegated invite wrapper. The bulk of the
 * interesting crypto lives in `age-encryption`, so these tests verify
 * the wrapper honours the API contract — round-trip, correct-recipient
 * authorization, tamper rejection — without attempting to re-test age
 * itself.
 */

let inviterIdentity: string;
let inviterRecipient: string;
let inviteeIdentity: string;
let inviteeRecipient: string;
let strangerIdentity: string;
let strangerRecipient: string;

beforeAll(async () => {
  inviterIdentity = await generateX25519Identity();
  inviterRecipient = await identityToRecipient(inviterIdentity);
  inviteeIdentity = await generateX25519Identity();
  inviteeRecipient = await identityToRecipient(inviteeIdentity);
  strangerIdentity = await generateX25519Identity();
  strangerRecipient = await identityToRecipient(strangerIdentity);
});

function fakeProjectKey(): Uint8Array {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

describe('invite / acceptInvite', () => {
  it('round-trips a project key', async () => {
    const pk = fakeProjectKey();
    const wrapped = await invite(pk, inviteeRecipient);
    const recovered = await acceptInvite(wrapped, inviteeIdentity);
    expect(Array.from(recovered)).toEqual(Array.from(pk));
  });

  it('produces different ciphertext each call (age uses fresh ephemeral keys)', async () => {
    const pk = fakeProjectKey();
    const a = await invite(pk, inviteeRecipient);
    const b = await invite(pk, inviteeRecipient);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });

  it('refuses decryption with a different identity', async () => {
    const pk = fakeProjectKey();
    const wrapped = await invite(pk, inviteeRecipient);
    await expect(acceptInvite(wrapped, strangerIdentity)).rejects.toThrow();
  });

  it('refuses decryption with the sender`s own identity when encrypted to someone else', async () => {
    const pk = fakeProjectKey();
    const wrapped = await invite(pk, inviteeRecipient);
    await expect(acceptInvite(wrapped, inviterIdentity)).rejects.toThrow();
  });

  it('rejects tampered ciphertext (age payload AEAD tag fails)', async () => {
    const pk = fakeProjectKey();
    const wrapped = await invite(pk, inviteeRecipient);
    // Flip a byte in the middle of the ciphertext — age's payload is
    // chunked ChaCha20-Poly1305 so a single byte flip fails the tag.
    const tampered = Uint8Array.from(wrapped);
    const i = Math.floor(tampered.length / 2);
    tampered[i] = ((tampered[i] ?? 0) ^ 0xff) & 0xff;
    await expect(acceptInvite(tampered, inviteeIdentity)).rejects.toThrow();
  });

  it('rejects a completely random blob that is not an age ciphertext', async () => {
    const junk = new Uint8Array(256);
    globalThis.crypto.getRandomValues(junk);
    await expect(acceptInvite(junk, inviteeIdentity)).rejects.toThrow();
  });

  it('generates age X25519 identities and recipients', async () => {
    const id = await generateX25519Identity();
    expect(id).toMatch(/^AGE-SECRET-KEY-1/);
    const rcp = await identityToRecipient(id);
    expect(rcp).toMatch(/^age1/);
  });

  it('identityToRecipient is deterministic for a given identity', async () => {
    const id = await generateX25519Identity();
    const rcp1 = await identityToRecipient(id);
    const rcp2 = await identityToRecipient(id);
    expect(rcp1).toBe(rcp2);
  });

  it('wraps the full 32-byte payload, not just a truncated prefix', async () => {
    // Use a distinctive pattern so a truncation bug is visible.
    const pk = new Uint8Array(32);
    for (let i = 0; i < 32; i++) pk[i] = (i * 7 + 3) & 0xff;
    const wrapped = await invite(pk, inviteeRecipient);
    const recovered = await acceptInvite(wrapped, inviteeIdentity);
    expect(recovered.length).toBe(32);
    expect(Array.from(recovered)).toEqual(Array.from(pk));
  });
});
