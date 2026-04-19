// MaximumTier prototype via age scrypt recipient.
//
// Compare against chaoskb/src/crypto/tiers/maximum.ts (35 LOC):
// chaoskb derives an Argon2id KDF, then hand-rolls an AEAD over the master.
//
// age uses scrypt (not Argon2id) by spec — see §security-delta in the report
// for the trade-off. The wire format is age v1, frozen, NCC-audited (2021).
//
// Public surface (mirrors keyring §5):
//   wrapWithPassphrase(master, passphrase, opts?) -> Uint8Array
//   unwrapWithPassphrase(wrapped, passphrase)     -> Uint8Array

import { Encrypter, Decrypter } from "age-encryption";

export interface PassphraseWrapOptions {
  /** Base-2 log of the scrypt work factor. age default is 18 (~1s desktop). */
  scryptLogN?: number;
}

export async function wrapWithPassphrase(
  master: Uint8Array,
  passphrase: string,
  opts: PassphraseWrapOptions = {},
): Promise<Uint8Array> {
  if (master.length === 0) throw new Error("master must be non-empty");
  if (passphrase.length === 0) throw new Error("passphrase must be non-empty");
  const e = new Encrypter();
  if (opts.scryptLogN !== undefined) e.setScryptWorkFactor(opts.scryptLogN);
  e.setPassphrase(passphrase);
  return e.encrypt(master);
}

export async function unwrapWithPassphrase(
  wrapped: Uint8Array,
  passphrase: string,
): Promise<Uint8Array> {
  const d = new Decrypter();
  d.addPassphrase(passphrase);
  // age throws "no identity matched" on wrong passphrase; that becomes our
  // WrongPassphrase. Caller is expected to map to keyring's error hierarchy.
  return d.decrypt(wrapped);
}
