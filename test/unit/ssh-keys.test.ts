import { describe, expect, it } from 'vitest';
import { UnsupportedSshKeyType } from '../../src/errors.js';
import {
  ed25519ToX25519PublicKey,
  ed25519ToX25519SecretKey,
  parseSshPublicKey,
  sshFingerprint,
} from '../../src/ssh/keys.js';

/**
 * Error-path coverage for SSH key parsing. The happy-path tests live in
 * `standard-tier.test.ts` which exercises the full pipeline with real
 * keys.
 */

describe('parseSshPublicKey — error paths', () => {
  it('rejects strings with too few parts', () => {
    expect(() => parseSshPublicKey('ssh-ed25519')).toThrow(/invalid SSH public key format/);
    expect(() => parseSshPublicKey('')).toThrow();
  });

  it('rejects ECDSA keys with UnsupportedSshKeyType', () => {
    expect(() => parseSshPublicKey('ecdsa-sha2-nistp256 AAAAE2VjZHNh xxx')).toThrow(
      UnsupportedSshKeyType,
    );
    expect(() => parseSshPublicKey('ssh-dss AAAA')).toThrow(UnsupportedSshKeyType);
  });

  it('rejects truncated SSH blobs', () => {
    // Valid base64 of just 2 bytes — too short for any meaningful wire format.
    expect(() => parseSshPublicKey('ssh-ed25519 AAE=')).toThrow(/unexpected end of data/);
  });

  it('rejects blobs where the wire-format type mismatches the declared type', () => {
    // Build an ssh-ed25519 LINE but put ssh-rsa type field INSIDE the blob.
    const typeField = Buffer.from('ssh-rsa');
    const blob = Buffer.alloc(4 + typeField.length);
    blob.writeUInt32BE(typeField.length, 0);
    typeField.copy(blob, 4);
    expect(() => parseSshPublicKey(`ssh-ed25519 ${blob.toString('base64')}`)).toThrow(
      /SSH key type mismatch/,
    );
  });

  it('rejects Ed25519 blobs with wrong public-key length', () => {
    const typeField = Buffer.from('ssh-ed25519');
    // 16-byte "pubkey" instead of 32.
    const pk = Buffer.alloc(16).fill(0xaa);
    const blob = Buffer.alloc(4 + typeField.length + 4 + pk.length);
    let pos = 0;
    blob.writeUInt32BE(typeField.length, pos);
    pos += 4;
    typeField.copy(blob, pos);
    pos += typeField.length;
    blob.writeUInt32BE(pk.length, pos);
    pos += 4;
    pk.copy(blob, pos);
    expect(() => parseSshPublicKey(`ssh-ed25519 ${blob.toString('base64')}`)).toThrow(
      /must be 32 bytes/,
    );
  });

  it('accepts a public key with a comment field', () => {
    // Parse a valid ed25519 key with comment. Uses the same wire-format
    // construction as the main StandardTier tests.
    const { generateKeyPairSync } = require('node:crypto') as typeof import('node:crypto');
    const { publicKey } = generateKeyPairSync('ed25519');
    const jwk = publicKey.export({ format: 'jwk' }) as { x: string };
    const pkBytes = Buffer.from(jwk.x.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
    const typeBytes = Buffer.from('ssh-ed25519');
    const blob = Buffer.alloc(4 + typeBytes.length + 4 + pkBytes.length);
    blob.writeUInt32BE(typeBytes.length, 0);
    typeBytes.copy(blob, 4);
    blob.writeUInt32BE(pkBytes.length, 4 + typeBytes.length);
    pkBytes.copy(blob, 8 + typeBytes.length);

    const parsed = parseSshPublicKey(
      `ssh-ed25519 ${blob.toString('base64')} alice@example.com hostname`,
    );
    expect(parsed.comment).toBe('alice@example.com hostname');
    expect(parsed.fingerprint).toMatch(/^SHA256:/);
  });
});

describe('sshFingerprint', () => {
  it('produces stable SHA256:<base64> format', () => {
    const blob = Buffer.from('any input');
    expect(sshFingerprint(blob)).toMatch(/^SHA256:[A-Za-z0-9+/]+$/);
    // No trailing '=' padding.
    expect(sshFingerprint(blob)).not.toMatch(/=/);
  });

  it('is deterministic', () => {
    const blob = new Uint8Array([1, 2, 3, 4]);
    expect(sshFingerprint(blob)).toBe(sshFingerprint(blob));
  });

  it('differs for different inputs', () => {
    expect(sshFingerprint(new Uint8Array([1]))).not.toBe(sshFingerprint(new Uint8Array([2])));
  });
});

describe('ed25519ToX25519 conversions — validation', () => {
  it('rejects wrong-length Ed25519 public keys', () => {
    expect(() => ed25519ToX25519PublicKey(new Uint8Array(16))).toThrow(/32 bytes/);
    expect(() => ed25519ToX25519PublicKey(new Uint8Array(64))).toThrow(/32 bytes/);
  });

  it('rejects wrong-length Ed25519 secret keys', () => {
    expect(() => ed25519ToX25519SecretKey(new Uint8Array(32))).toThrow(/64 bytes/);
    expect(() => ed25519ToX25519SecretKey(new Uint8Array(128))).toThrow(/64 bytes/);
  });

  it('returns a SecureBuffer that can be disposed (B5 fix)', () => {
    // Real Ed25519 secrets would be generated from a private key; here
    // we just feed 64 zero bytes. libsodium accepts any 64-byte input.
    const sk = new Uint8Array(64);
    const buf = ed25519ToX25519SecretKey(sk);
    expect(buf.length).toBe(32);
    expect(buf.isDisposed).toBe(false);
    buf.dispose();
    expect(buf.isDisposed).toBe(true);
  });
});
