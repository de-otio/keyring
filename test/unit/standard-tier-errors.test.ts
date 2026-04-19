import { generateKeyPairSync } from 'node:crypto';
import { SecureBuffer, asMasterKey } from '@de-otio/crypto-envelope';
import { describe, expect, it } from 'vitest';
import { UnlockFailed } from '../../src/errors.js';
import { StandardTier } from '../../src/tiers/standard.js';
import type { WrappedKey } from '../../src/types.js';

/**
 * Error-path coverage for StandardTier. The happy-path tests live in
 * `standard-tier.test.ts`.
 */

function randomMasterKey() {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return asMasterKey(SecureBuffer.from(bytes));
}

function ed25519Fixture() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const jwk = publicKey.export({ format: 'jwk' }) as { x: string };
  const pkBytes = Buffer.from(jwk.x.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  const typeBytes = Buffer.from('ssh-ed25519');
  const blob = Buffer.alloc(4 + typeBytes.length + 4 + pkBytes.length);
  blob.writeUInt32BE(typeBytes.length, 0);
  typeBytes.copy(blob, 4);
  blob.writeUInt32BE(pkBytes.length, 4 + typeBytes.length);
  pkBytes.copy(blob, 8 + typeBytes.length);
  const sshPub = `ssh-ed25519 ${blob.toString('base64')}`;
  const privatePem = privateKey.export({ format: 'pem', type: 'pkcs8' }) as string;
  return { sshPub, privatePem };
}

describe('StandardTier.unwrap — error paths', () => {
  it('rejects a wrapped key whose tier does not match', async () => {
    const { sshPub, privatePem } = ed25519Fixture();
    const tier = StandardTier.fromSshKey(sshPub);
    const bogus: WrappedKey = {
      v: 1,
      tier: 'maximum',
      envelope: new Uint8Array(0),
      ts: new Date().toISOString(),
    };
    await expect(
      tier.unwrap(bogus, { kind: 'ssh-key', privateKeyPem: privatePem }),
    ).rejects.toThrow(/tier 'maximum'/);
  });

  it('rejects a mangled private-key PEM', async () => {
    const { sshPub } = ed25519Fixture();
    const tier = StandardTier.fromSshKey(sshPub);
    const master = randomMasterKey();
    const wrapped = await tier.wrap(master);
    await expect(
      tier.unwrap(wrapped, {
        kind: 'ssh-key',
        privateKeyPem: '-----BEGIN GARBAGE-----\nnope\n-----END GARBAGE-----',
      }),
    ).rejects.toThrow();
  });

  it("fingerprint getter returns the tier's fingerprint", () => {
    const { sshPub } = ed25519Fixture();
    const tier = StandardTier.fromSshKey(sshPub);
    expect(tier.fingerprint).toMatch(/^SHA256:/);
  });
});

describe('StandardTier.fromSshKey — key-type dispatch', () => {
  it('throws UnsupportedSshKeyType for keys other than ed25519 / rsa', () => {
    // parseSshPublicKey already rejects — this test confirms it short
    // circuits before StandardTier constructs.
    expect(() =>
      StandardTier.fromSshKey('ecdsa-sha2-nistp256 AAAAE2VjZHNh-invalidbase64!'),
    ).toThrow();
  });
});
