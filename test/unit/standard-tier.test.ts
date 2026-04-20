import { generateKeyPairSync } from 'node:crypto';
import { SecureBuffer, asMasterKey } from '@de-otio/crypto-envelope';
import { describe, expect, it } from 'vitest';
import { UnlockFailed } from '../../src/errors.js';
import { StandardTier } from '../../src/tiers/standard.js';

/**
 * Tests are Node-only (sodium-native + crypto.createPrivateKey). A
 * helper generates real Ed25519 and RSA keypairs and converts them
 * into the OpenSSH public-key wire format that `parseSshPublicKey`
 * expects.
 */

function randomMasterKey() {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return asMasterKey(SecureBuffer.from(bytes));
}

function generateEd25519Pair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  // Convert to OpenSSH authorized_keys format: "ssh-ed25519 <base64> comment"
  const jwk = publicKey.export({ format: 'jwk' }) as { x: string };
  const pkBytes = Buffer.from(jwk.x.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  // SSH wire format: [4-byte len]["ssh-ed25519"][4-byte len][32 pk bytes]
  const typeBytes = Buffer.from('ssh-ed25519');
  const blob = Buffer.alloc(4 + typeBytes.length + 4 + pkBytes.length);
  blob.writeUInt32BE(typeBytes.length, 0);
  typeBytes.copy(blob, 4);
  blob.writeUInt32BE(pkBytes.length, 4 + typeBytes.length);
  pkBytes.copy(blob, 8 + typeBytes.length);
  const sshPub = `ssh-ed25519 ${blob.toString('base64')} test@localhost`;
  const privatePem = privateKey.export({ format: 'pem', type: 'pkcs8' }) as string;
  return { sshPub, privatePem };
}

function generateRsaPair(bits = 2048) {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: bits });
  const jwk = publicKey.export({ format: 'jwk' }) as { n: string; e: string };
  const n = Buffer.from(jwk.n.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  const e = Buffer.from(jwk.e.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  // SSH wire format: [len]["ssh-rsa"][len][e][len][n + optional leading 0 if high bit set]
  const typeBytes = Buffer.from('ssh-rsa');
  const nWire = n[0] !== undefined && n[0] >= 0x80 ? Buffer.concat([Buffer.from([0]), n]) : n;
  const eWire = e[0] !== undefined && e[0] >= 0x80 ? Buffer.concat([Buffer.from([0]), e]) : e;
  const blob = Buffer.alloc(4 + typeBytes.length + 4 + eWire.length + 4 + nWire.length);
  let pos = 0;
  blob.writeUInt32BE(typeBytes.length, pos);
  pos += 4;
  typeBytes.copy(blob, pos);
  pos += typeBytes.length;
  blob.writeUInt32BE(eWire.length, pos);
  pos += 4;
  eWire.copy(blob, pos);
  pos += eWire.length;
  blob.writeUInt32BE(nWire.length, pos);
  pos += 4;
  nWire.copy(blob, pos);
  const sshPub = `ssh-rsa ${blob.toString('base64')} rsa-test@localhost`;
  const privatePem = privateKey.export({ format: 'pem', type: 'pkcs8' }) as string;
  return { sshPub, privatePem };
}

describe('StandardTier — Ed25519 path', () => {
  it('round-trips wrap + unwrap', async () => {
    const { sshPub, privatePem } = generateEd25519Pair();
    const tier = StandardTier.fromSshKey(sshPub);
    const master = randomMasterKey();
    const wrapped = await tier.wrap(master);
    expect(wrapped.tier).toBe('standard');
    expect(wrapped.sshFingerprint).toMatch(/^SHA256:/);

    const recovered = await tier.unwrap(wrapped, { kind: 'ssh-key', privateKeyPem: privatePem });
    expect(Buffer.from(recovered.buffer).equals(Buffer.from(master.buffer))).toBe(true);
  });

  it('rejects an envelope wrapped to a different public key', async () => {
    const a = generateEd25519Pair();
    const b = generateEd25519Pair();
    const tier = StandardTier.fromSshKey(a.sshPub);
    const wrapped = await tier.wrap(randomMasterKey());
    // Try to unwrap with b's private key — sealed-box open fails.
    await expect(
      tier.unwrap(wrapped, { kind: 'ssh-key', privateKeyPem: b.privatePem }),
    ).rejects.toBeInstanceOf(UnlockFailed);
  });

  it('rejects unwrap with wrong input.kind', async () => {
    const { sshPub } = generateEd25519Pair();
    const tier = StandardTier.fromSshKey(sshPub);
    const wrapped = await tier.wrap(randomMasterKey());
    await expect(tier.unwrap(wrapped, { kind: 'passphrase', passphrase: 'x' })).rejects.toThrow(
      /ssh-key/,
    );
  });
});

describe('StandardTier — RSA path (with B2 AAD fix)', () => {
  // RSA-OAEP decrypt is slow; raise per-suite timeout modestly.
  it('round-trips wrap + unwrap', { timeout: 15_000 }, async () => {
    const { sshPub, privatePem } = generateRsaPair();
    const tier = StandardTier.fromSshKey(sshPub);
    const master = randomMasterKey();
    const wrapped = await tier.wrap(master);
    expect(wrapped.tier).toBe('standard');
    expect(wrapped.sshFingerprint).toMatch(/^SHA256:/);

    const recovered = await tier.unwrap(wrapped, { kind: 'ssh-key', privateKeyPem: privatePem });
    expect(Buffer.from(recovered.buffer).equals(Buffer.from(master.buffer))).toBe(true);
  });

  it('rejects an envelope wrapped to a different RSA public key', { timeout: 60_000 }, async () => {
    const a = generateRsaPair();
    const b = generateRsaPair();
    const tier = StandardTier.fromSshKey(a.sshPub);
    const wrapped = await tier.wrap(randomMasterKey());
    await expect(
      tier.unwrap(wrapped, { kind: 'ssh-key', privateKeyPem: b.privatePem }),
    ).rejects.toBeInstanceOf(UnlockFailed);
  });

  it(
    'B2 fix: envelope AAD binds fingerprint — tampering sshFingerprint fails decrypt',
    { timeout: 15_000 },
    async () => {
      const { sshPub, privatePem } = generateRsaPair();
      const tier = StandardTier.fromSshKey(sshPub);
      const wrapped = await tier.wrap(randomMasterKey());
      // Tamper: flip the stored fingerprint. The envelope-client's AAD
      // binds it into `kid`; AAD mismatch at decrypt time → UnlockFailed.
      const tampered = { ...wrapped, sshFingerprint: 'SHA256:attackerforged' };
      await expect(
        tier.unwrap(tampered, { kind: 'ssh-key', privateKeyPem: privatePem }),
      ).rejects.toBeInstanceOf(UnlockFailed);
    },
  );

  it('rejects under-2048-bit RSA keys', { timeout: 15_000 }, async () => {
    const { sshPub } = generateRsaPair(1024);
    const tier = StandardTier.fromSshKey(sshPub);
    await expect(tier.wrap(randomMasterKey())).rejects.toThrow(/too small|2048/);
  });
});
