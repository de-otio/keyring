import { SecureBuffer, asMasterKey } from '@de-otio/crypto-envelope';
import { beforeEach, describe, expect, it } from 'vitest';
import { type RemoteBlobTransport, RemoteServerStorage } from '../../src/storage/remote-server.js';
import { RecoveryKeyTier } from '../../src/tiers/recovery-key.js';
import type { WrappedKey } from '../../src/types.js';

/** In-memory RemoteBlobTransport stand-in. Records calls so we can assert the
 *  store treats the blob as opaque (never parses it). */
class FakeTransport implements RemoteBlobTransport {
  readonly blobs = new Map<string, string>();
  readonly stored: Array<{ slot: string; blob: string }> = [];

  async fetchBlob(slot: string): Promise<string | null> {
    return this.blobs.get(slot) ?? null;
  }
  async storeBlob(slot: string, blob: string): Promise<void> {
    this.stored.push({ slot, blob });
    this.blobs.set(slot, blob);
  }
  async removeBlob(slot: string): Promise<void> {
    this.blobs.delete(slot);
  }
  async listSlots(): Promise<string[]> {
    return [...this.blobs.keys()];
  }
}

function randomMasterKey() {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return asMasterKey(SecureBuffer.from(bytes));
}

describe('RemoteServerStorage', () => {
  let transport: FakeTransport;
  beforeEach(() => {
    transport = new FakeTransport();
  });

  it('defaults to recovery-key-only and node platform', () => {
    const store = new RemoteServerStorage(transport);
    expect(store.acceptedTiers).toEqual(['recovery-key']);
    expect(store.platform).toBe('node');
  });

  it('round-trips a recovery-key wrapped master through wrap → put → get → unwrap', async () => {
    const { tier, recoveryKey } = RecoveryKeyTier.generate();
    const master = randomMasterKey();
    const wrapped = await tier.wrap(master);

    const store = new RemoteServerStorage(transport);
    await store.put('keyring', wrapped);
    const got = await store.get('keyring');
    expect(got).not.toBeNull();
    if (!got) throw new Error('null');

    const recovered = await tier.unwrap(got, { kind: 'recovery-key', recoveryKey });
    expect(Buffer.from(recovered.buffer).equals(Buffer.from(master.buffer))).toBe(true);
  });

  it('stores the blob OPAQUELY — the transport receives the serialised string verbatim', async () => {
    const { tier } = RecoveryKeyTier.generate();
    const wrapped = await tier.wrap(randomMasterKey());
    const store = new RemoteServerStorage(transport);
    await store.put('keyring', wrapped);

    expect(transport.stored).toHaveLength(1);
    const blob = transport.stored[0]?.blob ?? '';
    // It's the JSON-serialised WrappedKey, not the raw envelope bytes.
    expect(JSON.parse(blob)).toMatchObject({ v: 1, tier: 'recovery-key' });
  });

  it('returns null for an absent slot', async () => {
    const store = new RemoteServerStorage(transport);
    expect(await store.get('missing')).toBeNull();
  });

  it('deletes and lists slots', async () => {
    const { tier } = RecoveryKeyTier.generate();
    const store = new RemoteServerStorage(transport);
    await store.put('a', await tier.wrap(randomMasterKey()));
    await store.put('b', await tier.wrap(randomMasterKey()));
    expect((await store.list()).sort()).toEqual(['a', 'b']);
    await store.delete('a');
    expect(await store.list()).toEqual(['b']);
  });

  it('REFUSES a low-entropy (maximum) tier by default — server-grindable guard', async () => {
    const grindable: WrappedKey = {
      v: 1,
      tier: 'maximum',
      envelope: new Uint8Array([1, 2, 3]),
      kdfParams: { algorithm: 'argon2id', t: 3, m: 65_536, p: 1, salt: new Uint8Array([0]) },
      ts: '2026-06-20T00:00:00.000Z',
    };
    const store = new RemoteServerStorage(transport);
    await expect(store.put('keyring', grindable)).rejects.toThrow(/refuses tier 'maximum'/);
    expect(transport.stored).toHaveLength(0); // never reached the transport
  });

  it('accepts other tiers only when explicitly opted in', async () => {
    const store = new RemoteServerStorage(transport, { acceptedTiers: ['maximum'] });
    const w: WrappedKey = {
      v: 1,
      tier: 'maximum',
      envelope: new Uint8Array([1]),
      kdfParams: { algorithm: 'argon2id', t: 3, m: 65_536, p: 1, salt: new Uint8Array([0]) },
      ts: '2026-06-20T00:00:00.000Z',
    };
    await expect(store.put('k', w)).resolves.toBeUndefined();
  });

  it('rejects an empty slot name', async () => {
    const { tier } = RecoveryKeyTier.generate();
    const store = new RemoteServerStorage(transport);
    await expect(store.put('', await tier.wrap(randomMasterKey()))).rejects.toThrow(/non-empty/);
    await expect(store.get('')).rejects.toThrow(/non-empty/);
  });
});
