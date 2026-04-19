import { describe, expect, it } from 'vitest';
import { InMemoryStorage } from '../../src/storage/in-memory.js';
import type { WrappedKey } from '../../src/types.js';

function wrappedFixture(tier: 'standard' | 'maximum' = 'maximum'): WrappedKey {
  return {
    v: 1,
    tier,
    envelope: new Uint8Array([1, 2, 3]),
    ts: new Date().toISOString(),
  };
}

describe('InMemoryStorage', () => {
  it('round-trips put + get', async () => {
    const s = new InMemoryStorage();
    const w = wrappedFixture();
    await s.put('slot1', w);
    expect(await s.get('slot1')).toEqual(w);
  });

  it('returns null for a missing slot', async () => {
    const s = new InMemoryStorage();
    expect(await s.get('nope')).toBeNull();
  });

  it('overwrites on second put', async () => {
    const s = new InMemoryStorage();
    await s.put('slot1', wrappedFixture('standard'));
    await s.put('slot1', wrappedFixture('maximum'));
    const got = await s.get('slot1');
    expect(got?.tier).toBe('maximum');
  });

  it('deletes existing slots', async () => {
    const s = new InMemoryStorage();
    await s.put('slot1', wrappedFixture());
    await s.delete('slot1');
    expect(await s.get('slot1')).toBeNull();
  });

  it('delete on a missing slot is a no-op (idempotent)', async () => {
    const s = new InMemoryStorage();
    await expect(s.delete('nope')).resolves.not.toThrow();
  });

  it('list returns all slot names', async () => {
    const s = new InMemoryStorage();
    await s.put('a', wrappedFixture());
    await s.put('b', wrappedFixture());
    const names = await s.list();
    expect(names.sort()).toEqual(['a', 'b']);
  });

  it('list is empty on an empty storage', async () => {
    const s = new InMemoryStorage();
    expect(await s.list()).toEqual([]);
  });

  it('default acceptedTiers includes both standard and maximum', () => {
    const s = new InMemoryStorage();
    expect([...s.acceptedTiers].sort()).toEqual(['maximum', 'standard']);
  });

  it('restricts acceptedTiers when narrowed', () => {
    const s = new InMemoryStorage<'standard'>({ acceptedTiers: ['standard'] });
    expect([...s.acceptedTiers]).toEqual(['standard']);
  });

  it('clear() wipes all slots', async () => {
    const s = new InMemoryStorage();
    await s.put('a', wrappedFixture());
    await s.put('b', wrappedFixture());
    s.clear();
    expect(await s.list()).toEqual([]);
  });
});
