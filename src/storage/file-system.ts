import { mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';
import type { KeyStorage, TierKind, WrappedKey } from '../types.js';
import { deserializeWrappedKey, serializeWrappedKey } from './wrapped-key-codec.js';

/**
 * Filesystem-backed `KeyStorage`. One file per slot under a configured
 * root directory; contents are the {@link WrappedKey} serialised as JSON
 * with binary fields base64-encoded.
 *
 * ## Security posture
 *
 * - Files are written with mode `0o600` (user read/write only). The
 *   root directory is created with mode `0o700` if it doesn't exist.
 *   This does not protect against an attacker who gains the user's
 *   filesystem privileges; for that, use `OsKeychainStorage` (Phase D).
 * - **No overwrite-before-unlink on delete.** `fs.unlink` removes the
 *   directory entry; the block contents persist until the filesystem
 *   reuses them. On ext4, APFS, and most journaling filesystems there is
 *   no portable way to force secure erasure from userspace. Consumers
 *   needing sanitary deletion should `shred` / `srm` / `secure-erase`
 *   around the delete, or use full-disk encryption (FileVault, LUKS).
 * - Slot names are validated (`[A-Za-z0-9._-]+`, ≤128 chars) to keep
 *   path-traversal attacks and filesystem-illegal characters out. Slot
 *   names are filenames with no extension.
 *
 * ## Crypto-shredding (GDPR Art. 17)
 *
 * `delete(slot)` is the Art. 17 erasure affordance at this layer. Honest
 * framing: erasure is satisfied at the envelope layer (once the wrapped
 * master is gone and its unlock secret is unrecoverable, the envelopes
 * it sealed are permanently unreadable). Bytes persisting in free blocks
 * are cryptographically useless without the master.
 */
export class FileSystemStorage<K extends TierKind = TierKind> implements KeyStorage<K> {
  readonly platform: 'node' | 'browser' | 'webext' = 'node';
  readonly acceptedTiers: readonly K[];
  private readonly root: string;

  constructor(options: { root: string; acceptedTiers?: readonly K[] }) {
    this.root = options.root;
    this.acceptedTiers =
      options.acceptedTiers ?? (['standard', 'maximum'] as unknown as readonly K[]);
  }

  async put(slot: string, wrapped: WrappedKey): Promise<void> {
    assertValidSlotName(slot);
    await ensureDir(this.root);
    const path = this.slotPath(slot);
    const json = serializeWrappedKey(wrapped);
    await writeFile(path, json, { encoding: 'utf8', mode: 0o600 });
  }

  async get(slot: string): Promise<WrappedKey | null> {
    assertValidSlotName(slot);
    try {
      const json = await readFile(this.slotPath(slot), 'utf8');
      return deserializeWrappedKey(json);
    } catch (err) {
      if (isNotFound(err)) return null;
      throw err;
    }
  }

  async delete(slot: string): Promise<void> {
    assertValidSlotName(slot);
    await rm(this.slotPath(slot), { force: true });
  }

  async list(): Promise<string[]> {
    try {
      const entries = await readdir(this.root);
      return entries.filter(isValidSlotFilename).map((n) => basename(n));
    } catch (err) {
      if (isNotFound(err)) return [];
      throw err;
    }
  }

  private slotPath(slot: string): string {
    return join(this.root, slot);
  }
}

// ── slot-name validation ───────────────────────────────────────────────

const SLOT_NAME_PATTERN = /^[A-Za-z0-9._-]{1,128}$/;

function assertValidSlotName(slot: string): void {
  if (!SLOT_NAME_PATTERN.test(slot) || slot === '.' || slot === '..') {
    throw new Error(
      `invalid slot name '${slot}': must match ${SLOT_NAME_PATTERN} (letters, digits, '.', '_', '-'; 1–128 chars; not '.' or '..')`,
    );
  }
}

function isValidSlotFilename(name: string): boolean {
  return SLOT_NAME_PATTERN.test(name) && name !== '.' && name !== '..';
}

// ── fs helpers ─────────────────────────────────────────────────────────

async function ensureDir(path: string): Promise<void> {
  await mkdir(path, { recursive: true, mode: 0o700 });
  // Defensive: if the dir already existed with laxer perms, tighten
  // only on create. `mkdir` returns the first-segment path created or
  // undefined if nothing was created, so a pre-existing directory
  // retains its permissions — document this rather than silently
  // changing perms under a shared install.
  void dirname(path);
}

function isNotFound(err: unknown): boolean {
  return typeof err === 'object' && err !== null && (err as { code?: string }).code === 'ENOENT';
}
