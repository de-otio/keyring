import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import type { MasterKey } from '@de-otio/crypto-envelope';
import { TofuMismatch, TofuPinFileTampered } from './errors.js';

/**
 * Trust-On-First-Use key pinning for SSH public keys (and other
 * identity-bearing pubkeys).
 *
 * ## Security fix — B6 (integrity MAC)
 *
 * The chaoskb predecessor stored pins as plaintext JSON with no
 * integrity protection. A filesystem-write attacker could silently
 * swap a pin's fingerprint. The design review flagged this as a High
 * finding for the journalist threat model where filesystem-write is
 * explicitly in scope.
 *
 * Fix: the pin file is HMAC-SHA256 authenticated under a key derived
 * from the consumer-supplied {@link MasterKey} via HKDF with
 * `info = "keyring/v1/tofu-pin-mac"`. On read, the MAC is verified
 * before any pin is trusted; a mismatch throws
 * {@link TofuPinFileTampered}. On write, a fresh MAC is computed.
 *
 * The MAC key is derived by computing
 * `HMAC-SHA256(master, "keyring/v1/tofu-pin-mac")` once per
 * `KnownKeys` instance. This is not HKDF-expand per se, but is the
 * standard "key-separation via HMAC" construction that `crypto-envelope`
 * uses for its commitment key; treating the master as the HMAC key
 * with a fixed label yields 32 bytes of output domain-separated from
 * every other use of the master.
 *
 * The integrity MAC defends against offline tamper but not against an
 * attacker who also has the master — if your master is compromised,
 * TOFU pins are the least of your problems.
 *
 * ## File format
 *
 * ```json
 * {
 *   "v": 1,
 *   "pins": { "<identifier>": { fingerprint, publicKey, source, firstSeen, verifiedAt } },
 *   "mac": "<hex HMAC-SHA256 over canonical JSON of {v, pins}>"
 * }
 * ```
 */

export interface PinnedKey {
  fingerprint: string;
  /** The original public-key representation (`ssh-ed25519 AAAA...` or
   *  similar). Stored for later re-verification. */
  publicKey: string;
  /** Source from which this pin was established: e.g. `'github:alice'`,
   *  `'direct'`, `'keybase:alice'`. */
  source: string;
  firstSeen: string;
  verifiedAt: string;
}

export type CheckPinResult = 'match' | 'mismatch' | 'new';

const FILE_VERSION = 1;
const MAC_LABEL = new TextEncoder().encode('keyring/v1/tofu-pin-mac');

export interface KnownKeysOptions {
  /** Path to the pin file. Directory is created with 0700 perms if
   *  it doesn't exist. */
  filePath: string;
  /** Master key whose HKDF-derived sub-key authenticates the pin
   *  file. Lifetime is the caller's concern — the `KnownKeys` instance
   *  reads the master once during `load()` to derive the MAC key and
   *  does not retain a reference. */
  masterKey: MasterKey;
}

/**
 * Crypto-shredding and concurrency: `KnownKeys` is a thin wrapper
 * over the pin file — each public method reads-then-writes. Not safe
 * across concurrent processes writing the same file. Single-consumer
 * use is the intended pattern.
 */
export class KnownKeys {
  private readonly filePath: string;
  private readonly macKey: Buffer;

  constructor(options: KnownKeysOptions) {
    this.filePath = options.filePath;
    this.macKey = deriveMacKey(options.masterKey);
  }

  /** Pin a new key for `identifier`, or update the `verifiedAt` on
   *  an existing matching pin. Throws {@link TofuMismatch} if the
   *  identifier is already pinned with a different fingerprint. */
  async pin(
    identifier: string,
    fingerprint: string,
    publicKey: string,
    source: string,
  ): Promise<void> {
    const store = await this.loadStore();
    const existing = store[identifier];

    if (existing) {
      if (!fingerprintsEqual(existing.fingerprint, fingerprint)) {
        throw new TofuMismatch(fingerprint, existing.firstSeen);
      }
      // Same fingerprint — just refresh verifiedAt.
      existing.verifiedAt = new Date().toISOString();
      await this.saveStore(store);
      return;
    }

    store[identifier] = {
      fingerprint,
      publicKey,
      source,
      firstSeen: new Date().toISOString(),
      verifiedAt: new Date().toISOString(),
    };
    await this.saveStore(store);
  }

  /** Retrieve a pinned key. Returns `null` for an unseen identifier. */
  async get(identifier: string): Promise<PinnedKey | null> {
    const store = await this.loadStore();
    return store[identifier] ?? null;
  }

  /** Check a fingerprint against the pin store. */
  async check(identifier: string, fingerprint: string): Promise<CheckPinResult> {
    const store = await this.loadStore();
    const existing = store[identifier];
    if (!existing) return 'new';
    return fingerprintsEqual(existing.fingerprint, fingerprint) ? 'match' : 'mismatch';
  }

  /** Update a pinned key after out-of-band verification (e.g. the user
   *  confirmed the new key on GitHub). Unlike `pin`, this deliberately
   *  replaces an existing fingerprint. */
  async update(
    identifier: string,
    fingerprint: string,
    publicKey: string,
    source: string,
  ): Promise<void> {
    const store = await this.loadStore();
    const existing = store[identifier];
    store[identifier] = {
      fingerprint,
      publicKey,
      source,
      firstSeen: existing?.firstSeen ?? new Date().toISOString(),
      verifiedAt: new Date().toISOString(),
    };
    await this.saveStore(store);
  }

  /** List all pinned identifiers. */
  async list(): Promise<string[]> {
    const store = await this.loadStore();
    return Object.keys(store);
  }

  // ── internals ────────────────────────────────────────────────────────

  private async loadStore(): Promise<Record<string, PinnedKey>> {
    let raw: string;
    try {
      raw = await readFile(this.filePath, 'utf8');
    } catch (err) {
      if (isNotFound(err)) return {};
      throw err;
    }

    let parsed: { v: number; pins: Record<string, PinnedKey>; mac: string };
    try {
      parsed = JSON.parse(raw);
    } catch (cause) {
      throw new TofuPinFileTampered('pin file is not valid JSON', { cause });
    }

    if (parsed.v !== FILE_VERSION) {
      throw new TofuPinFileTampered(`unsupported pin-file version: ${parsed.v}`);
    }
    if (typeof parsed.mac !== 'string') {
      throw new TofuPinFileTampered('pin file missing MAC');
    }

    const expected = this.computeMac(parsed.pins);
    const actual = Buffer.from(parsed.mac, 'hex');
    if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
      throw new TofuPinFileTampered(
        'pin file HMAC does not verify — the file has been tampered with or a different master was used',
      );
    }
    return parsed.pins;
  }

  private async saveStore(pins: Record<string, PinnedKey>): Promise<void> {
    const mac = this.computeMac(pins).toString('hex');
    const json = JSON.stringify({ v: FILE_VERSION, pins, mac }, null, 2);
    await mkdir(dirname(this.filePath), { recursive: true, mode: 0o700 });
    await writeFile(this.filePath, json, { encoding: 'utf8', mode: 0o600 });
  }

  private computeMac(pins: Record<string, PinnedKey>): Buffer {
    const canonical = canonicalisePins(pins);
    return createHmac('sha256', this.macKey).update(canonical).digest();
  }
}

// ── helpers ───────────────────────────────────────────────────────────

function deriveMacKey(master: MasterKey): Buffer {
  // HMAC-SHA256(master, label) — 32 bytes of key material,
  // domain-separated from every other use of the master by the label.
  return createHmac('sha256', Buffer.from(master.buffer)).update(MAC_LABEL).digest();
}

function fingerprintsEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

function canonicalisePins(pins: Record<string, PinnedKey>): Buffer {
  // Canonical JSON with sorted keys so the MAC is stable across
  // object-insertion-order variations. The fingerprints themselves are
  // already canonical strings.
  const sortedIdentifiers = Object.keys(pins).sort();
  const canonical = sortedIdentifiers.reduce<Record<string, PinnedKey>>((acc, id) => {
    const p = pins[id];
    if (p) {
      acc[id] = {
        fingerprint: p.fingerprint,
        publicKey: p.publicKey,
        source: p.source,
        firstSeen: p.firstSeen,
        verifiedAt: p.verifiedAt,
      };
    }
    return acc;
  }, {});
  return Buffer.from(JSON.stringify(canonical));
}

function isNotFound(err: unknown): boolean {
  return typeof err === 'object' && err !== null && (err as { code?: string }).code === 'ENOENT';
}

// ── SHA-256 helper re-exported for callers computing ad-hoc fingerprints ──
export function sha256Fingerprint(blob: Uint8Array): string {
  const hash = createHash('sha256').update(blob).digest();
  return `SHA256:${hash.toString('base64').replace(/=+$/, '')}`;
}
