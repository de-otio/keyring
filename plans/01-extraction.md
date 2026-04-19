# v0.1 Keyring Plan

Create `@de-otio/keyring` — the key-lifecycle layer that sits on top of `@de-otio/crypto-envelope`. Extract chaoskb's `src/crypto/tiers/`, `ssh-*.ts`, `project-keys.ts`, `known-keys.ts`, `invite.ts` into the new package (fixing two Critical security findings en route), replace chaoskb's OS-keychain shell-out with `@napi-rs/keyring`, add browser storage backends (MV3 extensions + IndexedDB), and give both consumers (chaoskb + trellis) a single key-management surface with resumable rotation.

Target: `@de-otio/keyring@0.1.0-alpha.1`. Internal consumers only until chaoskb and trellis each ship a production release against it (same gate as [crypto-envelope plan-01 §8](../../crypto-envelope/plans/01-extraction.md#8-wire-format-and-stability-commitment)).

This plan integrates the findings of [tmp/design-review/](../tmp/design-review/). Blockers are folded into the plan text; should-fix and nit items are marked in-line or moved to §10 risk register.

## 1. Why this package exists now

[crypto-envelope plan-01 §9](../../crypto-envelope/plans/01-extraction.md#9-out-of-scope-for-v01) stubbed `@de-otio/keyring` as a follow-up. Two things have since changed:

- **Chaoskb is adding a browser plugin** (and eventually a browser UI). The tier model currently lives in chaoskb's Node-only `src/crypto/tiers/` — reusing it in-browser means either shipping it twice or extracting it now.
- **crypto-envelope v0.2** ([plan-02](../../crypto-envelope/plans/02-trellis-widening.md)) adds AES-GCM with a hard 2³² per-key message cap. Consumers hitting the cap need a rekey path. crypto-envelope's scope stops at `rewrapEnvelope(oldEnvelope, oldMaster, newMaster)` — the primitive; orchestrating a full rotation across every blob for a master is keyring's job.

The scope boundary:

- **crypto-envelope** owns: AEAD, HKDF, Argon2id/PBKDF2, canonical JSON, envelope v1/v2, `SecureBuffer`, `rewrapEnvelope` primitive.
- **keyring** owns: tier model (how a master key is *wrapped* for storage), storage backends (OS keychain via `@napi-rs/keyring`, WebExtension storage, IndexedDB, filesystem), SSH-key interop, TOFU pinning, project-key wrapping, rotation orchestration, optional audit-event sink.
- **chaoskb / trellis** own: their own application storage (what envelopes live where), product-specific flows (device linking, sync, voting, ActivityPub signatures), UI.

## 2. Pre-Phase-A gate — age-delegation spike: **COMPLETE, HYBRID**

Spike ran 2026-04-18. Report: [plans/03-age-spike-report.md](./03-age-spike-report.md).

**Library assessment.** `age-encryption@0.3.0` (Filippo Valsorda / FiloSottile, BSD-3, Dec 2025, noble-only deps, npm SLSA provenance) is the only viable maintained TS/JS port of age in 2026. Acceptable as a runtime dep — ESM-only, noble-based, browser-clean, matches keyring's dependency policy.

**Recommendation: HYBRID.** Adopt age for some surfaces, port custom code for others. Decision disposition per component:

| Component | Disposition | Rationale |
|---|---|---|
| **Invite** (`invite.ts`) | **DELEGATE to age X25519 recipient** | 61% SLOC win (172 → ~40 LOC wiring); eliminates B4 (small-order check) and the previously-unflagged invite empty-AAD bug for free via age's header MAC; X25519 recipient is the most exercised path in `age-encryption`. |
| **MaximumTier** (`tiers/maximum.ts`) | **PORT custom code, Argon2id** | Adopting age means Argon2id → scrypt regression. CLAUDE.md Priority 4 (safe defaults) rejects the downgrade. LOC delta is negative anyway (spike is larger). Revisit in v0.2 if `age-encryption` adds an Argon2id recipient. |
| **StandardTier** (`tiers/standard.ts` + SSH keys/agent) | **PORT custom code, Ed25519 + RSA** | `age-encryption@0.3.0` does **not** ship an SSH recipient. Options were (a) implement a custom age-wire-compat `SshRecipient` (~150 LOC of new framing that doesn't exist anywhere else on npm) or (b) convert the SSH pubkey to an age X25519 recipient at the boundary (wire-incompatible with `age -R` from the CLI). Neither is better than the port; the B2 AAD fix in Phase C closes the security finding directly. |
| **TOFU** (`known-keys.ts`) | **PORT custom code with B6 MAC fix** | Spike proposed delegating to OpenSSH `known_hosts` format, but that format has no integrity protection either — B6 (filesystem-write attacker) is not resolved by format reuse. Browsers also have no `known_hosts`-equivalent; a separate code path per platform adds complexity. Staying custom with the HMAC-SHA256 MAC (HKDF-derived from master via `info: "keyring/v1/tofu-pin-mac"`) is simpler and browser-parity-correct. v0.2 can add a `known_hosts` import/export bridge for Node power users. |

**LOC delta:** plan's ~1,080 LOC of runtime port drops to ~830 LOC (~23% reduction). The win is concentrated in `invite.ts` (172 → ~40 LOC) with a smaller contribution from TOFU-still-custom-but-simpler. Phase C (SSH) and Phase B (passphrase) are unaffected by the HYBRID decision — §3's plan text stands.

**Migration path (Phase H):** chaoskb's existing wrapped masters use chaoskb-specific wire formats (`crypto_box_seal` for Ed25519, RSA-OAEP KEM+DEM for RSA, custom Argon2id framing, custom invite ECDH) that are not age-decryptable. ~250 LOC of legacy decoders land in `src/legacy/` for the one-time decrypt-and-rewrap pass on first unlock. Deletable in v0.2 once no legacy wrappings remain.

**Trigger for revisiting:** if `age-encryption` ships a native SSH recipient before Phase C starts, flip StandardTier to ADOPT (meaningful product feature: power users can `age -d` keyring-wrapped masters from the Go CLI). If it adds an Argon2id recipient, flip MaximumTier.

**New runtime dep:** `age-encryption@^0.3.0` as a peer dep — joins `@de-otio/crypto-envelope` on the peer-dep list so consumers control the version. Rationale: age's wire format evolves slowly but independently of keyring; giving consumers version control avoids keyring-driven bumps.

## 3. Files moving in from chaoskb

From `/Users/rmyers/repos/dot/chaoskb/src/crypto/`:

| chaoskb file | new location | LOC | notes |
|---|---|---|---|
| `tiers/standard.ts` | `src/tiers/standard.ts` | 215 | **Fix [B2]**: the RSA-OAEP KEM+DEM master wrap currently uses empty AAD (`standard.ts:99,149-150`). Port under non-empty AAD binding SSH fingerprint + `"keyring/v1/standard/rsa-kemdem"` + envelope version. Old vectors become migration-only. **(age-if-adopted: replaced by `age` SSH recipient wiring)** |
| `tiers/maximum.ts` | `src/tiers/maximum.ts` | 35 | Argon2id passphrase → master. **(age-if-adopted: replaced by `age` scrypt recipient)** |
| `tiers/enhanced.ts` | — | 68 | **Dropped.** Deprecated in chaoskb (BIP39 mnemonic). |
| `ssh-keys.ts` | `src/ssh/keys.ts` | 136 | `sshpk`-based parsing for Ed25519 + RSA. **Plan-text fix:** v0.1 is Ed25519 + RSA **only** (chaoskb's code rejects ECDSA; ECDSA is v0.2 scope). **Fix [B5]**: `ed25519ToX25519SecretKey` returns `SecureBuffer`, not plain `Uint8Array`; all callers dispose. |
| `ssh-agent.ts` | `src/ssh/agent.ts` | 272 | ssh-agent socket IPC (Node-only). Port test harness from chaoskb alongside the code. PKCS#1 v1.5 padding stays for agent protocol interop. |
| `project-keys.ts` | `src/project-keys.ts` | 100 | Per-project master wrapped by personal master. **Fix [S1]**: HKDF info must include the project name; today it's a static constant shared across all projects for a given master. |
| `invite.ts` | `src/invite.ts` | 172 → **~40** | **DELEGATED to `age-encryption` X25519 recipient per §2 HYBRID.** Keyring exposes `invite(projectKey, inviteePubKey): Promise<Uint8Array>` and `acceptInvite(wrapped, myIdentity): Promise<MasterKey>` — both are thin wrappers over age's `Encrypter.encrypt` / `Decrypter.decrypt`. Age's header MAC eliminates B4 (small-order check) and the previously-unflagged invite empty-AAD finding for free. Threat-model spec-out: `ChallengeStore` interface is still required (age doesn't manage challenge state) — see §15. |
| `known-keys.ts` | `src/known-keys.ts` | 150 | TOFU pinning. **Fix [B6] mandatory:** MAC the pin file with an HKDF-derived key (`info: "keyring/v1/tofu-pin-mac"`) and verify before use. Browsers have no `known_hosts`-equivalent; staying custom is simpler and browser-parity-correct. v0.2 can add a `known_hosts` import/export bridge for Node power users. |
| `keyring.ts` | **DELETED** | (243) | **Not ported.** The shell-out OS-keychain code carries a Critical **Windows PowerShell-injection RCE** (`keyring.ts:184-192`: hex secret splatted into `ConvertTo-SecureString` / `cmdkey /pass:...`) and a High **macOS `security -w` leak via `ps`** (`storeMacOS`). Neither is fixed by porting. Replace with `@napi-rs/keyring` wiring (see §5 below). |

**~830 LOC** of ported runtime code (HYBRID per §2) plus ~250 LOC of legacy decoders in `src/legacy/` for Phase H migration. Down from the pre-review 1,323 LOC via: `keyring.ts` deleted (→ `@napi-rs/keyring`); `invite.ts` shrunk 172 → ~40 LOC (→ age X25519).

**Interop gate (Phase H):** every existing on-disk chaoskb wrapped-master must decrypt byte-identically under the new package. Strategy:
1. Generate fixture vectors from current chaoskb (Ed25519 wrap, RSA wrap, Argon2id-passphrase wrap) → commit under `test/vectors/chaoskb-interop/`.
2. Run chaoskb's full test suite against the new package in CI.

Both gates must be green before Phase H merges. See §13 testing strategy.

## 4. Scope additions (new to keyring)

### 4.1 Browser storage backends

- `WebExtensionStorage` — MV3 `chrome.storage.local` / `chrome.storage.session` (constructor option). `local` is the default for wrapped masters; `session` is memory-only, cleared on browser close. **Warning in docs:** `chrome.storage.local` is **plaintext on disk** — profile-level attacker or malware reads it directly. The tier's wrap is the only protection.
- `IndexedDbStorage` — non-extension browser pages (trellis). Accessible to every same-origin XSS. **Documented:** Standard-tier wrapped keys in IndexedDB *are* XSS-reachable; CSP hardening is the consumer's responsibility.
- `InMemoryStorage` — tests, short-lived tabs.

Both browser backends **refuse MaximumTier storage at compile time** via capability typing (see §5 `Storage<T>`). Passphrase-derived masters must not land in WebExtension/IndexedDB storage.

### 4.2 Rotation orchestration (resumable + backpressured)

The Q2 answer from [crypto-envelope plan-02 review](../../crypto-envelope/tmp/design-review/05-open-questions.md#q2):

```ts
interface BlobEnumerator {
  /** Required ordering guarantee; 'arbitrary' disables resume. */
  readonly ordering: 'stable' | 'arbitrary';
  /** Yield every envelope that should be rewrapped. */
  enumerate(options?: { startAfter?: string; signal?: AbortSignal }): AsyncIterable<AnyEnvelope>;
  /** Consumer persists the rewrapped envelope. Idempotent-preferred. */
  persist(updated: AnyEnvelope, signal?: AbortSignal): Promise<void>;
}

export interface RotationResult {
  rotated: number;
  skipped: number;                  // already on new master (idempotent re-run)
  failed: Array<{ id: string; error: Error; retriable: boolean }>;
  lastPersistedId: string | null;   // resume cursor
  oldMasterStillRequired: boolean;  // true if failed.length > 0 or signal aborted
}

async function rotate(
  newTier: Tier,
  enumerator: BlobEnumerator,
  options?: {
    batchSize?: number;             // default 8, bounds concurrency
    startAfter?: string;            // resume cursor from previous call
    signal?: AbortSignal;
  },
): Promise<RotationResult>;
```

Contract:

- **Resumable.** On interrupt (`signal`, `persist` error, process crash), the caller persists `lastPersistedId` and re-invokes `rotate` with `startAfter: lastPersistedId`. The library skips already-rewrapped envelopes (detected by matching the envelope's commitment against the new master's commit key — a no-op rewrap, not a re-decrypt).
- **Backpressured.** Bounded concurrency via `batchSize`-sized semaphore. Library never holds more than `batchSize` unpersisted rewrapped envelopes in memory.
- **Old-master retention.** `KeyRing.rotate` holds a reference that blocks old-master retirement until the returned promise resolves. If `failed.length > 0` or `signal` aborts, `oldMasterStillRequired: true` — consumer must preserve the old wrapped master for retry.
- **AbortSignal propagation.** Checked between each `rewrapEnvelope` call; passed to `enumerate()` and `persist()` if they accept one. Partial-state guarantee on abort: `rotated` count is accurate; old master still usable.
- **`persist` failure policy.** Rejection is added to `failed[]`; rotation continues. Library does not retry; consumer's `persist` should be idempotent. Signal-triggered abort propagates as a thrown `AbortError`, not a resolved result.
- **MV3 service-worker warning.** `rotate` is **not safe in an MV3 service worker** (30s-idle termination mid-flight). Browser-extension consumers drive rotation from an extension page. A future `rotateBatch(cursor, n)` primitive could unblock worker-driven rotation; not in v0.1.
- **Event emission.** `ring.events` (see §5) emits `{ kind: 'blob-rewrapped', id, index, total }` for UX progress bars.

### 4.3 Optional audit-event sink

For consumers implementing SOC 2 CC6.1 / CC7.2 controls:

```ts
interface EventSink {
  emit(event: KeyRingEvent): void;
}
type KeyRingEvent =
  | { kind: 'unlock'|'lock'|'rotate-start'|'rotate-complete'|'create-project'|'delete'|'blob-rewrapped'|'soft-threshold'|'hard-threshold'; ... };
```

Keyring emits; consumer persists (where, in what format, with what retention — all consumer-owned).

## 5. Core interfaces

```ts
// Tier = how a master is wrapped for storage
export type TierKind = 'standard' | 'maximum';
export interface Tier<K extends TierKind = TierKind> {
  readonly kind: K;
  wrap(master: MasterKey): Promise<WrappedKey>;
  unwrap(wrapped: WrappedKey, input: UnlockInput): Promise<MasterKey>;
}

// Storage = where wrapped keys live; generic in tier set for compile-time safety
export interface KeyStorage<K extends TierKind = TierKind> {
  readonly platform: 'node' | 'browser' | 'webext';
  put(slot: string, wrapped: WrappedKey): Promise<void>;
  get(slot: string): Promise<WrappedKey | null>;
  delete(slot: string): Promise<void>;    // GDPR Art.17 affordance; see §8
  list(): Promise<string[]>;
}
// Browsers can only store Standard:
export class WebExtensionStorage implements KeyStorage<'standard'> { ... }
export class IndexedDbStorage implements KeyStorage<'standard'> { ... }
// Node backends accept any tier:
export class OsKeychainStorage implements KeyStorage { ... }  // via @napi-rs/keyring
export class FileSystemStorage implements KeyStorage { ... }
export class InMemoryStorage implements KeyStorage { ... }

// High-level client, generic in tier kind
export class KeyRing<K extends TierKind = TierKind> {
  constructor(options: {
    tier: Tier<K>;
    storage: KeyStorage<K>;          // mismatch is a compile-time error
    insecureMemory?: boolean;        // acknowledge non-mlock browser posture; throws at construction if omitted in browser without hardware-backed store
    events?: EventSink;
    rotationPolicy?: {
      softThreshold: number;         // e.g. 2**24
      hardThreshold: number;         // e.g. 2**31
    };
  });

  // No throwing getter. Two safe forms:
  async withMaster<T>(fn: (m: MasterKey) => Promise<T>): Promise<T>;  // scoped, auto-relocks at end
  tryGetMaster(): MasterKey | null;

  async unlock(input: UnlockInput): Promise<void>;
  async lock(): Promise<void>;

  // Sugar factories (the discoverable surface):
  async unlockWithPassphrase(p: string): Promise<void>;
  async unlockWithSshAgent(): Promise<void>;
  async unlockWithSshKey(pem: string, passphrase?: string): Promise<void>;

  async createProjectKey(name: string): Promise<MasterKey>;
  async getProjectKey(name: string): Promise<MasterKey>;          // throws ProjectKeyNotFound
  async tryGetProjectKey(name: string): Promise<MasterKey | null>;
  async listProjectKeys(): Promise<string[]>;

  async rotate(newTier: Tier<K>, enumerator: BlobEnumerator, options?: RotateOptions): Promise<RotationResult>;

  // Observability: threshold events, lifecycle events, rotation progress
  events(options?: { signal?: AbortSignal }): AsyncIterable<KeyRingEvent>;
}

// Top-level factories for the common cases
namespace KeyRing {
  function forChaoskbNode(options: { service?: string }): KeyRing;
  function forBrowserExtension(options: { insecureMemory: true; service?: string }): KeyRing<'standard'>;
}

// Tier factories
class StandardTier {
  static fromSshAgent(): Tier<'standard'>;
  static fromSshKey(pem: string, passphrase?: string): Tier<'standard'>;
}
class MaximumTier {
  static fromPassphrase(params?: { t?: number; m?: number; p?: number }): Tier<'maximum'>;
}

// Unlock input (low-level; most callers use the sugar methods)
export type UnlockInput =
  | { kind: 'passphrase'; passphrase: string }
  | { kind: 'ssh-agent' }
  | { kind: 'ssh-key'; privateKeyPem: string; passphrase?: string };

// Wrapped key on-disk shape (frozen per §9):
export interface WrappedKey {
  v: 1;
  tier: TierKind;
  envelope: Uint8Array;       // crypto-envelope envelope bytes
  kdfParams?: { t: number; m: number; p: number; salt: Uint8Array };  // MaximumTier
  sshFingerprint?: string;    // StandardTier
  ts: string;
}

// Error hierarchy
export class KeyRingError extends Error { readonly code: string; }
export class NotUnlocked extends KeyRingError {}
export class UnlockFailed extends KeyRingError {}
export class WrongPassphrase extends UnlockFailed {}
export class ProjectKeyNotFound extends KeyRingError {}
export class RotationPartialFailure extends KeyRingError {
  readonly result: RotationResult;
}
export class TofuMismatch extends KeyRingError {}
export class TierStorageMismatch extends KeyRingError {}   // runtime fallback for compile-time narrowing
// crypto-envelope errors (DecryptionFailure, CommitmentMismatch, NonceBudgetExceeded, etc.)
// are re-exported unchanged — do not wrap, do not lose the cause chain.
```

Rationale for the shape choices traces to [tmp/design-review/01-blockers.md](../tmp/design-review/01-blockers.md) B14–B16 and [02-should-fix.md](../tmp/design-review/02-should-fix.md) S17–S24. The short version: safe-by-construction via TypeScript generics; scoped resource use via `withMaster`; composable events via async iterable.

## 6. Peer-dep on crypto-envelope

```json
"peerDependencies": {
  "@de-otio/crypto-envelope": ">=0.2.0-alpha.1 <0.3.0"
}
```

**Range tightened from earlier draft.** Per npm/Node 0.x convention, minor bumps are breaking — a crypto-envelope 0.3.0 wire-format revision would silently satisfy a `<1.0.0` range. The `<0.3.0` ceiling encodes §14's co-promotion commitment.

Uses from crypto-envelope:
- `EnvelopeClient` — wraps/unwraps master-key bytes as envelopes
- `rewrapEnvelope` — rotation primitive (§4.2)
- `SecureBuffer` / `MasterKey` (branded) — key material handling
- `deriveMasterKeyFromPassphrase` — MaximumTier implementation
- `MessageCounter` interface — threshold events feed `rotationPolicy`

**Dependabot policy:** `.github/dependabot.yml` in Phase A scaffold — weekly check, group `@de-otio/*` updates into a single PR, ignore pre-release labels during the joint-alpha window to avoid constant-green-tick-chasing.

## 7. Browser posture (chaoskb plugin + trellis)

Chaoskb's journalist/activist threat model is materially stricter than trellis's Border Safety Mode.

- **`SecureBufferBrowser` is strict-by-default.** `KeyRing` constructor accepts `insecureMemory?: boolean`; in a browser runtime with no hardware-backed key store, the constructor **throws** if `insecureMemory` is not explicitly set. One construction-time acknowledgement is as discoverable as thirty per-allocation flags, and less noisy. (Change from pre-review draft: was per-allocation; now once-per-ring.)
- **MV3 service-worker lifetime.** Chrome's 30s idle was relaxed in 2024 (5 min while a port is connected; `chrome.runtime` keeps the worker alive on message traffic). `KeyRing` state **must not** be stored on the worker's global scope — rehydrate from `chrome.storage` on `onStartup` / `onInstalled` / message events. Cite: [Chrome MV3 service-worker lifecycle docs](https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle).
- **`WebExtensionStorage` / `IndexedDbStorage` refuse MaximumTier by construction.** Compile-time via `KeyStorage<'standard'>` typing; runtime fallback throws `TierStorageMismatch` for consumers that evade the type system.
- **`chrome.storage.local` vs `chrome.storage.session`.** `WebExtensionStorage({ persistence: 'local' | 'session' })` — `local` default for wrapped masters (persistent, plaintext on disk); `session` for transient unwrapped material (memory-only, cleared on browser close). Document the tradeoff in each backend's JSDoc.
- **Rotation in browsers.** `rotate()` not safe in MV3 service workers (see §4.2). Consumer drives from an extension page. Document loudly.
- **No UI in the library.** Passphrases come from the consumer. Keyring never prompts, displays UI, or caches passphrases.

## 8. Compliance affordances

- **GDPR Art. 17 (right to erasure) / crypto-shredding.** `KeyStorage.delete(slot)` is the affordance. Named explicitly in API docs. **Honest framing:** Art. 17 is satisfied at the envelope layer (existing ciphertext remains exfiltrable but permanently unreadable once the master is unrecoverable), **not** at the storage layer. Per-backend residue is out of keyring's hands — library documents what residue exists: `OsKeychainStorage` (OS DB vacuum varies), `IndexedDbStorage` (opportunistic LevelDB compaction), `FileSystemStorage` (no pre-unlink overwrite; ext4/APFS journal residue), `WebExtensionStorage` (Chromium LevelDB tombstones).
- **SOC 2 audit hook.** Optional `events?: EventSink` on `KeyRing` (§5). Keyring emits lifecycle events; consumer persists wherever their audit pipeline lives. Keyring does not own an audit log.
- **GDPR Art. 32 / StandardTier EU adequacy.** `StandardTier` inherits the strength of the user's SSH-key passphrase (user-chosen, not library-enforced). Consumers processing EU personal data under their own DPIA should default `MaximumTier` (Argon2id, library-enforced floors) for EU users. Noted in SECURITY.md.
- **HIPAA/PCI.** N/A for known consumers. README states: "not validated for PHI/PAN; regulated-domain consumers perform their own controls mapping."
- **SBOM / EO 14028.** Phase J ships `sbom.spdx.json` alongside the tarball; inherit crypto-envelope's SBOM workflow.
- **Rotation orphans.** `BlobEnumerator` is authoritative — keyring has no visibility into blobs the consumer does not surface. Retention policy is the consumer's problem; documented to head off "why did an old blob decrypt after rotation" incidents.

## 9. Wire-format stability

Mirrors [crypto-envelope plan-01 §8](../../crypto-envelope/plans/01-extraction.md#8-wire-format-and-stability-commitment).

Formats frozen between versions:
- `WrappedKey` v1 wire shape (§5)
- StandardTier wrap formats: Ed25519 sealed-box envelope, RSA-OAEP KEM+DEM envelope (with the corrected AAD from B2)
- MaximumTier wrap format (Argon2id-derived master → envelope)
- TOFU pin-file format (JSON + HMAC)
- Project-key wrap format (envelope with project-name-bound HKDF info, S1 fix)
- Invite envelope format

Stability posture:
- **v0.1–v0.x:** wire format mutable between minor versions. CHANGELOG documents each change + migration path.
- **v1.0 cut** gated on both consumers shipping a production release. Same gate as crypto-envelope.
- Post-v1.0: wire formats frozen within the major. `v` field in `WrappedKey` makes `v2`, etc. possible without breaking decoders.

Under `age`-adoption (§2), "our wire format" becomes "age's wire format"; the `v1.0` gate still applies to keyring's own surface (tier/storage/rotation/invite APIs).

## 10. Risk register

| Risk | Mitigation |
|---|---|
| **SECURITY — Windows PowerShell RCE in chaoskb `keyring.ts`** | Not ported. Replaced by `@napi-rs/keyring` in Phase D. See §3 `keyring.ts` row. |
| **SECURITY — Empty AAD on RSA-OAEP master wrap** | B2 fix in Phase C: non-empty AAD binding SSH fingerprint + wrap-context + version. Old vectors become migration-only. |
| **SECURITY — macOS `security -w` leaks via `ps`** | Eliminated by `@napi-rs/keyring` adoption (Phase D). |
| **SECURITY — Invite small-order point** | B4 fix in Phase F: reject all-zero scalarmult output. Test vector for rejection path. |
| **SECURITY — Unzeroed X25519 secret key** | B5 fix in Phase C: `ed25519ToX25519SecretKey` returns `SecureBuffer`; dispose asserted in tests. |
| **SECURITY — TOFU pin integrity** | B6 fix in Phase C: MAC pin file with HKDF-derived key. |
| `sshpk` supply-chain (aging, CVEs in ASN.1) | Accept for v0.1; SECURITY.md entry; v0.2 exit criterion = replace or document acceptance explicitly. Under `age`-adoption: eliminated. |
| `sodium-native` leaking into browser bundles | Phase E smoke asserts `sodium-native` does not appear in Vite/esbuild browser output. |
| MV3 test harness doesn't exist | In-repo minimal harness built in Phase A: load-unpacked extension via Playwright, exercise `chrome.storage` round-trip. Not blocked on chaoskb's harness landing. |
| `@napi-rs/keyring` prebuild coverage gaps (BSD, Alpine musl) | Document fallback: users on uncovered platforms see a clear "OS keychain unavailable on this platform; use `FileSystemStorage` with appropriate permissions" error. |
| Linux `libsecret` missing | `OsKeychainStorage.put` throws clear "install libsecret-tools" error. |
| Rotation orphaned blobs under old master | `oldMasterStillRequired` in result; documented consumer responsibility. |
| Rotation mid-flight in MV3 worker | Unsupported; documented; consumer runs rotation from an extension page. |
| CI cost creep | §13 hard budget: PR CI ≤ 10 min wall; OS-keychain + MV3 nightly-only. |
| Three-package coordination tax | Measured monthly; reconsidered at v0.2 if cross-repo PR volume > 3/month. |
| StandardTier EU adequacy | Documented in SECURITY.md; DPIA guidance favours MaximumTier for EU users. |
| ECDSA SSH key types unsupported in v0.1 | Plan text updated (§3); v0.2 scope; clear error for ECDSA key attempts. |

## 11. Phases

Each phase is one PR, independently reviewable. Tests ported from chaoskb's `__tests__/` where code already exists. New browser code uses `@vitest/browser` + Playwright (same tooling as crypto-envelope).

### Phase A — Scaffold + interfaces + CI + dependabot

- `package.json`, `tsconfig` (strict + verbatimModuleSyntax), CI workflows lifted from crypto-envelope shape
- **`pkgroll` as build driver** (not hand-rolled `exports`); **`@arethetypeswrong/cli` in CI** for types-first condition ordering verification
- `.github/dependabot.yml` per §6
- `.github/workflows/ci.yml` (PR jobs) and `.github/workflows/nightly.yml` (OS-keychain + MV3 integration) — §13 CI budget
- `src/types.ts` with `Tier`, `KeyStorage`, `BlobEnumerator`, `UnlockInput`, `WrappedKey`, error classes (no runtime code)
- `src/index.ts` re-exports; contract-types-only
- MV3 Playwright test harness skeleton in `test/webext-harness/`
- ssh-agent test harness skeleton in `test/ssh-agent-harness/` (or port from chaoskb if present)
- Peer-dep `@de-otio/crypto-envelope@>=0.2.0-alpha.1 <0.3.0`
- **Exit:** `npm run build` produces dual ESM/CJS artifacts via pkgroll; types resolution passes `attw`; CI green; harnesses load an empty extension and start an ssh-agent respectively.

### Phase B — `MaximumTier` + `InMemoryStorage` + `FileSystemStorage`

- **`age`-if-adopted:** `MaximumTier` delegates to `age` scrypt recipient; port-custom otherwise.
- Port simplest tier first; chaoskb's tests apply unchanged.
- Exit: chaoskb MaximumTier tests green against package; fixture vectors committed.

### Phase C — `StandardTier` + SSH interop + TOFU

- **B2 fix (non-empty AAD) mandatory in implementation.**
- **B5 fix (SecureBuffer return from ed25519 conversion) mandatory.**
- **B6 fix (MAC pin file) mandatory.**
- Port `ssh-keys.ts`, `ssh-agent.ts`, `tiers/standard.ts`, `known-keys.ts`. Ed25519 + RSA only (ECDSA is v0.2).
- Exit: chaoskb StandardTier tests pass; chaoskb-interop fixture vectors decrypt byte-identically (the old vectors, generated pre-B2-fix, are decrypted via a documented "migration" code path Phase H will exercise).

### Phase D — `OsKeychainStorage` via `@napi-rs/keyring`

- **Shell-out is not ported.** Direct migration to `@napi-rs/keyring` (Rust napi; prebuild binaries darwin/win/linux).
- Tests: `@napi-rs/keyring` mocked at unit level; real-keychain integration nightly (self-hosted runners or manual quarterly).
- Phase D exit: `list()` ≤ 50ms for 20 project keys on reference hardware (napi is ~100× faster than shell-out; benchmark asserted).

### Phase E — Browser storage (`WebExtensionStorage`, `IndexedDbStorage`)

- `@vitest/browser` + Playwright + in-repo MV3 harness from Phase A
- Bundler smoke: assert `sodium-native` absent from browser output (Vite + esbuild)
- Enforce §5 capability typing at compile time + runtime fallback
- Exit: MV3 extension round-trips `chrome.storage.local` and `session`; IndexedDB round-trips; tree-shake removes non-browser storage classes; browser bundle ≤ budget (§13).

### Phase F — Project keys + invite flow

- **`age`-if-adopted:** invite delegates to `age` X25519 recipient; `known-keys` delegates to OpenSSH `known_hosts` with `chaoskb:` prefix.
- **S1 fix (project-name-bound HKDF info) mandatory.**
- **B4 fix (small-order check) mandatory.**
- **Invite challenge-state spec** — see §15 open decision.
- Port `project-keys.ts`, `invite.ts`
- Tests ported from chaoskb
- Exit: chaoskb's project-key and invite tests pass under the fixed primitives.

### Phase G — `rotateMaster` orchestration

- **Depends on crypto-envelope plan-02 Phase IV (`rewrapEnvelope`) landing.** Explicit cross-repo gate.
- Implements §4.2 orchestration on crypto-envelope's `rewrapEnvelope`
- Resumability via `startAfter` + commitment-based idempotence skip
- Bounded concurrency via `batchSize` semaphore
- AbortSignal propagation
- Tests: happy path, partial-failure + resume, concurrent abort, 100k-blob stress (memory stays bounded), MV3-worker-termination simulation (documents the "not safe" posture, doesn't pretend to handle it)
- Exit: stress test green; documentation explicitly says MV3 worker rotation is not supported.

### Phase H — Chaoskb migration

- Replace chaoskb's `src/crypto/tiers/`, `src/crypto/ssh-*`, `src/crypto/project-keys.ts`, `src/crypto/invite.ts`, `src/crypto/known-keys.ts`, `src/crypto/keyring.ts` with re-exports from `@de-otio/keyring`
- **Migration guide** at `chaoskb/docs/migration-from-legacy-crypto.md` — ships with Phase H
- **Old-format migration path** for wrapped-masters generated before B2's AAD fix: runtime detects format version, decrypts via legacy path, re-wraps under new AAD, persists. One-way migration.
- **Rollback plan:** pin pre-keyring chaoskb SHA; 48h monitoring window; dual-maintain if regression reported.
- Exit: chaoskb's full suite green; every on-disk wrapped-master from a pre-keyring chaoskb install decrypts; migration path exercised by a test that loads a pre-v0.1 fixture.

### Phase I — Trellis migration (Border Safety Mode)

- Trellis is not live, no data migration
- Replace `apps/api/src/lib/encryption-key-service.ts` with `new KeyRing({ tier: MaximumTier.fromPassphrase(), storage: new IndexedDbStorage(...), insecureMemory: true })`
- Combines with crypto-envelope plan-02 Phase VI (same trellis PR or coordinated-split)
- Bundle-size budget: non-Border-Safety-Mode pages must tree-shake out MaximumTier + IndexedDB
- Exit: trellis Border Safety Mode passes tests against the new stack; bundle budget green.

### Phase J — Publish `0.1.0-alpha.1`

- Version-aware dist-tag workflow from crypto-envelope
- `sbom.spdx.json` generated and shipped
- SECURITY.md published (browser posture, `sshpk` acceptance, StandardTier EU adequacy, TOFU threat model)
- README with escape-hatch import path docs (`@de-otio/keyring/browser`)
- No `@latest` until both consumers ship production

## 12. Out of scope for v0.1

- **Device linking / sync** — chaoskb product feature.
- **Voting crypto, ActivityPub RSA signing** — trellis-specific protocol surfaces.
- **Hardware-backed keys (YubiKey, Secure Enclave, WebAuthn large-blob)** — v0.2 scope. Under `age`-adoption, `age-plugin-yubikey` comes for free and v0.2 scope shrinks.
- **Cloud-KMS-backed tiers (AWS KMS, GCP KMS)** — v0.2+.
- **Sharing beyond the existing ECDH invite flow.**
- **Audit-log storage** — library emits events; consumer stores.
- **ECDSA SSH keys** — v0.2 scope.
- **MV2 WebExtension support** — MV3 only.

## 13. Testing strategy

- **Unit tests** per primitive: chaoskb's existing suites port directly to Phases B, C, F.
- **chaoskb-interop vectors** under `test/vectors/chaoskb-interop/` — dumped from a current chaoskb install; decrypted by every Phase B–F build. The interop gate for Phase H.
- **Browser tests** via `@vitest/browser` + Playwright; one ubuntu cell per listed browser-engine family (no OS matrix per [crypto-envelope plan-02 review S10](../../crypto-envelope/tmp/design-review/02-should-fix.md)).
- **MV3 Playwright harness** in `test/webext-harness/`: loads an unpacked extension, drives `chrome.storage` round-trips.
- **ssh-agent harness** in `test/ssh-agent-harness/`: spawns an agent, imports a test key, exercises the socket IPC.
- **OS-keychain integration:** mocked at unit level; real nightly via `@napi-rs/keyring` on self-hosted runners (or manual quarterly if self-hosted capacity unavailable).
- **Bundler smoke:** Vite + esbuild + webpack 5 asserting (a) `sodium-native` absent from browser output, (b) tree-shake removes unused tier/storage classes, (c) types resolve correctly in bundler + node16 moduleResolution.
- **Property-based tests** for rotation: random-blob-count + random-ordering + random-abort-point, assert idempotent resumption.

**CI budget:** PR jobs ≤ 10 min wall; OS-keychain real + MV3 real run nightly only.

## 14. Release cadence with crypto-envelope

- crypto-envelope v0.2-alpha lands first (plan-02 Phase I–V)
- keyring v0.1-alpha follows, pinning `crypto-envelope@>=0.2.0-alpha.1 <0.3.0`
- crypto-envelope plan-02 Phase VI (trellis migration) and keyring Phase I (trellis migration) become the **same** trellis PR — one coordinated migration.
- Both packages promote to `@beta` / `@latest` on the **same gate**: chaoskb and trellis each shipped a production release against the alpha chain.
- Dependabot policy (§6) groups `@de-otio/*` upgrades so single-package alphas don't flap CI.

## 15. Open decisions

All decisions default-if-unresolved; owner: Richard unless otherwise specified. Decision deadline = phase start.

1. **Adopt `age` as transport?** Spike gate (§2). **Default: port custom code** (current plan text assumes this); re-evaluate if spike lands before Phase A.
2. **MV3-only WebExtension support?** **Default: yes.** §11.1 draft decision confirmed. MV2 users stay on chaoskb CLI.
3. **`UnlockInput` shape.** **Default: discriminated union + per-tier `unlockWithX` sugar methods**, as spec'd in §5. Both surfaces stable; sugar is the first-taught.
4. **`sshpk` replacement.** **Default: keep for v0.1; SECURITY.md entry listing CVE paths; v0.2 exit criterion = replace or document acceptance.** Eliminated under `age`-adoption.
5. **`unlock()` idempotence.** **Default: no-op on matching input; throw on mismatch.** `lock()` + `unlock()` with new input is the explicit re-key path. Concurrent unlock calls serialise via internal promise latch.
6. **`invite.ts` challenge-state.** **Default: keyring provides a `ChallengeStore` interface; chaoskb wires to sync backend, trellis to API.** Alternative (B): invite becomes consumer-driven with keyring exposing only the X25519 primitives. Decide in Phase F.
7. **Audit-event schema.** **Default: de-otio-specific `KeyRingEvent` union (§5).** Alternative: CloudEvents or OpenTelemetry logs format. Revisit if trellis has an existing audit pipeline to interoperate with.
8. **`rotate` cursor MAC.** If resumability cursor is surfaced to consumers for persistence, should keyring MAC it? **Default: yes** — HKDF-derived MAC over cursor bytes; consumers pass it back verbatim on resume.

## 16. Success criteria for v0.1

v0.1 ships when all of the following hold:

- All Phase A–J exit criteria green.
- The three critical/high security findings from the chaoskb code being ported are fixed and covered by new tests: Windows RCE (not ported), RSA empty-AAD (fixed), macOS `ps` leak (not ported), invite small-order (fixed), unzeroed X25519 secret (fixed), TOFU integrity (fixed).
- The chaoskb-interop vector set decrypts byte-identically (including the migration-path vectors for RSA wraps generated pre-B2-fix).
- chaoskb's full test suite passes against keyring.
- trellis Border Safety Mode passes against keyring.
- SECURITY.md documents: browser posture, `sshpk` acceptance window, StandardTier EU adequacy, TOFU threat-model.
- `@arethetypeswrong/cli` green.
- Bundle-size budgets (browser, non-browser) green.
- CI budget: PR jobs ≤ 10 min wall.
- SBOM `.spdx.json` generated and published.

## 17. Sequencing

| Phase | Effort | Depends on | Parallel with |
|---|---|---|---|
| A (Scaffold + CI + harnesses) | Small | — | — |
| B (MaxTier + fs storage) | Small | A | C, D |
| C (StandardTier + SSH + TOFU + B2/B5/B6 fixes) | Medium | A | B, D |
| D (OsKeychainStorage via @napi-rs/keyring) | Small | A | B, C |
| E (Browser storage) | Medium | A | F |
| F (Project keys + invite + B4/S1 fixes) | Small | C | E |
| G (rotateMaster) | Medium | C, **crypto-envelope plan-02 Phase IV** | — |
| H (Chaoskb migration) | Medium | B, C, D, E, F, G | — |
| I (Trellis migration) | Small | B, E | crypto-envelope plan-02 Phase VI (same PR) |
| J (Publish + SECURITY.md + SBOM) | Small | A–I | — |

**Critical path:** A → C → G → H.
**Cross-repo gate:** Phase G blocks on crypto-envelope plan-02 Phase IV.
**Joint gate:** Phase I ships as one coordinated trellis PR alongside crypto-envelope Phase VI.

## 18. Cadence commitments

Inherited from crypto-envelope's SECURITY.md (published as part of Phase J):

- **Argon2id / PBKDF2 parameter floors** reviewed annually against current OWASP Password Storage Cheat Sheet; bumped via minor version.
- **SSH key-type support** reviewed on each OpenSSH release (twice yearly).
- **`@napi-rs/keyring` prebuild coverage** reviewed on OS keychain API changes (macOS major updates, Windows Credential Manager changes).
- **`sshpk` / supply-chain** reviewed on each advisory; replace-or-accept decision revisited at v0.2 cut.
