# Implementation Checklist — @de-otio/keyring v0.1

Derived from [01-extraction.md](./01-extraction.md). Designed for multiple agents working in parallel.

## Legend

- **🟢 parallel** — this task runs concurrently with its siblings in the same subsection
- **🔴 serialized** — this task must complete before siblings proceed
- **model** — `opus` for security-critical + design decisions, `sonnet` for bulk implementation + tests + CI, `haiku` for config/docs/trivial refactor
- **coverage** — minimum test coverage for runtime modules (types-only modules are N/A). Overall repo floor: **80%** line+branch via `c8` gate in CI
- **gate** — cross-repo or cross-phase dependency that must be green before starting

All tasks inherit the plan's security invariants: security fixes are **mandatory** at the relevant port site, not an afterthought.

## Blockers before any implementation

- **B0 ✅ age-delegation spike — RESOLVED: HYBRID** (2026-04-18). See [plans/03-age-spike-report.md](./03-age-spike-report.md) and plan 01 §2. Invite delegates to `age-encryption`; MaximumTier, StandardTier, TOFU port custom code (SSH recipient doesn't exist in `age-encryption@0.3.0`; passphrase adoption would downgrade Argon2id → scrypt).
- **B1 🔴 crypto-envelope v0.2** — `>=0.2.0-alpha.1` does not exist yet. Phases B+ (runtime code that depends on `EnvelopeClient`, `rewrapEnvelope`, `MasterKey`, `deriveMasterKeyFromPassphrase`, `MessageCounter`) are **blocked** on crypto-envelope plan-02 shipping. Phase A (scaffold + types) is unblocked.

## Pre-Phase-A Gate: age-delegation spike

**Owner:** 1 × opus agent. ~1 engineer-day.

| Task | Parallel | Model | Coverage | Description |
|---|---|---|---|---|
| S1 | 🟢 | opus | N/A (spike) | Prototype `StandardTier.fromSshKey()` via `age`'s SSH recipient. Measure LOC, time-to-wrap, time-to-unwrap. |
| S2 | 🟢 | opus | N/A | Prototype `MaximumTier.fromPassphrase()` via `age`'s scrypt recipient. Measure. |
| S3 | 🟢 | opus | N/A | Prototype `invite()` via `age`'s X25519 recipient. Measure. |
| S4 | 🔴 | opus | N/A | After S1–S3: measure bundle size (age-js vs ported code), write migration-cost estimate for pre-keyring chaoskb wrappings. |
| S5 | 🔴 | opus | N/A | Decision doc in `plans/03-age-spike-report.md` with recommendation. |

**Decision deadline:** before Phase B starts.
**Default if not run:** port custom code.

## Phase A — Scaffold + Interfaces + CI

**Owner:** can be split across 3 sonnet agents + 1 opus agent in parallel. Phase A is entirely type-level and config — no runtime code, no crypto-envelope dependency needed at runtime (peer-dep pinned but unresolved until crypto-envelope v0.2 ships).

### A.1 Package metadata (parallel, all 🟢)

| Task | Model | Coverage | Files |
|---|---|---|---|
| A1a | sonnet | N/A | `package.json` — deps (`sshpk`, `@napi-rs/keyring` as optional), peer-deps (`@de-otio/crypto-envelope@>=0.2.0-alpha.1 <0.3.0`), `pkgroll` as build driver, scripts, exports map placeholder |
| A1b | sonnet | N/A | `tsconfig.json`, `tsconfig.build.json` — strict, verbatimModuleSyntax, noImplicitAny, moduleResolution: bundler |
| A1c | sonnet | N/A | `pkgroll.config` if needed; otherwise verify `pkgroll --src src` drives off package.json |
| A1d | haiku | N/A | `biome.json` — inherit crypto-envelope rules |
| A1e | haiku | N/A | `.gitignore`, `LICENSE` (MIT to match crypto-envelope) |

### A.2 CI + dependabot (parallel, all 🟢)

| Task | Model | Coverage | Files |
|---|---|---|---|
| A2a | sonnet | N/A | `.github/workflows/ci.yml` — PR jobs: lint, typecheck, build, unit tests (ubuntu only for browser tests; Node matrix for Node-only tests). **Budget: ≤10 min wall.** |
| A2b | sonnet | N/A | `.github/workflows/nightly.yml` — integration tests: real OS keychain (self-hosted or manual), real MV3 extension via Playwright, real ssh-agent |
| A2c | sonnet | N/A | `.github/workflows/publish.yml` — version-aware dist-tag (lift from crypto-envelope) |
| A2d | haiku | N/A | `.github/dependabot.yml` — weekly, group `@de-otio/*`, ignore pre-release labels during joint-alpha |
| A2e | sonnet | N/A | `c8`/`vitest` coverage config — fail CI below 80% line+branch |

### A.3 Public interfaces (serialized with runtime modules) (all 🟢 among themselves)

| Task | Model | Coverage | Files |
|---|---|---|---|
| A3a | **opus** | N/A (types only) | `src/types.ts` — `Tier<K>`, `KeyStorage<K>`, `TierKind`, `BlobEnumerator`, `UnlockInput`, `WrappedKey`, `RotationResult`, `KeyRingEvent`, `EventSink` |
| A3b | **opus** | N/A (types only) | `src/errors.ts` — `KeyRingError` hierarchy (NotUnlocked, UnlockFailed, WrongPassphrase, ProjectKeyNotFound, RotationPartialFailure, TofuMismatch, TierStorageMismatch) |
| A3c | haiku | N/A | `src/index.ts` — re-exports of types/errors only (runtime classes stubbed + `throw new Error('not implemented')`) |

### A.4 Test harness skeletons (parallel) (all 🟢)

| Task | Model | Coverage | Files |
|---|---|---|---|
| A4a | sonnet | N/A (harness) | `test/webext-harness/` — Playwright + load-unpacked extension; smoke test round-trips `chrome.storage.local` |
| A4b | sonnet | N/A (harness) | `test/ssh-agent-harness/` — spawn ssh-agent subprocess, import test key, verify socket IPC |
| A4c | sonnet | N/A | `vitest.config.ts` — unit + browser projects; happy-dom NOT used (per crypto-envelope plan-02 review) |

### A.5 Documentation skeletons (parallel, all 🟢)

| Task | Model | Coverage | Files |
|---|---|---|---|
| A5a | haiku | N/A | `README.md` — pre-alpha banner, install, browser escape-hatch import path, algorithm-selection guidance, link to SECURITY.md |
| A5b | haiku | N/A | `SECURITY.md` — threat model, browser posture, `sshpk` acceptance, StandardTier EU adequacy, TOFU + MAC |
| A5c | haiku | N/A | `CHANGELOG.md` — `[Unreleased]` section with planned additions |
| A5d | haiku | N/A | `docs/migration-from-chaoskb.md` — skeleton; filled during Phase H |

**Phase A exit criteria:**
- `npm install` succeeds (peer-dep unresolved is OK during dev)
- `npm run build` produces dual ESM/CJS via pkgroll
- `npm run lint` green (biome)
- `npm run typecheck` green (strict)
- `@arethetypeswrong/cli` green (types-first condition ordering)
- CI PR workflow green (runs lint + typecheck + build only at this point; no tests to run)
- `@de-otio/keyring` package published at `0.1.0-alpha.0` on `@alpha` dist-tag (metadata-only; publishing validates the package shape and exports map)

## Phase B — MaximumTier + InMemoryStorage + FileSystemStorage

**Gate:** crypto-envelope v0.2 published (`deriveMasterKeyFromPassphrase`, `EnvelopeClient`, `MasterKey` available) AND Phase A green.

**Fork point per spike outcome:**
- **If age adopted:** single agent, sonnet, ~100 LOC wiring to `age` scrypt recipient. Coverage: 85%.
- **If port custom:** single agent, sonnet, port chaoskb's 35-LOC `tiers/maximum.ts`. Coverage: 90%.

### B (port-custom default)

| Task | Parallel | Model | Coverage | Files |
|---|---|---|---|---|
| B1 | 🔴 | sonnet | 90% | `src/tiers/maximum.ts` — port from chaoskb; consume `deriveMasterKeyFromPassphrase` from crypto-envelope |
| B2 | 🟢 | sonnet | 85% | `src/storage/in-memory.ts` — tests + impl |
| B3 | 🟢 | sonnet | 85% | `src/storage/file-system.ts` — Node fs-based; document no-overwrite-before-unlink |
| B4 | 🔴 | sonnet | 90% | `src/keyring.ts` (minimal — just enough for MaximumTier + InMemory/FS storage) |
| B5 | 🟢 | sonnet | 90% | Tests: passphrase round-trip, wrong-passphrase rejection, dispose zeroing, concurrent unlock races (see S15) |

**Exit:** chaoskb's MaximumTier tests pass against the new package; coverage ≥ 80% repo-wide.

## Phase C — StandardTier + SSH interop + TOFU + security fixes

**Gate:** Phase A green (does not need crypto-envelope runtime for SSH key parsing itself, but envelope wrapping does — so effectively waits for crypto-envelope v0.2).

**Mandatory security fixes during port (not optional):**
- **B2 fix:** non-empty AAD on RSA-OAEP KEM+DEM. AAD binds SSH fingerprint + `"keyring/v1/standard/rsa-kemdem"` + version.
- **B5 fix:** `ed25519ToX25519SecretKey` returns `SecureBuffer`; all callers dispose.
- **B6 fix:** MAC pin file with HKDF-derived key (`info: "keyring/v1/tofu-pin-mac"`).

### C (port-custom default)

| Task | Parallel | Model | Coverage | Files |
|---|---|---|---|---|
| C1 | 🟢 | sonnet | 95% | `src/ssh/keys.ts` — port; B5 fix; Ed25519 + RSA only (ECDSA is v0.2; clear error) |
| C2 | 🟢 | sonnet | 90% | `src/ssh/agent.ts` — port; no API changes; document PKCS#1 v1.5 for agent interop |
| C3 | 🔴 | **opus** | 95% | `src/tiers/standard.ts` — **B2 fix mandatory**; port `crypto_box_seal` (Ed25519) + RSA-OAEP KEM+DEM paths under new AAD; vectors regenerated |
| C4 | 🔴 | **opus** | 95% | `src/known-keys.ts` — **B6 fix mandatory**; HMAC the pin file, verify before use |
| C5 | 🟢 | sonnet | 90% | Tests: chaoskb's StandardTier suite + new tests for B2/B5/B6 fixes; chaoskb-interop vectors under `test/vectors/chaoskb-interop/` |

**Exit:** chaoskb StandardTier tests pass; chaoskb-interop fixtures decrypt via documented migration path for pre-B2 vectors; coverage ≥ 80%.

**If age adopted:** C1/C2 reduce to wrapper code (~50 LOC each); C3/C4 mostly evaporate (age handles wrap; known-hosts adopts OpenSSH format). Coverage targets same.

## Phase D — OsKeychainStorage via @napi-rs/keyring

**Gate:** Phase A green.

**Shell-out is NOT ported.** Replaced with `@napi-rs/keyring`.

| Task | Parallel | Model | Coverage | Files |
|---|---|---|---|---|
| D1 | 🔴 | sonnet | 85% | `src/storage/os-keychain.ts` — wire `@napi-rs/keyring`; capability-typed `KeyStorage<TierKind>` |
| D2 | 🟢 | sonnet | 85% | Unit tests with `@napi-rs/keyring` mocked |
| D3 | 🟢 | sonnet | N/A (integration) | Nightly integration test: real macOS / Linux keychain round-trip; Windows on self-hosted runner or manual |
| D4 | 🟢 | sonnet | N/A | Benchmark: `list()` ≤ 50ms for 20 project keys (asserted in CI as perf regression gate) |

**Exit:** chaoskb can substitute `OsKeychainStorage` for its current `keyring.ts`; shell-out code deleted from chaoskb in Phase H.

## Phase E — Browser storage (WebExtension + IndexedDB)

**Gate:** Phase A green. MV3 harness operational (A4a).

| Task | Parallel | Model | Coverage | Files |
|---|---|---|---|---|
| E1 | 🟢 | sonnet | 85% | `src/storage/webextension.ts` — MV3; `{ persistence: 'local' \| 'session' }` option; capability-typed `KeyStorage<'standard'>` |
| E2 | 🟢 | sonnet | 85% | `src/storage/indexeddb.ts` — via `idb` library; capability-typed `KeyStorage<'standard'>` |
| E3 | 🔴 | sonnet | N/A | Playwright MV3 smoke test (real Chromium) — validates round-trip |
| E4 | 🔴 | sonnet | N/A | Bundler smoke: assert `sodium-native` absent from Vite + esbuild + webpack 5 browser output |
| E5 | 🟢 | sonnet | N/A | Tree-shake test: bundle a `MaximumTier`-only Node path; assert browser storage not pulled |

**Exit:** MV3 extension round-trips `chrome.storage.local` and `session`; IndexedDB round-trips; bundle-size budget green.

## Phase F — Project keys + invite flow (HYBRID: invite delegates to age)

**Gate:** Phase C green (crypto-envelope `MasterKey` / `EnvelopeClient` required).

**Mandatory security fix:**
- **S1 fix:** HKDF info for project-key wrap includes project name (not just static `"chaoskb-project-wrap"`).

B4 (small-order check) and the previously-unflagged invite empty-AAD finding are eliminated by age delegation — `@noble/curves` rejects low-order peer inputs; age's header MAC binds all recipient stanzas.

| Task | Parallel | Model | Coverage | Files |
|---|---|---|---|---|
| F1 | 🟢 | sonnet | 95% | `src/project-keys.ts` — **S1 fix mandatory**; port + rebind HKDF info with project name |
| F2 | 🟢 | sonnet | 95% | `src/invite.ts` — thin wrapper (~40 LOC) over `age-encryption`'s `X25519Recipient` / `X25519Identity`. API: `invite(projectKey, inviteePubKey)` / `acceptInvite(wrapped, myIdentity)`. New peer-dep `age-encryption@^0.3.0`. |
| F3 | 🟢 | sonnet | 90% | Tests: project-key round-trip, invite round-trip, invite rejects tampered wrapped output (age header MAC), invite rejects wrong identity, name collision (`__personal` reserved) |
| F4 | 🔴 | **opus** | N/A | **Decision**: invite challenge-state interface — spec plan §15.6 (ChallengeStore injection vs consumer-driven). Age doesn't manage challenge state. |

## Phase G — rotateMaster orchestration

**Gate:** crypto-envelope plan-02 Phase IV (`rewrapEnvelope` shipped) AND Phase C green. **Cross-repo gate.**

| Task | Parallel | Model | Coverage | Files |
|---|---|---|---|---|
| G1 | 🔴 | **opus** | 95% | `src/rotate.ts` — resumable via `startAfter` cursor; bounded concurrency via `batchSize`-sized semaphore; idempotent-skip via commitment detection; `oldMasterStillRequired` contract |
| G2 | 🟢 | sonnet | 90% | `src/keyring.ts` — wire `KeyRing.rotate()` method; emit `blob-rewrapped` + `rotate-start`/`rotate-complete` on `ring.events` |
| G3 | 🟢 | sonnet | 95% | Tests: happy path, partial-failure + resume, AbortSignal mid-batch, concurrent-unlock-during-rotate, 100k-blob stress (memory bounded) |
| G4 | 🟢 | sonnet | N/A (docs) | Document MV3 worker not safe for rotation; `rotateBatch` deferred to v0.2 |

**Exit:** stress test green (memory stays bounded under 100k-blob rotation); resumability test proves cursor-based continuation; abort test proves old-master-still-required contract.

## Phase H — Chaoskb migration

**Gate:** Phases B–G green in keyring.

| Task | Parallel | Model | Coverage | Files |
|---|---|---|---|---|
| H1 | 🔴 | sonnet | (inherit chaoskb) | Replace chaoskb's `src/crypto/tiers/`, `ssh-*`, `project-keys`, `invite`, `known-keys`, `keyring.ts` with re-exports / adapters |
| H2 | 🔴 | **opus** | 100% | Migration path for pre-B2-fix RSA wraps: detect old-AAD format, decrypt via legacy path, re-wrap under new AAD, persist |
| H3 | 🟢 | sonnet | N/A | Migration guide at `chaoskb/docs/migration-from-legacy-crypto.md` |
| H4 | 🟢 | sonnet | N/A | Chaoskb's full test suite green against keyring |
| H5 | 🔴 | **opus** | N/A | Security review of the diff (opus as code reviewer; verify B1–B6 security fixes actually applied at the call sites) |

**Exit:** chaoskb full suite green; every on-disk wrapped-master from a pre-keyring chaoskb install decrypts via the migration path; pin pre-keyring SHA for rollback.

## Phase I — Trellis migration

**Gate:** Phases B, E green in keyring; crypto-envelope plan-02 Phase VI ready.

| Task | Parallel | Model | Coverage | Files |
|---|---|---|---|---|
| I1 | 🔴 | sonnet | (inherit trellis) | Replace `trellis/apps/api/src/lib/encryption-key-service.ts` with `new KeyRing({ tier: MaximumTier.fromPassphrase(), storage: new IndexedDbStorage(...), insecureMemory: true })` |
| I2 | 🔴 | sonnet | N/A | Delete `trellis/packages/crypto/src/encryption-service.ts`, `versioning.ts`, `types.ts` |
| I3 | 🟢 | sonnet | N/A | Trellis full test suite green; bundle-size budget green for non-Border-Safety-Mode pages |

**Coordination:** I1–I3 ship as **the same trellis PR** as crypto-envelope plan-02 Phase VI.

## Phase J — Publish

**Gate:** Phases A–I green.

| Task | Parallel | Model | Coverage | Files |
|---|---|---|---|---|
| J1 | 🟢 | sonnet | N/A | Bump `package.json` to `0.1.0-alpha.1` |
| J2 | 🟢 | sonnet | N/A | `CHANGELOG.md` — `[0.1.0-alpha.1]` section |
| J3 | 🟢 | sonnet | N/A | Generate `sbom.spdx.json` |
| J4 | 🟢 | haiku | N/A | README update — remove under-construction banner |
| J5 | 🔴 | sonnet | N/A | Tag `v0.1.0-alpha.1`; publish workflow picks `alpha` dist-tag |
| J6 | 🟢 | **opus** | N/A | SECURITY.md final review (browser posture, EU adequacy, `sshpk` acceptance, TOFU threat model) |

**Exit:** published on `@alpha`. No `@latest` until both chaoskb + trellis ship a production release on it.

## Parallelization summary

| Concurrent work group | Agents | Phase gate |
|---|---|---|
| Pre-phase | 3× opus (S1, S2, S3 in parallel) + 1× opus (S4, S5 serialized) | None |
| Phase A | 2× sonnet (A.1, A.2 in parallel) + 1× opus (A.3) + 1× sonnet (A.4) + 1× haiku (A.5) | None |
| Phase B (after A + crypto-envelope v0.2) | 1× sonnet | A green, CE v0.2 published |
| Phase C (after A + CE v0.2) | 2× sonnet (C1, C2) + 1× opus (C3, C4 serialized) + 1× sonnet (C5) | A green, CE v0.2 |
| Phase D (after A) | 1× sonnet | A green |
| Phase E (after A) | 2× sonnet (E1, E2) + 1× sonnet (E3, E4, E5) | A green |
| Phase F (after C) | 1× opus (F1, F2 serialized) + 1× sonnet (F3) | C green |
| Phase G (after C + CE plan-02 Phase IV) | 1× opus + 1× sonnet | C green, CE plan-02 Phase IV |
| Phase H (after B–G) | 1× sonnet + 1× opus (H2, H5) | All keyring work |
| Phase I (after B + E) | 1× sonnet | B + E green, CE plan-02 Phase VI |
| Phase J | 1× sonnet + 1× opus | A–I |

**B + C + D + E can run simultaneously after Phase A.** That's the widest parallelism point, with ~5 agents concurrently.

## Coverage policy

- Overall repo floor: **80% line + branch** via `c8` gate in CI
- Per-module targets in the phase tables above (generally 85–95% for runtime modules)
- Types-only modules (`src/types.ts`, `src/errors.ts`): N/A (`c8` ignore via config)
- Harness code, CI config, docs: N/A
- **Security-critical modules** (`tiers/standard.ts`, `known-keys.ts`, `invite.ts`, `project-keys.ts`): **95%** — every error path exercised; negative test vectors for every security invariant (B2 AAD tampering, B4 small-order, B5 unzeroed, B6 TOFU-mismatch)
- `rotate.ts`: **95%** including property-based tests for resumability

## Critical path

A → C (opus-heavy, security fixes) → G (opus, cross-repo gate) → H (opus security review) → J

Elapsed-time estimate assuming spike lands cleanly, crypto-envelope v0.2 ships in parallel, and 4-wide agent parallelism:

- Pre-phase spike: ~1 day
- Phase A: ~1–2 days
- Phase B/D/E (parallel after A): ~2 days
- Phase C (serial on opus, security-heavy): ~3 days
- Phase F (after C): ~1 day
- Phase G (after C + CE v0.2): ~2 days
- Phase H (chaoskb migration + security review): ~2 days
- Phase I (trellis migration): ~1 day
- Phase J: ~0.5 day

**Total critical path: ~12–14 days** if crypto-envelope v0.2 finishes in parallel by the time Phase B starts. Adjust upward if CE v0.2 slips.
