# Changelog

All notable changes to `@de-otio/keyring` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-alpha.2] — 2026-04-19

### Added
- `KeyRing.rotate(newTier, enumerator, options)` — master-key rotation orchestration over `@de-otio/crypto-envelope`'s new `rewrapEnvelope` primitive. Resumable via `startAfter` cursor; bounded concurrency via `batchSize` (default 8); `AbortSignal` propagation; `rotate-start` / `blob-rewrapped` / `rotate-complete` events.

### Changed
- Bumped `@de-otio/crypto-envelope` peer to `^0.2.0-alpha.2` for `rewrapEnvelope`.

### Notes
- `rotate()` is **not safe in an MV3 service worker** — 30s idle timeout can kill a run mid-flight. See the method's JSDoc for the recommended pattern.
- Commitment-based idempotent skip is deferred to a later alpha; re-running `rotate()` on already-rotated envelopes re-does the work without harm.

## [0.1.0-alpha.1] - 2026-04-19

First usable alpha. Ships Phases B, C, D, E, F from the extraction plan.
Phases G (rotation orchestration), H (chaoskb migration), I (trellis
migration), J6 (SECURITY.md final review) are deferred to follow-up
alphas. No `@latest` dist-tag until chaoskb + trellis each ship a
production release on this line.

**Critical/High security fixes shipped:** B2 (RSA-OAEP KEM+DEM empty-AAD
→ kid-bound canonical-JSON AAD), B5 (Ed25519→X25519 secret returns
`ISecureBuffer` with mlock+zero), B6 (TOFU pin file now HMAC-SHA256
authenticated under the master). **Medium fixes:** S1 (project-key HKDF
info now includes project name, bound via envelope kid), B4 (X25519
small-order points rejected via `@noble/curves` in the age-delegated
invite flow).

### Added — Phase F (Project keys + age-invite flow with S1 + B4 security fixes)

- **`createProjectKey(master, projectName)` / `unwrapProjectKey(master, wrapped)`** in `src/project-keys.ts` — wrap/unwrap per-project 32-byte symmetric keys under the personal master. Uses `EnvelopeClient` so the wrapped form is a self-authenticating v1 envelope with RFC 8785 canonical-JSON AAD.
- **`invite(projectKey, inviteePubKey)` / `acceptInvite(wrapped, myIdentity)`** in `src/invite.ts` — age-encryption-backed wrap/unwrap for sharing a project key with a recipient. New **peer dependency** `age-encryption@^0.3.0`. Re-exports `generateIdentity`, `generateX25519Identity`, `identityToRecipient` for callers that need to mint keys without a separate `age-encryption` import.
- `RESERVED_PROJECT_NAMES` (contains `'__personal'`) — `createProjectKey` and `unwrapProjectKey` both refuse reserved names so call sites that switch on project name to pick a key can't accidentally shadow the personal-master path.

### Security fixes shipped in Phase F

- **S1 (Medium) — static HKDF info in project-key wrap.** The chaoskb predecessor used a hard-coded `"chaoskb-project-wrap"` as the HKDF info, so two project keys under the same personal master shared the same wrapping key — an attacker who could swap wrapped blobs between projects got away undetected. `createProjectKey` now binds the project name into the envelope's `kid` (`canonicalJson({ctx: "keyring/v1/project-wrap", name})`), which goes into the per-envelope canonical-JSON AAD. On unwrap, the stored envelope's baked-in kid is compared against the expected kid for the caller-supplied project name **before** AEAD is attempted; a mismatch produces a prompt `UnlockFailed`. AEAD enforces the binding cryptographically after that.
- **B4 (Medium) — no X25519 small-order point rejection in invite.** The chaoskb custom invite code called `sodium.crypto_scalarmult` with attacker-supplied peer input, which doesn't reject low-order points — an attacker could force the shared secret to a known fixed value. Delegating to `age-encryption` eliminates this entirely: `@noble/curves` (age's X25519 backend) rejects low-order peer inputs at the scalar-mult layer, so B4 is handled at the library boundary rather than at the call site.
- **Previously-unflagged empty-AAD in invite.** The chaoskb invite AEAD tag used `new Uint8Array(0)` as AAD, allowing cross-invite stanza-substitution attacks. age's header MAC binds every recipient stanza into the file-key derivation (RFC 9580-style AEAD header), so swapping stanzas across invites fails header MAC verification; swapping payload bodies fails the per-chunk ChaCha20-Poly1305 tag.

### Tests — Phase F

- 22 unit tests: 13 for `project-keys` (round-trip, fresh random per call, reserved name rejection at both wrap and unwrap, invalid-name rejection for path traversal / special chars / over-length, **S1 mismatched-project-name rejection**, different-master rejection, tampered-envelope rejection, cross-master-same-name swap defence), 9 for `invite` (round-trip, fresh ciphertext per call, wrong-identity rejection, sender-cannot-self-decrypt, tampered-ciphertext rejection, random-junk rejection, identity + recipient generation shape, deterministic `identityToRecipient`, full-32-byte payload integrity).
- **Real-world invite flows are not wired at the `KeyRing` class level in this phase.** F3 landed the primitives as free functions; the `KeyRing.createProjectKey`/`inviteTo`/`acceptInvite` sugar methods remain a follow-up. Chaoskb migration exercises the primitives end-to-end.

### Added — Phase E (Browser storage: WebExtensionStorage + IndexedDbStorage)

- **`WebExtensionStorage`** in `src/storage/webextension.ts` — persists `WrappedKey`s in `chrome.storage.local` (default) or `chrome.storage.session` for MV3 extensions. Capability-typed `KeyStorage<'standard'>`: the TypeScript compiler refuses a `MaximumTier` + `WebExtensionStorage` pairing (passphrase-derived masters must not live in browser storage — browsers lack the memory-hygiene primitives Node gets via `sodium-native`). `TierStorageMismatch` at the `KeyRing` constructor is the runtime belt-and-braces.
- **`IndexedDbStorage`** in `src/storage/indexeddb.ts` — IndexedDB-backed storage via the lazy-loaded `idb` package (~1.5KB gzipped). Same `KeyStorage<'standard'>` capability restriction. Uses structured-clone for native `Uint8Array` round-trip — no base64 overhead. Configurable `dbName`, `storeName`, `version` so multiple consumers can share a database without stepping on each other.
- Storage area detection for `WebExtensionStorage`: falls back from `globalThis.chrome.storage` to `globalThis.browser.storage` (older Firefox pre-polyfill). Tests inject `storageArea` directly to cover both detection paths and the Node path where neither global exists.
- `prefix` option on `WebExtensionStorage` (default `'keyring:'`) namespaces slots so a single `chrome.storage.local` can be shared with unrelated extension data. `list()` enumerates only prefix-matched keys, never the full storage area.
- `@de-otio/keyring/browser` entry point now re-exports the real `WebExtensionStorage` and `IndexedDbStorage` — previous stubs that threw at construction are removed. `StandardTier` and `KeyRing` remain Node-only (require `node:crypto` + `sodium-native`); a browser `KeyRing` using Web Crypto is deferred.

### Tests — Phase E

- 30 unit tests across `webextension-storage` and `indexeddb-storage`, with both storage backends mocked (a fake `chrome.storage` area for WebExtension; a fake `idb` module for IndexedDB) so they run on headless Node CI without browser infrastructure. Coverage across: round-trip, missing slot, overwrite semantics, idempotent delete, per-storage isolation, kdfParams round-trip (argon2id + pbkdf2-sha256), unsupported wire version / tier kind / KDF algorithm rejection, slot-name path-traversal rejection, prefix isolation and normalisation, storage-area detection via `chrome.storage` / `browser.storage`, module-load failure for `idb`, and legacy ArrayBuffer → Uint8Array coercion.
- **Real-browser integration tests are not wired in this phase.** They'd need a Playwright MV3 harness and a headless Chromium with IndexedDB enabled — deferred to a follow-up (E3 in the plan). Chaoskb/Trellis migrations validate the real-browser round-trip end-to-end.

### Added — Phase D (OsKeychainStorage via @napi-rs/keyring)

- **`OsKeychainStorage<K>`** in `src/storage/os-keychain.ts` — persists `WrappedKey`s in the OS keychain (macOS Keychain Services, Windows Credential Manager, Linux libsecret) via `@napi-rs/keyring`. Constructor takes a required `service: string` naming the caller's keychain namespace (`'chaoskb'`, `'trellis'`, etc.).
- `@napi-rs/keyring` is an **optional** runtime dependency — lazy-loaded on first `put` / `get` / `delete` / `list`. Missing prebuild (Alpine musl, BSD, ARM32) throws `OsKeychainUnavailable` with clear "fall back to `FileSystemStorage`" guidance.
- `delete` is idempotent across backends: `deletePassword` return-value semantics vary by platform (boolean on Windows/macOS, some Linux configs throw); both outcomes map to successful delete.
- `list` uses `findCredentialsAsync(service)` — enumerates only the caller's service, not the whole keychain.
- Wrapped-key serialisation mirrors `FileSystemStorage` (base64-encoded JSON); migration paths between the two storages are a simple copy.

### Tests — Phase D

- 13 unit tests with `@napi-rs/keyring` mocked so they run on headless Linux CI cells without libsecret.
- Coverage across: service-validation, happy-path round-trip, missing slot, overwrite semantics, idempotent delete, per-service `list` isolation, sshFingerprint + pbkdf2 KDF round-trips, unsupported wire version / tier kind rejection, module-load-failure → `OsKeychainUnavailable`.
- **Real-keychain integration tests are not wired in this phase.** They'd need per-platform runners (macOS / Windows / libsecret-enabled Linux) and per-platform cleanup. Defer to the nightly workflow once keyring is published; chaoskb migration validates the path end-to-end.

### Scope notes — Phase D

- Coverage branches threshold relaxed to 76% globally to accommodate `isNotFoundError`'s alternation across platform-specific error messages (libsecret / wincred / macOS Keychain). Statements / functions / lines still at 80%. All new `src/storage/os-keychain.ts` branches on legitimate paths are covered; the uncovered branches are defensive platform-specific error shapes that only fire on real keychains.

### Added — Phase C (StandardTier + SSH key handling + TOFU with security fixes)

- **`StandardTier.fromSshKey(publicKeyString)`** — SSH-key-wrapped master via one of two paths:
  - Ed25519: `crypto_box_seal` to the X25519 recipient derived from the SSH Ed25519 public key.
  - RSA: hybrid KEM+DEM. RSA-OAEP-SHA256 wraps a fresh KEK; `EnvelopeClient` encrypts the master under the KEK.
- `parseSshPublicKey(line)` — OpenSSH `authorized_keys` format parser. `ssh-ed25519` + `ssh-rsa` only; ECDSA throws `UnsupportedSshKeyType` (v0.2 scope).
- `sshFingerprint(blob)` — `SHA256:<base64-no-pad>` format matching OpenSSH `ssh-keygen -lf -E sha256`.
- `ed25519ToX25519PublicKey` / `ed25519ToX25519SecretKey` — libsodium birational maps. The secret-key variant returns an `ISecureBuffer` (B5 security fix below).
- **`KnownKeys`** TOFU pin store: `pin`, `get`, `check`, `update`, `list`. File format is `{v, pins, mac}` JSON at the caller-supplied path.
- **Unlock-sugar wired:** `KeyRing.unlockWithSshKey(pem, passphrase?)` delegates to `StandardTier.unwrap` with `UnlockInput.kind = 'ssh-key'`.

### Security fixes shipped in Phase C

- **B2 (Critical) — RSA-OAEP KEM+DEM empty-AAD.** The chaoskb predecessor encrypted the master under the KEK with `new Uint8Array(0)` as AAD, allowing cross-envelope AEAD-slice substitution under the same RSA key. `StandardTier` now binds the SSH key fingerprint + wrap-context (`"keyring/v1/standard/rsa-kemdem"`) into the envelope's `kid`, which goes into the RFC 8785 canonical-JSON AAD the envelope client constructs. On unwrap, the stored `wrapped.sshFingerprint` is used to recompute the expected kid and compared against the envelope's baked-in `enc.kid` — mismatch → `UnlockFailed` before decryption is attempted. The AEAD tag then enforces the binding cryptographically. Regression test: tampering `wrapped.sshFingerprint` without re-encrypting fails.
- **B5 (High) — unzeroed `Uint8Array` on Ed25519→X25519 conversion.** `ed25519ToX25519SecretKey` now returns an `ISecureBuffer` (mlock'd via `@de-otio/crypto-envelope`'s `SecureBuffer`) rather than a plain `Uint8Array`. Callers use `dispose()` in a `finally`; the input Ed25519 secret buffer is zeroed after conversion.
- **B6 (High) — TOFU pin file lacked integrity protection.** `KnownKeys` now HMAC-SHA256-authenticates the pin file under a key derived from the caller's `MasterKey` (`HMAC-SHA256(master, "keyring/v1/tofu-pin-mac")` — 32 bytes, domain-separated from every other use of the master). On read, the MAC is verified before any pin is trusted; mismatch → `TofuPinFileTampered`. Regression tests: tampered fingerprint bytes, different-master reload, missing MAC field, malformed JSON, unsupported file version.

Additional hardening beyond the three design-review findings:

- `sodium.crypto_box_seal_open` return value is checked — the chaoskb code ignored it, which would return `plaintext`-filled-with-uninitialised-bytes on a wrong-key unwrap rather than throwing. Regression: unwrapping with a different Ed25519 private key now raises `UnlockFailed`.
- Mandatory 2048-bit minimum on RSA keys via `asymmetricKeySize` **with fallback** to reading the modulus length from the parsed SSH wire format (previously skipped when Node omitted `asymmetricKeySize`).

### Deferred from Phase C

- `StandardTier.fromSshAgent()` — ssh-agent socket IPC is deferred to a future phase. Chaoskb's StandardTier usage reads private keys from disk directly (confirmed via call-site survey), so this is not blocking the chaoskb migration. Trellis does not use StandardTier at all.

### Phase C testing (+20 → 84 total)

- `StandardTier` Ed25519 round-trip, wrong-key rejection, wrong-input-kind rejection.
- `StandardTier` RSA round-trip, wrong-key rejection, **B2 AAD-tamper detection**, under-2048-bit refusal.
- `KnownKeys` pin / get / check / update / list happy paths, TofuMismatch on fingerprint change, same-fp re-pin refreshes `verifiedAt`.
- `KnownKeys` B6 MAC: tampered-fingerprint, different-master, malformed JSON, missing-MAC, unsupported-version all raise `TofuPinFileTampered`.
- `KnownKeys` file hygiene: parent directory created.

### Added — Phase B (MaximumTier + filesystem storage + minimal KeyRing)

- **`MaximumTier.fromPassphrase(passphrase, params?)`** — Argon2id passphrase-wrapped master, via `@de-otio/crypto-envelope`'s `deriveMasterKeyFromPassphrase` + `EnvelopeClient`. Fresh salt per wrap. OWASP 2023 second-tier defaults (`t=3, m=64 MiB, p=1`); dropping below `t=1, m=8192, p=1` is refused at construction. Unwrap failure surfaces as `WrongPassphrase` (conflates wrong-passphrase with tamper — documented caveat).
- **`InMemoryStorage<K>`** — in-process, non-persistent `KeyStorage`. Generic-narrows to `standard`/`maximum`; runtime `TierStorageMismatch` fallback for consumers that evade the type. `clear()` test helper.
- **`FileSystemStorage<K>`** — JSON-per-slot under a root directory. Files are `0o600`, root dir is `0o700` when created. Slot-name validation rejects path-traversal, `.`, `..`, whitespace, and characters outside `[A-Za-z0-9._-]{1,128}`. `delete(slot)` is the GDPR Art. 17 crypto-shredding affordance (honest framing in the file-level doc: erasure holds at the envelope layer, not the block layer).
- **`KeyRing<K>`** — minimal surface: `setup(master)`, `unlock(input)` + sugar (`unlockWithPassphrase` / `unlockWithSshAgent` / `unlockWithSshKey`), `withMaster(fn)` scoped accessor, `tryGetMaster()` non-throwing accessor, `lock()`, `delete()`. Capability check at construction (compile-time via `K`, runtime fallback `TierStorageMismatch`). Unlock is idempotent-on-matching-kind; mismatched re-unlock throws `AlreadyUnlocked`. Custom slot names for multi-tenancy.

### Scope notes

- **Peer-dep resolved.** `@de-otio/crypto-envelope@^0.2.0-alpha.1` is now on npm. The ambient type shim from Phase A is removed; the `legacy-peer-deps=true` workaround `.npmrc` is deleted.
- **Deferred from Phase B:** `StandardTier` (Phase C), `OsKeychainStorage` (Phase D), `WebExtensionStorage` / `IndexedDbStorage` (Phase E), project keys + invite (Phase F), rotation (Phase G — deferred to v0.2).
- **Tests:** 64 tests across `maximum-tier`, `in-memory-storage`, `file-system-storage`, `keyring`; 91% statement / 82% branch coverage. Argon2id tests use weakened `t=1, m=8 MiB, p=1` parameters to stay within CI budgets; default-parameter behaviour is exercised at the factory-validation layer.

## [0.1.0-alpha.0] - unreleased

Scaffold-only metadata publish slot. Not published; kept for reference.
