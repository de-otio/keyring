# Changelog

All notable changes to `@de-otio/keyring` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
