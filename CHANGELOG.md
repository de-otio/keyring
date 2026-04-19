# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Phase A scaffold: package layout, dual-build via `pkgroll`, conditional `node`/`browser` exports with types-first ordering, CI (PR + nightly) workflows, Dependabot grouping for `@de-otio/*`, MV3 Playwright harness skeleton, ssh-agent harness skeleton.
- Public type surface: `Tier<K>`, `KeyStorage<K>`, `TierKind`, `BlobEnumerator`, `UnlockInput`, `WrappedKey`, `RotationResult`, `KeyRingEvent`, `EventSink`, `RotationPolicy`.
- Error hierarchy with stable codes: `KeyRingError` base + `NotUnlocked`, `UnlockFailed`/`WrongPassphrase`/`SshAgentRefused`/`InvalidSshKey`, `ProjectKeyNotFound`, `ReservedSlotName`, `RotationPartialFailure`, `TofuMismatch`, `TierStorageMismatch`, `TofuPinFileTampered`, `InviteSmallOrderPoint`, `AlreadyUnlocked`, `OsKeychainUnavailable`, `UnsupportedSshKeyType`.
- Ambient type shim for `@de-otio/crypto-envelope` to unblock typecheck before the v0.2 peer-dep publishes.

### Planned (not yet implemented)

_Runtime classes (`KeyRing`, `StandardTier`, `MaximumTier`, all `*Storage`) are currently stubs that throw `NotImplementedError` naming the phase that implements them. See [plans/01-extraction.md](./plans/01-extraction.md) phases B–J._

## [0.1.0-alpha.0] - TBD

_Scaffold-only metadata publish. Validates package shape and exports map; no runtime functionality._

[0.1.0-alpha.0]: https://github.com/de-otio/keyring/releases/tag/v0.1.0-alpha.0
