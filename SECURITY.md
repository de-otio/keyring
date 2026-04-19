# Security

This document describes the threat model for `@de-otio/keyring`, the guarantees the library makes, and the guarantees it does **not** make.

## Reporting a vulnerability

Email `security@de-otio.org`. Please do not open public issues for security reports.

## Threat model

### In scope

- **Confidentiality of wrapped master keys at rest.** Storage backends (OS keychain, WebExtension, IndexedDB, filesystem) carry wrapped blobs. Confidentiality depends on the tier's wrap strength (user's SSH-key passphrase for StandardTier; library-enforced Argon2id parameters for MaximumTier).
- **Integrity of TOFU pin files.** Pin files are HMAC-authenticated with a key derived from the master via HKDF (`info: "keyring/v1/tofu-pin-mac"`). A filesystem-write attacker cannot replace or forge pins without the master, which means they cannot bootstrap without either the master or an already-unlocked ring.
- **AAD binding on StandardTier RSA-OAEP wraps.** The AAD binds the SSH key fingerprint + wrap-context constant + envelope version; ciphertext slices cannot be swapped between envelopes wrapped under the same RSA key.
- **Small-order point rejection in ECDH invite flow.** Attacker-supplied ephemeral pubkeys that produce an all-zero shared secret are rejected before HKDF.
- **Memory locking of masters on Node.** `SecureBuffer` uses `sodium-native`'s `sodium_malloc` / `sodium_memzero` — keys are mlock'd (not swappable) and zeroed on dispose.

### Not in scope

- **UI layer.** Keyring never prompts for passphrases, displays keys, or caches credentials. Consumer owns these surfaces and their threat models.
- **Browser memory protection.** `SecureBufferBrowser` is plain `Uint8Array` with zero-on-dispose. V8 garbage-collector relocation may leave copies; there is no mlock in browsers. Constructing a browser `KeyRing` without `insecureMemory: true` throws — the flag is the explicit acknowledgement that browser memory is not mlock'd.
- **XSS on pages storing wrapped keys.** `IndexedDbStorage` and `WebExtensionStorage` content is accessible to same-origin JavaScript. Browser backends refuse `MaximumTier` at compile time (passphrase-derived masters must not land there); but Standard-tier wraps *are* XSS-reachable. Consumer's CSP is the mitigation.
- **OS-level compromise.** Root on the host reads OS-keychain contents, ssh-agent memory, and `FileSystemStorage` files. Nothing keyring does defends against this.
- **Side-channel attacks on the browser runtime.** Timing, cache, Spectre/Meltdown-class — not in scope.
- **Post-compromise recovery.** Once a master is exposed, all envelopes encrypted under it are compromised. `rotate()` is the forward-recovery primitive; it does not retroactively protect previously-exposed ciphertext.
- **Device linking / sync.** Chaoskb's feature; trust graph lives in chaoskb, not here.

## Tier choice guidance

- **Default for EU user data under GDPR Art. 32:** `MaximumTier` (Argon2id, library-enforced floors). `StandardTier` inherits the strength of the user's SSH-key passphrase, which the library cannot verify; consumers performing their own DPIA should default MaximumTier for EU personal data.
- **Browser (WebExtension, IndexedDB):** StandardTier only. MaximumTier constructor refuses browser-scoped storage at compile time.
- **Node CLI / server:** Either tier. StandardTier is more ergonomic when the user already has an SSH key in their agent; MaximumTier is more portable across environments without SSH infrastructure.

## Crypto-shredding (GDPR Art. 17)

`KeyStorage.delete(slot)` is the GDPR Art. 17 affordance. **Honest framing:** Art. 17 is satisfied at the envelope layer — existing ciphertext remains exfiltrable but permanently unreadable once the master is unrecoverable. The storage layer's residue is out of keyring's hands:

- `OsKeychainStorage` — OS DB vacuum behaviour varies by platform and version.
- `IndexedDbStorage` — Chromium LevelDB tombstones remain until opportunistic compaction.
- `FileSystemStorage` — library does not overwrite before `fs.unlink`; ext4/APFS journal residue is possible. Consumers needing sanitary deletion should perform a pass with `shred`/`secure-erase` before or after.
- `WebExtensionStorage` — Chromium LevelDB tombstones, same as above.

## Parameter-floor commitments

Reviewed annually against current OWASP Password Storage Cheat Sheet; bumped via minor version.

| Parameter | v0.1 floor | Source |
|---|---|---|
| Argon2id time cost | t = 3 | OWASP 2023 + RFC 9106 |
| Argon2id memory cost | m = 65 536 KiB (64 MiB) | OWASP 2023 |
| Argon2id parallelism | p = 1 | OWASP 2023 |
| PBKDF2-SHA256 iterations | 1 000 000 | OWASP 2023, raised from 600 k floor for 2026 |

PBKDF2 is a **compatibility-only fallback** — WebCrypto runtimes that cannot ship wasm Argon2. A `console.warn` fires when the PBKDF2 branch is taken.

## Accepted supply-chain risk (v0.1)

- **`sshpk`** (~3 MB installed, last meaningful release 2022, ASN.1 CVE history). Accepted for v0.1 to avoid regressing chaoskb's SSH-key-parsing surface. Replacement gate: **v1.0 cut or v0.2 exit, whichever comes first.** Tracked in [plans/01-extraction.md §11 open decision 4](./plans/01-extraction.md#15-open-decisions).
- **OS-keychain prebuild coverage** via `@napi-rs/keyring`. Platforms without prebuild binaries (BSD, Alpine musl, ARM32) receive a clear `OsKeychainUnavailable` error; consumers on those platforms use `FileSystemStorage` with appropriate file permissions.

## Algorithm posture

Algorithm choices are FIPS 140-3-**approved** (AES-256-GCM, XChaCha20-Poly1305 via `@noble/ciphers`; SHA-256 via `@noble/hashes`; Argon2id via `@noble/hashes`; PBKDF2-SHA256 via `@noble/hashes`). The **implementation is not** a FIPS-validated module. Consumers in regulated domains (FIPS-constrained, HIPAA, PCI-DSS) must perform their own controls mapping.

## Wire-format stability

See [plans/01-extraction.md §9](./plans/01-extraction.md#9-wire-format-stability). v0.1–v0.x formats are mutable between minor versions; v1.0 freeze is gated on both `chaoskb` and `trellis` shipping production releases against this library.
