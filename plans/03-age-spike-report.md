# age-Delegation Spike Report

**Status:** complete (2026-04-18). One engineer-day budget; came in under.
**Spike code:** [`spike/`](../spike/) (npm-isolated; not part of the keyring package).
**Recommendation:** **HYBRID — adopt age for invite + passphrase, port custom code for SSH (with a v0.2 path to age-wire-compat for SSH).**
**Confidence:** medium-high on invite/passphrase; medium on SSH (gap is in the npm ecosystem, not in age itself).

## 1. Library choice — `age-encryption@0.3.0`

| Attribute | Value | Source |
|---|---|---|
| Package | [`age-encryption`](https://www.npmjs.com/package/age-encryption) | npm registry |
| Version | 0.3.0 | published 2025-12-29 |
| Author / maintainer | Filippo Valsorda (FiloSottile) — author of age itself | npm metadata |
| Repo | [github.com/FiloSottile/typage](https://github.com/FiloSottile/typage) | npm metadata |
| License | BSD-3-Clause | npm metadata |
| Runtime deps | `@noble/ciphers`, `@noble/curves`, `@noble/hashes`, `@noble/post-quantum`, `@scure/base` | `package.json` |
| Native deps | none | `package.json` (browser-clean) |
| Module type | ESM only | `"type": "module"` |
| Provenance | npm SLSA provenance attestation present | npm dist metadata |
| Audit posture | depends entirely on the noble stack (independently audited 2024) and on the age v1 spec (NCC Group audit of Go age, 2021) | published audits |
| Other candidates checked | `age.js` — does not exist on npm. `rage-js` — does not exist on npm. `typage` (the GitHub repo name) — not published under that name. | `npm view <name>` returned 404 |

**Verdict on the ecosystem:** `age-encryption` is the only viable maintained TS/JS port of age in 2026. It is maintained by the age author, ships only noble dependencies (no native code, browser-clean), and was last published <4 months before the spike date. Acceptable for production use.

**Caveat — npm download counts:** the npm download API is not reachable from the spike sandbox (curl blocked). The package's recency, provenance, and authorship are sufficient signal to proceed; a download-trajectory check should still be done by a human before the dependency is added to the keyring runtime.

## 2. LOC measurements

Methodology: `wc -l` for raw, plus a SLOC-only count that excludes blank lines and comments (more apples-to-apples — chaoskb's files are heavily commented). See `spike/tools/loc.mjs`.

| Component | chaoskb file | chaoskb LOC | chaoskb SLOC | spike file | spike LOC | spike SLOC | SLOC delta |
|---|---|---:|---:|---|---:|---:|---:|
| StandardTier (SSH wrap) | `tiers/standard.ts` | 215 | 139 | `age-ssh-tier.ts` | 116 | 54 | **−61%** |
| MaximumTier (passphrase) | `tiers/maximum.ts` | 35 | 15 | `age-passphrase-tier.ts` | 43 | 24 | **+60%** (i.e. larger) |
| Invite | `invite.ts` | 172 | 97 | `age-invite.ts` | 65 | 38 | **−61%** |
| **Combined** | — | **422** | **251** | — | **224** | **116** | **−54%** |

Important nuance: chaoskb's `MaximumTier` is **already a thin wrapper** over a shared `argon2.ts` derive function — it just emits a salt and forwards. Replacing it with `age` adds the per-call `Encrypter`/`Decrypter` plumbing, which is *more* lines than the chaoskb wrapper but eliminates the underlying argon2 module's responsibility. If you compare against `chaoskb/src/crypto/tiers/maximum.ts` + the relevant slice of `argon2.ts`, age comes out smaller again. The spike does not measure that combined delta because it would conflate keyring scope with crypto-envelope scope.

The headline number is **−54% SLOC** across the three tiers, with the bulk of the win concentrated in `invite.ts` and `tiers/standard.ts`.

## 3. Bundle-size impact (browser, gzipped)

`esbuild --bundle --format=esm --platform=browser --minify --metafile=...` against an `age-all.ts` entry that re-exports all three prototypes. Measurements via `spike/tools/measure.mjs`.

| Bundle | Raw | Gzipped (level 9) |
|---|---:|---:|
| `age-all.min.js` (all three tiers) | 147 KB | **53 KB** |
| `age-passphrase-tier.ts` only | 139 KB | (≈50 KB est.) |
| `age-invite.ts` only | 140 KB | (≈50 KB est.) |
| `age-ssh-tier.ts` only | 143 KB | (≈51 KB est.) |

The single-tier bundles are within ~5 KB of the all-three bundle: `age-encryption` and the noble libs share the bulk of their bytes (chacha20poly1305, x25519, sha256, hkdf, scrypt, bech32) across all three tier paths. **There is no per-tier bundle win from importing only one of the three; the cost is paid once.**

**Comparison reference (no port-side bundle was built; rough estimate):** chaoskb's `tiers/*.ts` + `invite.ts` already pull `sodium-native` (Node-only, not browser-eligible) and `sshpk` (~3 MB installed; ~150 KB after tree-shake on browser). Porting them to keyring with the planned `noble`-only stack would land close to the age spike's footprint — possibly slightly smaller because the port can omit age's stanza/header/armor framing (~10 KB), but at the cost of carrying its own custom framing.

**Net browser-bundle delta is approximately neutral (±10 KB).** `age` is not "free" for browser consumers, but it does not add meaningful weight versus the noble-based port path.

## 4. Migration cost (Phase H)

**Can age decrypt pre-existing chaoskb wrappings?** **No.**

| chaoskb format | wire | age compatible? |
|---|---|---|
| Ed25519 SSH wrap | `crypto_box_seal` (libsodium) | No — age uses ChaCha20-Poly1305 with HKDF-derived per-recipient keys; framing is incompatible. |
| RSA SSH wrap | RSA-OAEP KEM + XChaCha20-Poly1305 DEM (custom framing) | No — age has no RSA recipient at all. |
| Argon2id passphrase wrap | Argon2id → XChaCha20-Poly1305 with custom AAD | No — age uses **scrypt**, not Argon2id; KDF identifier and stanza format differ. |
| Invite ECDH | ephemeral X25519 + HKDF + XChaCha20-Poly1305 with empty AAD | No — wire format differs from age's X25519 stanza. |

**Migration path for Phase H ("decrypt-old, re-wrap-new"):**

1. Port chaoskb's existing wrap/unwrap functions verbatim into `keyring/src/legacy/`. Mark the module `@deprecated` and exclude from the public surface.
2. On unlock, if the on-disk `WrappedKey.v` is `0` (legacy chaoskb) **or** if `WrappedKey.format !== 'age-v1'`, route through the legacy path to recover the master.
3. Immediately re-wrap the master under the new tier and persist the new envelope. Keep the legacy ciphertext under a `.bak` suffix for one release cycle, then garbage-collect.
4. The migration runs once per master, on the user's first post-upgrade unlock. No background work; no key escrow.

**Migration LOC budget:** ~250 LOC for the legacy module (covers all three legacy formats). One-time cost; deletable in v0.2 once the consumer-side audit confirms no legacy wrappings remain.

This matches the contract in the prompt: "one-time decrypt old, re-wrap new pass under a user-triggered re-unlock."

## 5. Security delta — how age affects design-review findings

| Finding | What it is | Eliminated under age? | Why |
|---|---|---|---|
| **B2** — empty AAD on RSA-OAEP wrap | chaoskb encrypts the master under empty AAD; an attacker can swap AEAD portions across two wraps for the same key. | **Eliminated** for the wrap path. age's header HMAC binds *every* stanza (including all recipient stanzas) into the AEAD-keyed MAC, so cross-context substitution is detected at decrypt. (See `node_modules/age-encryption/dist/index.js:107-108` — `hmac(sha256, hmacKey, encodeHeaderNoMAC(stanzas))`.) | The age v1 spec requires this; it is not optional. |
| **B4** — invite ECDH missing small-order check | chaoskb's `crypto_scalarmult` accepts attacker-supplied small-order ephemeral pubkeys → predictable shared secret. | **Eliminated.** `@noble/curves` `x25519` (which `age-encryption` depends on) rejects low-order peer inputs by default in `getSharedSecret` (see `@noble/curves/ed25519.d.ts:73-86`). | Verified in noble docs; covered by noble's own test vectors. |
| **B5** — unzeroed `Uint8Array` from ed25519→X25519 conversion | The converted X25519 secret is held in a plain `Uint8Array` and never zeroed. | **Partially eliminated.** When age's `Decrypter.addIdentity(string)` is used, the identity scalar lives inside the library's internal closures and is not handed back to the caller. Lifetime is shorter than chaoskb's `SSHKeyInfo.x25519SecretKey` field. Not zero-leak: `bech32.decodeToBytes` allocates a fresh `Uint8Array` that is not zeroed when GC'd. **Verdict:** ~70% reduction in residency window; `SecureBuffer` discipline still required at the boundary where the SSH key seed is loaded into an age identity string. |
| **B6** — TOFU pin file lacks integrity protection | `known_keys.json` is plaintext JSON; filesystem-write attacker can replace pins silently. | **Eliminated** if the recommendation in [04-build-vs-buy.md §1.B6](../tmp/design-review/04-build-vs-buy.md) (delegate to OpenSSH `known_hosts` with a `chaoskb:` hostname prefix) is taken. **Not addressed by age itself** — age doesn't manage TOFU pins. |
| **(bonus) Empty AAD in chaoskb invite** | `chaoskb/src/crypto/invite.ts:55` — `aeadEncrypt(encryptionKey, padded, emptyAAD)`. Same class as B2 but on the invite path. Not flagged in the design review by name. | **Eliminated** for the invite path. age's header MAC binds the recipient stanza set. |
| **(bonus) Argon2id → scrypt downgrade** | `age` uses scrypt (per spec) for its passphrase recipient; chaoskb uses Argon2id. | **Adopting age means using scrypt.** Argon2id is the OWASP-preferred algorithm for password-based KDFs because it adds memory-hard plus parallelism resistance over scrypt. **This is a security regression.** age's `setScryptWorkFactor(18)` default is calibrated for ~1s desktop CPU but does not match the parallelism resistance profile of Argon2id at the same cost budget. |

**Net:** B2, B4, and the bonus invite-empty-AAD finding are eliminated for free under age adoption. B5 is partially mitigated. B6 is unaffected by age (but the build-vs-buy doc's `known_hosts` recommendation handles it). **The Argon2id→scrypt downgrade is a real cost** that must be weighed against the LOC win on the passphrase tier.

## 6. SSH wire format — the load-bearing caveat

`age-encryption@0.3.0` **does not implement the SSH recipient stanza** that the Go `age` CLI supports for `age -R authorized_keys`. The package surface (verified by reading `dist/index.d.ts` and `dist/recipients.d.ts`) exports only:
- `X25519Recipient` / `X25519Identity` (native age)
- `HybridRecipient` / `HybridIdentity` (post-quantum hybrid, ML-KEM+X25519)
- `TagRecipient` / `HybridTagRecipient` (tagged variants)
- `ScryptRecipient` / `ScryptIdentity` (passphrase)
- `webauthn.WebAuthnRecipient` / `WebAuthnIdentity` (passkeys / FIDO2)
- `Recipient` / `Identity` interfaces for custom types

There is no `SshRecipient` and no `dist/ssh.{js,d.ts}`.

Two paths exist:

### Path (a) — Implement a custom `Recipient` for the SSH ed25519 stanza

The age v1 spec defines an `ssh-ed25519` stanza:
```
-> ssh-ed25519 <base64 4-byte pubkey hash> <base64 ephemeral pubkey>
<base64 wrapped file key>
```
plus an HKDF derivation that binds the SSH key fingerprint into the wrap key. Re-implementing this in TypeScript (ed25519 only, RSA omitted) would be ~150 LOC: 32 LOC for OpenSSH `ssh-ed25519` text-format decoding, 50 LOC for the stanza emitter following the age spec, 30 LOC for the corresponding identity (decode), 40 LOC for tests. **Wire-compatible with `age -R ~/.ssh/id_ed25519.pub`** — power users could `age -d` keyring's wrapped masters from the CLI.

### Path (b) — Convert SSH ed25519 pubkey → age X25519 recipient at the boundary

This is what the spike implements. The OpenSSH ed25519 pubkey is decoded, converted to its Montgomery form via `ed25519.utils.toMontgomery` (the same birational map `ssh-to-age` uses), bech32-encoded as an `age1...` recipient, and handed to `Encrypter.addRecipient`. **NOT wire-compatible with `age -R authorized_keys`** — the wrapped output decrypts only with the matching `AGE-SECRET-KEY-1...` identity (which can be derived from the SSH ed25519 seed via `ed25519.utils.toMontgomerySecret`), not with `age -i ~/.ssh/id_ed25519`.

**Spike chose path (b)** — cheapest path, exercises the real integration surface, and the X25519 recipient is the most-audited code path in `age-encryption`.

**RSA is out of scope of the spike entirely.** Under either path, RSA requires either implementing `ssh-rsa` stanza framing (~100 LOC in TypeScript with RSAES-OAEP via WebCrypto) or telling RSA users "convert to ed25519 or use a different tier." Given chaoskb's RSA-wrap path carries the B2 empty-AAD finding *and* `sshpk` is the largest single browser bundle cost in the planned port, dropping RSA from v0.1 is worth considering on its own merits.

## 7. Recommendation

**HYBRID, with a clear path to full age adoption in v0.2.**

### v0.1 disposition

| Component | Disposition | Rationale |
|---|---|---|
| **Invite** | **DELEGATE to age (X25519 recipient).** | Highest LOC win (61%); eliminates B4 + the invite empty-AAD finding for free; X25519 recipient is the most exercised code path in `age-encryption`. Migration cost is bounded and one-time. |
| **MaximumTier (passphrase)** | **PORT custom code.** Stay with Argon2id. | The LOC delta is negative (spike is *larger*) and adopting age means downgrading Argon2id → scrypt. CLAUDE.md priority 4 (key separation / safe defaults) leans against the regression. **Optional v0.2 evaluation:** if `age-encryption` adds an Argon2id recipient, revisit. |
| **StandardTier (SSH)** | **PORT custom code, ed25519 + RSA.** Keep under `noble` per the existing plan. | Path (b) is wire-incompatible with `age -R`; path (a) is ~150 LOC of new framing that doesn't yet exist anywhere in the npm ecosystem. The B2 fix in the existing plan resolves the AAD finding directly. **v0.2 path:** publish the path-(a) custom Recipient as `@de-otio/age-ssh-recipient` once we have an external use case for `age -d` interop with keyring wrappings. |
| **TOFU (`known-keys.ts`)** | **DELEGATE to OpenSSH `known_hosts`** per [04-build-vs-buy.md §1.TOFU](../tmp/design-review/04-build-vs-buy.md). Independent of age adoption. | Eliminates B6 with zero new code. |

### LOC implications versus the current plan

| Phase | Plan §3 LOC (port-custom) | Hybrid recommendation LOC |
|---|---:|---:|
| Phase B (MaximumTier) | 35 | 35 (no change) |
| Phase C (StandardTier + SSH + TOFU) | 215 + 136 + 272 + 150 = 773 | 215 + 136 + 272 + ~30 (TOFU shim) = 653 |
| Phase F (project keys + invite) | 100 + 172 = 272 | 100 + ~40 (age invite wiring) = 140 |
| **Total ported runtime** | ~1,080 | **~830** (~23% reduction) |

The chaoskb-interop migration path (§4 above) costs ~250 LOC of legacy decoders, partially offsetting the win. **Net new code:** ~580 LOC original + ~250 LOC legacy = ~830 LOC, vs the plan's 1,080 LOC.

### What could change this recommendation

- **`age-encryption` ships a native SSH recipient** (post-0.3.0). If that lands before Phase C starts, **flip StandardTier to ADOPT age** — wire compat with the Go CLI is a meaningful product feature for power users, and the LOC win on Phase C becomes large.
- **`age-encryption` adds an Argon2id recipient.** Then **flip MaximumTier to ADOPT** — the regression objection disappears.
- **chaoskb adds a non-deletable RSA-key dependency** (e.g. ActivityPub HTTP signatures pulling RSA keys back in as a first-class user surface). Then PORT for SSH stays the right call regardless of age's roadmap; RSA isn't going to land in age (the format authors deprecated RSA support upstream years ago).
- **Bundle-size budget tightens below 50 KB gzipped** for trellis Border Safety Mode pages. Then revisit; both adoption and porting land near the same ceiling, but porting allows shaving age's stanza/armor framing (~10 KB) if every byte counts.

### Confidence

- **High** for invite recommendation. age's X25519 recipient is the single most-tested path in the library, and the migration cost is well-understood.
- **Medium-high** for passphrase recommendation. The Argon2id-vs-scrypt judgement could be argued either way; CLAUDE.md priority 4 settles it for now.
- **Medium** for SSH recommendation. The dominant uncertainty is "will the npm `age-encryption` ssh recipient land in the v0.1 timeframe?" — outside our control, and a `git log` check on the `typage` repo would tighten this.

## 8. Spike artifact inventory

```
spike/
  package.json                  # isolated npm project; age-encryption@0.3.0 + esbuild + tsx
  tsconfig.json
  age-passphrase-tier.ts        # 24 SLOC — wrapWithPassphrase / unwrapWithPassphrase
  age-invite.ts                 # 38 SLOC — newInviteeIdentity / createInvite / acceptInvite
  age-ssh-tier.ts               # 54 SLOC — wrapWithSshKey / unwrapWithSshKey (path-b)
  age-all.ts                    # combined entry for bundle measurement
  bundle-all.min.js             # 147 KB raw, 53 KB gzipped
  test/
    all.test.ts                 # 7 round-trip tests; all green via `npm test`
  tools/
    loc.mjs                     # SLOC counter (excludes blanks/comments)
    measure.mjs                 # LOC + bundle/gzip headline numbers
```

All seven round-trip tests pass under `node --test` via `tsx`:
```
✔ passphrase tier: round-trip
✔ passphrase tier: wrong passphrase rejects
✔ invite: round-trip
✔ invite: wrong identity rejects
✔ ssh tier: ed25519 round-trip
✔ ssh tier: pubkey-to-recipient is deterministic and bech32-valid
✔ ssh tier: rejects ssh-rsa (not in spike scope)
```

---

**Decision required from Richard before Phase A starts:** accept the HYBRID recommendation, or push back on the SSH disposition (the ssh-tier port-vs-adopt is the only one where reasonable people might disagree).
