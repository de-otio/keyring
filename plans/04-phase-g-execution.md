# Phase G Execution Plan — `KeyRing.rotate` + `rewrapEnvelope`

Concrete, parallelised execution plan for keyring Phase G. The design
rationale lives in `plans/01-extraction.md` §4.2 and §5; this document
is purely for driving the work.

## Deliverables

1. **`@de-otio/crypto-envelope` gains a `rewrapEnvelope` primitive** — ~30
   LOC, published as `0.2.0-alpha.2`.
2. **`@de-otio/keyring` gains `KeyRing.rotate()`** — method + tests +
   events + docs, published as `0.1.0-alpha.2`.
3. **Phase H retired** — the clean-cut chaoskb migration made the legacy
   decoder moot. Update `01-extraction.md` / `02-implementation-checklist.md`
   to reflect that.

Chaoskb **does not** adopt the new packages in this phase; it can upgrade
later when it actually needs to rotate a master.

## Scope cuts from the plan-01 spec

To keep the phase landable in one pass instead of the plan's 2-day estimate:

- **Drop the 100k-blob stress test** — replace with a 2k-blob test. Goal
  is to show bounded memory (`batchSize`-sized semaphore holds), not to
  benchmark at scale. CI-friendly.
- **Drop the MV3-worker-termination simulation** — replace with a
  docstring note on `rotate()` that calls out the 30s-idle posture and
  recommends driving rotation from an extension page. The plan itself
  says keyring "documents the 'not safe' posture, doesn't pretend to
  handle it" — so the test wasn't adding coverage, only ceremony.
- **Keep commitment-based idempotence skip as a stretch goal.** Ship
  rotate without it, then add the skip logic in a follow-up if a second
  consumer actually re-runs rotate on already-rotated envelopes. Without
  the skip, re-running is not unsafe — it just does the work twice.

Everything else from the plan stands: resumability, bounded concurrency,
`AbortSignal`, `rotate-start` / `blob-rewrapped` / `rotate-complete`
events, `oldMasterStillRequired` contract, `failed[]` list.

## Interface contracts (pinned — workers code against these)

```ts
// crypto-envelope: new export
export function rewrapEnvelope(
  oldEnvelope: AnyEnvelope,
  oldMaster: MasterKey,
  newMaster: MasterKey,
): AnyEnvelope;
```

Semantics:
- Decrypts `oldEnvelope` with `oldMaster`'s derived `(cek, commitKey)`.
- Re-encrypts the plaintext payload with `newMaster`'s derived
  `(cek, commitKey)`.
- **Preserves**: envelope version, `id`, `ts` (the original create time —
  don't overwrite; this is content-identity, not a new blob), `alg`, `kid`.
- **Regenerates**: nonce, ciphertext, tag, commitment (all necessarily new
  under the new master).
- Throws on master-key-mismatch (AEAD tag failure), truncated input,
  commitment mismatch — same surface as `decryptV1`.
- **Not async**. The primitive is sync; keyring wraps it in a Promise
  for orchestration.

```ts
// keyring: new method on KeyRing
async rotate(
  newTier: Tier<K>,
  enumerator: BlobEnumerator,
  options?: RotateOptions,
): Promise<RotationResult>;
```

`BlobEnumerator`, `RotateOptions`, `RotationResult` are already defined in
`src/types.ts` — no changes needed.

Behaviour the method owns (detailed in plan-01 §4.2):
- For each envelope yielded by `enumerator.enumerate({ startAfter, signal })`,
  call `rewrapEnvelope(env, oldMaster, newMaster)` then
  `enumerator.persist(rewrapped, signal)`.
- `batchSize`-sized semaphore (default 8) — never more than `batchSize`
  in-flight rewraps.
- `AbortSignal` checked between each rewrap; propagated to `enumerate`
  and `persist`; on abort, resolves with partial result (not thrown)
  unless the signal fires mid-await inside `persist`, in which case the
  AbortError propagates.
- `failed[]` gets an entry per `rewrapEnvelope` OR `persist` rejection
  (`retriable: true` only for `persist` rejections — decrypt failures
  are always unrecoverable).
- `lastPersistedId` = id of the last envelope for which `persist`
  resolved.
- `oldMasterStillRequired` = `failed.length > 0 || signal.aborted`.
- Emits `rotate-start`, `blob-rewrapped` (one per success), `rotate-complete`.
- After success (`failed.length === 0 && !signal.aborted`): the method
  **does not** swap `this.tier` / `this.master` automatically. Consumer
  calls `storage.put(slot, wrappedByNewTier)` and re-constructs the
  KeyRing with the new tier. (Reason: rotate owns blob orchestration;
  the master-key swap is storage-layer and belongs in a separate call.
  The plan text is ambiguous here — this resolves it in favour of
  explicit consumer control.)

## Execution plan

### Phase G0 — Solo prep (~10 min, main agent)

1. Verify crypto-envelope's current working tree is clean on `main`.
2. Verify keyring's current working tree is clean on `main`.
3. Commit this plan doc.
4. Create two feature branches:
   - `crypto-envelope`: `feat/phase-iv-rewrap`
   - `keyring`: `feat/phase-g-rotate`
5. In keyring's branch, add a temporary local stub:
   `src/_stubs/rewrap.ts` exporting a `rewrapEnvelope` with the pinned
   signature, body `throw new Error('stub')`. Worker B imports from this
   local stub; the integration step swaps it for the real import.

### Phase G1 — Parallel workers (single message, three `Agent` calls)

All three run concurrently. Each is a general-purpose agent with
`model: opus`, `isolation: worktree`.

**Worker A — crypto-envelope primitive**

Prompt summary:
- Implement `rewrapEnvelope(oldEnvelope, oldMaster, newMaster): AnyEnvelope`
  in `src/envelope/rewrap.ts`.
- Re-use `deriveContentKey` / `deriveCommitKey` from
  `src/primitives/hkdf.ts` for both masters.
- Re-use `decryptV1` + `encryptV1` for the work; preserve `id`, `ts`, `alg`,
  `kid`. For v2 envelopes, downgrade to v1 via existing
  `downgradeToV1`, rewrap, upgrade via `upgradeToV2`. (Or handle v2
  natively — worker's call, document reasoning.)
- Export from `src/index.ts`.
- Unit tests: round-trip with same/different masters, AES-GCM and
  XChaCha20-Poly1305, tamper detection, v1 and v2 envelopes.
- Test vectors under `test/vectors/rewrap/` — at least one happy-path
  vector per (v1, v2) × (XChaCha, AES-GCM) = 4 vectors.
- CHANGELOG entry under a new `[0.2.0-alpha.2]` section.
- Bump `package.json` to `0.2.0-alpha.2`.
- Do **not** tag or publish — main agent does that at integration.

**Worker B — keyring `KeyRing.rotate` orchestration**

Prompt summary:
- Implement `KeyRing.rotate()` per the pinned signature + behaviour above.
- Import `rewrapEnvelope` from **`../_stubs/rewrap.js`** (the local stub
  — main agent swaps this at integration).
- Drop the throwing `rotateMaster` function-level stub from
  `src/index.ts`.
- Native semaphore — no new dependencies. `Promise.all` over a small
  bucket with explicit batching, or an `async generator` `for await` with
  a counter and `p-limit`-style pattern.
- `AbortSignal` wiring: check before each rewrap; pass through to
  `enumerate()` and `persist()`.
- `EventSink` emission; no-op if `events` option not supplied.
- Happy-path + abort + partial-failure + resume unit tests against
  `InMemoryStorage` and a fake enumerator. Keep the fake enumerator in a
  test helper (`test/helpers/fake-enumerator.ts`).
- Do **not** write the stress or chaoskb-interop tests — Worker C owns
  those.

**Worker C — keyring test expansion + docs**

Prompt summary:
- 2k-blob bounded-memory test (not 100k — see scope cut above).
- Concurrent abort test: 200 envelopes, abort at ~100, assert
  `lastPersistedId` accurate and `oldMasterStillRequired: true`.
- Idempotence: rotate twice — expect second run to still re-do the work
  correctly (commitment-based skip is out of scope this phase; second
  run should rotate again with no error).
- Docstring note on `rotate()` about MV3 service workers (replaces the
  dropped simulation).
- Update `README.md` (if rotation isn't documented yet) with a
  five-line "rotating a master" example.
- CHANGELOG entry under `[0.1.0-alpha.2]`.
- Bump `package.json` to `0.1.0-alpha.2`.
- Workers B and C may step on each other's CHANGELOG / package.json —
  main agent merges at integration.

All three workers return a structured report: files changed, tests
added, any off-script decisions. Each cap 400 words.

### Phase G2 — Integration (solo, ~20 min, main agent)

Sequenced:

1. Land Worker A's branch in crypto-envelope; run `npm test`.
2. Tag + push `v0.2.0-alpha.2` in crypto-envelope to trigger TP publish.
   Verify `npm view @de-otio/crypto-envelope@0.2.0-alpha.2` resolves.
3. Land Workers B and C's branches in keyring (resolve CHANGELOG /
   package.json merge conflicts by hand).
4. Delete `src/_stubs/rewrap.ts` and the stubs directory.
5. Replace the stub import in `src/keyring.ts` with
   `import { rewrapEnvelope } from '@de-otio/crypto-envelope'`.
6. Bump `@de-otio/crypto-envelope` dep in keyring's `package.json` to
   `^0.2.0-alpha.2`.
7. `npm install && npm run test:coverage && npm run attw && npm run lint`.
8. Commit the integration as one squash-like commit on
   `feat/phase-g-rotate`.
9. Tag + push `v0.1.0-alpha.2` in keyring to trigger TP publish.
10. Verify `npm view @de-otio/keyring@0.1.0-alpha.2` resolves.

### Phase G3 — Retire Phase H (solo, ~5 min)

1. Edit `plans/01-extraction.md` §11 "Phase H — Chaoskb migration" and
   `plans/02-implementation-checklist.md` "Phase H" — mark as
   **N/A (clean-cut chaoskb migration landed without legacy data)**.
2. Commit.

## Out of scope for Phase G (defer to later alphas)

- Commitment-based idempotence skip (stretch goal).
- `MessageCounter` integration for soft/hard-threshold events. Separate
  follow-up once a consumer emits counters.
- `KeyRing.rotate` auto-swapping `this.tier` / the stored wrapped master.
  The explicit-consumer-control resolution above keeps the method pure.
- Hardware-backed tiers. Out of scope for all of v0.1.

## Success criteria

- crypto-envelope 0.2.0-alpha.2 live on npm with `rewrapEnvelope` export,
  provenance signed via Trusted Publishing.
- keyring 0.1.0-alpha.2 live on npm with `KeyRing.rotate` method, no
  throwing stub, 0.2.0-alpha.2 as the crypto-envelope dep.
- All tests green in both repos. `npm audit` clean.
- `01-extraction.md` and `02-implementation-checklist.md` mark Phase H
  as N/A.
