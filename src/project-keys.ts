import { randomBytes } from 'node:crypto';
import {
  EnvelopeClient,
  SecureBuffer,
  asMasterKey,
  canonicalJson,
  deserialize,
} from '@de-otio/crypto-envelope';
import type { ISecureBuffer, MasterKey } from '@de-otio/crypto-envelope';
import { ProjectKeyNotFound, ReservedSlotName, UnlockFailed } from './errors.js';

const PROJECT_KEY_LENGTH = 32;
const WRAP_CONTEXT = 'keyring/v1/project-wrap';

/**
 * Reserved project name — chaoskb uses `__personal` to flag envelopes
 * sealed under the personal master rather than a project key. `createProjectKey`
 * refuses this name to prevent accidental shadowing at call sites that
 * switch on the project name to pick a key.
 */
export const RESERVED_PROJECT_NAMES = new Set<string>(['__personal']);

/**
 * Project-key shape: what a caller stores against a project name.
 *
 * - `wrappedKey`: the project key encrypted under the personal master
 *   (an `EnvelopeClient` v1 envelope, serialised as JSON bytes). Persist this
 *   wherever the caller stores per-project metadata.
 * - `projectName`: the name used at wrap time. Required at unwrap — the name
 *   is cryptographically bound to the ciphertext via the envelope's kid
 *   (RFC 8785 canonical JSON AAD binding). Passing the wrong name on unwrap
 *   fails AEAD before any plaintext is exposed.
 *
 * **Not** serialised into `wrappedKey`: the caller owns the name → wrapped-key
 * mapping. Storing the name inside the envelope would only be useful if
 * callers wanted self-describing envelopes, but that encourages
 * accepting-whatever-name-is-on-the-envelope, which defeats the binding.
 */
export interface WrappedProjectKey {
  projectName: string;
  wrappedKey: Uint8Array;
  /** ISO 8601 timestamp at wrap time. Informational. */
  ts: string;
}

/**
 * Create a fresh random 32-byte project key, wrap it under the given
 * personal master, and return both the raw key (as an `ISecureBuffer`) and
 * the wrapped form suitable for on-disk storage.
 *
 * ## Security fix — S1 (HKDF/kid domain separation)
 *
 * The chaoskb predecessor bound project-key wraps to a **static** HKDF info
 * string `"chaoskb-project-wrap"`. That meant two project keys wrapped under
 * the same personal master shared a wrapping key — an attacker who could
 * swap the wrapped blob for project A with the wrapped blob for project B
 * would get away with it, because the AEAD didn't see the project name at
 * encrypt or decrypt time.
 *
 * This implementation binds the project name into the envelope's `kid`:
 * `canonicalJson({ ctx: "keyring/v1/project-wrap", name: projectName })`.
 * The kid goes into the RFC 8785 canonical-JSON AAD that `EnvelopeClient`
 * computes per-envelope, so swapping one wrapped project key for another
 * flips the AAD and fails AEAD at decrypt time before any bytes are
 * released to the caller.
 *
 * On unwrap, the stored envelope's baked-in `enc.kid` is compared against
 * the expected kid for the caller-supplied project name **before** AEAD is
 * attempted, so a mismatch produces a prompt `UnlockFailed` instead of
 * relying on AEAD tag failure alone.
 *
 * The caller disposes the returned `ISecureBuffer` when done.
 */
export async function createProjectKey(
  master: MasterKey,
  projectName: string,
): Promise<{ projectKey: ISecureBuffer; wrapped: WrappedProjectKey }> {
  assertValidProjectName(projectName);

  const keyBytes = randomBytes(PROJECT_KEY_LENGTH);
  try {
    const kid = buildProjectKid(projectName);
    const client = new EnvelopeClient({ masterKey: master, kid });
    const envelopeBytes = await client.encrypt({
      projectKey: Buffer.from(keyBytes).toString('base64'),
    });

    return {
      projectKey: SecureBuffer.from(Buffer.from(keyBytes)),
      wrapped: {
        projectName,
        wrappedKey: envelopeBytes,
        ts: new Date().toISOString(),
      },
    };
  } finally {
    // The SecureBuffer has its own copy; zero our transient plaintext.
    keyBytes.fill(0);
  }
}

/**
 * Recover a previously-wrapped project key.
 *
 * `wrapped.projectName` must match the value used at `createProjectKey`
 * time — the name is bound cryptographically into the envelope's AAD.
 * Mismatched name → `UnlockFailed` before the AEAD tag is even checked.
 *
 * The caller owns the returned `ISecureBuffer` lifetime and must call
 * `dispose()` when done.
 */
export async function unwrapProjectKey(
  master: MasterKey,
  wrapped: WrappedProjectKey,
): Promise<ISecureBuffer> {
  assertValidProjectName(wrapped.projectName);

  const expectedKid = buildProjectKid(wrapped.projectName);
  const env = deserialize(wrapped.wrappedKey);
  if (env.enc.kid !== expectedKid) {
    throw new UnlockFailed(
      'project-key envelope kid does not match project name — wrong project or tampered store',
    );
  }

  const client = new EnvelopeClient({ masterKey: master, kid: expectedKid });
  let decrypted: { projectKey: string };
  try {
    decrypted = (await client.decrypt(wrapped.wrappedKey)) as { projectKey: string };
  } catch (cause) {
    throw new UnlockFailed('project-key decrypt failed (wrong master or tampered envelope)', {
      cause,
    });
  }

  const keyBytes = Buffer.from(decrypted.projectKey, 'base64');
  try {
    if (keyBytes.length !== PROJECT_KEY_LENGTH) {
      throw new UnlockFailed(
        `project-key has wrong length: ${keyBytes.length} (expected ${PROJECT_KEY_LENGTH})`,
      );
    }
    return SecureBuffer.from(keyBytes);
  } finally {
    keyBytes.fill(0);
  }
}

// ── helpers ─────────────────────────────────────────────────────────────

/**
 * Build the envelope `kid` for a project-key wrap. The kid goes into the
 * per-envelope AAD (via `EnvelopeClient`'s canonical-JSON binding), so
 * changing the project name changes the AAD and breaks AEAD — the S1 fix.
 */
function buildProjectKid(projectName: string): string {
  return canonicalJson({ ctx: WRAP_CONTEXT, name: projectName });
}

const PROJECT_NAME_PATTERN = /^[A-Za-z0-9._-]{1,128}$/;

function assertValidProjectName(projectName: string): void {
  if (RESERVED_PROJECT_NAMES.has(projectName)) {
    throw new ReservedSlotName(projectName);
  }
  if (!PROJECT_NAME_PATTERN.test(projectName)) {
    throw new Error(
      `invalid project name '${projectName}': must match ${PROJECT_NAME_PATTERN} (letters, digits, '.', '_', '-'; 1–128 chars)`,
    );
  }
}

/**
 * Helper re-export so callers can distinguish "project not found at this
 * storage slot" from decrypt failures. Callers that want null rather than
 * throw should check with `tryGetProjectKey` at the `KeyRing` layer.
 */
export { ProjectKeyNotFound };

// Use the generic-unused imports so tree-shaking doesn't complain in
// strictly-unused reports; `asMasterKey` is part of the public re-surface
// for callers that assemble their own `EnvelopeClient` instances.
export { asMasterKey };
