/**
 * LOCAL STUB — replaced at Phase G integration with an import from
 * `@de-otio/crypto-envelope@^0.2.0-alpha.2`. See
 * `plans/04-phase-g-execution.md`.
 *
 * Signature is pinned so Worker B can code against it without waiting
 * for Worker A's implementation to land.
 */
import type { AnyEnvelope, MasterKey } from '@de-otio/crypto-envelope';

export function rewrapEnvelope(
  _oldEnvelope: AnyEnvelope,
  _oldMaster: MasterKey,
  _newMaster: MasterKey,
): AnyEnvelope {
  throw new Error(
    'rewrapEnvelope stub: keyring Phase G is mid-integration; link crypto-envelope@0.2.0-alpha.2 to wire the real primitive',
  );
}
