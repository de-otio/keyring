import { acceptInvite, generateX25519Identity, identityToRecipient, invite } from './invite.js';

/**
 * Device-link — transfer a 32-byte master (or recovery key) from an already-
 * unlocked device to a new device of the **same user**, over the authenticated
 * age channel ({@link invite}/{@link acceptInvite}), with a **Short
 * Authentication String (SAS)** the user compares on both screens to detect a
 * machine-in-the-middle.
 *
 * ## Why a SAS on top of age
 *
 * age gives confidentiality + integrity to a *named recipient*, but it cannot
 * tell the existing device whether the recipient it received is really the new
 * device's, or an attacker's substituted key relayed in the middle. The SAS
 * closes that gap: each side independently derives a short code from the
 * transcript it actually saw — the new device from *its own* recipient and the
 * blob it received, the existing device from the recipient it *used* and the
 * blob it produced. With no MITM both transcripts are identical, so the codes
 * match; a substituted recipient (or swapped blob) diverges the transcripts and
 * the codes differ. The user comparing the two codes is the security boundary.
 *
 * ## What this module does NOT do
 *
 * - **No rendezvous/transport.** The consuming app moves the recipient string
 *   (e.g. a QR code) to the existing device and the blob back to the new device.
 *   The server, if it relays, relays only opaque bytes (this is the same
 *   "challenge state is the consumer's concern" boundary as {@link invite}).
 * - **No replay/consume-once state.** The app tracks whether an offer has been
 *   used. age binds the transfer to the recipient; consume-once is policy.
 */

/** Bytes carried by a device-link transfer (a master or recovery key). */
export const DEVICE_LINK_SECRET_BYTES = 32;

/** Decimal digits in the SAS the user compares. 6 digits is the Signal/PIN-style
 *  default — enough to make a blind MITM's 1-in-10⁶ guess impractical for a
 *  one-shot interactive pairing. */
export const DEVICE_LINK_SAS_DIGITS = 6;

/** The new device's offer: a fresh age identity (kept private on the new
 *  device) and the recipient string to hand to the existing device. */
export interface DeviceLinkOffer {
  /** age secret key — stays on the new device. */
  identity: string;
  /** age public key (`age1…`) — shown to the existing device (e.g. as a QR). */
  recipient: string;
}

/** The existing device's grant: the encrypted master and the SAS to display. */
export interface DeviceLinkGrant {
  /** age ciphertext to transmit to the new device. */
  blob: Uint8Array;
  /** Short Authentication String the user compares against the new device. */
  sas: string;
}

/** The new device's completion: the recovered secret and the SAS to display. */
export interface DeviceLinkCompletion {
  /** The transferred 32-byte secret (typically the master key). */
  secret: Uint8Array;
  /** SAS the user compares against the existing device. Equal ⇒ no MITM. */
  sas: string;
}

/**
 * New device, step 1: mint an ephemeral age identity and expose its recipient.
 * The `identity` never leaves this device; the `recipient` is shown to the
 * existing device.
 */
export async function beginDeviceLink(): Promise<DeviceLinkOffer> {
  const identity = await generateX25519Identity();
  const recipient = await identityToRecipient(identity);
  return { identity, recipient };
}

/**
 * Existing device, step 2: encrypt the `secret` (a 32-byte master / recovery
 * key) to the new device's `recipient` and compute the SAS over the transcript.
 * Display `sas`; transmit `blob`.
 */
export async function authorizeDeviceLink(
  secret: Uint8Array,
  recipient: string,
): Promise<DeviceLinkGrant> {
  assertSecretShape(secret, 'authorizeDeviceLink');
  const blob = await invite(secret, recipient);
  const sas = await deviceLinkSas(recipient, blob);
  return { blob, sas };
}

/**
 * New device, step 3: decrypt the `blob` with the offer's identity and compute
 * the SAS over the transcript this device saw (its own recipient + the blob it
 * received). Display `sas`; the user confirms it matches the existing device's.
 *
 * **The caller MUST require the user to confirm the SAS match before trusting
 * `secret`.** A mismatch means a machine-in-the-middle — discard the secret.
 */
export async function completeDeviceLink(
  offer: DeviceLinkOffer,
  blob: Uint8Array,
): Promise<DeviceLinkCompletion> {
  const secret = await acceptInvite(blob, offer.identity);
  assertSecretShape(secret, 'completeDeviceLink (decrypted payload)');
  const sas = await deviceLinkSas(offer.recipient, blob);
  return { secret, sas };
}

/**
 * Derive the SAS from a transcript of `(recipient, blob)`. Deterministic and
 * language-portable (SHA-256 over a domain-separated, length-free-ambiguity
 * encoding), so the Dart port produces identical codes: a fixed ASCII context
 * label, then the UTF-8 recipient, a `0x1f` unit separator, then the blob.
 */
export async function deviceLinkSas(recipient: string, blob: Uint8Array): Promise<string> {
  const label = new TextEncoder().encode('keyring/v1/device-link/sas\x1f');
  const rec = new TextEncoder().encode(recipient);
  const transcript = new Uint8Array(label.length + rec.length + 1 + blob.length);
  transcript.set(label, 0);
  transcript.set(rec, label.length);
  transcript[label.length + rec.length] = 0x1f;
  transcript.set(blob, label.length + rec.length + 1);

  const digest = await globalThis.crypto.subtle.digest('SHA-256', transcript);
  // First 4 bytes → big-endian uint32 → fixed-width decimal SAS.
  const n = new DataView(digest).getUint32(0, false);
  const modulus = 10 ** DEVICE_LINK_SAS_DIGITS;
  return String(n % modulus).padStart(DEVICE_LINK_SAS_DIGITS, '0');
}

function assertSecretShape(secret: Uint8Array, where: string): void {
  if (!(secret instanceof Uint8Array) || secret.length !== DEVICE_LINK_SECRET_BYTES) {
    throw new Error(
      `${where}: device-link secret must be a ${DEVICE_LINK_SECRET_BYTES}-byte Uint8Array, got ${
        secret instanceof Uint8Array ? `${secret.length} bytes` : typeof secret
      }`,
    );
  }
}
