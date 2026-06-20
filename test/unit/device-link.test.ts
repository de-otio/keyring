import { describe, expect, it } from 'vitest';
import {
  DEVICE_LINK_SAS_DIGITS,
  authorizeDeviceLink,
  beginDeviceLink,
  completeDeviceLink,
  deviceLinkSas,
} from '../../src/device-link.js';
import { invite } from '../../src/invite.js';

function secret32(fill = 0): Uint8Array {
  const s = new Uint8Array(32);
  if (fill === 0) globalThis.crypto.getRandomValues(s);
  else s.fill(fill);
  return s;
}

describe('beginDeviceLink', () => {
  it('mints an age identity and its recipient', async () => {
    const offer = await beginDeviceLink();
    expect(offer.identity).toMatch(/^AGE-SECRET-KEY-1/);
    expect(offer.recipient).toMatch(/^age1/);
  });

  it('mints a different identity each call', async () => {
    const a = await beginDeviceLink();
    const b = await beginDeviceLink();
    expect(a.identity).not.toBe(b.identity);
  });
});

describe('device-link happy path', () => {
  it('transfers the secret and both sides derive the SAME sas (no MITM)', async () => {
    const offer = await beginDeviceLink();
    const master = secret32();

    const grant = await authorizeDeviceLink(master, offer.recipient);
    const done = await completeDeviceLink(offer, grant.blob);

    expect(Buffer.from(done.secret).equals(Buffer.from(master))).toBe(true);
    expect(done.sas).toBe(grant.sas); // user sees matching codes ⇒ trust
    expect(done.sas).toMatch(new RegExp(`^\\d{${DEVICE_LINK_SAS_DIGITS}}$`));
  });
});

describe('device-link MITM detection', () => {
  it('a substituted recipient diverges the two SAS values', async () => {
    // Legit new device and a relay attacker, each with their own identity.
    const newDevice = await beginDeviceLink();
    const attacker = await beginDeviceLink();
    const master = secret32();

    // Existing device is tricked into authorizing to the ATTACKER's recipient.
    const grantToAttacker = await authorizeDeviceLink(master, attacker.recipient);

    // Attacker decrypts and re-encrypts to the real new device.
    const stolen = await completeDeviceLink(attacker, grantToAttacker.blob);
    expect(Buffer.from(stolen.secret).equals(Buffer.from(master))).toBe(true); // relay works…
    const reEncrypted = await invite(stolen.secret, newDevice.recipient);

    // …but the SAS the new device shows differs from the existing device's,
    // because the transcripts (recipient + blob) differ. The user catches it.
    const newDeviceView = await completeDeviceLink(newDevice, reEncrypted);
    expect(newDeviceView.sas).not.toBe(grantToAttacker.sas);
  });
});

describe('deviceLinkSas', () => {
  it('is deterministic and zero-padded to the configured width', async () => {
    const blob = new Uint8Array([1, 2, 3, 4]);
    const a = await deviceLinkSas('age1xyz', blob);
    const b = await deviceLinkSas('age1xyz', blob);
    expect(a).toBe(b);
    expect(a).toMatch(new RegExp(`^\\d{${DEVICE_LINK_SAS_DIGITS}}$`));
  });

  it('changes when the blob or recipient changes', async () => {
    const base = await deviceLinkSas('age1xyz', new Uint8Array([1, 2, 3]));
    const otherBlob = await deviceLinkSas('age1xyz', new Uint8Array([1, 2, 4]));
    const otherRecip = await deviceLinkSas('age1abc', new Uint8Array([1, 2, 3]));
    expect(otherBlob).not.toBe(base);
    expect(otherRecip).not.toBe(base);
  });
});

describe('device-link input validation', () => {
  it('authorizeDeviceLink rejects a non-32-byte secret', async () => {
    const offer = await beginDeviceLink();
    await expect(authorizeDeviceLink(new Uint8Array(16), offer.recipient)).rejects.toThrow(
      /32-byte/,
    );
  });

  it('authorizeDeviceLink rejects a non-Uint8Array secret', async () => {
    const offer = await beginDeviceLink();
    // biome-ignore lint/suspicious/noExplicitAny: deliberately bypassing the type to exercise the runtime guard.
    await expect(authorizeDeviceLink('not bytes' as any, offer.recipient)).rejects.toThrow(
      /32-byte/,
    );
  });

  it('completeDeviceLink rejects a decrypted payload that is not 32 bytes', async () => {
    // Directly invite a 16-byte payload (bypassing authorizeDeviceLink's guard)
    // so the new device decrypts something of the wrong shape.
    const offer = await beginDeviceLink();
    const blob = await invite(new Uint8Array(16), offer.recipient);
    await expect(completeDeviceLink(offer, blob)).rejects.toThrow(/32-byte/);
  });
});
