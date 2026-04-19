import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { type BrowserContext, chromium } from 'playwright';

/**
 * Load the harness MV3 extension into a persistent Playwright context.
 * Returns the context and the extension id so callers can dispatch
 * `chrome.runtime.sendMessage` via the service-worker page.
 *
 * This harness is Phase A scaffolding — Phase E integration tests build on
 * it to drive real `chrome.storage.local` / `session` round-trips against
 * the built `@de-otio/keyring/browser` bundle.
 */
export async function loadHarnessExtension(): Promise<{
  context: BrowserContext;
  extensionId: string;
  dispose: () => Promise<void>;
}> {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const extensionPath = path.join(here, 'extension');

  const userDataDir = path.join(here, '..', '..', '.playwright-mv3-userdata');
  const context = await chromium.launchPersistentContext(userDataDir, {
    channel: 'chromium',
    args: [
      `--disable-extensions-except=${extensionPath}`,
      `--load-extension=${extensionPath}`,
      '--no-first-run',
      '--no-default-browser-check',
    ],
  });

  // Wait for the service-worker to register.
  let [sw] = context.serviceWorkers();
  if (!sw) {
    sw = await context.waitForEvent('serviceworker');
  }
  const url = sw.url();
  const extensionId = new URL(url).host;

  return {
    context,
    extensionId,
    dispose: () => context.close(),
  };
}
