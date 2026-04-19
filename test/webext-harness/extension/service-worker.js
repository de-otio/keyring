// Minimal MV3 service worker.
//
// Phase A: empty — just loads successfully. Phase E fills in a message
// listener that exercises WebExtensionStorage round-trips so Playwright can
// drive the tests end-to-end.

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  // Placeholder: Phase E adds put/get/delete/list commands here that call
  // into the built @de-otio/keyring/browser bundle.
  sendResponse({ ok: true, echo: message });
  return true;
});
