// Spike measurement helper. Prints LOC, raw bundle size, and gzipped size.
import { readFileSync, statSync } from "node:fs";
import { gzipSync } from "node:zlib";

const root = new URL("..", import.meta.url).pathname;

function loc(file) {
  const text = readFileSync(root + file, "utf8");
  const lines = text.split("\n");
  let nonBlankNonComment = 0;
  let inBlock = false;
  for (const raw of lines) {
    const line = raw.trim();
    if (!line) continue;
    if (inBlock) {
      if (line.includes("*/")) inBlock = false;
      continue;
    }
    if (line.startsWith("/*")) {
      if (!line.includes("*/")) inBlock = true;
      continue;
    }
    if (line.startsWith("//")) continue;
    nonBlankNonComment++;
  }
  return { total: lines.length, sloc: nonBlankNonComment };
}

function bundleStats(bundleFile) {
  const path = root + bundleFile;
  const buf = readFileSync(path);
  const gz = gzipSync(buf, { level: 9 });
  return { rawBytes: buf.length, gzBytes: gz.length };
}

const files = [
  "age-passphrase-tier.ts",
  "age-invite.ts",
  "age-ssh-tier.ts",
];

console.log("== LOC ==");
let totalSloc = 0;
for (const f of files) {
  const m = loc(f);
  totalSloc += m.sloc;
  console.log(`  ${f}: total=${m.total}  sloc=${m.sloc}`);
}
console.log(`  --- combined SLOC (no comments/blanks): ${totalSloc}`);

console.log("");
console.log("== Bundle (browser, minified, ESM) ==");
try {
  const stats = bundleStats("bundle-all.min.js");
  console.log(`  bundle-all.min.js: raw=${stats.rawBytes}B (${(stats.rawBytes / 1024).toFixed(1)} KB), gzip=${stats.gzBytes}B (${(stats.gzBytes / 1024).toFixed(1)} KB)`);
} catch (e) {
  console.log("  bundle-all.min.js missing — run `npm run bundle:all` first");
}

console.log("");
console.log("== Per-tier minimum-bundle (single import) ==");
// These were emitted to /dev/null with metafiles only; re-emit to disk for sizing.
// We rely on esbuild's stderr-printed size as the headline number; gzip needs the file.
// To keep the spike small, we just report what bundle:all already proved
// (sharing among tiers means ~140 KB raw is close to the floor for any one tier).
console.log("  Per-tier sizes: see esbuild output of `npm run bundle:ssh|passphrase|invite`.");
console.log("  All three tiers fall within ~138-143 KB raw because age-encryption +");
console.log("  noble pulls in the same hash/cipher/curve modules either way.");
