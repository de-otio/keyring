// Count SLOC (non-blank, non-comment lines) for any list of files.
// Same methodology as ./measure.mjs.
import { readFileSync } from "node:fs";

function sloc(path) {
  const text = readFileSync(path, "utf8");
  const lines = text.split("\n");
  let n = 0;
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
    n++;
  }
  return { total: lines.length, sloc: n };
}

const files = process.argv.slice(2);
let totalSloc = 0;
let totalLines = 0;
for (const f of files) {
  const m = sloc(f);
  totalSloc += m.sloc;
  totalLines += m.total;
  console.log(`${f}: total=${m.total}  sloc=${m.sloc}`);
}
console.log(`---`);
console.log(`combined: total=${totalLines}  sloc=${totalSloc}`);
