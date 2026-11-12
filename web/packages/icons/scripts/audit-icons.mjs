import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const root = "assets";
const themes = ["light", "dark"];

let errors = 0;
let warnings = 0;
let total = 0;

const geometry = new Map();

function walk(dir) {
  if (!fs.existsSync(dir)) return [];

  return fs.readdirSync(dir, { withFileTypes: true })
    .flatMap(entry => {
      const file = path.join(dir, entry.name);
      return entry.isDirectory() ? walk(file) : [file];
    });
}

function normalize(svg) {
  return svg
    .replace(/#[0-9A-Fa-f]{3,8}/g, "#COLOR")
    .replace(/stroke-width="[^"]+"/g, "")
    .replace(/width="[^"]+"/g, "")
    .replace(/height="[^"]+"/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

for (const theme of themes) {
  const files = walk(root)
    .filter(f => f.includes(path.sep + theme + path.sep))
    .filter(f => f.endsWith(".svg"));

  for (const file of files) {
    total++;

    const svg = fs.readFileSync(file, "utf8");

    if (!svg.includes("<svg")) {
      console.error("[ERROR] Invalid SVG:", file);
      errors++;
      continue;
    }

    if (!svg.includes("viewBox=")) {
      console.error("[ERROR] Missing viewBox:", file);
      errors++;
    }

    const hash = crypto
      .createHash("sha256")
      .update(normalize(svg))
      .digest("hex");

    if (geometry.has(hash)) {
      warnings++;
      console.warn(
        "[WARNING] Similar geometry:",
        file,
        "<->",
        geometry.get(hash)
      );
    } else {
      geometry.set(hash, file);
    }
  }
}

console.log("\\nOpenBastion SVG audit");
console.log("---------------------");
console.log("SVG files:", total);
console.log("Warnings:", warnings);
console.log("Errors:", errors);

if (errors > 0) {
  process.exit(1);
}
