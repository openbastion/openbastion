import { readdirSync, readFileSync } from "node:fs";
import { resolve, relative, extname, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const repository = resolve(dirname(fileURLToPath(import.meta.url)), "../../../..");
const roots = ["web/admin-ui/src", "web/packages/ui", "web/openbastion-icons/src"].map((path) => resolve(repository, path));
const extensions = new Set([".css", ".ts", ".tsx"]);
const literalColor = /(?:#[\da-f]{3,8}\b|\brgba?\s*\(|\bhsla?\s*\()/i;
const violations = [];

function walk(directory) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) {
      walk(path);
      continue;
    }
    if (!extensions.has(extname(path))) continue;
    const content = readFileSync(path, "utf8");
    for (const [index, line] of content.split("\n").entries()) {
      if (literalColor.test(line)) {
        violations.push(relative(repository, path) + ":" + (index + 1) + ": " + line.trim());
      }
    }
  }
}

for (const root of roots) walk(root);

if (violations.length > 0) {
  process.stderr.write("Hard-coded colors found outside design tokens:\n" + violations.join("\n") + "\n");
  process.exitCode = 1;
} else {
  process.stdout.write("No hard-coded colors in Admin UI source, shared UI primitives or React icon source.\n");
}
