import fs from "node:fs";
import path from "node:path";

fs.mkdirSync("dist", { recursive: true });

fs.copyFileSync(
  "src/styles/tokens.css",
  "dist/tokens.css"
);

console.log("[OK] CSS tokens copied to dist/");
