import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const css = readFileSync(resolve(root, "tokens.css"), "utf8");

function declarations(selector) {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = css.match(new RegExp(`${escaped}\\s*\\{([\\s\\S]*?)\\n\\}`, "m"));
  if (!match) throw new Error(`Missing token block: ${selector}`);
  const values = new Map();
  for (const line of match[1].split("\n")) {
    const declaration = line.match(/^\s*(--[\w-]+)\s*:\s*([^;]+);/);
    if (declaration) values.set(declaration[1], declaration[2].trim());
  }
  return values;
}

function resolveValue(name, values, seen = new Set()) {
  if (seen.has(name)) throw new Error(`Circular token reference: ${name}`);
  const raw = values.get(name);
  if (!raw) throw new Error(`Missing token: ${name}`);
  const reference = raw.match(/^var\((--[\w-]+)\)$/);
  if (!reference) return raw;
  seen.add(name);
  return resolveValue(reference[1], values, seen);
}

function rgb(token, values) {
  const value = resolveValue(token, values);
  const match = value.match(/^#([\da-f]{6})$/i);
  if (!match) throw new Error(`${token} must resolve to an opaque six-digit hex color, got ${value}`);
  const channels = [0, 2, 4].map((offset) => Number.parseInt(match[1].slice(offset, offset + 2), 16) / 255);
  return channels.map((channel) => channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4);
}

function luminance(color) {
  return 0.2126 * color[0] + 0.7152 * color[1] + 0.0722 * color[2];
}

function contrast(foreground, background, values) {
  const first = luminance(rgb(foreground, values));
  const second = luminance(rgb(background, values));
  const [lighter, darker] = first >= second ? [first, second] : [second, first];
  return (lighter + 0.05) / (darker + 0.05);
}

const pairs = [
  ["texte principal", "--ob-color-text-primary", "--ob-color-bg-surface", 4.5],
  ["texte secondaire", "--ob-color-text-secondary", "--ob-color-bg-surface", 4.5],
  ["accent", "--ob-color-accent", "--ob-color-bg-surface", 4.5],
  ["succès", "--ob-color-status-success", "--ob-color-bg-surface", 4.5],
  ["avertissement", "--ob-color-status-warning", "--ob-color-bg-surface", 4.5],
  ["danger", "--ob-color-status-danger", "--ob-color-bg-surface", 4.5],
  ["bordure de contrôle", "--ob-color-border-control", "--ob-color-bg-surface", 3],
  ["focus", "--ob-color-focus", "--ob-color-bg-surface", 3],
  ["texte sur action primaire", "--ob-color-text-on-accent", "--ob-color-accent", 4.5],
  ["texte navigation", "--ob-color-chrome-text", "--ob-color-chrome-background", 4.5],
  ["texte secondaire navigation", "--ob-color-chrome-muted", "--ob-color-chrome-background", 4.5],
  ["accent navigation", "--ob-color-chrome-accent", "--ob-color-chrome-background", 4.5],
  ["accent navigation active", "--ob-color-chrome-accent", "--ob-color-chrome-accent-subtle", 4.5],
];

const lightValues = declarations(":root");
for (const [theme, selector] of [["clair", null], ["sombre", ':root[data-theme="dark"]']]) {
  const values = selector ? new Map([...lightValues, ...declarations(selector)]) : lightValues;
  for (const [label, foreground, background, minimum] of pairs) {
    const actual = contrast(foreground, background, values);
    if (actual + 0.005 < minimum) {
      throw new Error(`${theme}: ${label} ${actual.toFixed(2)}:1 < ${minimum}:1`);
    }
    process.stdout.write(`${theme}: ${label} ${actual.toFixed(2)}:1 (>= ${minimum}:1)\n`);
  }
}
