#!/usr/bin/env node
import { createHash } from "node:crypto";
import { readdir, readFile, stat } from "node:fs/promises";
import { join, relative, sep } from "node:path";

const ROOT = process.cwd();
const MANIFEST_PATH = join(ROOT, "docs/licensing/skills-provenance.json");
const LOCK_PATH = join(ROOT, "skills-lock.json");
const SKILLS_ROOT = join(ROOT, ".agents/skills");

function fail(message) {
  console.error(`skills-provenance: ${message}`);
  process.exitCode = 1;
}

async function collectLegacyFiles(directory) {
  const files = [];
  async function walk(current) {
    const entries = await readdir(current, { withFileTypes: true });
    await Promise.all(entries.map(async (entry) => {
      const fullPath = join(current, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === ".git" || entry.name === "node_modules") return;
        await walk(fullPath);
      } else if (entry.isFile()) {
        files.push({
          path: relative(directory, fullPath).split(sep).join("/"),
          content: await readFile(fullPath),
        });
      }
    }));
  }
  await walk(directory);
  // This is intentionally localeCompare: skills-lock.json v1 used this exact
  // ordering. Do not replace with byte ordering without migrating the lock.
  files.sort((left, right) => left.path.localeCompare(right.path));
  return files;
}

async function legacySkillsV1Hash(directory) {
  const hash = createHash("sha256");
  for (const file of await collectLegacyFiles(directory)) {
    hash.update(file.path);
    hash.update(file.content);
  }
  return hash.digest("hex");
}

async function listInstalledSkills() {
  const entries = await readdir(SKILLS_ROOT, { withFileTypes: true });
  const names = [];
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    try {
      const info = await stat(join(SKILLS_ROOT, entry.name, "SKILL.md"));
      if (info.isFile()) names.push(entry.name);
    } catch {
      // Directories without SKILL.md are not skills.
    }
  }
  return names.sort((a, b) => a.localeCompare(b));
}

async function main() {
  const [manifestRaw, lockRaw] = await Promise.all([
    readFile(MANIFEST_PATH, "utf8"),
    readFile(LOCK_PATH, "utf8"),
  ]);
  const manifest = JSON.parse(manifestRaw);
  const lock = JSON.parse(lockRaw);

  if (manifest.schemaVersion !== 1) fail("unsupported provenance manifest schema");
  if (lock.version !== 1) {
    fail(`skills-lock.json version ${lock.version} is not supported by this v1 verifier; review the Skills CLI migration before changing the algorithm`);
    return;
  }
  if (!manifest.skills || !Array.isArray(manifest.skills)) fail("manifest.skills must be an array");
  if (!lock.skills || typeof lock.skills !== "object") fail("skills-lock.json has no skills object");

  const names = new Set();
  const thirdParty = new Set();
  const internal = new Set();
  for (const skill of manifest.skills) {
    if (names.has(skill.name)) fail(`duplicate skill entry: ${skill.name}`);
    names.add(skill.name);

    const localPath = join(ROOT, skill.localPath);
    let bytes;
    try {
      bytes = await readFile(localPath);
    } catch {
      fail(`missing skill file: ${skill.localPath}`);
      continue;
    }
    const sha256 = createHash("sha256").update(bytes).digest("hex");
    if (sha256 !== skill.skillMdSha256) fail(`SKILL.md integrity mismatch: ${skill.name}`);

    if (skill.kind === "third-party") {
      thirdParty.add(skill.name);
      const locked = lock.skills[skill.name];
      if (!locked) {
        fail(`third-party skill missing from skills-lock.json: ${skill.name}`);
        continue;
      }
      if (locked.source !== skill.source || locked.skillPath !== skill.skillPath) {
        fail(`lockfile source/path mismatch: ${skill.name}`);
      }
      if (locked.computedHash !== skill.lockComputedHash) {
        fail(`manifest/lock computedHash mismatch: ${skill.name}`);
      }
      if (!/^[0-9a-f]{40}$/.test(skill.sourceRevision ?? "")) {
        fail(`invalid immutable upstream revision: ${skill.name}`);
      }
      const source = manifest.sources?.[skill.source];
      if (!source || source.license !== "MIT" || source.revision !== skill.sourceRevision) {
        fail(`upstream source metadata mismatch: ${skill.name}`);
      }
      const folder = join(SKILLS_ROOT, skill.name);
      const computed = await legacySkillsV1Hash(folder);
      if (computed !== locked.computedHash) {
        fail(`skills-lock v1 content hash mismatch: ${skill.name}`);
      }
      if (skill.upstreamFilesMatch === false && (!Array.isArray(skill.localDeltas) || skill.localDeltas.length === 0)) {
        fail(`local upstream delta is not documented: ${skill.name}`);
      }
      for (const delta of skill.localDeltas ?? []) {
        if (!/^[0-9a-f]{40}$/.test(delta.introducedByCommit ?? "") || !delta.path || !delta.description) {
          fail(`invalid local delta attribution: ${skill.name}`);
        }
      }
    } else if (skill.kind === "internal") {
      internal.add(skill.name);
      if (lock.skills[skill.name]) fail(`internal skill must not be recorded as a third-party lock entry: ${skill.name}`);
      if (skill.license !== "AGPL-3.0-only" || skill.source !== "openbastion/openbastion") {
        fail(`internal skill licence/source mismatch: ${skill.name}`);
      }
      if (!/^[0-9a-f]{40}$/.test(skill.sourceRevision ?? "")) {
        fail(`invalid internal origin commit: ${skill.name}`);
      }
      if (!skill.originAuthor || !Array.isArray(skill.originCoAuthors)) {
        fail(`missing Git attribution: ${skill.name}`);
      }
    } else {
      fail(`unknown skill kind for ${skill.name}`);
    }
  }

  for (const name of Object.keys(lock.skills)) {
    if (!thirdParty.has(name)) fail(`lockfile entry has no third-party provenance: ${name}`);
  }
  const installed = new Set(await listInstalledSkills());
  for (const name of installed) {
    if (!names.has(name)) fail(`unclassified installed skill: ${name}`);
  }
  for (const name of names) {
    if (!installed.has(name)) fail(`manifest skill is not installed: ${name}`);
  }

  if (thirdParty.size !== 85 || internal.size !== 10 || names.size !== 95) {
    fail(`unexpected inventory counts: ${thirdParty.size} third-party, ${internal.size} internal, ${names.size} total`);
  }

  const notices = await readFile(join(ROOT, "THIRD_PARTY_NOTICES.md"), "utf8");
  for (const copyright of [
    "Copyright (c) 2026 Samuel Berthe",
    "Copyright (c) 2025 Addy Osmani",
    "Copyright (c) 2026 Jakub Krehel",
  ]) {
    if (!notices.includes(copyright)) fail(`third-party notice missing: ${copyright}`);
  }

  if (process.exitCode) process.exit(process.exitCode);
  console.log("skills-provenance: 95 skills classified (85 third-party, 10 internal)");
  console.log("skills-provenance: all 85 Skills CLI v1 lock hashes and 95 SKILL.md SHA-256 values verified");
  console.log("skills-provenance: source revision metadata, licence declarations, notices and local deltas checked");
}

main().catch((error) => {
  console.error("skills-provenance: unexpected error", error);
  process.exitCode = 1;
});
