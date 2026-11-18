#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const ALLOWED_ADVISORY = 'https://github.com/advisories/GHSA-fc5q-39xc-vjpf';
const EXCEPTION_REVIEW_BY = '2026-12-02';

/**
 * Accepts only the explicitly reviewed picomatch advisory, and only when every
 * affected package in npm's dependency chain is locked as a dev dependency.
 * Every other advisory, ambiguous graph edge, or production dependency fails closed.
 */
export function evaluateAudit(audit, lock, now = new Date()) {
  const vulnerabilities = audit?.vulnerabilities;
  if (!vulnerabilities || typeof vulnerabilities !== 'object') {
    return { allowed: false, reason: 'npm audit JSON has no vulnerabilities object' };
  }

  const names = Object.keys(vulnerabilities);
  if (names.length === 0) return { allowed: true, reason: 'no known vulnerabilities', packages: [] };
  if (now.toISOString().slice(0, 10) > EXCEPTION_REVIEW_BY) {
    return { allowed: false, reason: `temporary exception expired on ${EXCEPTION_REVIEW_BY}` };
  }

  const packages = lock?.packages;
  if (!packages || typeof packages !== 'object') {
    return { allowed: false, reason: 'package-lock.json has no packages map' };
  }

  let advisoryFound = false;
  const visited = new Set();

  function trace(name, ancestry = new Set()) {
    if (ancestry.has(name)) return { ok: false, reason: `cyclic advisory chain at ${name}` };
    const vulnerability = vulnerabilities[name];
    if (!vulnerability || !Array.isArray(vulnerability.via) || vulnerability.via.length === 0) {
      return { ok: false, reason: `unresolved advisory chain at ${name}` };
    }

    for (const node of vulnerability.nodes ?? []) {
      const locked = packages[node];
      if (!locked) return { ok: false, reason: `${node} is missing from package-lock.json` };
      if (locked.dev !== true) return { ok: false, reason: `${node} is not exclusively a dev dependency` };
      if (name === 'picomatch' && compareVersions(locked.version, '4.0.7') > 0) {
        return { ok: false, reason: `picomatch ${locked.version} is outside the reviewed affected range` };
      }
    }
    if (!Array.isArray(vulnerability.nodes) || vulnerability.nodes.length === 0) {
      return { ok: false, reason: `${name} has no concrete lockfile nodes` };
    }

    const next = new Set(ancestry);
    next.add(name);
    for (const via of vulnerability.via) {
      if (typeof via === 'string') {
        const result = trace(via, next);
        if (!result.ok) return result;
        continue;
      }
      if (!via || typeof via !== 'object' || via.url !== ALLOWED_ADVISORY || via.name !== 'picomatch') {
        return { ok: false, reason: `unexpected advisory affecting ${name}` };
      }
      advisoryFound = true;
    }
    visited.add(name);
    return { ok: true };
  }

  for (const name of names) {
    const result = trace(name);
    if (!result.ok) return { allowed: false, reason: result.reason };
  }
  if (!advisoryFound || !visited.has('picomatch')) {
    return { allowed: false, reason: 'the exact reviewed picomatch advisory was not found' };
  }

  return {
    allowed: true,
    reason: `only ${ALLOWED_ADVISORY} remains, through dev dependencies; review by ${EXCEPTION_REVIEW_BY}`,
    packages: names.sort(),
  };
}

function compareVersions(left, right) {
  const parse = (value) => typeof value === 'string' && /^\d+(\.\d+){1,2}$/.test(value)
    ? value.split('.').map(Number)
    : null;
  const a = parse(left);
  const b = parse(right);
  if (!a || !b) return Number.POSITIVE_INFINITY;
  for (let i = 0; i < Math.max(a.length, b.length); i += 1) {
    const difference = (a[i] ?? 0) - (b[i] ?? 0);
    if (difference !== 0) return difference;
  }
  return 0;
}

function main() {
  let lock;
  try {
    lock = JSON.parse(readFileSync('package-lock.json', 'utf8'));
  } catch (error) {
    console.error(`npm audit gate: cannot read package-lock.json: ${error.message}`);
    process.exitCode = 1;
    return;
  }

  const result = spawnSync('npm', ['audit', '--json'], {
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.error) {
    console.error(`npm audit gate: could not execute npm audit: ${result.error.message}`);
    process.exitCode = 1;
    return;
  }

  let audit;
  try {
    audit = JSON.parse(result.stdout);
  } catch {
    console.error('npm audit gate: npm audit did not return valid JSON');
    if (result.stderr) console.error(result.stderr.trim());
    process.exitCode = 1;
    return;
  }

  const vulnerabilityNames = Object.keys(audit.vulnerabilities ?? {});
  if (result.status === 0 && vulnerabilityNames.length === 0) {
    console.log('npm audit gate: PASS — no known vulnerabilities');
    return;
  }
  if (result.status !== 0 && vulnerabilityNames.length === 0) {
    console.error('npm audit gate: FAIL — npm audit exited non-zero without a vulnerability report (registry or audit failure)');
    if (result.stderr) console.error(result.stderr.trim());
    process.exitCode = 1;
    return;
  }

  const decision = evaluateAudit(audit, lock);
  if (decision.allowed) {
    console.warn(`npm audit gate: TEMPORARY EXCEPTION — ${decision.reason}`);
    console.warn(`npm audit gate: affected dependency records: ${decision.packages.join(', ')}`);
    console.warn('npm audit gate: this is not a remediation; do not expose untrusted glob patterns to these build tools.');
    return;
  }

  console.error(`npm audit gate: FAIL — ${decision.reason}`);
  console.error(`npm audit exit status: ${result.status ?? 'unknown'}`);
  if (result.stderr) console.error(result.stderr.trim());
  process.exitCode = 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
