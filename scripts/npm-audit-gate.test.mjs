import assert from 'node:assert/strict';
import test from 'node:test';
import { evaluateAudit } from './npm-audit-gate.mjs';

const advisory = 'https://github.com/advisories/GHSA-fc5q-39xc-vjpf';
const date = new Date('2026-11-18T12:00:00Z');

function fixture({ runtime = false, extraAdvisory = false } = {}) {
  const vulnerabilities = {
    'picomatch': {
      nodes: ['node_modules/picomatch'],
      via: [{ name: 'picomatch', url: advisory }],
    },
    'tinyglobby': { nodes: ['node_modules/tinyglobby'], via: ['picomatch'] },
    'vite': { nodes: ['node_modules/vite'], via: ['tinyglobby'] },
  };
  if (extraAdvisory) vulnerabilities.vite.via.push({ name: 'vite', url: 'https://example.test/other-advisory' });
  const lock = {
    packages: {
      'node_modules/picomatch': { version: '4.0.7', dev: !runtime },
      'node_modules/tinyglobby': { version: '0.2.17', dev: true },
      'node_modules/vite': { version: '8.3.7', dev: true },
    },
  };
  return { audit: { vulnerabilities }, lock };
}

test('accepts only the reviewed advisory when the entire chain is dev-only', () => {
  const { audit, lock } = fixture();
  assert.equal(evaluateAudit(audit, lock, date).allowed, true);
});

test('rejects an additional unrelated advisory', () => {
  const { audit, lock } = fixture({ extraAdvisory: true });
  assert.equal(evaluateAudit(audit, lock, date).allowed, false);
});

test('rejects the advisory when picomatch is a production dependency', () => {
  const { audit, lock } = fixture({ runtime: true });
  assert.match(evaluateAudit(audit, lock, date).reason, /not exclusively a dev dependency/);
});

test('rejects an incomplete lockfile mapping', () => {
  const { audit, lock } = fixture();
  delete lock.packages['node_modules/tinyglobby'];
  assert.match(evaluateAudit(audit, lock, date).reason, /missing from package-lock/);
});

test('rejects an expired exception', () => {
  const { audit, lock } = fixture();
  assert.match(evaluateAudit(audit, lock, new Date('2026-12-03T00:00:00Z')).reason, /expired/);
});

test('accepts an empty audit report without using the exception', () => {
  assert.deepEqual(evaluateAudit({ vulnerabilities: {} }, { packages: {} }, date), {
    allowed: true,
    reason: 'no known vulnerabilities',
    packages: [],
  });
});

test('does not require an exception when the audit is clean after the review date', () => {
  assert.equal(evaluateAudit({ vulnerabilities: {} }, { packages: {} }, new Date('2026-12-03T00:00:00Z')).allowed, true);
});
