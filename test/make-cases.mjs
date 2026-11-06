#!/usr/bin/env node
/**
 * Build the inject files that demonstrate the failure paths.
 *
 *   node test/make-cases.mjs                 capture live answers, then build
 *   node test/make-cases.mjs --from <path>   build from a stored capture
 *
 * Every case starts from a real answer for `_ens.estmcmxci.co`, captured from
 * both resolvers, and changes one thing. The DNSSEC gate is upstream of the
 * fetch, so a case that must reach the hash comparison has to keep AD set.
 * A case built from nothing could not do that.
 *
 * The capture is written to test/fixtures/ and the cases to test/cases/.
 * The cases hold absolute file: paths for this machine, so they are generated
 * and not committed. The capture is portable and is kept.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dohAll } from '../lib/doh.mjs';

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.dirname(TEST_DIR);
const FIXTURES = path.join(TEST_DIR, 'fixtures');
const CASES = path.join(TEST_DIR, 'cases');
const NAME = 'estmcmxci.co';
const RESOLVERS = ['cf', 'gg'];

fs.mkdirSync(FIXTURES, { recursive: true });
fs.mkdirSync(CASES, { recursive: true });

const argOf = (f, d) => { const i = process.argv.indexOf(f); return i === -1 ? d : process.argv[i + 1]; };

/* ---------------------------------------------------------- the capture */

const from = argOf('--from', null);
let capture;
if (from) {
  capture = JSON.parse(fs.readFileSync(from, 'utf8'));
  console.log(`capture read from ${from} (${capture.captured_at})`);
} else {
  const apex = await dohAll(`_ens.${NAME}`, RESOLVERS);
  const nic = await dohAll(`_ens.nic.${NAME}`, RESOLVERS);
  capture = { name: NAME, captured_at: new Date().toISOString(), resolvers: RESOLVERS, apex, nic };
  const p = path.join(FIXTURES, `live-${NAME}-${capture.captured_at.slice(0, 10)}.json`);
  fs.writeFileSync(p, `${JSON.stringify(capture, null, 2)}\n`);
  console.log(`captured live to ${path.relative(REPO, p)}`);
}

const clone = o => JSON.parse(JSON.stringify(o));

/** Rewrite the policy= string in every TXT record of an answer. */
function setPolicyUrl(answer, url) {
  for (const rr of answer.Answer ?? []) {
    if (rr.type !== 16) continue;
    const quoted = String(rr.data).startsWith('"');
    const bare = quoted ? String(rr.data).slice(1, -1) : String(rr.data);
    if (!bare.startsWith('policy=')) continue;
    rr.data = quoted ? `"policy=${url}"` : `policy=${url}`;
  }
  return answer;
}

function setPolicyHash(answer, hash) {
  for (const rr of answer.Answer ?? []) {
    if (rr.type !== 16) continue;
    const quoted = String(rr.data).startsWith('"');
    const bare = quoted ? String(rr.data).slice(1, -1) : String(rr.data);
    if (!bare.startsWith('policy_hash=')) continue;
    rr.data = quoted ? `"policy_hash=${hash}"` : `policy_hash=${hash}`;
  }
  return answer;
}

const mapApex = fn => {
  const out = {};
  for (const k of RESOLVERS) out[k] = fn(clone(capture.apex[k]), k);
  return out;
};

const write = (file, apex, nic) => {
  const body = { [NAME]: { apex, ...(nic ? { nic } : {}) } };
  const p = path.join(CASES, file);
  fs.writeFileSync(p, `${JSON.stringify(body, null, 2)}\n`);
  console.log(`  ${path.relative(REPO, p)}`);
};

/* --------------------------------------------------------- the documents */

/* The altered document is the fixture with one line appended. Its bytes and
 * its size both differ, so a mismatch report can be checked on both. */
const original = fs.readFileSync(path.join(REPO, 'fixtures', 'specimen-deprecation-policy.md'));
const altered = Buffer.concat([original,
  Buffer.from('\nThis line was appended to make the bytes differ from the declared hash.\n')]);
const alteredPath = path.join(FIXTURES, 'altered-policy.md');
fs.writeFileSync(alteredPath, altered);
const alteredUrl = pathToFileURL(alteredPath).href;

console.log('cases:');

/* 2. hash mismatch. The declared hash is untouched, the document is not the
 *    one it commits to. This is the condition the archive exists to catch. */
write('hash-mismatch.json', mapApex(a => setPolicyUrl(a, alteredUrl)), clone(capture.nic));

/* 3. dead URL. A 404 at a live host. */
write('dead-url.json', mapApex(a => setPolicyUrl(a,
  'https://raw.githubusercontent.com/steg-eth/gtld-policy-archive/master/fixtures/this-file-was-deleted.md')),
  clone(capture.nic));

/* 3b. dead host, which fails before any HTTP status exists. */
write('dead-host.json', mapApex(a => setPolicyUrl(a,
  'https://policy.operator-that-no-longer-exists.invalid/deprecation.md')),
  clone(capture.nic));

/* 4. DNSSEC gate. The records are the real ones and AD is clear, which is
 *    what an unsigned zone or a resolver that did not validate looks like. */
write('dnssec-unvalidated.json', mapApex(a => { a.AD = false; return a; }), clone(capture.nic));

/* Extra. The two resolvers do not agree on the URL. */
let flip = false;
write('resolver-disagreement.json',
  mapApex(a => (flip = !flip) ? a : setPolicyUrl(a, 'https://example.com/other-policy.md')),
  clone(capture.nic));

/* Extra. The nic form declares a different document. Step 4 says to record
 * the disagreement and carry on from the apex. */
write('name-disagreement.json', mapApex(a => a), mapApex(a =>
  setPolicyHash(setPolicyUrl(a, 'https://example.com/nic-policy.md'),
    `0x${'11'.repeat(32)}`)));

/* Extra. The record is present but not well formed. */
write('malformed-hash.json', mapApex(a => setPolicyHash(a, '0xdeadbeef')), clone(capture.nic));

console.log(`\naltered document: ${path.relative(REPO, alteredPath)} (${altered.length} bytes)`);
