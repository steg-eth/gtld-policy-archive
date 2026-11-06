#!/usr/bin/env node
/**
 * Archive the policy document that a name declares in DNS.
 *
 *   node archive-policy.mjs estmcmxci.co
 *   node archive-policy.mjs --population population.example.json
 *
 * What it does, for each name:
 *
 *   1. Queries TXT at _ens.<name> and at _ens.nic.<name>, at two resolvers,
 *      and records whether the two resolvers said the same thing.
 *   2. Requires the apex answer to be DNSSEC validated. The whole point is
 *      that the operator signed the record, so an unvalidated answer is
 *      worthless and stops the run.
 *   3. Reads policy= and policy_hash= out of the TXT strings, in any order,
 *      and ignores every other string.
 *   4. Notes a disagreement with the nic form, then carries on with the apex.
 *      The nic form is this project's own convention, not ENS's, and it never
 *      decides anything.
 *   5. Fetches the URL, with a size cap and a redirect cap.
 *   6. Hashes the raw bytes with sha256 and compares to the declared hash.
 *   7. Writes the snapshot, or the failure.
 *
 * It guards against bitrot. It does not enforce anything, and it never judges
 * whether a policy is any good. What a compliant policy must contain is a
 * governance question for the ENS DAO and is not in this tool.
 *
 * See SPEC.md for the record format and README.md for the archive layout.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { AD_STATUS, adStatus, TYPE_TXT } from './lib/dnssec.mjs';
import { RESOLVERS, dohAll, CONCURRENCY } from './lib/doh.mjs';
import { parsePolicyRecord, sameRecord } from './lib/txt.mjs';
import {
  fetchPolicy, extensionFor, FetchProblem,
  MAX_BYTES, MAX_REDIRECTS, TIMEOUT_MS,
} from './lib/policy-fetch.mjs';
import {
  writeSnapshot, writeRaw, appendFailure, appendObservation,
  lastVerified, safeName, today, rawSha256,
} from './lib/archive.mjs';

const VERSION = '1.0';
const REPO_ROOT = path.dirname(fileURLToPath(import.meta.url));

/* ------------------------------------------------------------------ args */

/** The harness's argument shape: a flag, then its value. */
const arg = (name, fallback) => {
  const i = process.argv.indexOf(name);
  if (i === -1) return fallback;
  const v = process.argv[i + 1];
  if (!v || v.startsWith('--')) { console.error(`${name} needs a value`); process.exit(2); }
  return v;
};
const flag = name => process.argv.includes(name);
const num = (name, fallback) => {
  const v = arg(name, null);
  if (v === null) return fallback;
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) { console.error(`${name} needs a positive number`); process.exit(2); }
  return n;
};

if (flag('--help') || flag('-h')) {
  console.log(`archive-policy ${VERSION}

  node archive-policy.mjs <name> [<name> ...]
  node archive-policy.mjs --population <path>

Options
  --population <path>     a JSON array of names, or one name per line
  --archive <dir>         where to write          (default ${path.join(REPO_ROOT, 'archive')})
  --resolvers cf,gg       which resolvers to ask  (default cf,gg)
  --concurrency <n>       names at a time         (default ${CONCURRENCY})
  --max-bytes <n>         response size cap       (default ${MAX_BYTES})
  --max-redirects <n>     redirect cap            (default ${MAX_REDIRECTS})
  --timeout <ms>          per request timeout     (default ${TIMEOUT_MS})
  --allow-insecure-url    also read http: and file: URLs, to build test cases
  --no-nic                do not query _ens.nic.<name>
  --inject <path>         use stored DoH answers instead of querying, to build
                          test cases. See test/README.md
  --dry-run               do everything, write nothing
  --json                  print the run as JSON on stdout

Exit status is 1 if any name produced a failure, otherwise 0.`);
  process.exit(0);
}

const ARCHIVE_ROOT = path.resolve(arg('--archive', path.join(REPO_ROOT, 'archive')));
const RESOLVER_KEYS = arg('--resolvers', 'cf,gg').split(',').map(s => s.trim()).filter(Boolean);
for (const k of RESOLVER_KEYS) {
  if (!RESOLVERS[k]) { console.error(`unknown resolver: ${k}. known: ${Object.keys(RESOLVERS).join(', ')}`); process.exit(2); }
}
if (!RESOLVER_KEYS.length) { console.error('--resolvers needs at least one resolver'); process.exit(2); }

const OPTS = {
  maxBytes: num('--max-bytes', MAX_BYTES),
  maxRedirects: num('--max-redirects', MAX_REDIRECTS),
  timeout: num('--timeout', TIMEOUT_MS),
  allowInsecure: flag('--allow-insecure-url'),
};
const QUERY_NIC = !flag('--no-nic');
const DRY_RUN = flag('--dry-run');
const AS_JSON = flag('--json');
const CONC = num('--concurrency', CONCURRENCY);

const INJECT = (() => {
  const p = arg('--inject', null);
  if (!p) return null;
  const parsed = JSON.parse(fs.readFileSync(p, 'utf8'));
  return parsed;
})();

/** Names from the command line, plus a population file if one was given. */
function collectNames() {
  const flagsWithValues = new Set(['--population', '--archive', '--resolvers', '--concurrency',
    '--max-bytes', '--max-redirects', '--timeout', '--inject']);
  const argv = process.argv.slice(2);
  const positional = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) { if (flagsWithValues.has(a)) i++; continue; }
    positional.push(a);
  }
  const pop = arg('--population', null);
  const fromFile = [];
  if (pop) {
    const body = fs.readFileSync(pop, 'utf8');
    let parsed = null;
    try { parsed = JSON.parse(body); } catch { /* not JSON, read it as lines */ }
    if (Array.isArray(parsed)) fromFile.push(...parsed.map(String));
    else if (parsed && Array.isArray(parsed.names)) fromFile.push(...parsed.names.map(String));
    else fromFile.push(...body.split('\n').map(s => s.trim()).filter(s => s && !s.startsWith('#')));
  }
  return [...new Set([...positional, ...fromFile])];
}

const NAMES = collectNames();
if (!NAMES.length) {
  console.error('give a name, or --population <path>. --help for the rest.');
  process.exit(2);
}

/* ------------------------------------------------- read one name from DNS */

/** Classify one resolver's answer at one name. */
function readOne(answer) {
  const parsed = parsePolicyRecord(answer);
  return {
    answered: answer !== null && answer !== undefined,
    dns_status: answer && typeof answer.Status === 'number' ? answer.Status : null,
    ad_status: adStatus(answer, TYPE_TXT),
    txt_records: answer && Array.isArray(answer.Answer)
      ? answer.Answer.filter(a => a.type === TYPE_TXT).length : 0,
    url: parsed.url,
    declared_hash: parsed.declared_hash,
    present: parsed.present,
    well_formed: parsed.well_formed,
    problem: parsed.problem,
    strings: parsed.strings,
    other_strings: parsed.other_strings,
  };
}

/** validated only when every resolver that answered validated. */
function combineAd(perResolver) {
  const seen = Object.values(perResolver).map(r => r.ad_status)
    .filter(v => v !== AD_STATUS.NO_ANSWER);
  if (!seen.length) return AD_STATUS.NO_ANSWER;
  return seen.every(v => v === AD_STATUS.VALIDATED) ? AD_STATUS.VALIDATED : AD_STATUS.UNVALIDATED;
}

/**
 * Did the resolvers say the same thing?
 *
 * null means there was only one vantage point, because the others did not
 * answer at all. That is weaker evidence than agreement but it is not a
 * contradiction, so it does not read as false.
 */
function combineAgreement(perResolver) {
  const keys = Object.keys(perResolver).filter(k => perResolver[k].answered);
  if (keys.length < 2) return null;
  const first = perResolver[keys[0]];
  return keys.every(k => perResolver[k].url === first.url
    && perResolver[k].declared_hash === first.declared_hash);
}

/** One PolicyRecord: what DNS said at one name, at one observation. */
function buildRecord(nameQueried, raw, observedAt) {
  const per = {};
  for (const k of RESOLVER_KEYS) per[k] = readOne(raw[k]);
  const chosen = RESOLVER_KEYS.map(k => per[k]).find(r => r.answered && r.present) ?? null;
  return {
    name_queried: nameQueried,
    url: chosen ? chosen.url : null,
    declared_hash: chosen ? chosen.declared_hash : null,
    observed_at: observedAt,
    ad_status: combineAd(per),
    resolvers_agreed: combineAgreement(per),
    present: Object.values(per).some(r => r.present),
    well_formed: chosen ? chosen.well_formed : false,
    problem: chosen ? chosen.problem : null,
    per_resolver: per,
    raw,
  };
}

/* ------------------------------------------------------------- one name */

async function processName(rawName) {
  const name = safeName(rawName);
  const observedAt = new Date().toISOString();
  const apexName = `_ens.${name}`;
  const nicName = `_ens.nic.${name}`;
  const injected = (INJECT && INJECT[name]) || {};

  const apexRaw = injected.apex ?? await dohAll(apexName, RESOLVER_KEYS);
  const nicRaw = QUERY_NIC ? (injected.nic ?? await dohAll(nicName, RESOLVER_KEYS)) : null;

  const apex = buildRecord(apexName, apexRaw, observedAt);
  const nic = nicRaw ? buildRecord(nicName, nicRaw, observedAt) : null;

  const rawBundle = {
    name, observed_at: observedAt,
    resolvers: RESOLVER_KEYS,
    apex: { name: apexName, answers: apexRaw },
    nic: nic ? { name: nicName, answers: nicRaw } : null,
    injected: Boolean(injected.apex || injected.nic),
  };
  const records = { apex, nic };
  const tool = {
    name: 'gtld-policy-archive',
    version: VERSION,
    resolvers: RESOLVER_KEYS,
    hash: 'sha256',
    hashed: 'raw response bytes, no normalisation',
    raw_sha256: rawSha256(rawBundle),
  };

  /* Everything below either fails or writes a snapshot, never both. The one
   * exception is name_disagreement, which the brief says to record and then
   * carry on from. It is appended to failures.jsonl as the brief asks and it
   * is also carried on the snapshot as a note, so the snapshot stays the one
   * outcome of this observation. */
  const notes = [];

  const appendOrNot = (n, f) => DRY_RUN ? { ...f, kind: f.kind } : appendFailure(ARCHIVE_ROOT, n, f);
  const observe = (n, o) => DRY_RUN ? o : appendObservation(ARCHIVE_ROOT, n, o);

  const fail = (kind, detail, extra = {}) => {
    const rawPath = DRY_RUN ? null : writeRaw(ARCHIVE_ROOT, name, rawBundle);
    const failure = appendOrNot(name, {
      observed_at: observedAt, kind, detail,
      url: apex.url ?? null,
      declared_hash: apex.declared_hash ?? null,
      computed_hash: extra.computed_hash ?? null,
      byte_size: extra.byte_size ?? null,
      final_url: extra.final_url ?? null,
      ad_status: apex.ad_status,
      resolvers_agreed: apex.resolvers_agreed,
      raw_path: rawPath,
      raw_sha256: tool.raw_sha256,
    });
    observe(name, {
      observed_at: observedAt, outcome: 'failed', kind, detail,
      computed_hash: extra.computed_hash ?? null,
      snapshot: null, raw_path: rawPath, raw_sha256: tool.raw_sha256,
    });
    return { name, outcome: 'failed', kind, detail, failure, records, raw_path: rawPath };
  };


  /* 1 and 2. Is there a record at all, and did the operator sign it? The
   * no-answer class covers both "the query failed" and "the name has no TXT",
   * so nothing-there is no_record and there-but-unsigned is dnssec_unvalidated. */
  if (apex.ad_status === AD_STATUS.NO_ANSWER) {
    const anyAnswered = Object.values(apex.per_resolver).some(r => r.answered);
    return fail('no_record', anyAnswered
      ? `no TXT record at ${apexName}`
      : `no resolver answered for ${apexName}`);
  }
  if (apex.ad_status !== AD_STATUS.VALIDATED) {
    const per = RESOLVER_KEYS.map(k => `${k}=${apex.per_resolver[k].ad_status}`).join(' ');
    return fail('dnssec_unvalidated',
      `${apexName} did not validate, so the record is not evidence the operator signed it (${per})`);
  }

  /* 1, continued. Two vantage points that contradict each other cannot be
   * archived from, so the contradiction is the result. */
  if (apex.resolvers_agreed === false) {
    const per = RESOLVER_KEYS
      .map(k => `${k}: url=${apex.per_resolver[k].url ?? 'none'} hash=${apex.per_resolver[k].declared_hash ?? 'none'}`)
      .join(' | ');
    return fail('resolver_disagreement', `resolvers disagree at ${apexName}. ${per}`);
  }

  /* 3. A record that is present but not well formed is not a record. */
  if (!apex.present) return fail('no_record', `no policy= or policy_hash= at ${apexName}`);
  if (!apex.well_formed) return fail('no_record', `${apexName}: ${apex.problem}`);

  /* 4. The nic form is data, never authority. */
  if (nic && nic.present && nic.well_formed && !sameRecord(apex, nic)) {
    const detail = `${nicName} declares url=${nic.url} hash=${nic.declared_hash}, `
      + `${apexName} declares url=${apex.url} hash=${apex.declared_hash}. `
      + 'The apex is authoritative: ENS v1 reads _ens.<name> at DNSClaimChecker.getOwnerAddress '
      + 'and contracts-v2 #419 reads the same name. Archiving from the apex.';
    notes.push({ kind: 'name_disagreement', detail });
    if (!DRY_RUN) {
      appendFailure(ARCHIVE_ROOT, name, {
        observed_at: observedAt, kind: 'name_disagreement', detail,
        url: apex.url, declared_hash: apex.declared_hash,
        nic_url: nic.url, nic_declared_hash: nic.declared_hash,
        computed_hash: null, byte_size: null, final_url: null,
        archived_anyway: true, raw_path: null, raw_sha256: tool.raw_sha256,
      });
    }
  } else if (nic && nic.present && !nic.well_formed) {
    notes.push({ kind: 'nic_malformed', detail: `${nicName}: ${nic.problem}` });
  }

  /* 5 and 6. */
  let got;
  try {
    got = await fetchPolicy(apex.url, OPTS);
  } catch (e) {
    if (!(e instanceof FetchProblem)) throw e;
    return fail('fetch_failed', e.message);
  }

  if (got.computed_hash.toLowerCase() !== apex.declared_hash.toLowerCase()) {
    /* The bytes are not stored. The hash and the size are enough to prove
     * that something changed, and the archive does not hold content that
     * nobody signed for. */
    return fail('hash_mismatch',
      `declared ${apex.declared_hash}, computed ${got.computed_hash} over ${got.byte_size} bytes `
      + `from ${got.final_url}. The bytes are not stored.`,
      { computed_hash: got.computed_hash, byte_size: got.byte_size, final_url: got.final_url });
  }

  /* 7. An unchanged document is not a new snapshot. git then holds the
   * changes and nothing else, which is why the archive is a repository. */
  const previous = lastVerified(ARCHIVE_ROOT, name);
  if (previous && previous.computed_hash.toLowerCase() === got.computed_hash.toLowerCase()) {
    const rawPath = DRY_RUN ? null : writeRaw(ARCHIVE_ROOT, name, rawBundle);
    observe(name, {
      observed_at: observedAt, outcome: 'verified_unchanged', kind: null,
      computed_hash: got.computed_hash, declared_hash: apex.declared_hash,
      byte_size: got.byte_size, final_url: got.final_url,
      snapshot: previous.date, notes,
      raw_path: rawPath, raw_sha256: tool.raw_sha256,
    });
    return { name, outcome: 'verified_unchanged', snapshot: previous.date,
      computed_hash: got.computed_hash, byte_size: got.byte_size, notes, raw_path: rawPath };
  }

  if (DRY_RUN) {
    return { name, outcome: 'verified_new', snapshot: today(), dry_run: true,
      computed_hash: got.computed_hash, byte_size: got.byte_size, notes };
  }

  const written = writeSnapshot(ARCHIVE_ROOT, name, {
    bytes: got.bytes,
    ext: extensionFor(got.final_url, got.content_type),
    snapshot: {
      computed_hash: got.computed_hash,
      declared_hash: apex.declared_hash,
      final_url: got.final_url,
      requested_url: apex.url,
      redirects: got.redirects,
      content_type: got.content_type,
      byte_size: got.byte_size,
      http_status: got.http_status,
    },
    records, notes, tool,
  });
  appendObservation(ARCHIVE_ROOT, name, {
    observed_at: observedAt, outcome: 'verified_new', kind: null,
    computed_hash: got.computed_hash, declared_hash: apex.declared_hash,
    byte_size: got.byte_size, final_url: got.final_url,
    snapshot: written.label, notes,
    raw_path: path.join(written.label, 'record.json'), raw_sha256: tool.raw_sha256,
  });
  return { name, outcome: 'verified_new', snapshot: written.label,
    computed_hash: got.computed_hash, byte_size: got.byte_size,
    dir: path.relative(REPO_ROOT, written.dir), notes };
}

/* ----------------------------------------------------------------- run */

const results = [];
const queue = [...NAMES];
await Promise.all(Array.from({ length: Math.min(CONC, queue.length) }, async () => {
  while (queue.length) {
    const n = queue.shift();
    try {
      results.push(await processName(n));
    } catch (e) {
      results.push({ name: n, outcome: 'error', detail: e && e.message ? e.message : String(e) });
    }
  }
}));

results.sort((a, b) => String(a.name).localeCompare(String(b.name)));

if (AS_JSON) {
  console.log(JSON.stringify({
    tool: 'gtld-policy-archive', version: VERSION,
    archive: ARCHIVE_ROOT, resolvers: RESOLVER_KEYS,
    dry_run: DRY_RUN, results,
  }, null, 2));
} else {
  for (const r of results) {
    if (r.outcome === 'verified_new') {
      console.log(`${r.name}: archived ${r.snapshot} ${r.byte_size} bytes ${r.computed_hash}`);
    } else if (r.outcome === 'verified_unchanged') {
      console.log(`${r.name}: unchanged since ${r.snapshot} ${r.computed_hash}`);
    } else if (r.outcome === 'failed') {
      console.log(`${r.name}: ${r.kind}: ${r.detail}`);
    } else {
      console.log(`${r.name}: error: ${r.detail}`);
    }
    for (const n of r.notes ?? []) console.log(`  note ${n.kind}: ${n.detail}`);
  }
  if (DRY_RUN) console.log('(dry run, nothing written)');
}

const bad = results.filter(r => r.outcome === 'failed' || r.outcome === 'error').length;
process.exit(bad ? 1 : 0);
