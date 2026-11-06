/**
 * The archive on disk.
 *
 *   archive/<name>/<YYYY-MM-DD>/policy.<ext>    the document, verified
 *   archive/<name>/<YYYY-MM-DD>/record.json     what DNS said, and the result
 *   archive/<name>/failures.jsonl               append only, never overwritten
 *   archive/<name>/observations.jsonl           append only, one line per run
 *   archive/<name>/raw/<timestamp>.json         raw answers, when no snapshot
 *
 * The last two paths are not in the brief. observations.jsonl holds the
 * verified_unchanged line, which the brief asks for but gives no home: it is
 * not a failure, and failures.jsonl must stay a file of failures. The raw
 * directory keeps the promise that no raw answer is discarded, for the runs
 * that write no dated directory. A snapshot's record.json embeds its own raw
 * answers, so a raw answer is kept exactly once, and the observations line
 * always names the path that holds it.
 *
 * A snapshot never changes after it is written. A new snapshot is written only
 * when the document's bytes differ from the last verified copy, so git holds
 * the changes and nothing else, which is why the archive is a repository.
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

export const SCHEMA_SNAPSHOT = 'gtld-policy-archive/snapshot/1';
export const SCHEMA_OBSERVATION = 'gtld-policy-archive/observation/1';
export const SCHEMA_FAILURE = 'gtld-policy-archive/failure/1';

/** The failure kinds. The brief fixes this list. */
export const FAILURE_KINDS = [
  'no_record',
  'resolver_disagreement',
  'dnssec_unvalidated',
  'name_disagreement',
  'fetch_failed',
  'hash_mismatch',
];

const DATE_DIR = /^\d{4}-\d{2}-\d{2}(-\d{2})?$/;

/** A DNS name, safe to use as one path segment. */
export function safeName(name) {
  const n = String(name ?? '').trim().toLowerCase().replace(/\.$/, '');
  if (!n) throw new Error('empty name');
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/.test(n)) {
    throw new Error(`not a usable DNS name: ${JSON.stringify(String(name))}`);
  }
  return n;
}

export const today = (d = new Date()) => d.toISOString().slice(0, 10);

/** An ISO instant with the characters that are awkward in a filename removed. */
export const stamp = (d = new Date()) =>
  d.toISOString().replace(/[:]/g, '').replace(/\.\d{3}Z$/, 'Z');

export const rawSha256 = obj =>
  `0x${crypto.createHash('sha256').update(JSON.stringify(obj)).digest('hex')}`;

export function nameDir(root, name) {
  return path.join(root, safeName(name));
}

/**
 * The most recent verified snapshot for a name, or null.
 *
 * Dated directories sort lexically in time order, including the -02 form that
 * a second distinct document on one day takes.
 */
export function lastVerified(root, name) {
  const dir = nameDir(root, name);
  if (!fs.existsSync(dir)) return null;
  const dates = fs.readdirSync(dir)
    .filter(d => DATE_DIR.test(d))
    .sort()
    .reverse();
  for (const d of dates) {
    const rp = path.join(dir, d, 'record.json');
    if (!fs.existsSync(rp)) continue;
    try {
      const rec = JSON.parse(fs.readFileSync(rp, 'utf8'));
      if (rec.outcome === 'verified' && rec.snapshot && rec.snapshot.computed_hash) {
        return { date: d, dir: path.join(dir, d), record: rec,
          computed_hash: rec.snapshot.computed_hash };
      }
    } catch { /* an unreadable record is not a last good copy */ }
  }
  return null;
}

/** A dated directory that does not exist yet. Snapshots are immutable. */
function freeSnapshotDir(root, name, date) {
  const base = nameDir(root, name);
  let candidate = path.join(base, date);
  if (!fs.existsSync(candidate)) return { dir: candidate, label: date };
  for (let i = 2; i < 100; i++) {
    const label = `${date}-${String(i).padStart(2, '0')}`;
    candidate = path.join(base, label);
    if (!fs.existsSync(candidate)) return { dir: candidate, label };
  }
  throw new Error(`${base}: more than 99 snapshots on ${date}`);
}

/** Write the document and its record. Returns the paths written. */
export function writeSnapshot(root, name, { bytes, ext, snapshot, records, notes, tool, date }) {
  const { dir, label } = freeSnapshotDir(root, name, date ?? today());
  fs.mkdirSync(dir, { recursive: true });
  const file = `policy.${ext}`;
  fs.writeFileSync(path.join(dir, file), bytes);
  const record = {
    schema: SCHEMA_SNAPSHOT,
    name: safeName(name),
    outcome: 'verified',
    snapshot: { date: label, file, ...snapshot },
    records,
    notes: notes ?? [],
    tool,
  };
  fs.writeFileSync(path.join(dir, 'record.json'), `${JSON.stringify(record, null, 2)}\n`);
  return { dir, label, file, record_path: path.join(dir, 'record.json') };
}

/** Raw answers for a run that writes no snapshot. Returns the relative path. */
export function writeRaw(root, name, raw, at = new Date()) {
  const dir = path.join(nameDir(root, name), 'raw');
  fs.mkdirSync(dir, { recursive: true });
  let file = `${stamp(at)}.json`;
  for (let i = 2; fs.existsSync(path.join(dir, file)); i++) {
    file = `${stamp(at)}-${String(i).padStart(2, '0')}.json`;
  }
  fs.writeFileSync(path.join(dir, file), `${JSON.stringify(raw, null, 2)}\n`);
  return path.join('raw', file);
}

function appendLine(file, obj) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.appendFileSync(file, `${JSON.stringify(obj)}\n`);
}

/** Append a failure. Nothing is ever overwritten and no previous copy is touched. */
export function appendFailure(root, name, failure) {
  if (!FAILURE_KINDS.includes(failure.kind)) {
    throw new Error(`unknown failure kind: ${failure.kind}`);
  }
  const line = { schema: SCHEMA_FAILURE, name: safeName(name), ...failure };
  appendLine(path.join(nameDir(root, name), 'failures.jsonl'), line);
  return line;
}

/** Append the one line that records what this run did. */
export function appendObservation(root, name, observation) {
  const line = { schema: SCHEMA_OBSERVATION, name: safeName(name), ...observation };
  appendLine(path.join(nameDir(root, name), 'observations.jsonl'), line);
  return line;
}
