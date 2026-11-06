/**
 * Read the policy record out of a TXT RRset.
 *
 * Two resolvers present the same RRset differently, which this parser must
 * absorb. Observed live on 6 November 2026 against `_ens.estmcmxci.co`:
 *
 *   Cloudflare  returns each character-string quoted, and returned the three
 *               strings in the order a=, policy_hash=, policy=
 *   Google      returns each character-string bare, and returned the same
 *               three strings in the order policy_hash=, a=, policy=
 *
 * So the parser is insensitive to order and to quoting, and it ignores any
 * string it does not recognise. An RRset that carries the claim also carries
 * a= and can carry more.
 *
 * On character-strings. TXT rdata is a sequence of character-strings, each at
 * most 255 bytes. ENS v1 parses each one independently: see
 * `DNSClaimChecker.parseRR`, which reads a length byte and then calls
 * parseString on that one string. It does not join them. A value split across
 * two character-strings is therefore invisible to the claim path, so this tool
 * does not join them either, and a split policy value is a malformed record
 * rather than a value to repair. The 255 byte limit is in the spec.
 */

/** The two keys this tool reads. Case sensitive, lowercase. */
export const KEY_URL = 'policy=';
export const KEY_HASH = 'policy_hash=';

/** 0x and 64 hex characters, which is the 32 bytes the record declares. */
const HASH_RE = /^0[xX][0-9a-fA-F]{64}$/;

/**
 * Split a DoH `data` field into its character-strings.
 *
 * Cloudflare quotes them, so `"a" "b"` is two strings. Google returns them
 * joined with no delimiter, so a split record is indistinguishable from one
 * long string there. `quoted` records which form was seen.
 *
 * @param {string} data   the `data` field of one TXT answer
 * @returns {{strings: string[], quoted: boolean}}
 */
export function characterStrings(data) {
  const s = String(data ?? '');
  if (!s.startsWith('"')) return { strings: [s.trim()], quoted: false };
  const out = [];
  let i = 0;
  while (i < s.length) {
    while (i < s.length && s[i] === ' ') i++;
    if (i >= s.length) break;
    if (s[i] !== '"') { out.push(s.slice(i)); break; }  // unbalanced, keep the rest
    i++;
    let cur = '';
    while (i < s.length && s[i] !== '"') {
      if (s[i] === '\\' && i + 1 < s.length) { cur += s[i + 1]; i += 2; }
      else { cur += s[i]; i++; }
    }
    i++;
    out.push(cur);
  }
  return { strings: out, quoted: true };
}

/**
 * Every character-string in a DoH answer's TXT records, with the split ones
 * marked.
 *
 * @param {object|null} answer   parsed DoH JSON
 * @returns {{strings: string[], splitRecords: string[][]}}
 */
export function txtStrings(answer) {
  const strings = [];
  const splitRecords = [];
  if (!answer || !Array.isArray(answer.Answer)) return { strings, splitRecords };
  for (const rr of answer.Answer) {
    if (rr.type !== 16) continue;
    const { strings: parts } = characterStrings(rr.data);
    if (parts.length > 1) splitRecords.push(parts);
    for (const p of parts) strings.push(p.trim());
  }
  return { strings, splitRecords };
}

/**
 * Read the policy record out of one resolver's answer.
 *
 * A record is well formed only when it has exactly one policy URL and exactly
 * one policy hash, the hash is 32 bytes, and no policy value is split across
 * character-strings. If policy strings are present but not well formed, the
 * caller records no_record and `problem` says what is wrong. A well formed
 * record is not a verified one: nothing here fetches or compares.
 *
 * @param {object|null} answer   parsed DoH JSON
 * @returns {object}
 */
export function parsePolicyRecord(answer) {
  const { strings, splitRecords } = txtStrings(answer);
  const urls = [];
  const hashes = [];
  const other = [];
  for (const s of strings) {
    if (s.startsWith(KEY_HASH)) hashes.push(s.slice(KEY_HASH.length).trim());
    else if (s.startsWith(KEY_URL)) urls.push(s.slice(KEY_URL.length).trim());
    else other.push(s);
  }

  const uniqUrls = [...new Set(urls)];
  const uniqHashes = [...new Set(hashes.map(h => h.toLowerCase()))];
  const present = urls.length > 0 || hashes.length > 0;

  const split = splitRecords.find(parts =>
    parts.some(p => p.trim().startsWith(KEY_URL) || p.trim().startsWith(KEY_HASH)));

  let problem = null;
  if (split) {
    problem = `a policy value is split across ${split.length} character-strings; `
      + 'a policy value must fit in one 255 byte character-string';
  } else if (!present) {
    problem = 'no policy= or policy_hash= string in the RRset';
  } else if (uniqUrls.length === 0) {
    problem = 'policy_hash= is present but policy= is absent';
  } else if (uniqHashes.length === 0) {
    problem = 'policy= is present but policy_hash= is absent';
  } else if (uniqUrls.length > 1) {
    problem = `${uniqUrls.length} different policy= values in one RRset`;
  } else if (uniqHashes.length > 1) {
    problem = `${uniqHashes.length} different policy_hash= values in one RRset`;
  } else if (!HASH_RE.test(uniqHashes[0])) {
    problem = `policy_hash= is not 0x and 64 hex characters: ${JSON.stringify(uniqHashes[0])}`;
  }

  return {
    present,
    well_formed: problem === null,
    problem,
    url: problem === null ? uniqUrls[0] : (uniqUrls[0] ?? null),
    declared_hash: problem === null ? `0x${uniqHashes[0].slice(2)}` : (uniqHashes[0] ?? null),
    strings,                 // every character-string seen, parsed or not
    other_strings: other,    // the ones this tool ignores, a= among them
    split_records: splitRecords,
  };
}

/** True when two parsed records name the same document. */
export function sameRecord(a, b) {
  if (!a || !b) return false;
  return a.url === b.url && a.declared_hash === b.declared_hash;
}
