/**
 * The DNSSEC chain, captured as wire format bytes.
 *
 * The archive used to keep one boolean for each resolver, the AD bit, and
 * nothing else. A reader in 2029 holding a snapshot could see that two
 * resolvers each said "I validated this", and had to take it on trust. That
 * contradicts SPEC.md §2: the record is evidence that the operator made a
 * commitment, and a boolean from a resolver is not that evidence.
 *
 * So the archiver walks from the signed RRset up to the root and keeps the
 * bytes of every link. A reader then validates the chain against the anchor
 * that IANA publishes and trusts the archiver for nothing.
 *
 * The walk is driven by the signatures, not by the labels of the name. The
 * RRSIG over the TXT RRset names the zone that signed it. The DNSKEY RRset of
 * that zone is the next link, the DS of that zone is the link after, and the
 * RRSIG over the DS names the parent zone. The walk repeats until the zone is
 * the root. This finds the real zone cuts, and a name such as
 * `_ens.estmcmxci.co` has no zone cut at `_ens`.
 *
 * Nothing here decides anything. A failure to capture a chain is recorded and
 * is not a failure kind, because the chain is evidence and the decision path
 * is the JSON path in lib/doh.mjs. See SPEC.md §8.
 */
import { sleep, PACE } from './doh.mjs';
import { TYPE, encodeQuery, frame, readMessage, dsDigest } from './wire.mjs';

export const CHAIN_SCHEMA = 'gtld-policy-archive/dnssec-chain/1';

/** The wire format endpoint of each resolver. RFC 8484 §4.1. */
export const WIRE_RESOLVERS = {
  cf: 'https://cloudflare-dns.com/dns-query',
  gg: 'https://dns.google/dns-query',
};

export const TRANSPORT =
  'DNS over HTTPS in wire format, application/dns-message, EDNS(0) with the DO bit set';

export const ROOT_ANCHOR_SOURCE = 'https://data.iana.org/root-anchors/root-anchors.xml';

/**
 * The root trust anchors that IANA publishes with no validUntil, read from
 * root-anchors.xml on 16 November 2026. Kjqmt7v, key tag 19036, is left out
 * because IANA retired it on 11 January 2019.
 *
 * The root rolled its key signing key on 11 October 2026 and signs with
 * Kmyv6jo, key tag 38696, alone. Klajeyz, key tag 20326, is still in the
 * published anchors and is still in the root DNSKEY RRset, so it is kept
 * here. A reader needs IANA's list, not this tool's opinion of it.
 */
export const ROOT_ANCHORS = [
  { id: 'Klajeyz', key_tag: 20326, algorithm: 8, digest_type: 2, valid_from: '2017-02-02T00:00:00Z',
    digest: 'E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D' },
  { id: 'Kmyv6jo', key_tag: 38696, algorithm: 8, digest_type: 2, valid_from: '2024-07-18T00:00:00Z',
    digest: '683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16' },
];

/** A chain cannot be deeper than this. A longer walk is a loop. */
const MAX_ZONES = 12;

const norm = n => String(n ?? '').toLowerCase().replace(/\.$/, '') || '.';

/** One wire query at one resolver. Never throws. */
async function wireQuery(resolverKey, name, type, { tries = 2, timeout = 10_000 } = {}) {
  const base = WIRE_RESOLVERS[resolverKey];
  if (!base) return { ok: false, error: `no wire endpoint for resolver ${resolverKey}` };
  const query = encodeQuery(name, type);
  let error = null;
  for (let i = 0; i < tries; i++) {
    if (i > 0) await sleep(300 * i);
    try {
      const res = await fetch(`${base}?dns=${query.toString('base64url')}`, {
        headers: { accept: 'application/dns-message' },
        signal: AbortSignal.timeout(timeout),
      });
      const bytes = Buffer.from(await res.arrayBuffer());
      if (!res.ok) { error = `HTTP ${res.status} ${res.statusText}`; continue; }
      return {
        ok: true,
        http_status: res.status,
        content_type: res.headers.get('content-type'),
        bytes,
      };
    } catch (e) {
      error = e && e.name === 'TimeoutError'
        ? `no response in ${timeout} ms`
        : (e && e.message ? e.message : String(e));
    }
  }
  return { ok: false, error };
}

/**
 * One link of the chain: ask every resolver in turn, and keep the first
 * answer that reads as a message. The bytes are the evidence, so a resolver
 * that gives bytes this tool cannot read is still a resolver that failed.
 */
async function captureLink(resolverKeys, { step, role, proves, name, type, opts }) {
  const link = {
    step, role, proves,
    query: { name: norm(name), type: Object.keys(TYPE).find(k => TYPE[k] === type) ?? String(type) },
    resolver: null, resolver_url: null,
    fetched_at: null, http_status: null, content_type: null,
    response_bytes: null, response_b64: null, message: null,
    signed: false, signer: null,
    attempts: [], error: null,
  };
  for (const key of resolverKeys) {
    const got = await wireQuery(key, name, type, opts);
    if (!got.ok) { link.attempts.push({ resolver: key, error: got.error }); continue; }
    let framed;
    try { framed = frame(got.bytes); }
    catch (e) {
      link.attempts.push({ resolver: key, error: `the response did not read as a message: ${e.message}` });
      continue;
    }
    link.resolver = key;
    link.resolver_url = WIRE_RESOLVERS[key];
    link.fetched_at = new Date().toISOString();
    link.http_status = got.http_status;
    link.content_type = got.content_type;
    link.response_bytes = got.bytes.length;
    link.response_b64 = got.bytes.toString('base64');
    link.message = framed;
    const sig = framed.answer.find(rr => rr.type === 'RRSIG' && rr.rrsig && rr.rrsig.type_covered === type);
    link.signed = Boolean(sig);
    link.signer = sig ? norm(sig.rrsig.signer) : null;
    return link;
  }
  link.error = link.attempts.length
    ? `no resolver answered: ${link.attempts.map(a => `${a.resolver}: ${a.error}`).join('; ')}`
    : 'no resolver was asked';
  return link;
}

/** Every DNSKEY record of a link, as owner name and rdata. */
function dnskeysOf(link) {
  if (!link || !link.response_b64) return [];
  const msg = readMessage(Buffer.from(link.response_b64, 'base64'));
  return msg.answer.filter(rr => rr.type === TYPE.DNSKEY)
    .map(rr => ({ name: rr.name, rdata: rr.rdata }));
}

/** Every DS record of a link, as the summary already read it. */
const dsOf = link => (link && link.message ? link.message.answer : [])
  .filter(rr => rr.type === 'DS' && rr.ds).map(rr => rr.ds);

/**
 * Capture the chain for one queried name.
 *
 * @param {string} qname         the signed name, such as `_ens.estmcmxci.co`
 * @param {string[]} resolverKeys  keys of WIRE_RESOLVERS, tried in order
 * @param {object} [opts]        tries and timeout, as wireQuery takes them
 */
export async function captureChain(qname, resolverKeys, opts = {}) {
  const keys = resolverKeys.filter(k => WIRE_RESOLVERS[k]);
  const chain = {
    schema: CHAIN_SCHEMA,
    captured_at: new Date().toISOString(),
    qname: norm(qname),
    transport: TRANSPORT,
    resolvers: keys,
    captured: true,
    reached_root: false,
    zones: [],
    links: [],
    digest_checks: [],
    root_anchor: { source: ROOT_ANCHOR_SOURCE, expected: ROOT_ANCHORS, matched: [] },
    checked_here: 'the DS digests, and the root DNSKEY against the IANA anchor. '
      + 'Signatures are not verified here. SPEC.md §9 says how a reader verifies them.',
    problems: [],
  };
  if (!keys.length) {
    chain.captured = false;
    chain.problems.push('no resolver has a wire format endpoint');
    return chain;
  }

  let step = 0;
  const take = async spec => {
    if (chain.links.length) await sleep(PACE);
    const link = await captureLink(keys, { step: ++step, opts, ...spec });
    chain.links.push(link);
    if (link.error) chain.problems.push(`step ${link.step}, ${link.query.name} ${link.query.type}: ${link.error}`);
    return link;
  };

  /* The leaf. Its RRSIG names the zone that signed the policy record, which
   * is where the walk up starts. */
  const leaf = await take({
    role: 'leaf-rrset', name: qname, type: TYPE.TXT,
    proves: `the TXT RRset at ${norm(qname)}, and the signature over it`,
  });
  if (!leaf.signer) {
    chain.captured = Boolean(leaf.response_b64);
    chain.problems.push(leaf.response_b64
      ? `no RRSIG over TXT at ${norm(qname)}, so there is no chain to walk`
      : 'the leaf RRset was not captured, so there is no chain to walk');
    return chain;
  }

  let zone = leaf.signer;
  const keysByZone = {};
  for (let i = 0; i < MAX_ZONES && zone; i++) {
    chain.zones.push(zone);
    const dnskey = await take({
      role: 'zone-keys', name: zone, type: TYPE.DNSKEY,
      proves: `the DNSKEY RRset of ${zone}, which holds the key that signed the link below`,
    });
    keysByZone[zone] = dnskey;
    if (zone === '.') { chain.reached_root = true; break; }

    const ds = await take({
      role: 'delegation', name: zone, type: TYPE.DS,
      proves: `the DS of ${zone}, served by its parent, which commits the parent to those keys`,
    });
    if (!ds.signer) {
      chain.problems.push(`no RRSIG over DS at ${zone}, so the walk stops below the root`);
      break;
    }
    if (ds.signer === zone) {
      chain.problems.push(`the DS of ${zone} is signed by ${zone} itself, which is not a parent`);
      break;
    }
    zone = ds.signer;
  }
  if (!chain.reached_root && !chain.problems.length) {
    chain.problems.push(`the walk did not reach the root in ${MAX_ZONES} zones`);
  }

  /* Every DS must be the digest of a key that the child served. This is the
   * whole of chain validation except the signature arithmetic. */
  for (const link of chain.links) {
    if (link.role !== 'delegation') continue;
    const zoneName = link.query.name;
    const keysHere = dnskeysOf(keysByZone[zoneName]);
    for (const ds of dsOf(link)) {
      const match = keysHere.find(k => dsDigest(k.name, k.rdata, ds.digest_type) === ds.digest);
      chain.digest_checks.push({
        zone: zoneName, ds_key_tag: ds.key_tag, digest_type: ds.digest_type,
        matched_a_captured_dnskey: Boolean(match),
      });
      if (!match) {
        chain.problems.push(
          `the DS of ${zoneName} with key tag ${ds.key_tag} is not the digest of any DNSKEY captured at ${zoneName}`);
      }
    }
  }

  /* The root DNSKEY against IANA's anchors. Nothing above this is anchored,
   * so a chain that fails here is a chain that proves nothing. */
  const rootKeys = dnskeysOf(keysByZone['.']);
  for (const anchor of ROOT_ANCHORS) {
    const key = rootKeys.find(k => dsDigest(k.name, k.rdata, anchor.digest_type) === anchor.digest);
    chain.root_anchor.matched.push({
      id: anchor.id, key_tag: anchor.key_tag,
      in_the_captured_root_dnskey: Boolean(key),
    });
  }
  chain.root_anchor.any_matched = chain.root_anchor.matched.some(m => m.in_the_captured_root_dnskey);
  if (chain.reached_root && !chain.root_anchor.any_matched) {
    chain.problems.push('no captured root DNSKEY is the digest of an IANA anchor');
  }
  return chain;
}

/** The chain as one line, for observations.jsonl. */
export function chainSummary(chain) {
  if (!chain) return null;
  if (!chain.captured) {
    return { captured: false, reason: chain.skipped_because ?? (chain.problems[0] ?? null) };
  }
  return {
    captured: true,
    links: chain.links.length,
    zones: chain.zones.length,
    reached_root: chain.reached_root,
    root_anchor_matched: chain.root_anchor.any_matched ?? false,
    problems: chain.problems.length,
  };
}

/** A chain that was not attempted, with the reason on it. */
export function chainSkipped(qname, reason) {
  return {
    schema: CHAIN_SCHEMA,
    captured_at: new Date().toISOString(),
    qname: norm(qname),
    transport: TRANSPORT,
    captured: false,
    skipped_because: reason,
    links: [],
    problems: [],
  };
}
