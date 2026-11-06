/**
 * DNS over HTTPS, across two resolvers.
 *
 * The RESOLVERS map, the retry and backoff shape in doh(), and the PACE and
 * CONCURRENCY constants follow `research/gtld/revoke-census.mjs` in the
 * author's `algo13-study` repository. The dual-resolver pattern is the point:
 * a single vantage point cannot tell you that it is wrong, and the census
 * found that disagreement between resolvers is itself a finding, so this tool
 * records it rather than resolving it.
 *
 * The census queries DNSKEY. This tool queries TXT.
 */

const sleep = ms => new Promise(r => setTimeout(r, ms));

/** Name to URL builders. A resolver is referred to by its short key. */
export const RESOLVERS = {
  cf: n => `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(n)}&type=TXT`,
  gg: n => `https://dns.google/resolve?name=${encodeURIComponent(n)}&type=TXT`,
};

/** Full names, for reports. */
export const RESOLVER_NAMES = {
  cf: 'Cloudflare (cloudflare-dns.com)',
  gg: 'Google (dns.google)',
};

/** Milliseconds between the two resolver queries for one name. */
export const PACE = 40;

/** Names processed at the same time in a population run. */
export const CONCURRENCY = 4;

/**
 * Query one resolver for TXT at one name. Retries with linear backoff.
 *
 * Returns the parsed DoH JSON, or null if every try failed. A null return and
 * an answer with no records are different conditions, and adStatus puts both
 * in the no-answer class. The response Status tells them apart, so callers
 * record it.
 *
 * @param {string} resolver   a key of RESOLVERS
 * @param {string} name       the name to query, fully qualified
 * @param {number} [tries]    attempts before giving up
 */
export async function doh(resolver, name, tries = 4) {
  const build = RESOLVERS[resolver];
  if (!build) throw new Error(`unknown resolver: ${resolver}`);
  let lastError = null;
  for (let i = 0; i < tries; i++) {
    try {
      const r = await fetch(build(name), {
        headers: { accept: 'application/dns-json' },
        signal: AbortSignal.timeout(10_000),
      });
      if (r.ok) return await r.json();
      lastError = `HTTP ${r.status}`;
    } catch (e) {
      lastError = e && e.message ? e.message : String(e);
    }
    await sleep(300 * (i + 1));
  }
  if (process.env.POLICY_ARCHIVE_DEBUG) {
    console.error(`  doh ${resolver} ${name}: gave up after ${tries} tries (${lastError})`);
  }
  return null;
}

/**
 * Query one name across several resolvers, in sequence with pacing.
 *
 * @param {string} name             the name to query
 * @param {string[]} resolverKeys   keys of RESOLVERS
 * @returns {Promise<Object>}       resolver key to DoH JSON or null
 */
export async function dohAll(name, resolverKeys) {
  const out = {};
  for (let i = 0; i < resolverKeys.length; i++) {
    if (i > 0) await sleep(PACE);
    out[resolverKeys[i]] = await doh(resolverKeys[i], name);
  }
  return out;
}

export { sleep };
