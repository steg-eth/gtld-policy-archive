/**
 * Fetch the policy document and hash its bytes.
 *
 * The hash covers the raw response bytes with no normalisation. Any other
 * rule needs the operator and the archiver to agree on a canonical form,
 * and no such form is specified.
 *
 * Redirects are followed by hand rather than by fetch, for two reasons: the
 * limit must be small and recorded, and the final URL is part of the record.
 */
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';

export const MAX_BYTES = 5 * 1024 * 1024;   // a policy document, not a corpus
export const MAX_REDIRECTS = 5;
export const TIMEOUT_MS = 20_000;
export const USER_AGENT = 'gtld-policy-archive/1.0 (+https://github.com/steg-eth/gtld-policy-archive)';

const REDIRECT_CODES = new Set([301, 302, 303, 307, 308]);

/** sha256 over bytes, as 0x and 64 lowercase hex characters. */
export const sha256 = bytes => `0x${crypto.createHash('sha256').update(bytes).digest('hex')}`;

export class FetchProblem extends Error {
  constructor(detail) { super(detail); this.name = 'FetchProblem'; }
}

/** Read a body, and stop if it goes past the cap. */
async function readCapped(res, maxBytes) {
  const declared = Number(res.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > maxBytes) {
    throw new FetchProblem(`content-length ${declared} is more than the ${maxBytes} byte cap`);
  }
  if (!res.body) return Buffer.alloc(0);
  const chunks = [];
  let n = 0;
  for await (const chunk of res.body) {
    n += chunk.length;
    if (n > maxBytes) throw new FetchProblem(`response is more than the ${maxBytes} byte cap`);
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

/**
 * Fetch a policy document.
 *
 * `file:` and `http:` are refused unless allowInsecure is set. The archive is
 * for documents an operator publishes, which is https. The two other schemes
 * are there to build test cases.
 *
 * @returns {Promise<{bytes: Buffer, computed_hash: string, byte_size: number,
 *   final_url: string, content_type: string|null, http_status: number,
 *   redirects: string[]}>}
 * @throws {FetchProblem}
 */
export async function fetchPolicy(url, opts = {}) {
  const maxBytes = opts.maxBytes ?? MAX_BYTES;
  const maxRedirects = opts.maxRedirects ?? MAX_REDIRECTS;
  const timeout = opts.timeout ?? TIMEOUT_MS;
  const allowInsecure = opts.allowInsecure === true;

  let u;
  try { u = new URL(url); }
  catch { throw new FetchProblem(`not a URL: ${JSON.stringify(String(url))}`); }

  if (u.protocol !== 'https:' && !allowInsecure) {
    throw new FetchProblem(
      `scheme ${u.protocol} is refused; the archiver accepts https only `
      + '(use --allow-insecure-url to read http: or file: when you build a test case)');
  }
  if (!['https:', 'http:', 'file:'].includes(u.protocol)) {
    throw new FetchProblem(`scheme ${u.protocol} is not supported`);
  }

  if (u.protocol === 'file:') {
    let bytes;
    try { bytes = fs.readFileSync(fileURLToPath(u)); }
    catch (e) { throw new FetchProblem(`cannot read ${u.href}: ${e.message}`); }
    if (bytes.length > maxBytes) {
      throw new FetchProblem(`file is more than the ${maxBytes} byte cap`);
    }
    return {
      bytes,
      computed_hash: sha256(bytes),
      byte_size: bytes.length,
      final_url: u.href,
      content_type: null,
      http_status: 200,
      redirects: [],
    };
  }

  const redirects = [];
  let current = u.href;
  for (let hop = 0; ; hop++) {
    let res;
    try {
      res = await fetch(current, {
        redirect: 'manual',
        signal: AbortSignal.timeout(timeout),
        headers: { 'user-agent': USER_AGENT, accept: '*/*' },
      });
    } catch (e) {
      /* Node's fetch raises an opaque "fetch failed" and puts the reason,
       * such as ENOTFOUND for a host that no longer exists, on the cause.
       * A tool whose job is to report bitrot has to report which kind. */
      const cause = e && e.cause
        ? (e.cause.code ?? (e.cause.message ?? String(e.cause)))
        : null;
      const msg = e && e.name === 'TimeoutError'
        ? `no response in ${timeout} ms`
        : (e && e.message ? e.message : String(e));
      throw new FetchProblem(`${current}: ${msg}${cause ? ` (${cause})` : ''}`);
    }

    if (REDIRECT_CODES.has(res.status)) {
      const loc = res.headers.get('location');
      if (!loc) throw new FetchProblem(`${current}: HTTP ${res.status} with no location header`);
      if (hop >= maxRedirects) {
        throw new FetchProblem(`more than ${maxRedirects} redirects, last at ${current}`);
      }
      let next;
      try { next = new URL(loc, current).href; }
      catch { throw new FetchProblem(`${current}: location is not a URL: ${JSON.stringify(loc)}`); }
      if (next.startsWith('http:') && !allowInsecure) {
        throw new FetchProblem(`${current}: redirect to http: is refused`);
      }
      redirects.push(next);
      current = next;
      continue;
    }

    if (!res.ok) throw new FetchProblem(`${current}: HTTP ${res.status} ${res.statusText}`);

    const bytes = await readCapped(res, maxBytes);
    return {
      bytes,
      computed_hash: sha256(bytes),
      byte_size: bytes.length,
      final_url: current,
      content_type: res.headers.get('content-type'),
      http_status: res.status,
      redirects,
    };
  }
}

/** The file extension to archive under. The URL path wins, the type is a fallback. */
export function extensionFor(finalUrl, contentType) {
  try {
    const path = new URL(finalUrl).pathname;
    const m = path.match(/\.([A-Za-z0-9]{1,8})$/);
    if (m) return m[1].toLowerCase();
  } catch { /* fall through to the content type */ }
  const base = String(contentType ?? '').split(';')[0].trim().toLowerCase();
  const byType = {
    'text/markdown': 'md',
    'text/plain': 'txt',
    'text/html': 'html',
    'application/pdf': 'pdf',
    'application/json': 'json',
    'application/xhtml+xml': 'html',
  };
  return byType[base] ?? 'bin';
}
