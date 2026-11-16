/**
 * DNS wire format: a query encoder, and a reader for a response.
 *
 * This is the evidence path. It exists because a signature covers exact bytes.
 * The JSON resolver API returns presentation format, which a person can read
 * but nobody can verify, and it returns no signature at all. So the archiver
 * asks for the same records in wire format with the DO bit set, keeps the
 * response bytes, and stores them.
 *
 * Nothing here decides anything. The decision path is the JSON path in
 * lib/doh.mjs and lib/txt.mjs, and it is unchanged. See SPEC.md §8.
 *
 * The reader is deliberately generic. It walks a section by reading the owner
 * name, the type, the class, the TTL and the rdata length, and it steps over
 * the rdata without reading it. That works for every record type, now and
 * later, so the archive does not go stale when a new type arrives.
 *
 * Three types then get a summary on top of the stored bytes, because a reader
 * of the archive needs to see the shape of a chain without a parser: RRSIG,
 * DNSKEY and DS. The summary is a convenience. The bytes are the evidence,
 * and every field of a summary is recomputable from them.
 *
 * References: RFC 1035 §4 for the message, RFC 6891 for EDNS(0), RFC 8484 §4
 * for the transport, RFC 4034 §2, §3 and §5 for the three record types and
 * for the key tag and the DS digest.
 */
import crypto from 'node:crypto';

/** The record types this tool names. Any other type reads as TYPE<n>. */
export const TYPE = {
  A: 1, NS: 2, CNAME: 5, SOA: 6, TXT: 16, AAAA: 28, OPT: 41,
  DS: 43, RRSIG: 46, NSEC: 47, DNSKEY: 48, NSEC3: 50,
};
const TYPE_BY_NUM = Object.fromEntries(Object.entries(TYPE).map(([k, v]) => [v, k]));
export const typeName = n => TYPE_BY_NUM[n] ?? `TYPE${n}`;

const RCODE = { 0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED' };

/** The DO bit, in the TTL field of the OPT record. RFC 3225. */
const DO_BIT = 0x00008000;

/** A name as wire labels, uncompressed. The root is one zero byte. */
export function encodeName(name) {
  const n = String(name ?? '').replace(/\.$/, '');
  if (!n) return Buffer.from([0]);
  const parts = [];
  for (const label of n.split('.')) {
    const b = Buffer.from(label, 'utf8');
    if (b.length < 1 || b.length > 63) throw new Error(`label out of range in ${name}`);
    parts.push(Buffer.from([b.length]), b);
  }
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}

/**
 * One query message, with EDNS(0) and the DO bit set.
 *
 * The id is 0. RFC 8484 §4.1 asks for that, because a DoH query is cacheable
 * by the HTTP layer and a random id defeats the cache.
 */
export function encodeQuery(name, type, { id = 0, dnssecOk = true, udpSize = 4096 } = {}) {
  const q = encodeName(name);
  const buf = Buffer.alloc(12 + q.length + 4 + 11);
  let o = 0;
  buf.writeUInt16BE(id, o); o += 2;
  buf.writeUInt16BE(0x0100, o); o += 2;        // RD, nothing else
  buf.writeUInt16BE(1, o); o += 2;             // QDCOUNT
  buf.writeUInt16BE(0, o); o += 2;             // ANCOUNT
  buf.writeUInt16BE(0, o); o += 2;             // NSCOUNT
  buf.writeUInt16BE(1, o); o += 2;             // ARCOUNT, the OPT record below
  q.copy(buf, o); o += q.length;
  buf.writeUInt16BE(type, o); o += 2;
  buf.writeUInt16BE(1, o); o += 2;             // class IN
  buf.writeUInt8(0, o); o += 1;                // OPT owner name is the root
  buf.writeUInt16BE(TYPE.OPT, o); o += 2;
  buf.writeUInt16BE(udpSize, o); o += 2;       // class field carries the payload size
  buf.writeUInt32BE(dnssecOk ? DO_BIT : 0, o); o += 4;
  buf.writeUInt16BE(0, o);                     // RDLENGTH
  return buf;
}

/** A label as presentation text. An awkward byte becomes a decimal escape. */
const escapeLabel = b => Array.from(b).map(c =>
  (c > 32 && c < 127 && c !== 0x2e && c !== 0x5c)
    ? String.fromCharCode(c)
    : `\\${String(c).padStart(3, '0')}`).join('');

/**
 * Read one name, and follow compression pointers.
 *
 * `next` is the offset after the name as it was written at `offset`, not the
 * offset after whatever a pointer led to.
 */
export function decodeName(buf, offset) {
  const labels = [];
  let o = offset, jumps = 0, end = null;
  for (;;) {
    if (o >= buf.length) throw new Error('a name runs past the end of the message');
    const len = buf[o];
    if (len === 0) { o += 1; break; }
    if ((len & 0xc0) === 0xc0) {
      if (o + 1 >= buf.length) throw new Error('a compression pointer is cut short');
      if (end === null) end = o + 2;
      if (++jumps > 64) throw new Error('a compression pointer loops');
      o = ((len & 0x3f) << 8) | buf[o + 1];
      continue;
    }
    if ((len & 0xc0) !== 0) throw new Error(`unknown label type 0x${len.toString(16)}`);
    o += 1;
    if (o + len > buf.length) throw new Error('a label runs past the end of the message');
    labels.push(escapeLabel(buf.subarray(o, o + len)));
    o += len;
  }
  return { name: labels.length ? `${labels.join('.')}.` : '.', next: end ?? o };
}

/** Read the records of one section. Rdata is kept whole and is not read. */
function readSection(buf, start, count) {
  const out = [];
  let o = start;
  for (let i = 0; i < count; i++) {
    const { name, next } = decodeName(buf, o);
    o = next;
    if (o + 10 > buf.length) throw new Error('a record header runs past the end of the message');
    const type = buf.readUInt16BE(o);
    const rr = {
      name,
      type,
      type_name: typeName(type),
      class: buf.readUInt16BE(o + 2),
      ttl: buf.readUInt32BE(o + 4),
      rdlength: buf.readUInt16BE(o + 8),
    };
    o += 10;
    if (o + rr.rdlength > buf.length) throw new Error('rdata runs past the end of the message');
    rr.rdata_offset = o;
    rr.rdata = buf.subarray(o, o + rr.rdlength);
    o += rr.rdlength;
    out.push(rr);
  }
  return { records: out, next: o };
}

/** Read a whole message: the header, the question, and the three sections. */
export function readMessage(buf) {
  if (buf.length < 12) throw new Error('the message is shorter than a header');
  const flags = buf.readUInt16BE(2);
  const counts = {
    qd: buf.readUInt16BE(4), an: buf.readUInt16BE(6),
    ns: buf.readUInt16BE(8), ar: buf.readUInt16BE(10),
  };
  let o = 12;
  const question = [];
  for (let i = 0; i < counts.qd; i++) {
    const { name, next } = decodeName(buf, o);
    o = next;
    if (o + 4 > buf.length) throw new Error('the question runs past the end of the message');
    question.push({
      name, type: buf.readUInt16BE(o), type_name: typeName(buf.readUInt16BE(o)),
      class: buf.readUInt16BE(o + 2),
    });
    o += 4;
  }
  const an = readSection(buf, o, counts.an);
  const ns = readSection(buf, an.next, counts.ns);
  const ar = readSection(buf, ns.next, counts.ar);
  const rcode = flags & 0x0f;
  return {
    id: buf.readUInt16BE(0),
    rcode,
    rcode_name: RCODE[rcode] ?? `RCODE${rcode}`,
    aa: Boolean(flags & 0x0400),
    tc: Boolean(flags & 0x0200),
    ra: Boolean(flags & 0x0080),
    ad: Boolean(flags & 0x0020),
    cd: Boolean(flags & 0x0010),
    counts,
    question,
    answer: an.records,
    authority: ns.records,
    additional: ar.records,
  };
}

/* ------------------------------------------- the three signed record types */

/** RRSIG rdata. RFC 4034 §3.1. The signer name names the zone that signed. */
function readRrsig(rr, msg) {
  const d = rr.rdata;
  if (d.length < 19) return { malformed: `rdata is ${d.length} bytes, too short for an RRSIG` };
  const signer = decodeName(msg, rr.rdata_offset + 18);
  const covered = d.readUInt16BE(0);
  const expiration = d.readUInt32BE(8);
  const inception = d.readUInt32BE(12);
  return {
    type_covered: covered,
    type_covered_name: typeName(covered),
    algorithm: d[2],
    labels: d[3],
    original_ttl: d.readUInt32BE(4),
    inception,
    inception_utc: new Date(inception * 1000).toISOString(),
    expiration,
    expiration_utc: new Date(expiration * 1000).toISOString(),
    key_tag: d.readUInt16BE(16),
    signer: signer.name,
    signature_bytes: rr.rdata_offset + rr.rdlength - signer.next,
  };
}

/**
 * The key tag of a DNSKEY, from its rdata. RFC 4034 appendix B.1.
 *
 * Algorithm 1 took a different rule, and algorithm 1 is forbidden since
 * RFC 8624, so the one rule here is the whole rule.
 */
export function keyTag(rdata) {
  let ac = 0;
  for (let i = 0; i < rdata.length; i++) ac += (i & 1) ? rdata[i] : rdata[i] << 8;
  ac += (ac >> 16) & 0xffff;
  return ac & 0xffff;
}

/**
 * DNSKEY rdata. RFC 4034 §2.1 and §2.1.1. Bit 7 of the flags, which is
 * 0x0100, is the zone key. Bit 15, which is 0x0001, is the secure entry
 * point, and a key signing key sets both.
 */
function readDnskey(rr) {
  const d = rr.rdata;
  if (d.length < 5) return { malformed: `rdata is ${d.length} bytes, too short for a DNSKEY` };
  const flags = d.readUInt16BE(0);
  return {
    flags,
    protocol: d[2],
    algorithm: d[3],
    key_tag: keyTag(d),
    zone_key: Boolean(flags & 0x0100),
    secure_entry_point: Boolean(flags & 0x0001),
    key_bytes: d.length - 4,
  };
}

/** DS rdata. RFC 4034 §5.1. The digest is over the parent's view of a key. */
function readDs(rr) {
  const d = rr.rdata;
  if (d.length < 5) return { malformed: `rdata is ${d.length} bytes, too short for a DS` };
  return {
    key_tag: d.readUInt16BE(0),
    algorithm: d[2],
    digest_type: d[3],
    digest: d.subarray(4).toString('hex').toUpperCase(),
  };
}

/**
 * The DS digest of a DNSKEY. RFC 4034 §5.1.4.
 *
 * The digest covers the owner name in canonical form, which is lower case and
 * uncompressed, and then the whole DNSKEY rdata. This is the one check that
 * ties a captured root DNSKEY to the anchor that IANA publishes, so the
 * archiver computes it. A reader recomputes it from the stored bytes.
 */
export function dsDigest(ownerName, dnskeyRdata, digestType = 2) {
  const algorithm = { 1: 'sha1', 2: 'sha256', 4: 'sha384' }[digestType];
  if (!algorithm) return null;
  const owner = encodeName(String(ownerName).toLowerCase());
  return crypto.createHash(algorithm)
    .update(Buffer.concat([owner, Buffer.from(dnskeyRdata)]))
    .digest('hex').toUpperCase();
}

/**
 * A message as a JSON safe summary: the header, the question, and one entry
 * for each record with the rdata summarised but not copied.
 *
 * The rdata is left out on purpose. The whole message is stored as bytes next
 * to this summary, so a copy of the rdata would say the same thing twice.
 */
export function frame(bytes) {
  const msg = readMessage(bytes);
  const describe = rr => {
    const out = {
      name: rr.name, type: rr.type_name, class: rr.class,
      ttl: rr.ttl, rdlength: rr.rdlength,
    };
    if (rr.type === TYPE.RRSIG) out.rrsig = readRrsig(rr, bytes);
    else if (rr.type === TYPE.DNSKEY) out.dnskey = readDnskey(rr);
    else if (rr.type === TYPE.DS) out.ds = readDs(rr);
    return out;
  };
  return {
    rcode: msg.rcode_name,
    flags: { aa: msg.aa, tc: msg.tc, ra: msg.ra, ad: msg.ad, cd: msg.cd },
    counts: msg.counts,
    question: msg.question.map(q => ({ name: q.name, type: q.type_name, class: q.class })),
    answer: msg.answer.map(describe),
    authority: msg.authority.map(describe),
    additional: msg.additional.map(describe),
  };
}
