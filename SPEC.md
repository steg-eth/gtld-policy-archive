# The gTLD policy record

**Version** 1 · **Date** 6 November 2026 · **Status** proposed

**Revised** 16 November 2026. §8, §9 and §10 are new. They describe what the archiver stores and how a
reader checks it. The record format in §1 to §5 did not change.

## 1. Purpose

The policy record does two things. It tells a reader where an operator publishes its policy
document. It also tells the reader which bytes are the correct bytes.

A reader can then do two things years later. The reader can find the document, if an archive kept a
copy. The reader can also prove that the document changed, if the bytes no longer agree with the
hash.

This record protects against bitrot. The URL can die. The document can change without notice. In
both conditions the archive still has the bytes that the operator signed for.

This specification does not say what a policy must contain. The requirements for a policy are a
governance question for the ENS DAO. This specification is agnostic to them. A record that satisfies
this specification can point to a bad policy. The archiver does not judge the content.

This specification is not a contract change. No contract reads these strings.

## 2. Where the record goes

Put the two strings in the TXT RRset at `_ens.<name>`.

This is the same RRset that carries the `a=` claim string. One query gets the claim and the policy
record together. One signature covers both.

The zone must be DNSSEC signed. The archiver refuses a record that does not validate. The record is
evidence that the operator made a commitment. An unsigned record is not evidence of anything.

### 2.1 Why the apex

ENS reads `_ens.<name>` in both generations of the registry.

| Generation | Code | What it builds |
| --- | --- | --- |
| v1 | `DNSClaimChecker.getOwnerAddress` | `buf.append("\x04_ens"); buf.append(name)` |
| v2 | `contracts-v2` #419, through `NameCoder.addLabel(name, "_ens")` | the same name |

Verified on 6 November 2026 against `ensdomains/ens-contracts`, in
`contracts/dnsregistrar/DNSClaimChecker.sol`.

### 2.2 The nic form

`_ens.nic.<tld>` is the TLD Oracle's own convention. It is not an ENS convention.

An archiver can query the nic form. An archiver must record what the nic form says. An archiver must
not let the nic form decide anything.

If the nic form carries a policy record, and that record disagrees with the apex, the apex wins. The
disagreement is data. The archiver records it and continues.

## 3. The two strings

### 3.1 The URL

```
policy=<url>
```

The URL must use the `https` scheme. The URL must give the document, not a page about the document.

### 3.2 The hash

```
policy_hash=0x<64 hex characters>
```

The hash is **sha256**. The algorithm is sha256 because the record lives in DNS, where sha256 is
native. The comparison happens off chain, so keccak256 gives no benefit.

The hash covers **the raw response bytes**. No normalisation occurs. Any other rule needs the
operator and the archiver to agree on a canonical form. No such form exists.

The value is 32 bytes. Write the value as `0x` and 64 hexadecimal characters. Upper case and lower
case hexadecimal are both correct. The archiver makes the value lower case before it compares.

## 4. Rules for the RRset

1. **Order does not matter.** Resolvers return the strings in different orders. Cloudflare and
   Google both returned the strings of `_ens.estmcmxci.co` in a different order on 6 November 2026.
2. **Other strings are permitted.** The RRset carries `a=` and can carry more. A reader must ignore
   a string that it does not recognise. A reader must not fail because of one.
3. **One character-string for each value.** A value must fit in one character-string, which is 255
   bytes. Do not split a value across two character-strings. ENS v1 parses each character-string on
   its own, at `DNSClaimChecker.parseRR`. It does not join them. A split value is therefore invisible
   to the claim path.
4. **The keys are lower case.** Write `policy=` and `policy_hash=` in lower case. The archiver
   matches the keys exactly.
5. **Space at the start and at the end is ignored.** The archiver removes it before it reads the key.

### 4.1 Example

```
_ens.estmcmxci.co.  60  IN  TXT  "a=0x703ae03fB120eC91e9Ed6d08Ce8044E498CC789B"
_ens.estmcmxci.co.  60  IN  TXT  "policy=https://example.com/deprecation-policy.md"
_ens.estmcmxci.co.  60  IN  TXT  "policy_hash=0x5cd65fc5028170a6bf22b5285cc312c5b67c20291b291a7bf632d6bba63e12e6"
```

## 5. A well formed record

A record is well formed only if all of these conditions are true:

- The RRset has exactly one distinct `policy=` value.
- The RRset has exactly one distinct `policy_hash=` value.
- The hash value is `0x` and 64 hexadecimal characters.
- No policy value is split across character-strings.

If the policy strings are present, but the record is not well formed, the record is unusable. The
archiver records `no_record`. The detail says what is wrong. A record cannot be ambiguous and also be
a record.

A well formed record is not a verified record. Verification needs a fetch and a comparison.

## 6. What the archiver does

The archiver does these steps in this order. It stops at the first failure.

| Step | Action | Failure |
| --- | --- | --- |
| 1 | Query TXT at `_ens.<name>` and `_ens.nic.<name>`, at two resolvers | |
| 2 | Confirm that the apex has TXT records | `no_record` |
| 3 | Confirm that the apex answer validated | `dnssec_unvalidated` |
| 4 | Confirm that the resolvers agree | `resolver_disagreement` |
| 5 | Read the record, and confirm that it is well formed | `no_record` |
| 6 | Compare the nic form to the apex | `name_disagreement`, then continue |
| 7 | Fetch the URL, with a size cap and a redirect cap | `fetch_failed` |
| 8 | Hash the raw bytes, and compare to the declared hash | `hash_mismatch` |
| 9 | Write the document and the record | |

Step 3 asks for the apex answer. If more than one resolver answers, every answer must validate.

Step 8 is the only step that can prove that a document changed. On a mismatch the archiver records
the declared hash, the computed hash and the byte size. The archiver does not store the bytes. The
hash and the size prove that something changed. The archive does not hold content that nobody signed
for.

The archiver never changes a document that it already archived.

## 7. Failure kinds

| Kind | Meaning |
| --- | --- |
| `no_record` | There is no policy record, or the record is not well formed |
| `resolver_disagreement` | Two resolvers gave different records for the same name |
| `dnssec_unvalidated` | The answer has records, but it did not validate |
| `name_disagreement` | The nic form declares a different document than the apex |
| `fetch_failed` | The URL gave no document |
| `hash_mismatch` | The bytes do not agree with the declared hash |

`name_disagreement` is the only kind that does not stop the archiver.

## 8. The DNSSEC chain that the archiver stores

### 8.1 Why the archiver stores it

§2 says that the zone must be DNSSEC signed, and that an unsigned record is not evidence of anything.

The archiver at first kept one boolean for each resolver, which is the AD bit. A reader of such a
snapshot can see that two resolvers each said "I validated this" at one moment. The reader must trust
the two resolvers, and must trust this tool. That is not evidence.

So the archiver also keeps the signatures. It reads the same records a second time in wire format,
and it stores the bytes of every link from the signed name up to the root. A reader then validates
the chain against the trust anchor that IANA publishes, and trusts the archiver for nothing.

### 8.2 Two paths, and only one of them decides

The archiver reads DNS two times, in two formats.

| Path | Format | What it is for |
| --- | --- | --- |
| decision | JSON, `application/dns-json` | every step of §6, at two resolvers, with disagreement recorded |
| evidence | wire, `application/dns-message` | the chain, kept as bytes, never read for a decision |

A signature covers exact bytes. The JSON API gives presentation text, and it gives no signature at
all. So the JSON path cannot be the evidence path. The wire path uses GET with the query in the
`dns` parameter, which is RFC 8484 §4.1, and it sets EDNS(0) with the DO bit, which is RFC 3225.

The evidence path decides nothing. A capture that fails is recorded in the chain. It is never one of
the failure kinds of §7, and it never changes an outcome.

The archiver captures the chain only when the apex answers came off the wire. A chain captured now
is not evidence about an answer that came out of a stored file, so `--inject` suppresses the capture.
`--no-chain` also suppresses it. Both reasons are recorded.

### 8.3 The links

The signatures drive the walk, not the labels of the name. The RRSIG over the TXT RRset names the
zone that signed it. The DNSKEY RRset of that zone is the next link. The DS of that zone is the link
after it, and the RRSIG over that DS names the parent zone. The walk repeats until the zone is the
root.

This finds the true zone cuts. `_ens.estmcmxci.co` has no zone cut at `_ens`, and a walk that went
label by label would ask for keys at a name that holds none.

For `_ens.estmcmxci.co` the walk is six queries. The zones are `estmcmxci.co`, `co` and the root.

| Step | Query | Role | What the link proves |
| --- | --- | --- | --- |
| 1 | TXT at `_ens.estmcmxci.co` | `leaf-rrset` | the policy record, and the signature over it |
| 2 | DNSKEY at `estmcmxci.co` | `zone-keys` | the keys of the zone that signed step 1 |
| 3 | DS at `estmcmxci.co` | `delegation` | `co` commits to those keys |
| 4 | DNSKEY at `co` | `zone-keys` | the keys of the zone that signed step 3 |
| 5 | DS at `co` | `delegation` | the root commits to those keys |
| 6 | DNSKEY at `.` | `zone-keys` | the keys of the root, which IANA anchors |

### 8.4 What a link holds

```json
{
  "step": 1,
  "role": "leaf-rrset",
  "proves": "the TXT RRset at _ens.estmcmxci.co, and the signature over it",
  "query": { "name": "_ens.estmcmxci.co", "type": "TXT" },
  "resolver": "cf",
  "resolver_url": "https://cloudflare-dns.com/dns-query",
  "fetched_at": "2026-11-16T17:24:10.234Z",
  "http_status": 200,
  "content_type": "application/dns-message",
  "response_bytes": 431,
  "response_b64": "AACBoAABAAQAAAABBF9lbnMJZXN0bWNteGNpAmNvAA...",
  "message": { "rcode": "NOERROR", "flags": {}, "counts": {}, "question": [], "answer": [] },
  "signed": true,
  "signer": "estmcmxci.co",
  "attempts": [],
  "error": null
}
```

`response_b64` is the evidence. It is the whole DNS response, as bytes, in base64. Nothing else in
the record is needed to verify the link.

`message` is a reading of those bytes, and it is a convenience. It gives the header, the question and
one entry for each record, with the key tags, the algorithms, the digests and the signature validity
times read out of RRSIG, DNSKEY and DS. It lets a person see the shape of a chain with no parser.
Every field of it comes from `response_b64`, so a reader who disagrees with it can recompute it.

`resolver` names the resolver that served the link. The archiver asks the resolvers in order and
keeps the first answer that reads as a DNS message. `attempts` lists the resolvers that failed first.

One resolver is enough for the evidence path. A reader checks these bytes with arithmetic, and a
second resolver cannot add to what the signature already settles. The decision path still asks two
resolvers, because §6 has no arithmetic to fall back on and a disagreement there is a finding.

### 8.5 What the archiver checks, and what it does not

The archiver checks two things, and records the result of each.

1. **Each DS is the digest of a key that the child served.** `digest_checks` holds one entry for each
   DS. This is all of chain validation except the signature arithmetic.
2. **The root DNSKEY RRset holds a key that IANA anchors.** `root_anchor.matched` holds one entry for
   each published anchor. The digest rule is RFC 4034 §5.1.4.

The archiver does not verify the signatures. A reader must take any check this tool performs on
trust, and the signature arithmetic is the one part a reader can do alone. So the arithmetic belongs
to the reader. §9 is that path.

`root_anchor.expected` holds the anchors that IANA publishes with no `validUntil`, read from
`https://data.iana.org/root-anchors/root-anchors.xml`. Kjqmt7v, key tag 19036, is left out, because
IANA retired it on 11 January 2019. The root rolled its key signing key on 11 October 2026 and signs
with Kmyv6jo, key tag 38696, alone. Klajeyz, key tag 20326, is still published and is still in the
root DNSKEY RRset, so the record keeps both.

`problems` holds a line for each thing that went wrong. An empty `problems`, with `reached_root` and
`root_anchor.any_matched` both true, is a complete chain.

### 8.6 Where it is stored, and the format version

| Schema | Holds the chain |
| --- | --- |
| `gtld-policy-archive/snapshot/1` | no, only the AD boolean of each resolver |
| `gtld-policy-archive/snapshot/2` | yes, under `chain` |
| `gtld-policy-archive/observation/1` | no |
| `gtld-policy-archive/observation/2` | a one line summary, under `chain` |
| `gtld-policy-archive/failure/1` | the shape did not change. The raw file that the line names holds the chain |

The version tells a reader which snapshots carry proof and which carry hearsay. A `snapshot/1`
record is never rewritten. A chain captured today says nothing about a record that was read last
week, so a backfill would be a fabrication.

A run that writes no snapshot writes the chain to `archive/<name>/raw/<timestamp>.json`, under the
same `chain` key. No answer is discarded.

## 9. How a reader verifies a chain offline

These steps need the snapshot directory and nothing else. They touch no network.

They assume a complete chain, which is `chain.reached_root` true, `chain.root_anchor.any_matched`
true and `chain.problems` empty.

1. **Read the bytes.** Base64 decode `chain.links[i].response_b64` for each link. Each one is a whole
   DNS response, as RFC 1035 §4 defines it.
2. **Validate as of the capture time.** A signature has an inception and an expiration. An archived
   signature is expired, which is correct and is not a fault. Use `chain.captured_at` as the time.
   Each link also carries its own `fetched_at`.
3. **Check each DNSKEY RRset against itself.** The RRSIG over a DNSKEY RRset is made by a key in that
   same RRset.
4. **Check each DS.** The RRSIG over the DS of a zone is made by a key of the parent zone, which the
   step above validated. The DS value must also equal the digest of the child's own DNSKEY.
5. **Check the leaf.** The RRSIG over the TXT RRset at `_ens.<name>` is made by a key of the zone
   that its `signer` field names.
6. **Check the root against IANA.** Compute the DS digest of each root DNSKEY. One of them must equal
   a `Digest` in IANA's `root-anchors.xml`. The record repeats those anchors under
   `chain.root_anchor.expected`, and a reader must compare against IANA, not against the record.
7. **Check the document.** sha256 of `policy.<ext>` must equal `snapshot.declared_hash`, which is the
   value the chain above proves the operator signed for.

This script does all seven. It needs `pip install 'dnspython[dnssec]'` and no other tool.

```python
import base64, calendar, hashlib, json, os, sys, time
import dns.dnssec, dns.message, dns.name, dns.rdatatype

rec = json.load(open(sys.argv[1]))                # the snapshot's record.json
chain = rec["chain"]
when = calendar.timegm(time.strptime(chain["captured_at"][:19], "%Y-%m-%dT%H:%M:%S"))
msg = {(l["query"]["name"], l["query"]["type"]):
       dns.message.from_wire(base64.b64decode(l["response_b64"])) for l in chain["links"]}

def pair(key, text):
    t = dns.rdatatype.from_text(text)
    rrs = msg[key].answer
    return (next((r for r in rrs if r.rdtype == t), None),
            next((r for r in rrs if r.rdtype == dns.rdatatype.RRSIG and r.covers == t), None))

keys = {}
for zone in chain["zones"]:                       # 3. each zone's keys sign themselves
    k, s = pair((zone, "DNSKEY"), "DNSKEY")
    dns.dnssec.validate(k, s, {k.name: k}, now=when)
    keys[zone] = k

for zone in chain["zones"]:                       # 4. each DS commits the parent to them
    if zone == ".":
        continue
    ds, s = pair((zone, "DS"), "DS")
    parent = str(s[0].signer).rstrip(".") or "."
    dns.dnssec.validate(ds, s, {keys[parent].name: keys[parent]}, now=when)
    for d in ds:
        k = next(k for k in keys[zone] if dns.dnssec.key_id(k) == d.key_tag)
        assert dns.dnssec.make_ds(keys[zone].name, k, d.digest_type) == d

leaf = chain["links"][0]["query"]                 # 5. the policy record itself
data, s = pair((leaf["name"], leaf["type"]), leaf["type"])
signer = str(s[0].signer).rstrip(".") or "."
dns.dnssec.validate(data, s, {keys[signer].name: keys[signer]}, now=when)

anchors = chain["root_anchor"]["expected"]        # 6. the root, against IANA
got = {dns.dnssec.make_ds(dns.name.root, k, a["digest_type"]).digest.hex().upper()
       for k in keys["."] for a in anchors}
assert [a["id"] for a in anchors if a["digest"] in got]

body = open(os.path.join(os.path.dirname(sys.argv[1]),   # 7. the document
                         rec["snapshot"]["file"]), "rb").read()
assert "0x" + hashlib.sha256(body).hexdigest() == rec["snapshot"]["declared_hash"].lower()
print("the chain validates, and the document is the one the chain signed for")
```

Run it on the specimen snapshot:

```sh
python3 verify-chain.py archive/estmcmxci.co/<date>/record.json
```

A failure in step 3, 4 or 5 raises `dns.exception.ValidationFailure`. One changed byte anywhere in a
signed RRset is enough to raise it, so the archiver cannot write a chain that it did not receive.

## 10. The raw_sha256 recipe

`tool.raw_sha256` and the `raw_sha256` of a failure line and an observation line all name the raw
bundle of one observation. The value is sha256 over `JSON.stringify(bundle)`, which has no spacing
and no trailing newline. The archiver writes the file pretty printed and with a trailing newline.

So the hash of the stored file is **not** the recorded value. That is confusing, and it looks like
tampering. Two recipes reproduce it.

**A raw file,** which is `archive/<name>/raw/<timestamp>.json`. Read it, parse it, and write it back
with no spacing:

```sh
node -e 'const fs=require("fs"),c=require("crypto");
  console.log("0x"+c.createHash("sha256").update(JSON.stringify(JSON.parse(fs.readFileSync(process.argv[1],"utf8")))).digest("hex"))' \
  archive/estmcmxci.co/raw/<timestamp>.json
```

`jq` gives the same value, because `jq -c` keeps the order of the keys and `-j` drops the newline:

```sh
jq -c -j . archive/estmcmxci.co/raw/<timestamp>.json | shasum -a 256
```

**A snapshot record.** A snapshot holds the same answers in a different shape, so a reader must
rebuild the bundle first. The fields and their order are these:

```js
{ name:       record.name,
  observed_at: record.records.apex.observed_at,
  resolvers:  record.tool.resolvers,
  apex:       { name: record.records.apex.name_queried, answers: record.records.apex.raw },
  nic:        record.records.nic
                ? { name: record.records.nic.name_queried, answers: record.records.nic.raw }
                : null,
  injected:   false,
  chain:      record.chain }
```

sha256 over `JSON.stringify` of that object is `tool.raw_sha256`. `injected` is false in every
archived snapshot, because the archive holds live observations only.

A `snapshot/1` record has no `chain` key. Leave the field out of the rebuild for one of those.

## 11. Limits of this specification

This specification does not do these things:

- It does not say what a policy must contain.
- It does not enforce a policy.
- It does not judge whether a policy is good.
- It does not change a contract.
- It does not make the nic form authoritative.

## 12. Source

nick.eth asked for this record and this archive on 22 April 2026, in
[t/22020 #7](https://discuss.ens.domains/t/temp-check-authorize-tldminter-as-root-controller/22020/7).
