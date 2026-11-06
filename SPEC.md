# The gTLD policy record

**Version** 1 · **Date** 6 November 2026 · **Status** proposed

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

## 8. Limits of this specification

This specification does not do these things:

- It does not say what a policy must contain.
- It does not enforce a policy.
- It does not judge whether a policy is good.
- It does not change a contract.
- It does not make the nic form authoritative.

## 9. Source

nick.eth asked for this record and this archive on 22 April 2026, in
[t/22020 #7](https://discuss.ens.domains/t/temp-check-authorize-tldminter-as-root-controller/22020/7).
