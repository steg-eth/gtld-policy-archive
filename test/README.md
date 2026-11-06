# The failure cases

Four cases must work against the live record. This directory reproduces them, and three more.

## Reproduce

```sh
node test/make-cases.mjs    # capture the live answers, then build the cases
sh test/run-cases.sh        # run all of them into test/archive-demo/
```

`test/cases/` and `test/archive-demo/` are generated and are not committed. The capture in
`test/fixtures/` is committed, because it is portable. `node test/make-cases.mjs --from
test/fixtures/live-estmcmxci.co-2026-11-06.json` rebuilds the cases from the capture and queries
nothing.

## How a case is built

Every case starts from a real answer for `_ens.estmcmxci.co`, captured from Cloudflare and from
Google, and changes one thing.

The DNSSEC gate is upstream of the fetch. A case that must reach the hash comparison therefore has to
keep the AD bit set. A fabricated answer could not do that, so the cases are edits of real answers
and not inventions.

`--inject <path>` puts a stored answer in place of a live query. The file is keyed by name:

```json
{ "estmcmxci.co": { "apex": { "cf": {}, "gg": {} }, "nic": { "cf": {}, "gg": {} } } }
```

A key that the file omits is queried live. So a case can inject the apex and still read the real nic
form.

## The cases

| File | Kind | What changed |
| --- | --- | --- |
| none, the live record | verified | nothing |
| `hash-mismatch.json` | `hash_mismatch` | `policy=` points at `fixtures/altered-policy.md`, which is the specimen with one line appended. The declared hash is untouched |
| `dead-url.json` | `fetch_failed` | `policy=` points at a file that does not exist in this repository, so the host answers 404 |
| `dead-host.json` | `fetch_failed` | `policy=` points at a host in `.invalid`, so the name does not resolve |
| `dnssec-unvalidated.json` | `dnssec_unvalidated` | `AD` is false. The records are the real ones |
| `resolver-disagreement.json` | `resolver_disagreement` | Google declares a different URL than Cloudflare |
| `name-disagreement.json` | `name_disagreement` | `_ens.nic.estmcmxci.co` declares a different URL and hash. The run must still archive from the apex |
| `malformed-hash.json` | `no_record` | `policy_hash=` is `0xdeadbeef`, which is not 32 bytes |

The hash mismatch case uses a `file:` URL, so it needs `--allow-insecure-url`. The other cases do
not.

The nic answers of `name-disagreement.json` are edited copies of the apex answers, so their
`Question` names still read `_ens.estmcmxci.co`. The parser does not read those names, so this does
not change the result.

## What each case must show

1. **Verified write.** The document lands, `record.json` is right, the hashes agree.
2. **Hash mismatch.** A failure line carries both hashes and the byte size. No bytes are stored. The
   earlier good copy is untouched.
3. **Dead URL.** A failure line appears. The earlier good copy is untouched.
4. **DNSSEC gate.** The run gives `dnssec_unvalidated` and archives nothing.
