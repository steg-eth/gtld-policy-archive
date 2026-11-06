# gtld-policy-archive

An operator publishes a policy document at a URL, then puts that URL and the hash of the document in
the DNSSEC signed TXT record that claims its name in ENS. This tool reads that record, fetches the
document, confirms the hash, and writes the document into this repository.

The archive protects against bitrot. The URL can die. The document can change without notice. In both
conditions the archive still holds the bytes that the operator signed for.

**The archive does not enforce anything.** It does not judge whether a policy is good. The
requirements that a policy must satisfy are a governance question for the ENS DAO. They are not in
this repository and the tool does not know them.


## Verify this yourself

Nothing here asks you to trust the archive. Three commands reproduce the whole claim. The live test
bed is `estmcmxci.co`, a DNSSEC signed zone under algorithm 13.

**1. Read the signed record.**

```sh
dig +dnssec TXT _ens.estmcmxci.co
```

The RRset carries `policy=`, `policy_hash=` and the claim record `a=0x…`, with an RRSIG over it. A
validating resolver returns the `ad` flag.

**2. Reproduce the hash from the document itself.**

```sh
curl -sL https://raw.githubusercontent.com/steg-eth/gtld-policy-archive/master/fixtures/specimen-deprecation-policy.md | shasum -a 256
```

That is `5cd65fc5028170a6bf22b5285cc312c5b67c20291b291a7bf632d6bba63e12e6`. It is the value published
in `policy_hash`, and it is `computed_hash` in `archive/estmcmxci.co/2026-11-06/record.json`. Three
independent paths to the same 32 bytes.

**3. Run the tool.**

```sh
node archive-policy.mjs estmcmxci.co
```

It reports `unchanged`, because the document has not moved since it was archived. A changed document
writes a new dated snapshot. A changed hash writes a failure and leaves the archived copy alone.

Every `record.json` holds the raw DNS over HTTPS answers from both resolvers, so anyone can check the
parse against the bytes it was made from. The failure cases are in [test/](test/README.md), with how
each one was produced.

## Use

Node 18 or later. No dependencies.

```sh
node archive-policy.mjs estmcmxci.co                        # one name
node archive-policy.mjs --population population.example.json  # many
node archive-policy.mjs estmcmxci.co --dry-run              # write nothing
```

`node archive-policy.mjs --help` lists every option. The exit status is 1 if any name gave a failure.

## What the archive holds

```
archive/<name>/<YYYY-MM-DD>/policy.<ext>   the document, as the bytes arrived
archive/<name>/<YYYY-MM-DD>/record.json    what DNS said, and the result
archive/<name>/failures.jsonl              every failure, appended
archive/<name>/observations.jsonl          one line for each run
archive/<name>/raw/<timestamp>.json        the raw answers, when no snapshot was written
```

Four rules govern it.

**A snapshot never changes.** The tool writes a dated directory one time. A second and different
document on the same day becomes `<YYYY-MM-DD>-02`.

**An unchanged document makes no new snapshot.** If the computed hash equals the last archived hash,
the tool appends a `verified_unchanged` line and writes nothing else. Git then holds the changes and
nothing else, which is why the archive is a repository and not a bucket.

**Failures append.** A failure never overwrites an earlier one and never removes a good copy.

**No raw answer is discarded.** Every observation keeps the full answer from every resolver, so a
later question about a field nobody extracted costs a re-read rather than a new query. This is a
lesson from the measurement harness below, where an earlier census parsed one field, threw the answer
away, and had to fetch it all again.

[SPEC.md §6](SPEC.md#6-what-the-archiver-does) has the decision table, and §7 the failure kinds.

## Layout

| Path | What it is |
| --- | --- |
| `archive-policy.mjs` | The tool |
| `lib/dnssec.mjs` | The DNSSEC gate. Vendored, see the file header |
| `lib/doh.mjs` | DNS over HTTPS, at two resolvers, with retries |
| `lib/txt.mjs` | The TXT parser |
| `lib/policy-fetch.mjs` | The fetch, the caps and the hash |
| `lib/archive.mjs` | The archive on disk |
| `fixtures/` | The specimen document that the test bed points at |
| `test/` | The failure cases, and how to reproduce them |
| `SPEC.md` | The record format |

## Borrowed code

`lib/dnssec.mjs` copies `AD_STATUS` and `adStatus` from `research/gtld/dnssec.mjs` in the author's
published measurement repository, and `lib/doh.mjs` follows the dual-resolver pattern of
`research/gtld/revoke-census.mjs`. Both file headers name their original.

The copies are deliberate. That corpus produced published figures and must stay frozen, so a
dependency on it would make this tool fail if it moves. The census also found that disagreement
between two resolvers is itself a finding, so this tool records disagreement rather than resolving it.
