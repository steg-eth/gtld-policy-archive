# gtld-policy-archive

This repository keeps copies of the policy documents that gTLD operators declare in DNS. It also
holds the tool that fetches them.

An operator publishes a policy document at a URL. The operator then puts the URL and the hash of the
document in the DNSSEC signed TXT record that claims its name in ENS. This tool reads that record,
fetches the document, confirms the hash, and writes the document into this repository.

The archive protects against bitrot. The URL can die. The document can change without notice. In both
conditions the archive still holds the bytes that the operator signed for.

**The archive does not enforce anything.** It does not judge whether a policy is good. The
requirements that a policy must satisfy are a governance question for the ENS DAO. They are not in
this repository and the tool does not know them.

nick.eth asked for this on 22 April 2026, in
[t/22020 #7](https://discuss.ens.domains/t/temp-check-authorize-tldminter-as-root-controller/22020/7).

The record format is in [SPEC.md](SPEC.md).

## Use

The tool needs Node 18 or later. It has no dependencies. It uses the standard library and `fetch`.

```sh
# one name
node archive-policy.mjs estmcmxci.co

# many names, from a file
node archive-policy.mjs --population population.example.json

# see what would happen, and write nothing
node archive-policy.mjs estmcmxci.co --dry-run
```

`node archive-policy.mjs --help` lists every option.

The exit status is 1 if any name gave a failure. The status is 0 if every name verified.

### Options that matter

| Option | Effect |
| --- | --- |
| `--population <path>` | A JSON array of names, or one name for each line |
| `--archive <dir>` | Where to write. The default is `archive/` in this repository |
| `--resolvers cf,gg` | Which resolvers to ask. Two is the default, and two is the point |
| `--dry-run` | Do the work, write nothing |
| `--json` | Print the run as JSON |
| `--inject <path>` | Use stored answers in place of live queries. See [test/README.md](test/README.md) |
| `--allow-insecure-url` | Also read `http:` and `file:` URLs. For test cases only |

## What the archive holds

```
archive/<name>/<YYYY-MM-DD>/policy.<ext>   the document, as the bytes arrived
archive/<name>/<YYYY-MM-DD>/record.json    what DNS said, and the result
archive/<name>/failures.jsonl              every failure, appended
archive/<name>/observations.jsonl          one line for each run
archive/<name>/raw/<timestamp>.json        the raw answers, when no snapshot was written
```

### Rules

**A snapshot never changes.** The tool writes a dated directory one time. If a second and different
document arrives on the same day, the tool writes `<YYYY-MM-DD>-02`.

**An unchanged document does not make a new snapshot.** The tool compares the computed hash to the
last archived hash. If the two agree, the tool appends a `verified_unchanged` line and writes nothing
else. Git then holds the changes and nothing else. That is the reason the archive is a repository and
not a bucket.

**Failures append.** The tool never overwrites a failure and never removes a good copy because of
one. A failure leaves the last good document exactly as it was.

**No raw answer is discarded.** The tool keeps the full DoH answer from every resolver for every
observation. A snapshot keeps its answers inside `record.json`. A run that writes no snapshot keeps
them in `raw/`. The observation line always names the path that holds them.

The last rule comes from the measurement harness this tool borrows from. In that repository,
`research/gtld/reparse.mjs` exists only because an earlier census parsed one field and threw the
answer away. A later question then forced a second pass over data that the census had already
fetched. A future question about a field that nobody extracted should cost nothing.

## How a run decides

The tool stops at the first failure. [SPEC.md §6](SPEC.md#6-what-the-archiver-does) has the table.

Two conditions are easy to confuse:

- A name with no TXT record at all gives `no_record`.
- A name with TXT records that did not validate gives `dnssec_unvalidated`.

`adStatus` puts both in its `no-answer` class, so the tool separates them before it applies the
DNSSEC gate.

One failure kind does not stop the run. `name_disagreement` means that `_ens.nic.<name>` declares a
different document than `_ens.<name>`. The apex is authoritative, so the tool records the
disagreement and archives from the apex.

## Verify this yourself

Nothing here asks you to trust the archive. Three commands reproduce the whole claim. The live test
bed is `estmcmxci.co`, a DNSSEC signed zone under algorithm 13.

**1. Read the signed record.**

```sh
dig +dnssec TXT _ens.estmcmxci.co
```

The RRset carries `policy=`, `policy_hash=` and the claim record `a=0x…`, with an RRSIG over it. A
validating resolver returns the `ad` flag. `SPEC.md` defines the two policy strings.

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

**Re-derive any field without querying.** Every `record.json` holds the raw DNS over HTTPS answers
from both resolvers, at `records.apex.raw` and `records.nic.raw`. A question about a field the tool
did not extract costs a re-read rather than a new observation, and anyone can check the parse against
the bytes it was made from.

**The failure cases are in `test/`.** `test/README.md` says how each one was produced and what it
wrote.

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

`lib/dnssec.mjs` is a copy of `AD_STATUS` and `adStatus` from `research/gtld/dnssec.mjs` in the
author's published measurement repository. The file header names the original.

The copy is deliberate. The published corpus must stay frozen, because it produced published
figures. A dependency on it would make this tool fail if that repository moves.

`lib/doh.mjs` follows the dual-resolver pattern of `research/gtld/revoke-census.mjs`: a map of
resolvers, retries with linear backoff, the pacing and concurrency constants, and a record of whether
the resolvers agreed. That census found that disagreement between two resolvers is itself a finding.
This tool therefore records disagreement. It does not resolve it.
