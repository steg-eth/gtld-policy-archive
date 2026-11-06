#!/bin/sh
# Run every case into a demonstration archive, and leave archive/ alone.
#
#   sh test/run-cases.sh
#
# Run `node test/make-cases.mjs` first. The exit status of each run is shown,
# because a failure must give 1 and a verified run must give 0.
set -u
cd "$(dirname "$0")/.." || exit 1

DEMO=test/archive-demo
rm -rf "$DEMO"

run() {
  label="$1"; shift
  printf '\n=== %s ===\n' "$label"
  node archive-policy.mjs estmcmxci.co --archive "$DEMO" "$@"
  printf 'exit=%s\n' "$?"
}

run '1. verified write, from the live record'
printf '    archived: %s\n' "$(ls "$DEMO"/estmcmxci.co | tr '\n' ' ')"
before=$(shasum -a 256 "$DEMO"/estmcmxci.co/*/policy.md | awk '{print $1}')

run '1b. the same record again, so no new snapshot'

run '2. hash mismatch' --inject test/cases/hash-mismatch.json --allow-insecure-url
run '3. dead URL, 404'  --inject test/cases/dead-url.json
run '3b. dead host'     --inject test/cases/dead-host.json
run '4. DNSSEC gate'    --inject test/cases/dnssec-unvalidated.json
run '5. resolver disagreement' --inject test/cases/resolver-disagreement.json
run '6. nic disagreement, which must still archive' --inject test/cases/name-disagreement.json
run '7. malformed hash' --inject test/cases/malformed-hash.json

after=$(shasum -a 256 "$DEMO"/estmcmxci.co/*/policy.md | awk '{print $1}')
printf '\n=== the good copy ===\n'
printf 'before the failures: %s\n' "$before"
printf 'after  the failures: %s\n' "$after"
[ "$before" = "$after" ] && printf 'untouched\n' || printf 'CHANGED, which is a bug\n'

printf '\n=== dated snapshots, which must be one ===\n'
ls -d "$DEMO"/estmcmxci.co/2*/ 2>/dev/null

printf '\n=== failures.jsonl ===\n'
node -e '
const fs = require("fs");
for (const l of fs.readFileSync("'"$DEMO"'/estmcmxci.co/failures.jsonl", "utf8").trim().split("\n")) {
  const d = JSON.parse(l);
  console.log(`  ${d.kind.padEnd(22)} ${d.detail.slice(0, 120)}`);
}'

printf '\n=== observations.jsonl ===\n'
node -e '
const fs = require("fs");
for (const l of fs.readFileSync("'"$DEMO"'/estmcmxci.co/observations.jsonl", "utf8").trim().split("\n")) {
  const d = JSON.parse(l);
  console.log(`  ${d.outcome.padEnd(19)} ${(d.kind ?? "-").padEnd(22)} raw=${d.raw_path}`);
}'
