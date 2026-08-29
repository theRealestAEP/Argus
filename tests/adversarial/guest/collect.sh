#!/bin/sh
set -eu

output=${1:-/tmp/argus-benchmark-results}
rm -rf "$output"
install -d -m 0755 "$output/argus-reports" "$output/containment-receipts"

/opt/argus-benchmark/snapshot.sh "$output/host"
cp /var/log/audit/audit.log "$output/audit.log"
journalctl --no-pager --since '30 minutes ago' >"$output/journal.log"
cp /var/lib/argus-ids/logs/events.jsonl "$output/argus-events.jsonl" 2>/dev/null || true
cp /var/lib/argus-ids/reports/* "$output/argus-reports/" 2>/dev/null || true
cp /var/lib/argus-ids/containment-receipts/* "$output/containment-receipts/" 2>/dev/null || true
cp /opt/argus-benchmark/run-config.json "$output/run-config.json"
chmod -R a+rX "$output"
