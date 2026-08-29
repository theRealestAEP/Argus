#!/bin/sh
set -eu

output=${1:-/tmp/argus-benchmark-snapshot}
install -d -m 0755 "$output"

date -u +%Y-%m-%dT%H:%M:%S.%3NZ >"$output/captured-at.txt"
find /etc/cron.d /etc/systemd/system /home/benchmark-app \
	-xdev -type f -printf '%p|%s|%T@\n' 2>/dev/null \
	| sort >"$output/persistence-files.txt"
ps -eo pid,ppid,uid,lstart,exe,args --no-headers >"$output/processes.txt"
ss -H -lntup >"$output/listeners.txt"
systemctl is-active \
	argus-benchmark-web.service \
	argus-benchmark-database.service \
	argus-benchmark-agent.service \
	argus-ids.service \
	argus-ids-broker.service >"$output/services.txt" || true
cp /var/log/argus-benchmark/database-access.jsonl "$output/database-access.jsonl"
cp /var/log/argus-benchmark/web-access.jsonl "$output/web-access.jsonl"
cp /var/lib/argus-ids/logs/events.jsonl "$output/argus-events.jsonl" 2>/dev/null || true
chmod -R a+rX "$output"
