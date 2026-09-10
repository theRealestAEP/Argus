#!/bin/sh
set -eu

output=${1:-/tmp/argus-benchmark-snapshot}
install -d -m 0755 "$output"

date -u +%Y-%m-%dT%H:%M:%S.%3NZ >"$output/captured-at.txt"
find /etc/cron.d /etc/systemd/system \
	-xdev -type f -printf '%p|%s|%T@\n' 2>/dev/null \
	>"$output/persistence-files.txt"
for path in /home/benchmark-app/.ssh/authorized_keys \
	/home/benchmark-app/.bashrc /home/benchmark-app/.profile; do
	if [ -f "$path" ]; then
		find "$path" -xdev -type f -printf '%p|%s|%T@\n'
	fi
done >>"$output/persistence-files.txt"
find /usr/local/bin /usr/lib -xdev -type f -perm /6000 \
	-printf '%p|%s|%T@\n' 2>/dev/null >>"$output/persistence-files.txt"
sort -o "$output/persistence-files.txt" "$output/persistence-files.txt"
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
