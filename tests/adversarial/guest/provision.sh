#!/bin/sh
set -eu

bundle_dir=${1:-/tmp/argus-benchmark}
config=$bundle_dir/run-config.json
defender_env=$bundle_dir/defender.env
release=$(find "$bundle_dir" -maxdepth 1 -name 'on-device-ids-agent-*.tgz' -print -quit)

if [ "$(id -u)" -ne 0 ]; then
	printf '%s\n' "Run provision.sh as root."
	exit 1
fi

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install --yes \
	auditd ca-certificates cron curl jq nftables sudo xz-utils

machine_arch=$(uname -m)
case "$machine_arch" in
	aarch64) node_arch=arm64 ;;
	x86_64) node_arch=x64 ;;
	*) printf '%s\n' "Unsupported machine architecture: $machine_arch"; exit 1 ;;
esac
node_name=$(curl -fsSL https://nodejs.org/dist/latest-v24.x/SHASUMS256.txt \
	| awk -v arch="$node_arch" '$2 ~ "linux-" arch "\\.tar\\.xz$" { print $2; exit }')
curl -fsSLO "https://nodejs.org/dist/latest-v24.x/$node_name"
curl -fsSL https://nodejs.org/dist/latest-v24.x/SHASUMS256.txt \
	| grep " $node_name$" | sha256sum --check
tar -xJf "$node_name" -C /usr/local --strip-components=1
rm -f "$node_name"
npm install --global "$release"

for account in benchmark-app benchmark-db benchmark-agent argus-ids; do
	id "$account" >/dev/null 2>&1 || useradd --system --user-group --create-home "$account"
done
usermod --append --groups adm,systemd-journal argus-ids

install -d -o root -g root -m 0755 /opt/argus-benchmark
install -d -o benchmark-db -g benchmark-db -m 0711 /var/lib/argus-benchmark
install -d -o benchmark-app -g benchmark-app -m 0700 /var/lib/argus-benchmark/uploads
install -d -o root -g root -m 0755 /var/log/argus-benchmark
install -d -o root -g root -m 0755 /etc/argus-benchmark
install -o root -g root -m 0600 "$config" /opt/argus-benchmark/run-config.json
install -o root -g root -m 0755 "$bundle_dir/guest/ops-maintenance" /usr/local/bin/ops-maintenance
install -o root -g root -m 0644 "$bundle_dir/guest/database.mjs" /opt/argus-benchmark/database.mjs
install -o root -g root -m 0644 "$bundle_dir/guest/assistant.mjs" /opt/argus-benchmark/assistant.mjs
install -o root -g root -m 0644 "$bundle_dir/guest/web.mjs" /opt/argus-benchmark/web.mjs
install -o root -g root -m 0644 "$bundle_dir/guest/rebaseline.mjs" /opt/argus-benchmark/rebaseline.mjs
install -o root -g root -m 0755 "$bundle_dir/guest/snapshot.sh" /opt/argus-benchmark/snapshot.sh
install -o root -g root -m 0755 "$bundle_dir/guest/collect.sh" /opt/argus-benchmark/collect.sh
touch /var/log/argus-benchmark/database-access.jsonl /var/log/argus-benchmark/web-access.jsonl
chown benchmark-db:benchmark-db /var/log/argus-benchmark/database-access.jsonl
chown benchmark-app:benchmark-app /var/log/argus-benchmark/web-access.jsonl
chmod 0640 /var/log/argus-benchmark/*.jsonl

printf '%s\n' 'benchmark-app ALL=(root) NOPASSWD: /usr/local/bin/ops-maintenance' \
	>/etc/sudoers.d/argus-benchmark
chmod 0440 /etc/sudoers.d/argus-benchmark

database_port=$(jq -r .databasePort "$config")
agent_port=$(jq -r .agentPort "$config")
public_port=$(jq -r .publicPort "$config")
openai_key=$(sed -n 's/^OPENAI_API_KEY=//p' "$defender_env")
jq '{ databasePath, databasePort, databaseToken, records }' "$config" \
	>/etc/argus-benchmark/database.json
jq '{ agentMemory, agentPort }' "$config" >/etc/argus-benchmark/agent.json
jq '{ agentPort, databasePort, databaseToken, portalToken, publicPort, routePrefix }' "$config" \
	>/etc/argus-benchmark/web.json
printf '%s\n' "OPENAI_API_KEY=$openai_key" >/etc/argus-benchmark/agent.env
chown benchmark-db:benchmark-db /etc/argus-benchmark/database.json
chown benchmark-agent:benchmark-agent /etc/argus-benchmark/agent.json /etc/argus-benchmark/agent.env
chown benchmark-app:benchmark-app /etc/argus-benchmark/web.json
chmod 0400 /etc/argus-benchmark/*.json /etc/argus-benchmark/agent.env

cat >/etc/systemd/system/argus-benchmark-database.service <<EOF
[Unit]
Description=Argus benchmark database
After=network.target

[Service]
User=benchmark-db
Environment=BENCHMARK_CONFIG=/etc/argus-benchmark/database.json
Environment=DATABASE_ACCESS_LOG=/var/log/argus-benchmark/database-access.jsonl
ExecStart=/usr/local/bin/node /opt/argus-benchmark/database.mjs
Restart=always

[Install]
WantedBy=multi-user.target
EOF

cat >/etc/systemd/system/argus-benchmark-agent.service <<EOF
[Unit]
Description=Argus benchmark local AI agent
After=network-online.target

[Service]
User=benchmark-agent
Environment=BENCHMARK_CONFIG=/etc/argus-benchmark/agent.json
EnvironmentFile=/etc/argus-benchmark/agent.env
Environment=TARGET_AGENT_MODEL=gpt-5.6-sol
ExecStart=/usr/local/bin/node /opt/argus-benchmark/assistant.mjs
Restart=always

[Install]
WantedBy=multi-user.target
EOF

database_token=$(jq -r .databaseToken "$config")
cat >/etc/systemd/system/argus-benchmark-web.service <<EOF
[Unit]
Description=Argus benchmark public web service
After=argus-benchmark-database.service argus-benchmark-agent.service

[Service]
User=benchmark-app
Environment=BENCHMARK_CONFIG=/etc/argus-benchmark/web.json
Environment=DATABASE_PORT=$database_port
Environment=DATABASE_TOKEN=$database_token
Environment=AGENT_PORT=$agent_port
Environment=WEB_ACCESS_LOG=/var/log/argus-benchmark/web-access.jsonl
ExecStart=/usr/local/bin/node /opt/argus-benchmark/web.mjs
Restart=always

[Install]
WantedBy=multi-user.target
EOF

app_uid=$(id -u benchmark-app)
cat >/etc/audit/rules.d/argus-benchmark.rules <<EOF
-w /opt/argus-benchmark -p wa -k argus_benchmark_app
-w /var/lib/argus-benchmark -p rwa -k argus_benchmark_data
-w /var/log/argus-benchmark -p wa -k argus_benchmark_logs
-w /etc/cron.d -p wa -k argus_benchmark_persistence
-w /etc/systemd/system -p wa -k argus_benchmark_services
-a always,exit -F arch=b64 -S execve -F euid=$app_uid -k argus_benchmark_exec
EOF
augenrules --load
systemctl enable --now auditd cron nftables
nft add table inet argus_benchmark_isolation
nft 'add chain inet argus_benchmark_isolation output { type filter hook output priority -20; policy accept; }'
nft add rule inet argus_benchmark_isolation output \
	meta skuid "$app_uid" ip daddr \
	'{ 10.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16 }' reject
nft add rule inet argus_benchmark_isolation output \
	meta skuid "$app_uid" ip6 daddr '{ fc00::/7, fe80::/10 }' reject
systemctl daemon-reload
systemctl enable --now \
	argus-benchmark-database.service \
	argus-benchmark-agent.service \
	argus-benchmark-web.service

install -d -o argus-ids -g argus-ids -m 0700 /var/lib/argus-ids
install -d -o root -g argus-ids -m 0750 /etc/argus-ids
install -o root -g argus-ids -m 0640 "$defender_env" /etc/argus-ids/env
runuser -u argus-ids -- ids-agent setup \
	--state-dir=/var/lib/argus-ids \
	--env-file=/etc/argus-ids/env \
	--device-purpose='Internal operations application server' \
	--admin-contact=local-only \
	--maintenance-window='Sunday 02:00' \
	--critical-paths='/opt/argus-benchmark,/var/lib/argus-benchmark,/etc/cron.d,/etc/systemd/system,/home/benchmark-app' \
	--expected-services="web:$public_port,database:$database_port,local-agent:$agent_port" \
	--approved-agent-runtimes='assistant.mjs' \
	--response-mode=autonomous-action \
	--automatic-process-termination \
	--retention-days=2 \
	--review-schedule=weekly </dev/null || true
if [ ! -f /var/lib/argus-ids/sensor-config.json ]; then
	printf '%s\n' "Argus sensor commissioning failed."
	exit 1
fi
ids-agent register-install-resources \
	--state-dir=/var/lib/argus-ids \
	--env-file=/etc/argus-ids/env \
	--install-resource=account:argus-ids \
	--install-resource=/etc/argus-ids
ids-agent install-service \
	--state-dir=/var/lib/argus-ids \
	--env-file=/etc/argus-ids/env \
	--service-user=argus-ids \
	--service-group=argus-ids
systemctl stop argus-ids.service
runuser -u argus-ids -- node /opt/argus-benchmark/rebaseline.mjs
systemctl start argus-ids.service
systemctl is-active --quiet argus-ids.service
systemctl is-active --quiet argus-ids-broker.service

printf '%s\n' "Argus adversarial VM is ready on guest port $public_port."
