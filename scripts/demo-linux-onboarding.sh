#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(dirname -- "$script_dir")
image=ids-agent-onboarding-demo
volume=ids-agent-onboarding-state

if [ ! -f "$project_dir/.env" ]; then
	printf '%s\n' "Create .env and set OPENAI_API_KEY before you run this demo."
	exit 1
fi

cd "$project_dir"
docker build --tag "$image" --file tests/e2e/Dockerfile .
docker volume inspect "$volume" >/dev/null 2>&1 || docker volume create "$volume" >/dev/null
printf '%s\n' "Host role: internal operations application server"
printf '%s\n' "Expected service: operations-api on TCP port 8080"
printf '%s\n' "Approved local agent: local-operations-assistant"
printf '%s\n' "Critical paths: /opt/operations,/var/lib/operations"
docker run --rm -it \
	--cap-add NET_ADMIN \
	--env-file "$project_dir/.env" \
	--env IDS_AGENT_PRIMARY_MODEL=gpt-5.6-sol \
	--env IDS_AGENT_FALLBACK_MODEL=gpt-5.6-sol \
	--publish 127.0.0.1:18080:8080 \
	--volume "$volume:/state" \
	"$image" \
	sh -lc 'node /opt/operations/operations-api.mjs >/var/log/operations/api.log 2>&1 & node /opt/operations/local-assistant.mjs >/var/log/operations/assistant.log 2>&1 & sleep 1; node dist/cli.js setup --state-dir=/state/argus; exec sh'
