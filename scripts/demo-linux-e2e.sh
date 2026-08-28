#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(dirname -- "$script_dir")

if [ ! -f "$project_dir/.env" ]; then
	printf '%s\n' "Create .env and set OPENAI_API_KEY before you run this demo."
	exit 1
fi

cd "$project_dir"
docker build --tag ids-agent-live-demo --file tests/e2e/Dockerfile .
docker run --rm \
	--env-file "$project_dir/.env" \
	--env IDS_AGENT_PRIMARY_MODEL=gpt-5.6-sol \
	--env IDS_AGENT_FALLBACK_MODEL=gpt-5.6-sol \
	ids-agent-live-demo \
	node tests/e2e/live-service-demo.mjs
