#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(dirname -- "$script_dir")

cd "$project_dir"
npm run dist
docker run --rm \
	--volume "$project_dir/release:/release:ro" \
	node:24-bookworm-slim \
	sh -c 'npm install --global /release/*.tgz >/dev/null && ids-agent help | grep "Run first-time setup" && command -v ids-agent-install-macos'

printf '%s\n' "Release archive evaluation passed."
