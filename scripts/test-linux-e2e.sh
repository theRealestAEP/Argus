#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(dirname -- "$script_dir")

cd "$project_dir"
docker build --tag on-device-ids-agent-e2e --file tests/e2e/Dockerfile .
docker run --rm on-device-ids-agent-e2e
