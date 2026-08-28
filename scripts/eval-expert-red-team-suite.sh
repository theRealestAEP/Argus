#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(dirname -- "$script_dir")

cd "$project_dir"
for scenario in $(node tests/e2e/expert-security-scenario-cli.mjs ids); do
	printf '\n%s\n' "Running expert security scenario: $scenario"
	"$script_dir/eval-expert-red-team.sh" "$scenario"
done
