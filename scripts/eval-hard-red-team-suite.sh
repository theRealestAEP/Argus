#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(dirname -- "$script_dir")

cd "$project_dir"
suite_result=0
for scenario in $(node tests/e2e/hard-security-scenario-cli.mjs ids); do
	printf '\n%s\n' "Running hard security scenario: $scenario"
	"$script_dir/eval-hard-red-team.sh" "$scenario" || suite_result=1
done
exit "$suite_result"
