#!/bin/sh
set -eu

node tests/e2e/setup-evaluation.mjs
node tests/e2e/daemon-evaluation.mjs
printf '%s\n' "Linux container end-to-end evaluation passed."
