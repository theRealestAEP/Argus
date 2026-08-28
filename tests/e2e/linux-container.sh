#!/bin/sh
set -eu

node tests/e2e/setup-evaluation.mjs
node tests/e2e/daemon-evaluation.mjs
node tests/e2e/linux-operational-evaluation.mjs
node tests/e2e/containment-load-evaluation.mjs
printf '%s\n' "Linux container end-to-end evaluation passed."
