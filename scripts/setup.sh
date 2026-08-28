#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(dirname -- "$script_dir")

cd "$project_dir"

if [ -f "$project_dir/.env" ]; then
	chmod 600 "$project_dir/.env"
fi

if ! command -v node >/dev/null 2>&1; then
	printf '%s\n' "Node.js 24 or later is required."
	exit 1
fi

if ! command -v npm >/dev/null 2>&1; then
	printf '%s\n' "npm is required."
	exit 1
fi

node -e 'if (Number(process.versions.node.split(".")[0]) < 24) process.exit(1)' || {
	printf '%s\n' "Node.js 24 or later is required."
	exit 1
}

printf '%s\n' "Installing locked dependencies..."
npm ci

printf '%s\n' "Building the local IDS command..."
npm run build

printf '%s\n' "Starting host commissioning..."
setup_status=0
node --env-file-if-exists="$project_dir/.env" dist/cli.js setup "$@" || setup_status=$?

state_dir=${IDS_AGENT_STATE_DIR:-"$project_dir/.ids-agent"}
service_user=$(id -un)
service_group=$(id -gn)
node_path=$(command -v node)

if [ -f "$state_dir/install-manifest.json" ]; then
	printf '%s\n' "Administrator authorization installs the boot service."
	sudo "$node_path" "$project_dir/dist/cli.js" install-service \
		--state-dir="$state_dir" \
		--service-user="$service_user" \
		--service-group="$service_group"
fi

exit "$setup_status"
