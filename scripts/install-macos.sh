#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
	printf '%s\n' "This installer supports macOS."
	exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
	printf '%s\n' "Run this installer with sudo."
	exit 1
fi

source_env=${1:-}
if [ -z "$source_env" ] || [ ! -f "$source_env" ]; then
	printf '%s\n' "Usage: sudo ids-agent-install-macos /path/to/.env"
	exit 1
fi

service_user=${SUDO_USER:-}
if [ -z "$service_user" ] || [ "$service_user" = "root" ]; then
	printf '%s\n' "Run this installer from the macOS account that Argus will protect."
	exit 1
fi

ids_agent=$(command -v ids-agent)
service_group=$(id -gn "$service_user")
base_dir="/Library/Application Support/Argus"
state_dir="$base_dir/state"
config_dir="$base_dir/config"
service_env="$config_dir/env"

install -d -o "$service_user" -g "$service_group" -m 0700 "$state_dir"
install -d -o root -g "$service_group" -m 0750 "$config_dir"
install -o root -g "$service_group" -m 0640 "$source_env" "$service_env"

setup_status=0
sudo -u "$service_user" "$ids_agent" setup \
	--state-dir="$state_dir" \
	--env-file="$service_env" || setup_status=$?

"$ids_agent" register-install-resources \
	--state-dir="$state_dir" \
	--env-file="$service_env" \
	--install-resource="$base_dir" \
	--install-resource="$config_dir" \
	--install-resource="$service_env"

"$ids_agent" install-service \
	--state-dir="$state_dir" \
	--env-file="$service_env" \
	--service-user="$service_user" \
	--service-group="$service_group"

printf '%s\n' "Argus is installed for $service_user."
printf '%s\n' "State: $state_dir"
printf '%s\n' "Run doctor and complete each requested macOS privacy approval."
exit "$setup_status"
