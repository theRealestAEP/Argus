#!/bin/sh
set -eu

if [ "$(uname -s)" != "Linux" ]; then
	printf '%s\n' "This installer supports Linux."
	exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
	printf '%s\n' "Run this installer with sudo."
	exit 1
fi

source_env=${1:-}
if [ -z "$source_env" ] || [ ! -f "$source_env" ]; then
	printf '%s\n' "Usage: sudo install-linux.sh /path/to/.env"
	exit 1
fi

ids_agent=$(command -v ids-agent)
state_dir=/var/lib/argus-ids
config_dir=/etc/argus-ids
service_user=argus-ids
service_group=argus-ids
service_env=$config_dir/env

if ! id "$service_user" >/dev/null 2>&1; then
	useradd --system --user-group --home-dir "$state_dir" --shell /usr/sbin/nologin "$service_user"
fi

install -d -o "$service_user" -g "$service_group" -m 0700 "$state_dir"
install -d -o root -g "$service_group" -m 0750 "$config_dir"
install -o root -g "$service_group" -m 0640 "$source_env" "$service_env"

setup_status=0
runuser -u "$service_user" -- "$ids_agent" setup \
	--state-dir="$state_dir" \
	--env-file="$service_env" || setup_status=$?

if [ ! -f "$state_dir/sensor-config.json" ]; then
	printf '%s\n' "Linux sensor commissioning is incomplete. Correct the reported setup issue and run this installer again."
	exit 1
fi

"$ids_agent" register-install-resources \
	--state-dir="$state_dir" \
	--env-file="$service_env" \
	--install-resource="account:$service_user" \
	--install-resource="$config_dir" \
	--install-resource="$service_env"

"$ids_agent" install-service \
	--state-dir="$state_dir" \
	--env-file="$service_env" \
	--service-user="$service_user" \
	--service-group="$service_group"

printf '%s\n' "Argus is installed as $service_user."
exit "$setup_status"
