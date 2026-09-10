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
audit_rules=/etc/audit/rules.d/argus.rules

if ! id "$service_user" >/dev/null 2>&1; then
	useradd --system --user-group --home-dir "$state_dir" --shell /usr/sbin/nologin "$service_user"
fi

for access_group in adm systemd-journal; do
	if getent group "$access_group" >/dev/null 2>&1; then
		usermod --append --groups "$access_group" "$service_user"
	fi
done

install -d -o "$service_user" -g "$service_group" -m 0700 "$state_dir"
install -d -o root -g "$service_group" -m 0750 "$config_dir"
install -o root -g "$service_group" -m 0640 "$source_env" "$service_env"

if [ -d /etc/audit/rules.d ]; then
	rules_tmp=$(mktemp)
	trap 'rm -f "$rules_tmp"' EXIT
	for credential in /etc/shadow /etc/gshadow; do
		if [ -f "$credential" ]; then
			printf '%s\n' "-w $credential -p r -k argus_credential" >>"$rules_tmp"
		fi
	done
	for persistent_path in \
		/etc/cron.d /etc/crontab /etc/systemd/system /etc/profile.d /etc/ld.so.preload; do
		if [ -e "$persistent_path" ]; then
			printf '%s\n' "-w $persistent_path -p wa -k argus_persistence" >>"$rules_tmp"
		fi
	done
	for kernel_path in /etc/audit /etc/modules /etc/modules-load.d /etc/modprobe.d /etc/sysctl.d; do
		if [ -e "$kernel_path" ]; then
			printf '%s\n' "-w $kernel_path -p wa -k argus_kernel" >>"$rules_tmp"
		fi
	done
	getent passwd | while IFS=: read -r _ _ _ _ _ account_home _; do
		case "$account_home" in
			*' '*|'') continue ;;
		esac
		for credential in "$account_home"/.ssh/id_rsa "$account_home"/.ssh/id_ecdsa \
			"$account_home"/.ssh/id_ed25519 "$account_home"/.aws/credentials; do
			if [ -f "$credential" ]; then
				printf '%s\n' "-w $credential -p r -k argus_credential"
			fi
		done
		for persistent_file in "$account_home"/.ssh/authorized_keys \
			"$account_home"/.bashrc "$account_home"/.profile; do
			if [ -e "$persistent_file" ]; then
				printf '%s\n' "-w $persistent_file -p wa -k argus_persistence"
			fi
		done
	done >>"$rules_tmp"
	for shell_path in /bin/bash /bin/dash /bin/sh /bin/zsh /usr/bin/bash /usr/bin/dash /usr/bin/zsh; do
		if [ -x "$shell_path" ]; then
			printf '%s\n' "-a always,exit -F arch=b64 -S execve -F auid=unset -F euid!=0 -F exe=$shell_path -k argus_exec" >>"$rules_tmp"
		fi
	done
	printf '%s\n' '-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k argus_kernel' >>"$rules_tmp"
	printf '%s\n' '-a always,exit -F arch=b64 -S bpf -F a0=5 -k argus_kernel' >>"$rules_tmp"
	printf '%s\n' '-a always,exit -F arch=b64 -S fchmodat -F a2&06000 -k argus_persistence' >>"$rules_tmp"
	if [ "$(uname -m)" = "x86_64" ]; then
		printf '%s\n' '-a always,exit -F arch=b64 -S chmod,fchmod -F a1&06000 -k argus_persistence' >>"$rules_tmp"
	fi
	install -o root -g root -m 0644 "$rules_tmp" "$audit_rules"
	if command -v augenrules >/dev/null 2>&1; then
		augenrules --load || printf '%s\n' "Argus installed its Audit rules. Restart auditd before you start Argus."
	fi
fi

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

if [ -f "$audit_rules" ]; then
	"$ids_agent" register-install-resources \
		--state-dir="$state_dir" \
		--env-file="$service_env" \
		--install-resource="$audit_rules"
fi

"$ids_agent" install-service \
	--state-dir="$state_dir" \
	--env-file="$service_env" \
	--service-user="$service_user" \
	--service-group="$service_group"

printf '%s\n' "Argus is installed as $service_user."
exit "$setup_status"
