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
sensor_app="/Applications/Argus Sensor.app"
sensor_executable="$sensor_app/Contents/MacOS/argus-sensor"
node_path=$(command -v node)
node_real=$("$node_path" -p 'process.execPath')
node_lib=$(find "$(dirname "$node_real")/../lib" -name 'libnode.*.dylib' -print -quit)

install -d -o "$service_user" -g "$service_group" -m 0700 "$state_dir"
install -d -o root -g wheel -m 0711 "$config_dir"
install -o "$service_user" -g "$service_group" -m 0600 "$source_env" "$service_env"

setup_status=0
sudo -u "$service_user" "$ids_agent" setup \
	--state-dir="$state_dir" \
	--env-file="$service_env" || setup_status=$?

install -d -o root -g wheel -m 0755 "$base_dir/sensor"
install -d -o root -g wheel -m 0755 "$sensor_app/Contents/MacOS"
install -d -o root -g wheel -m 0755 "$sensor_app/Contents/lib"
install -o root -g wheel -m 0755 "$node_path" "$sensor_executable"
install -o root -g wheel -m 0755 "$node_lib" "$sensor_app/Contents/lib/$(basename "$node_lib")"
cat > "$sensor_app/Contents/Info.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDisplayName</key>
  <string>Argus Sensor</string>
  <key>CFBundleExecutable</key>
  <string>argus-sensor</string>
  <key>CFBundleIdentifier</key>
  <string>com.argus.ids-agent.sensor</string>
  <key>CFBundleName</key>
  <string>Argus Sensor</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>0.1.0</string>
  <key>CFBundleVersion</key>
  <string>1</string>
  <key>LSUIElement</key>
  <true/>
</dict>
</plist>
EOF
chown root:wheel "$sensor_app/Contents/Info.plist"
chmod 0644 "$sensor_app/Contents/Info.plist"
/usr/bin/codesign --force --deep --sign - "$sensor_app"

"$ids_agent" register-install-resources \
	--state-dir="$state_dir" \
	--env-file="$service_env" \
	--install-resource="$base_dir" \
	--install-resource="$config_dir" \
	--install-resource="$service_env" \
	--install-resource="$sensor_app"

"$ids_agent" install-service \
	--state-dir="$state_dir" \
	--env-file="$service_env" \
	--service-user="$service_user" \
	--service-group="$service_group"

printf '%s\n' "Argus is installed for $service_user."
printf '%s\n' "State: $state_dir"
printf '%s\n' "ACTION REQUIRED: Grant Argus Sensor Full Disk Access."
printf '%s\n' "Open System Settings > Privacy & Security > Full Disk Access."
printf '%s\n' "Select +, open /Applications/Argus Sensor.app, and enable it."
printf '%s\n' "For SSH use, enable full disk access for remote users in Remote Login settings."
sudo -u "$service_user" open "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_AllFiles" >/dev/null 2>&1 || true
printf '%s\n' "After approval, run: ids-agent access"
printf '%s\n' "Then run: ids-agent doctor"
exit "$setup_status"
