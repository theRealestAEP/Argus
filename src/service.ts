import { chmodSync, existsSync, unlinkSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

import type { HostIdentity } from "./contracts.js";

export const LINUX_SERVICE_PATH = "/etc/systemd/system/argus-ids.service";
export const LINUX_SERVICE_LINK =
	"/etc/systemd/system/multi-user.target.wants/argus-ids.service";
export const LINUX_BROKER_SERVICE_PATH =
	"/etc/systemd/system/argus-ids-broker.service";
export const LINUX_BROKER_SERVICE_LINK =
	"/etc/systemd/system/multi-user.target.wants/argus-ids-broker.service";
export const MACOS_SERVICE_PATH =
	"/Library/LaunchDaemons/com.argus.ids-agent.plist";
export const MACOS_BROKER_SERVICE_PATH =
	"/Library/LaunchDaemons/com.argus.ids-agent.broker.plist";

export interface ServiceCommand {
	args: string[];
	command: string;
	ignoreFailure: boolean;
}

export interface ServicePlan {
	content: string;
	disable: ServiceCommand[];
	enable: ServiceCommand[];
	label: string;
	path: string;
}

export interface ServiceGateway {
	remove(path: string): void;
	run(command: ServiceCommand): void;
	write(path: string, content: string): void;
}

function xml(value: string): string {
	return value
		.replaceAll("&", "&amp;")
		.replaceAll("<", "&lt;")
		.replaceAll(">", "&gt;");
}

function systemdValue(value: string): string {
	return JSON.stringify(value);
}

export function serviceResourcePaths(
	platformName: HostIdentity["platform"],
): string[] {
	return platformName === "linux"
		? [
			LINUX_SERVICE_PATH,
			LINUX_SERVICE_LINK,
			LINUX_BROKER_SERVICE_PATH,
			LINUX_BROKER_SERVICE_LINK,
		]
		: [MACOS_SERVICE_PATH, MACOS_BROKER_SERVICE_PATH];
}

function linuxServicePlan(
	root: string,
	projectDirectory: string,
	environmentFile: string,
	nodePath: string,
	serviceUser: string,
	serviceGroup: string,
): ServicePlan {
	const command = [
		systemdValue(nodePath),
		systemdValue(`--env-file-if-exists=${environmentFile}`),
		systemdValue(`${projectDirectory}/dist/cli.js`),
		"daemon",
		systemdValue(`--state-dir=${root}`),
	].join(" ");
	return {
		content: `[Unit]
Description=Argus on-device intrusion detection agent
After=network-online.target argus-ids-broker.service
Wants=network-online.target

[Service]
Type=simple
User=${serviceUser}
Group=${serviceGroup}
WorkingDirectory=${systemdValue(root)}
ExecStart=${command}
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
`,
		disable: [
			{
				args: ["disable", "--now", "argus-ids.service"],
				command: "/usr/bin/systemctl",
				ignoreFailure: true,
			},
			{
				args: ["daemon-reload"],
				command: "/usr/bin/systemctl",
				ignoreFailure: false,
			},
		],
		enable: [
			{
				args: ["daemon-reload"],
				command: "/usr/bin/systemctl",
				ignoreFailure: false,
			},
			{
				args: ["enable", "--now", "argus-ids.service"],
				command: "/usr/bin/systemctl",
				ignoreFailure: false,
			},
		],
		label: "argus-ids.service",
		path: LINUX_SERVICE_PATH,
	};
}

export function buildBrokerServicePlan(
	root: string,
	projectDirectory: string,
	nodePath: string,
): ServicePlan {
	const command = [
		systemdValue(nodePath),
		systemdValue(`${projectDirectory}/dist/cli.js`),
		"broker",
		systemdValue(`--state-dir=${root}`),
	].join(" ");
	return {
		content: `[Unit]
Description=Argus privileged containment broker
Before=argus-ids.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=${systemdValue(root)}
ExecStart=${command}
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=${systemdValue(root)}
CapabilityBoundingSet=CAP_NET_ADMIN CAP_KILL
AmbientCapabilities=CAP_NET_ADMIN CAP_KILL

[Install]
WantedBy=multi-user.target
`,
		disable: [
			{
				args: ["disable", "--now", "argus-ids-broker.service"],
				command: "/usr/bin/systemctl",
				ignoreFailure: true,
			},
			{
				args: ["daemon-reload"],
				command: "/usr/bin/systemctl",
				ignoreFailure: false,
			},
		],
		enable: [
			{
				args: ["daemon-reload"],
				command: "/usr/bin/systemctl",
				ignoreFailure: false,
			},
			{
				args: ["enable", "--now", "argus-ids-broker.service"],
				command: "/usr/bin/systemctl",
				ignoreFailure: false,
			},
		],
		label: "argus-ids-broker.service",
		path: LINUX_BROKER_SERVICE_PATH,
	};
}

export function buildMacosBrokerServicePlan(
	root: string,
	projectDirectory: string,
	nodePath: string,
): ServicePlan {
	return {
		content: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.argus.ids-agent.broker</string>
  <key>ProgramArguments</key>
  <array>
    <string>${xml(nodePath)}</string>
    <string>${xml(`${projectDirectory}/dist/cli.js`)}</string>
    <string>broker</string>
    <string>${xml(`--state-dir=${root}`)}</string>
  </array>
  <key>WorkingDirectory</key>
  <string>${xml(root)}</string>
  <key>UserName</key>
  <string>root</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ProcessType</key>
  <string>Background</string>
  <key>StandardOutPath</key>
  <string>${xml(`${root}/runtime/broker.log`)}</string>
  <key>StandardErrorPath</key>
  <string>${xml(`${root}/runtime/broker-error.log`)}</string>
</dict>
</plist>
`,
		disable: [{
			args: ["bootout", "system/com.argus.ids-agent.broker"],
			command: "/bin/launchctl",
			ignoreFailure: true,
		}],
		enable: [
			{
				args: ["bootout", "system/com.argus.ids-agent.broker"],
				command: "/bin/launchctl",
				ignoreFailure: true,
			},
			{
				args: ["bootstrap", "system", MACOS_BROKER_SERVICE_PATH],
				command: "/bin/launchctl",
				ignoreFailure: false,
			},
		],
		label: "com.argus.ids-agent.broker",
		path: MACOS_BROKER_SERVICE_PATH,
	};
}

function macosServicePlan(
	root: string,
	projectDirectory: string,
	environmentFile: string,
	nodePath: string,
	serviceUser: string,
): ServicePlan {
	return {
		content: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.argus.ids-agent</string>
  <key>ProgramArguments</key>
  <array>
	    <string>${xml(nodePath)}</string>
	    <string>${xml(`--env-file-if-exists=${environmentFile}`)}</string>
	    <string>${xml(`${projectDirectory}/dist/cli.js`)}</string>
    <string>daemon</string>
    <string>${xml(`--state-dir=${root}`)}</string>
  </array>
  <key>WorkingDirectory</key>
	<string>${xml(root)}</string>
  <key>UserName</key>
  <string>${xml(serviceUser)}</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ProcessType</key>
  <string>Background</string>
  <key>StandardOutPath</key>
  <string>${xml(`${root}/runtime/daemon.log`)}</string>
  <key>StandardErrorPath</key>
  <string>${xml(`${root}/runtime/daemon-error.log`)}</string>
</dict>
</plist>
`,
		disable: [
			{
				args: ["bootout", "system/com.argus.ids-agent"],
				command: "/bin/launchctl",
				ignoreFailure: true,
			},
		],
		enable: [
			{
				args: ["bootout", "system/com.argus.ids-agent"],
				command: "/bin/launchctl",
				ignoreFailure: true,
			},
			{
				args: ["bootstrap", "system", MACOS_SERVICE_PATH],
				command: "/bin/launchctl",
				ignoreFailure: false,
			},
		],
		label: "com.argus.ids-agent",
		path: MACOS_SERVICE_PATH,
	};
}

export function buildServicePlan(
	platformName: HostIdentity["platform"],
	root: string,
	projectDirectory: string,
	environmentFile: string,
	nodePath: string,
	serviceUser: string,
	serviceGroup: string,
): ServicePlan {
	const accountName = /^[a-zA-Z0-9._-]+$/u;
	if (!accountName.test(serviceUser) || !accountName.test(serviceGroup)) {
		throw new Error("Service user and group names must contain safe account characters.");
	}
	return platformName === "linux"
		? linuxServicePlan(
				root,
				projectDirectory,
				environmentFile,
				nodePath,
				serviceUser,
				serviceGroup,
			)
		: macosServicePlan(root, projectDirectory, environmentFile, nodePath, serviceUser);
}

export function nativeServiceGateway(): ServiceGateway {
	return {
		remove(path) {
			if (existsSync(path)) {
				unlinkSync(path);
			}
		},
		run(command) {
			const result = spawnSync(command.command, command.args, { stdio: "inherit" });
			if (result.status !== 0 && !command.ignoreFailure) {
				throw new Error(`${command.command} failed.`);
			}
		},
		write(path, content) {
			writeFileSync(path, content, { encoding: "utf8", mode: 0o644 });
			chmodSync(path, 0o644);
		},
	};
}

export function installService(
	plan: ServicePlan,
	effectiveUserId: number,
	gateway: ServiceGateway = nativeServiceGateway(),
): void {
	if (effectiveUserId !== 0) {
		throw new Error("Administrator authorization is required to install the service.");
	}
	gateway.write(plan.path, plan.content);
	for (const command of plan.enable) {
		gateway.run(command);
	}
}

export function uninstallService(
	plan: ServicePlan,
	effectiveUserId: number,
	gateway: ServiceGateway = nativeServiceGateway(),
): void {
	if (effectiveUserId !== 0) {
		throw new Error("Administrator authorization is required to remove the service.");
	}
	for (const command of plan.disable) {
		gateway.run(command);
	}
	gateway.remove(plan.path);
}
