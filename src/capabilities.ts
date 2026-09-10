import { constants, accessSync, existsSync } from "node:fs";
import { delimiter, join } from "node:path";
import { spawnSync } from "node:child_process";

import type { CapabilityProbe, CapabilityReport, HostIdentity } from "./contracts.js";
import { jsonText, writePrivate } from "./files.js";
import { detectHost } from "./host.js";
import { statePaths } from "./paths.js";
import { macosPipelineReady, macosSensorReady } from "./macos-eslogger.js";

export function commandExists(
	command: string,
	searchPath = process.env.PATH ?? "",
): boolean {
	const directories = searchPath.split(delimiter);
	return directories.some((directory) => existsSync(join(directory, command)));
}

export function canRead(path: string): boolean {
	try {
		accessSync(path, constants.R_OK);
		return true;
	} catch {
		return false;
	}
}

export function canRun(command: string, args: string[]): boolean {
	const result = spawnSync(command, args, {
		encoding: "utf8",
		stdio: "ignore",
		timeout: 3000,
	});
	return result.error === undefined && result.status === 0;
}

function probe(
	id: string,
	category: CapabilityProbe["category"],
	ready: boolean,
	detail: string,
	instruction: string,
): CapabilityProbe {
	return {
		category,
		detail,
		id,
		instruction,
		required: true,
		status: ready ? "ready" : "action-required",
	};
}

function macSensorReady(root: string | undefined): boolean {
	return root === undefined ? false : macosSensorReady(root);
}

function macProbes(root: string | undefined): CapabilityProbe[] {
	const brokerReady = canRun(
		"/bin/launchctl",
		["print", "system/com.argus.ids-agent.broker"],
	);
	const sensorReady = canRun(
		"/bin/launchctl",
		["print", "system/com.argus.ids-agent.sensor"],
	) && macSensorReady(root);
	const pipelineReady = root !== undefined && macosPipelineReady(root);
	return [
		probe(
			"macos-unified-log",
			"collect",
			canRun("/usr/bin/log", ["show", "--last", "1m", "--style", "ndjson"]),
			"Read recent macOS Unified Log events.",
			"Grant log access to the installed agent service, then run doctor again.",
		),
		probe(
			"macos-full-disk-access",
			"investigate",
			sensorReady,
			"Allow Apple's eslogger to receive Endpoint Security events.",
			"Open System Settings > Privacy & Security > Full Disk Access. Add Argus Sensor from Applications. Then run ids-agent access.",
		),
		probe(
			"macos-endpoint-events",
			"detect",
			commandExists("eslogger") && pipelineReady,
			"Receive process, file, and authentication events through Endpoint Security.",
			"Start the Argus daemon and sensor. Grant Argus Sensor Full Disk Access. Wait for one event, then run ids-agent access.",
		),
		probe(
			"macos-mitigation-broker",
			"mitigate",
			brokerReady,
			"Perform approved process, service, and persistence actions.",
			"Install the root-owned broker with native administrator authentication.",
		),
	];
}

function linuxProbes(): CapabilityProbe[] {
	const auditPath = "/var/log/audit/audit.log";
	const auditRulesPath = "/etc/audit/rules.d/argus.rules";
	const journalReady = commandExists("journalctl") && canRun("journalctl", ["--no-pager", "-n", "1"]);
	const firewallReady = commandExists("nft") || commandExists("iptables");
	const brokerReady = commandExists("systemctl") && canRun(
		"systemctl",
		["is-active", "--quiet", "argus-ids-broker.service"],
	);
	return [
		probe(
			"linux-journal",
			"collect",
			journalReady,
			"Read system and service events from the journal.",
			"Add the service account to the systemd-journal group, then run doctor again.",
		),
		probe(
			"linux-audit",
			"detect",
			canRead(auditPath) && canRead(auditRulesPath),
			"Read Linux Audit events from the installed Argus rules.",
			"Install and enable auditd. Install the Argus Audit rules. Give the agent read access to the audit log.",
		),
		probe(
			"linux-process-state",
			"investigate",
			canRead("/proc/1/status"),
			"Inspect local process state and ownership.",
			"Mount procfs and allow the service account to read process metadata.",
		),
		probe(
			"linux-firewall-tool",
			"mitigate",
			firewallReady,
			"Provide a supported firewall backend for containment.",
			"Install nftables and keep its rules under administrator control.",
		),
		probe(
			"linux-mitigation-broker",
			"mitigate",
			brokerReady,
			"Perform approved process, service, account, and firewall actions.",
			"Install the root-owned broker with its fixed action allowlist.",
		),
	];
}

export function platformProbes(
	platform: HostIdentity["platform"],
	root?: string,
): CapabilityProbe[] {
	return platform === "darwin" ? macProbes(root) : linuxProbes();
}

export function inspectCapabilities(now = new Date(), root?: string): CapabilityReport {
	const host = detectHost();
	const probes = platformProbes(host.platform, root);
	return {
		checkedAt: now.toISOString(),
		hostFingerprint: host.fingerprint,
		platform: host.platform,
		probes,
		ready: probes.every((item) => !item.required || item.status === "ready"),
		schemaVersion: 1,
	};
}

export function saveCapabilityReport(root: string, report: CapabilityReport): void {
	writePrivate(statePaths(root).capabilityReport, jsonText(report));
}
