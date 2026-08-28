import { constants, accessSync, existsSync } from "node:fs";
import { delimiter, join } from "node:path";
import { spawnSync } from "node:child_process";

import type { CapabilityProbe, CapabilityReport, HostIdentity } from "./contracts.js";
import { jsonText, writePrivate } from "./files.js";
import { detectHost } from "./host.js";
import { statePaths } from "./paths.js";

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

function macProbes(): CapabilityProbe[] {
	const root = process.geteuid?.() === 0;
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
			canRead("/Library/Application Support/com.apple.TCC/TCC.db"),
			"Read protected security and application data selected by policy.",
			"Open System Settings > Privacy & Security > Full Disk Access. Add the installed agent service.",
		),
		probe(
			"macos-endpoint-events",
			"detect",
			commandExists("eslogger") && root,
			"Receive process, file, and authentication events through Endpoint Security.",
			"Install the signed sensor and approve its Endpoint Security access.",
		),
		probe(
			"macos-mitigation-broker",
			"mitigate",
			false,
			"Perform approved process, service, account, and firewall actions.",
			"Install the signed privileged broker and approve it with native administrator authentication.",
		),
	];
}

function linuxProbes(): CapabilityProbe[] {
	const auditPath = "/var/log/audit/audit.log";
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
			canRead(auditPath),
			"Read Linux Audit events.",
			"Install and enable auditd. Give the broker read access to the audit log.",
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
): CapabilityProbe[] {
	return platform === "darwin" ? macProbes() : linuxProbes();
}

export function inspectCapabilities(now = new Date()): CapabilityReport {
	const host = detectHost();
	const probes = platformProbes(host.platform);
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
