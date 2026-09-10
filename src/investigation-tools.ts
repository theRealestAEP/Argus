import { existsSync, readFileSync } from "node:fs";

import type { Alert, HostIdentity } from "./contracts.js";
import { linuxSnapshotSchema } from "./contracts.js";
import type { InvestigationDecision } from "./model-runtime.js";
import { readPolicy } from "./onboarding.js";
import { statePaths } from "./paths.js";
import { readPrivilegedProcessSnapshot } from "./privileged-inspection.js";
import { collectCriticalFiles } from "./linux-native.js";
import { collectMacosConnections } from "./macos-native.js";
import { readInstallManifest } from "./bootstrap.js";

type ToolName = InvestigationDecision["evidenceRequests"][number];

function evidencePids(alert: Alert): Set<number> {
	return new Set(alert.evidence.flatMap((item) => {
		const match = /^(?:child-pid|parent-pid):(\d+)$/u.exec(item);
		return match === null ? [] : [Number.parseInt(match[1] ?? "", 10)];
	}));
}

function processEvidence(root: string, alert: Alert) {
	const pids = evidencePids(alert);
	try {
		return {
			processes: readPrivilegedProcessSnapshot(root)
				.filter((process) => pids.has(process.pid)),
		};
	} catch (error) {
		return { unavailable: error instanceof Error ? error.message : "Process snapshot failed." };
	}
}

function networkEvidence(root: string, platform: HostIdentity["platform"]) {
	if (platform === "darwin") {
		return collectMacosConnections();
	}
	const path = statePaths(root).sensorState;
	if (!existsSync(path)) {
		return { unavailable: "Linux sensor state is absent." };
	}
	const snapshot = linuxSnapshotSchema.parse(JSON.parse(readFileSync(path, "utf8")));
	return {
		establishedConnectionCount: snapshot.establishedConnectionCount,
		listeners: snapshot.listeners.slice(0, 100),
	};
}

function criticalFileEvidence(root: string, platform: HostIdentity["platform"]) {
	if (platform === "darwin") {
		return { criticalFiles: collectCriticalFiles(readPolicy(root).criticalPaths).slice(0, 200) };
	}
	const path = statePaths(root).sensorState;
	if (!existsSync(path)) {
		return { unavailable: "Linux sensor state is absent." };
	}
	const snapshot = linuxSnapshotSchema.parse(JSON.parse(readFileSync(path, "utf8")));
	return { criticalFiles: snapshot.criticalFiles.slice(0, 200) };
}

function runTool(
	root: string,
	alert: Alert,
	name: ToolName,
	platform: HostIdentity["platform"],
) {
	if (name === "audit-events") {
		return {
			records: alert.evidence.filter((item) =>
				item.startsWith("audit-") || item.startsWith("macos-")
			),
		};
	}
	if (name === "process") {
		return processEvidence(root, alert);
	}
	if (name === "service") {
		const policy = readPolicy(root);
		return {
			criticalPaths: policy.criticalPaths,
			devicePurpose: policy.devicePurpose,
			expectedServices: policy.expectedServices,
			...processEvidence(root, alert),
		};
	}
	if (name === "connections") {
		return networkEvidence(root, platform);
	}
	return criticalFileEvidence(root, platform);
}

export function collectInvestigationEvidence(
	root: string,
	alert: Alert,
	requests: ToolName[],
	platform: HostIdentity["platform"] = readInstallManifest(root).host.platform,
) {
	return Object.fromEntries([...new Set(requests)].map((name) => [
		name,
		runTool(root, alert, name, platform),
	]));
}
