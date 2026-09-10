import { randomUUID, sign, verify } from "node:crypto";
import { existsSync, readFileSync, unlinkSync } from "node:fs";
import { spawnSync } from "node:child_process";

import type {
	Alert,
	FileObservation,
	LinuxSnapshot,
	ListenerObservation,
	OnboardingPolicy,
	SensorCanary,
	SensorConfig,
	SensorSelection,
} from "./contracts.js";
import { linuxSnapshotSchema, sensorConfigSchema } from "./contracts.js";
import { jsonText, writePrivate } from "./files.js";
import { statePaths } from "./paths.js";
import { collectLinuxSnapshot } from "./linux-native.js";
import { initializeLinuxAuditCursor } from "./linux-audit.js";
import { requestAutomaticContainment } from "./containment-broker.js";
import { isPersistencePathAllowed } from "./containment.js";
import { recordEvidence } from "./evidence-store.js";
import { readPolicy } from "./onboarding.js";

export { collectLinuxSnapshot } from "./linux-native.js";

const canaryKinds = [
	["authentication", "authentication-burst"],
	["criticalFiles", "critical-file-change"],
	["listeners", "new-listener"],
	["networkConnections", "outbound-connection-burst"],
	["processes", "process-start-burst"],
] as const;

export function createSensorConfig(
	baseline: LinuxSnapshot,
	criticalPaths: string[],
	selection: SensorSelection,
	now = new Date(),
): SensorConfig {
	const config: SensorConfig = {
		baseline,
		canary: {
			checkedAt: now.toISOString(),
			checks: [{ kind: "new-listener", passed: false }],
			passed: false,
		},
		createdAt: now.toISOString(),
		criticalPaths,
		pollIntervalSeconds: 30,
		schemaVersion: 1,
		selection,
		thresholds: selection.thresholds,
	};
	config.canary = runSensorCanary(config, now);
	if (!config.canary.passed) {
		throw new Error("The commissioned sensor canary failed.");
	}
	return config;
}

export function commissionLinuxSensors(
	root: string,
	policy: OnboardingPolicy,
	selection: SensorSelection,
	baseline: LinuxSnapshot,
	now = new Date(),
): SensorConfig {
	const paths = statePaths(root);
	const config = createSensorConfig(
		baseline,
		policy.criticalPaths,
		selection,
		now,
	);
	const text = jsonText(config);
	writePrivate(paths.sensorConfig, text);
	writePrivate(paths.sensorState, jsonText(config.baseline));
	initializeLinuxAuditCursor(root);
	const signature = sign(null, Buffer.from(text), readFileSync(paths.privateKey, "utf8"));
	writePrivate(paths.sensorSignature, `${signature.toString("base64")}\n`);
	return config;
}

export function readSensorConfig(root: string): SensorConfig {
	const paths = statePaths(root);
	const text = readFileSync(paths.sensorConfig, "utf8");
	const signature = Buffer.from(readFileSync(paths.sensorSignature, "utf8").trim(), "base64");
	if (!verify(null, Buffer.from(text), readFileSync(paths.publicKey, "utf8"), signature)) {
		throw new Error("The sensor configuration signature is invalid.");
	}
	return sensorConfigSchema.parse(JSON.parse(text));
}

function listenerKey(listener: ListenerObservation): string {
	return `${listener.protocol}:${listener.address}:${listener.port}`;
}

function fileChanged(previous: FileObservation | undefined, current: FileObservation): boolean {
	return previous === undefined ||
		previous.modifiedAtMs !== current.modifiedAtMs ||
		previous.size !== current.size;
}

function alert(
	kind: Alert["kind"],
	severity: Alert["severity"],
	summary: string,
	evidence: string[],
	now: Date,
): Alert {
	return { createdAt: now.toISOString(), evidence, id: randomUUID(), kind, severity, summary };
}

function processAlerts(
	config: SensorConfig,
	previous: LinuxSnapshot,
	current: LinuxSnapshot,
	now: Date,
): Alert[] {
	const previousPids = new Set(previous.processes.map((item) => item.pid));
	const processes = current.processes.filter((item) => !previousPids.has(item.pid));
	return !config.selection.processes || processes.length < config.thresholds.processStartBurst
		? []
		: [alert(
			"process-start-burst",
			"medium",
			`${processes.length} processes started in one sensor interval.`,
			processes.map((item) => `${item.pid}:${item.executable}`),
			now,
		)];
}

function listenerAlerts(
	config: SensorConfig,
	previous: LinuxSnapshot,
	current: LinuxSnapshot,
	now: Date,
): Alert[] {
	const baseline = new Set(config.baseline.listeners.map(listenerKey));
	const seen = new Set(previous.listeners.map(listenerKey));
	if (!config.selection.listeners) {
		return [];
	}
	return current.listeners
		.filter((listener) => !baseline.has(listenerKey(listener)) && !seen.has(listenerKey(listener)))
		.map((listener) => {
			const key = listenerKey(listener);
			return alert("new-listener", "high", `A new listener opened on ${key}.`, [key], now);
		});
}

function criticalFileAlerts(
	config: SensorConfig,
	previous: LinuxSnapshot,
	current: LinuxSnapshot,
	now: Date,
): Alert[] {
	if (!config.selection.criticalFiles) {
		return [];
	}
	const oldFiles = new Map(previous.criticalFiles.map((item) => [item.path, item]));
	const currentPaths = new Set(current.criticalFiles.map((item) => item.path));
	const changed = current.criticalFiles
		.filter((file) => fileChanged(oldFiles.get(file.path), file))
		.map((file) => oldFiles.has(file.path) || !isPersistencePathAllowed(file.path)
			? alert(
				"critical-file-change",
				"high",
				`A critical file changed: ${file.path}`,
				[`${file.path}:${file.size}:${file.modifiedAtMs}`],
				now,
			)
			: alert(
				"persistence-change",
				"critical",
				`A new persistent execution file appeared: ${file.path}`,
				[`persistence-path:${file.path}`],
				now,
			));
	const removed = previous.criticalFiles
		.filter((file) => !currentPaths.has(file.path))
		.map((file) => alert(
			"critical-file-change",
			"high",
			`A critical file was removed: ${file.path}`,
			[`${file.path}:removed`],
			now,
		));
	return [...changed, ...removed];
}

function requestPersistenceContainment(root: string, alerts: Alert[]): void {
	const policy = readPolicy(root);
	if (policy.responseMode !== "autonomous-action") {
		return;
	}
	for (const item of alerts.filter((alertItem) => alertItem.kind === "persistence-change")) {
		const path = item.evidence.find((entry) => entry.startsWith("persistence-path:"))?.slice(17);
		if (path === undefined) {
			continue;
		}
		try {
			requestAutomaticContainment(root, {
				action: "quarantine-persistence",
				evidence: item.evidence,
				reason: "Quarantine a new persistent execution file found by baseline comparison.",
				target: path,
			});
			item.evidence.push(`containment-requested:quarantine-persistence:${path}`);
			recordEvidence(root, "containment.requested", `${item.id}:${path}`);
		} catch (error) {
			const detail = error instanceof Error ? error.message : "Containment request failed.";
			recordEvidence(root, "containment.request.failed", detail);
		}
	}
}

export type ServiceStatusReader = (unit: string) => boolean;
export type SnapshotCollector = (criticalPaths: string[], now: Date) => LinuxSnapshot;

function nativeServiceActive(unit: string): boolean {
	const result = spawnSync("systemctl", ["is-active", "--quiet", unit], {
		stdio: "ignore",
		timeout: 5_000,
	});
	return result.status === 0;
}

export function detectStoppedServices(
	policy: OnboardingPolicy,
	now = new Date(),
	isActive: ServiceStatusReader = nativeServiceActive,
): Alert[] {
	return policy.expectedServices
		.filter((unit) => unit.endsWith(".service"))
		.filter((unit) => !isActive(unit))
		.map((unit) => alert(
			"service-stopped",
			"critical",
			`An expected service stopped: ${unit}`,
			[`service-unit:${unit}`, "systemctl-state:inactive"],
			now,
		));
}

function requestServiceRestoration(root: string, alerts: Alert[]): void {
	const policy = readPolicy(root);
	if (policy.responseMode !== "autonomous-action") {
		return;
	}
	for (const item of alerts.filter((alertItem) => alertItem.kind === "service-stopped")) {
		const unit = item.evidence.find((entry) => entry.startsWith("service-unit:"))?.slice(13);
		if (unit === undefined) {
			continue;
		}
		try {
			requestAutomaticContainment(root, {
				action: "start-service",
				evidence: item.evidence,
				reason: "Restore an expected service that stopped outside the declared plan.",
				target: unit,
			});
			item.evidence.push(`containment-requested:start-service:${unit}`);
			recordEvidence(root, "containment.requested", `${item.id}:${unit}`);
		} catch (error) {
			const detail = error instanceof Error ? error.message : "Containment request failed.";
			recordEvidence(root, "containment.request.failed", detail);
		}
	}
}

function authenticationAlerts(
	config: SensorConfig,
	previous: LinuxSnapshot,
	current: LinuxSnapshot,
	now: Date,
): Alert[] {
	const crossed = current.authFailureCount >= config.thresholds.authFailureBurst &&
		previous.authFailureCount < config.thresholds.authFailureBurst;
	return config.selection.authentication && crossed
		? [alert(
			"authentication-burst",
			"high",
			`${current.authFailureCount} authentication failures occurred in 30 seconds.`,
			[`journal-count:${current.authFailureCount}`],
			now,
		)]
		: [];
}

function connectionAlerts(
	config: SensorConfig,
	previous: LinuxSnapshot,
	current: LinuxSnapshot,
	now: Date,
): Alert[] {
	const currentIncrease =
		current.establishedConnectionCount - config.baseline.establishedConnectionCount;
	const previousIncrease =
		previous.establishedConnectionCount - config.baseline.establishedConnectionCount;
	const crossed = currentIncrease >= config.thresholds.establishedConnectionBurst &&
		previousIncrease >= config.thresholds.establishedConnectionBurst;
	return config.selection.networkConnections && crossed
		? [alert(
			"outbound-connection-burst",
			"medium",
			`${currentIncrease} connections exceed the commissioned baseline.`,
			[`established-count:${current.establishedConnectionCount}`],
			now,
		)]
		: [];
}

export function detectLinuxAlerts(
	config: SensorConfig,
	previous: LinuxSnapshot,
	current: LinuxSnapshot,
	now = new Date(),
): Alert[] {
	return [
		...processAlerts(config, previous, current, now),
		...listenerAlerts(config, previous, current, now),
		...criticalFileAlerts(config, previous, current, now),
		...authenticationAlerts(config, previous, current, now),
		...connectionAlerts(config, previous, current, now),
	];
}

export function runSensorCanary(
	config: SensorConfig,
	now = new Date(),
): SensorCanary {
	const baseline = config.baseline;
	const firstPid = Math.max(0, ...baseline.processes.map((item) => item.pid)) + 1;
	const current: LinuxSnapshot = {
		...baseline,
		authFailureCount: config.thresholds.authFailureBurst,
		criticalFiles: [
			...baseline.criticalFiles,
			{ modifiedAtMs: now.getTime(), path: "/argus-canary", size: 1 },
		],
		establishedConnectionCount:
			baseline.establishedConnectionCount + config.thresholds.establishedConnectionBurst,
		listeners: [
			...baseline.listeners,
			{ address: "argus-canary", port: 65_535, protocol: "udp" },
		],
		observedAt: now.toISOString(),
		processes: [
			...baseline.processes,
			...Array.from({ length: config.thresholds.processStartBurst }, (_, index) => ({
				command: "argus-canary",
				executable: "/argus-canary",
				pid: firstPid + index,
				userId: 0,
			})),
		],
	};
	const previous = {
		...baseline,
		establishedConnectionCount: current.establishedConnectionCount,
	};
	const observed = new Set(
		detectLinuxAlerts(config, previous, current, now).map((item) => item.kind),
	);
	const checks = canaryKinds
		.filter(([selection]) => config.selection[selection])
		.map(([, kind]) => ({ kind, passed: observed.has(kind) }));
	return {
		checkedAt: now.toISOString(),
		checks,
		passed: checks.length > 0 && checks.every((check) => check.passed),
	};
}

export function collectSensorAlerts(
	root: string,
	now = new Date(),
	collectSnapshot: SnapshotCollector = collectLinuxSnapshot,
	isServiceActive: ServiceStatusReader = nativeServiceActive,
): Alert[] {
	const paths = statePaths(root);
	let config: SensorConfig;
	try {
		config = readSensorConfig(root);
	} catch (error) {
		if (existsSync(paths.sensorIntegrityState)) {
			return [];
		}
		const detail = error instanceof Error ? error.message : "Sensor configuration failed.";
		writePrivate(paths.sensorIntegrityState, jsonText({ detail, observedAt: now.toISOString() }));
		return [alert(
			"sensor-integrity-failure",
			"critical",
			"The signed sensor configuration failed validation.",
			[detail],
			now,
		)];
	}
	if (existsSync(paths.sensorIntegrityState)) {
		unlinkSync(paths.sensorIntegrityState);
	}
	const previous = linuxSnapshotSchema.parse(JSON.parse(readFileSync(paths.sensorState, "utf8")));
	const current = collectSnapshot(config.criticalPaths, now);
	writePrivate(paths.sensorState, jsonText(current));
	const alerts = [
		...detectLinuxAlerts(config, previous, current, now),
		...detectStoppedServices(readPolicy(root), now, isServiceActive),
	];
	requestPersistenceContainment(root, alerts);
	requestServiceRestoration(root, alerts);
	return alerts;
}
