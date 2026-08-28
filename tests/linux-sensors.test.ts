import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "vitest";

import { bootstrap } from "../src/bootstrap.js";
import type {
	LinuxSnapshot,
	OnboardingAnswers,
	SensorSelection,
} from "../src/contracts.js";
import {
	collectSensorAlerts,
	commissionLinuxSensors,
	createSensorConfig,
	detectLinuxAlerts,
	readSensorConfig,
	runSensorCanary,
} from "../src/linux-sensors.js";
import { statePaths } from "../src/paths.js";
import { linuxSensorChecks } from "../src/doctor.js";

const selection: SensorSelection = {
	authentication: true,
	criticalFiles: true,
	listeners: true,
	networkConnections: true,
	processes: true,
	reason: "Protect the declared server workload.",
	thresholds: {
		authFailureBurst: 3,
		establishedConnectionBurst: 5,
		processStartBurst: 5,
	},
};

function snapshot(): LinuxSnapshot {
	return {
		authFailureCount: 0,
		criticalFiles: [{ modifiedAtMs: 1, path: "/etc/example", size: 10 }],
		establishedConnectionCount: 1,
		listeners: [{ address: "00000000", port: 22, protocol: "tcp" }],
		observedAt: "2026-01-01T00:00:00.000Z",
		processes: [{ command: "init", executable: "/sbin/init", pid: 1, userId: 0 }],
	};
}

function answers(): OnboardingAnswers {
	return {
		adminContact: "local-only",
		approvedAgentRuntimes: [],
		criticalPaths: ["/etc/example"],
		devicePurpose: "test server",
		expectedServices: ["sshd"],
		maintenanceWindow: "Sunday 02:00",
		responseMode: "approval-required",
		retentionDays: 30,
		reviewSchedule: "daily",
	};
}

describe("Linux sensors", () => {
	test("uses the model-selected sensor policy", () => {
		const config = createSensorConfig(snapshot(), ["/etc/example"], selection);

		expect(config.selection).toEqual(selection);
		expect(config.thresholds).toEqual(selection.thresholds);
		expect(config.criticalPaths).toEqual(["/etc/example"]);
		expect(config.canary.passed).toBe(true);
		expect(config.canary.checks).toHaveLength(5);
	});

	test("rejects a sensor selection with no active sensor", () => {
		expect(() => createSensorConfig(snapshot(), [], {
			...selection,
			authentication: false,
			criticalFiles: false,
			listeners: false,
			networkConnections: false,
			processes: false,
		})).toThrow("canary failed");
	});

	test("records a passing result for every selected sensor", () => {
		const config = createSensorConfig(snapshot(), ["/etc/example"], selection);
		const canary = runSensorCanary(config, new Date("2026-02-03T04:05:06.000Z"));

		expect(canary.passed).toBe(true);
		expect(canary.checks.every((check) => check.passed)).toBe(true);
	});

	test("detects each enabled alert class", () => {
		const baseline = snapshot();
		const config = createSensorConfig(baseline, ["/etc/example"], selection);
		const current: LinuxSnapshot = {
			...baseline,
			authFailureCount: 3,
			criticalFiles: [{ modifiedAtMs: 2, path: "/etc/example", size: 11 }],
			establishedConnectionCount: 6,
			listeners: [
				...baseline.listeners,
				{ address: "00000000", port: 8080, protocol: "tcp" },
			],
			processes: [
				...baseline.processes,
				...Array.from({ length: 5 }, (_, index) => ({
					command: "worker",
					executable: "/usr/bin/worker",
					pid: index + 2,
					userId: 1000,
				})),
			],
		};

		expect(detectLinuxAlerts(config, baseline, current).map((item) => item.kind)).toEqual([
			"process-start-burst",
			"new-listener",
			"critical-file-change",
			"authentication-burst",
			"outbound-connection-burst",
		]);
	});

	test("detects removed files and suppresses disabled sensors", () => {
		const baseline = snapshot();
		const enabled = createSensorConfig(baseline, ["/etc/example"], selection);
		const removed = { ...baseline, criticalFiles: [] };
		expect(detectLinuxAlerts(enabled, baseline, removed).at(0)?.summary).toContain(
			"was removed",
		);
		const disabled = {
			...enabled,
			selection: {
				...selection,
				authentication: false,
				criticalFiles: false,
				listeners: false,
				networkConnections: false,
				processes: false,
			},
		};
		expect(detectLinuxAlerts(disabled, baseline, removed)).toEqual([]);
	});

	test("signs and verifies the commissioned configuration", () => {
		const root = mkdtempSync(join(tmpdir(), "argus-sensor-test-"));
		const policyAnswers = answers();
		const manifest = bootstrap(root, policyAnswers);
		const policy = { ...policyAnswers, createdAt: manifest.createdAt };
		commissionLinuxSensors(root, policy, selection, snapshot());
		expect(readSensorConfig(root).selection.reason).toContain("Protect");

		const paths = statePaths(root);
		writeFileSync(
			paths.sensorConfig,
			readFileSync(paths.sensorConfig, "utf8").replace("Protect", "Change"),
		);
		expect(() => readSensorConfig(root)).toThrow("signature is invalid");
		expect(linuxSensorChecks(root).at(-1)).toMatchObject({
			name: "sensor configuration",
			ok: false,
		});
	});

	test("reports sensor configuration tampering once", () => {
		const root = mkdtempSync(join(tmpdir(), "argus-sensor-integrity-test-"));
		const policyAnswers = answers();
		const manifest = bootstrap(root, policyAnswers);
		commissionLinuxSensors(
			root,
			{ ...policyAnswers, createdAt: manifest.createdAt },
			selection,
			snapshot(),
		);
		const paths = statePaths(root);
		writeFileSync(paths.sensorConfig, "{}\n");

		expect(collectSensorAlerts(root).at(0)).toMatchObject({
			kind: "sensor-integrity-failure",
			severity: "critical",
		});
		expect(collectSensorAlerts(root)).toEqual([]);
	});

	test("reports commissioned sensor health to doctor", () => {
		const root = mkdtempSync(join(tmpdir(), "argus-sensor-doctor-test-"));
		const policyAnswers = answers();
		const manifest = bootstrap(root, policyAnswers);
		commissionLinuxSensors(
			root,
			{ ...policyAnswers, createdAt: manifest.createdAt },
			selection,
			snapshot(),
		);

		expect(linuxSensorChecks(root).at(-1)).toEqual({
			detail: "5 sensor checks",
			name: "sensor canary",
			ok: true,
		});
		expect(linuxSensorChecks(mkdtempSync(join(tmpdir(), "argus-no-sensor-test-"))))
			.toHaveLength(3);
	});
});
