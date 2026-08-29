import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "vitest";

import { bootstrap } from "../src/bootstrap.js";
import type { Alert } from "../src/contracts.js";
import { jsonText, writePrivate } from "../src/files.js";
import { collectInvestigationEvidence } from "../src/investigation-tools.js";
import { statePaths } from "../src/paths.js";
import { refreshPrivilegedProcessSnapshot } from "../src/privileged-inspection.js";

describe("investigation tools", () => {
	test("reports missing host evidence", () => {
		const root = mkdtempSync(join(tmpdir(), "argus-investigation-tools-test-"));
		bootstrap(root, {
			adminContact: "local-only",
			approvedAgentRuntimes: [],
			criticalPaths: [],
			devicePurpose: "test host",
			expectedServices: [],
			maintenanceWindow: "Sunday 02:00",
			responseMode: "report-only",
			retentionDays: 30,
			reviewSchedule: "daily",
		});
		const alert: Alert = {
			createdAt: new Date().toISOString(),
			evidence: ["parent-pid:42"],
			id: "123e4567-e89b-42d3-a456-426614174000",
			kind: "service-command-shell",
			severity: "critical",
			summary: "Service shell",
		};

		expect(collectInvestigationEvidence(root, alert, [
			"connections",
			"critical-files",
			"process",
		])).toEqual({
			connections: { unavailable: "Linux sensor state is absent." },
			"critical-files": { unavailable: "Linux sensor state is absent." },
			process: { unavailable: expect.stringContaining("ENOENT") },
		});
	});

	test("returns bounded host evidence requested by the model", () => {
		const root = mkdtempSync(join(tmpdir(), "argus-investigation-tools-test-"));
		bootstrap(root, {
			adminContact: "local-only",
			approvedAgentRuntimes: [],
			criticalPaths: ["/etc/app"],
			devicePurpose: "test host",
			expectedServices: ["web:8080"],
			maintenanceWindow: "Sunday 02:00",
			responseMode: "autonomous-action",
			retentionDays: 30,
			reviewSchedule: "daily",
		});
		refreshPrivilegedProcessSnapshot(root, new Date(), {
			identity: (pid) => ({ executable: "/usr/bin/node", pid, startTimeTicks: "8" }),
			processNames: () => ["42"],
		});
		writePrivate(statePaths(root).sensorState, jsonText({
			authFailureCount: 0,
			criticalFiles: [{ modifiedAtMs: 1, path: "/etc/app", size: 10 }],
			establishedConnectionCount: 2,
			listeners: [{ address: "00000000", port: 8080, protocol: "tcp" }],
			observedAt: new Date().toISOString(),
			processes: [],
		}));
		const alert: Alert = {
			createdAt: new Date().toISOString(),
			evidence: ["audit-serial:7", "parent-pid:42"],
			id: "123e4567-e89b-42d3-a456-426614174000",
			kind: "service-command-shell",
			severity: "critical",
			summary: "Service shell",
		};

		const evidence = collectInvestigationEvidence(root, alert, [
			"audit-events",
			"connections",
			"critical-files",
			"process",
			"service",
		]);

		expect(evidence).toMatchObject({
			"audit-events": { records: ["audit-serial:7"] },
			connections: { establishedConnectionCount: 2 },
			"critical-files": { criticalFiles: [{ path: "/etc/app" }] },
			process: { processes: [{ pid: 42 }] },
			service: { expectedServices: ["web:8080"] },
		});
	});
});
