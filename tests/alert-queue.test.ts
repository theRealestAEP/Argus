import { mkdirSync, mkdtempSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "vitest";

import {
	claimAlert,
	completeAlert,
	enqueueAlert,
	retryAlert,
	saveIncidentReport,
	pruneIncidentReports,
} from "../src/alert-queue.js";
import type { Alert } from "../src/contracts.js";
import { statePaths } from "../src/paths.js";

const queuedAlert: Alert = {
	createdAt: "2026-01-01T00:00:00.000Z",
	evidence: ["event-1"],
	id: "123e4567-e89b-42d3-a456-426614174000",
	kind: "new-listener",
	severity: "high",
	summary: "A listener opened.",
};

describe("alert queue", () => {
	test("claims, retries, and completes an alert", () => {
		const root = mkdtempSync(join(tmpdir(), "argus-queue-test-"));
		enqueueAlert(root, queuedAlert);
		const firstClaim = claimAlert(root);
		expect(firstClaim?.alert).toEqual(queuedAlert);
		if (firstClaim === null) {
			throw new Error("Expected a claimed alert.");
		}
		retryAlert(root, firstClaim);
		const secondClaim = claimAlert(root);
		if (secondClaim === null) {
			throw new Error("Expected a retried alert.");
		}
		completeAlert(secondClaim);
		expect(claimAlert(root)).toBeNull();
	});

	test("saves a local incident report", () => {
		const root = mkdtempSync(join(tmpdir(), "argus-report-test-"));
		const report = saveIncidentReport(root, queuedAlert, "model", "report text");
		expect(report.alertId).toBe(queuedAlert.id);
		expect(readdirSync(statePaths(root).reports)).toHaveLength(1);
	});

	test("removes incident reports after the onboarding retention period", () => {
		const root = mkdtempSync(join(tmpdir(), "argus-retention-test-"));
		saveIncidentReport(
			root,
			queuedAlert,
			"model",
			"old report",
			new Date("2026-01-01T00:00:00.000Z"),
		);
		const oldName = readdirSync(statePaths(root).reports)[0] ?? "";
		mkdirSync(statePaths(root).mailReceipts, { recursive: true });
		writeFileSync(join(statePaths(root).mailReceipts, `${oldName}.json`), "{}");
		saveIncidentReport(
			root,
			queuedAlert,
			"model",
			"current report",
			new Date("2026-02-01T00:00:00.000Z"),
		);

		expect(pruneIncidentReports(
			root,
			30,
			new Date("2026-02-01T00:00:01.000Z"),
		)).toBe(1);
		expect(readdirSync(statePaths(root).reports)).toHaveLength(1);
	});
});
