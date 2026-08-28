import { mkdtempSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "vitest";

import { claimAlert } from "../src/alert-queue.js";
import { bootstrap } from "../src/bootstrap.js";
import type { Alert, OnboardingAnswers } from "../src/contracts.js";
import {
	runOperationalCycle,
	type OperationalServices,
} from "../src/operational-loop.js";
import { statePaths } from "../src/paths.js";

const alert: Alert = {
	createdAt: "2026-01-01T00:00:00.000Z",
	evidence: ["event-1"],
	id: "123e4567-e89b-42d3-a456-426614174000",
	kind: "new-listener",
	severity: "high",
	summary: "A listener opened.",
};

function stateRoot(): string {
	const root = mkdtempSync(join(tmpdir(), "argus-loop-test-"));
	const answers: OnboardingAnswers = {
		adminContact: "local-only",
		approvedAgentRuntimes: [],
		criticalPaths: [],
		devicePurpose: "test host",
		expectedServices: [],
		maintenanceWindow: "Sunday 02:00",
		responseMode: "approval-required",
		retentionDays: 30,
		reviewSchedule: "daily",
	};
	bootstrap(root, answers);
	return root;
}

describe("operational loop", () => {
	test("queues, investigates, stores, and delivers an alert", async () => {
		const root = stateRoot();
		let deliveries = 0;
		const services: OperationalServices = {
			canInvestigate: () => true,
			collectAlerts: () => Promise.resolve([alert]),
			deliverReports: () => {
				deliveries += 1;
				return Promise.resolve();
			},
			investigate: () => Promise.resolve({ model: "model", report: "report text" }),
		};

		await runOperationalCycle(root, services);
		expect(claimAlert(root)).toBeNull();
		expect(readdirSync(statePaths(root).reports)).toHaveLength(1);
		expect(deliveries).toBe(1);
	});

	test("keeps an alert queued after investigation failure", async () => {
		const root = stateRoot();
		const services: OperationalServices = {
			canInvestigate: () => true,
			collectAlerts: () => Promise.resolve([alert]),
			deliverReports: () => Promise.resolve(),
			investigate: () => Promise.reject(new Error("model offline")),
		};

		await runOperationalCycle(root, services);
		expect(claimAlert(root)?.alert.id).toBe(alert.id);
	});

	test("continues delivery when collection fails and investigation is disabled", async () => {
		const root = stateRoot();
		let deliveries = 0;
		const services: OperationalServices = {
			canInvestigate: () => false,
			collectAlerts: () => Promise.reject(7),
			deliverReports: () => {
				deliveries += 1;
				return Promise.resolve();
			},
			investigate: () => Promise.reject(new Error("unexpected investigation")),
		};

		await runOperationalCycle(root, services);
		expect(deliveries).toBe(1);
	});
});
