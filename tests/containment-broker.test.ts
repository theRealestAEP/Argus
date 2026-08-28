import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "vitest";

import { bootstrap } from "../src/bootstrap.js";
import type { ContainmentGateway } from "../src/containment.js";
import {
	processBrokerRequests,
	requestAutomaticContainment,
} from "../src/containment-broker.js";
import type { OnboardingAnswers } from "../src/contracts.js";
import { statePaths } from "../src/paths.js";

function brokerState(mode: OnboardingAnswers["responseMode"]): string {
	const root = mkdtempSync(join(tmpdir(), "argus-broker-test-"));
	bootstrap(root, {
		adminContact: "local-only",
		approvedAgentRuntimes: [],
		criticalPaths: [],
		devicePurpose: "test host",
		expectedServices: [],
		maintenanceWindow: "Sunday 02:00",
		responseMode: mode,
		retentionDays: 30,
		reviewSchedule: "daily",
	});
	return root;
}

const plan = {
	action: "block-destination" as const,
	evidence: ["event-1"],
	reason: "active exfiltration",
	target: "203.0.113.4",
};

describe("containment broker", () => {
	test("applies a signed automatic request as root", () => {
		const root = brokerState("autonomous-action");
		requestAutomaticContainment(root, plan);
		const gateway: ContainmentGateway = {
			pause: () => undefined,
			processIdentity: () => ({ executable: "/bin/test", pid: 1, startTimeTicks: "1" }),
			runNft: () => undefined,
			terminate: () => undefined,
		};

		expect(processBrokerRequests(root, 0, gateway)).toHaveLength(1);
		expect(readdirSync(statePaths(root).brokerRequests)).toEqual([]);
	});

	test("rejects a changed signed request", () => {
		const root = brokerState("autonomous-action");
		const request = requestAutomaticContainment(root, plan);
		const path = join(statePaths(root).brokerRequests, `${request.id}.json`);
		writeFileSync(path, readFileSync(path, "utf8").replace("203.0.113.4", "203.0.113.5"));

		expect(processBrokerRequests(root, 0)).toEqual([]);
		expect(readdirSync(statePaths(root).brokerRejected)).toHaveLength(2);
	});

	test("enforces broker and policy authorization", () => {
		const root = brokerState("approval-required");
		expect(() => requestAutomaticContainment(root, plan)).toThrow("requires approval");
		expect(() => processBrokerRequests(root, 1000)).toThrow("must run as root");
	});
});
