import { describe, expect, test } from "vitest";

import { authorizeContainment } from "../src/containment.js";
import type { OnboardingPolicy } from "../src/contracts.js";

function policy(responseMode: OnboardingPolicy["responseMode"]): OnboardingPolicy {
	return {
		adminContact: "local-only",
		approvedAgentRuntimes: [],
		createdAt: "2026-01-01T00:00:00.000Z",
		criticalPaths: [],
		devicePurpose: "test host",
		expectedServices: [],
		maintenanceWindow: "Sunday 02:00",
		responseMode,
		retentionDays: 30,
		reviewSchedule: "weekly",
	};
}

const processPlan = {
	action: "terminate-process" as const,
	evidence: ["event-1"],
	reason: "malware behavior",
	target: "pid=42,start=2026-01-01T00:00:00Z,path=/tmp/bad",
};

describe("containment authorization", () => {
	test("requires approval for process termination", () => {
		expect(authorizeContainment(policy("autonomous-reversible"), processPlan)).toBe(
			"approval-required",
		);
	});

	test("allows a reversible block in autonomous mode", () => {
		expect(
			authorizeContainment(policy("autonomous-reversible"), {
				action: "block-destination",
				evidence: ["event-1"],
				reason: "active exfiltration",
				target: "203.0.113.4:443",
			}),
		).toBe("allowed");
	});

	test("keeps report-only mode free of containment", () => {
		expect(authorizeContainment(policy("report-only"), processPlan)).toBe(
			"report-only",
		);
	});

	test("requires approval for a block in approval mode", () => {
		expect(
			authorizeContainment(policy("approval-required"), {
				action: "block-destination",
				evidence: ["event-1"],
				reason: "active exfiltration",
				target: "203.0.113.4:443",
			}),
		).toBe("approval-required");
	});
});
