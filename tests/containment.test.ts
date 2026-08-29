import { mkdtempSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "vitest";

import {
	applyContainment,
	authorizeContainment,
	type ContainmentGateway,
} from "../src/containment.js";
import type { OnboardingPolicy } from "../src/contracts.js";
import { statePaths } from "../src/paths.js";

function policy(
	responseMode: OnboardingPolicy["responseMode"],
	automaticProcessTermination = false,
): OnboardingPolicy {
	return {
		adminContact: "local-only",
		automaticProcessTermination,
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
	test("applies a reversible IPv4 destination block as root", () => {
		const root = mkdtempSync(join(tmpdir(), "argus-containment-test-"));
		const commands: string[] = [];
		const gateway: ContainmentGateway = {
			pause: () => undefined,
			processIdentity: () => ({ executable: "/bin/test", pid: 42, startTimeTicks: "10" }),
			runNft: (args) => commands.push(args.join(" ")),
			terminate: () => undefined,
		};
		const receipt = applyContainment(
			root,
			policy("autonomous-action"),
			{
				action: "block-destination",
				evidence: ["event-1"],
				reason: "active exfiltration",
				target: "203.0.113.4",
			},
			0,
			gateway,
		);

		expect(commands.at(-1)).toContain("add element inet argus blocked_ipv4");
		expect(receipt.rollback).toContain("delete element");
		expect(readdirSync(statePaths(root).containmentReceipts)).toHaveLength(1);
	});

	test("blocks all egress for one service account", () => {
		const root = mkdtempSync(join(tmpdir(), "argus-containment-test-"));
		const commands: string[] = [];
		const gateway: ContainmentGateway = {
			pause: () => undefined,
			processIdentity: () => ({ executable: "/bin/test", pid: 42, startTimeTicks: "10" }),
			runNft: (args) => commands.push(args.join(" ")),
			terminate: () => undefined,
		};
		const plan = {
			action: "block-user-egress" as const,
			evidence: ["audit event"],
			reason: "active command execution",
			target: "999",
		};

		expect(applyContainment(
			root,
			policy("autonomous-action"),
			plan,
			0,
			gateway,
		).rollback).toContain("blocked_uids");
		expect(commands).toContain(
			"add rule inet argus output ct direction reply accept",
		);
		expect(commands.at(-1)).toContain("blocked_uids { 999 }");
		expect(() => applyContainment(
			root,
			policy("autonomous-action"),
			{ ...plan, target: "service-user" },
			0,
			gateway,
		)).toThrow("numeric user ID");
	});

	test("verifies process identity before termination", () => {
		const root = mkdtempSync(join(tmpdir(), "argus-containment-test-"));
		let terminatedPid = 0;
		const gateway: ContainmentGateway = {
			pause: () => undefined,
			processIdentity: () => ({ executable: "/bin/test", pid: 42, startTimeTicks: "10" }),
			runNft: () => undefined,
			terminate: (pid) => {
				terminatedPid = pid;
			},
		};
		applyContainment(
			root,
			policy("approval-required"),
			{
				action: "terminate-process",
				evidence: ["event-1"],
				reason: "confirmed malware",
				target: "pid=42,start=10,path=/bin/test",
			},
			0,
			gateway,
		);
		expect(terminatedPid).toBe(42);
	});

	test("requires native administrator authorization", () => {
		const gateway: ContainmentGateway = {
			pause: () => undefined,
			processIdentity: () => ({ executable: "/bin/test", pid: 42, startTimeTicks: "10" }),
			runNft: () => undefined,
			terminate: () => undefined,
		};
		expect(() => applyContainment(
			mkdtempSync(join(tmpdir(), "argus-containment-test-")),
			policy("approval-required"),
			processPlan,
			1000,
			gateway,
		)).toThrow("administrator authorization");
	});

	test("rejects invalid or changed containment targets", () => {
		const root = mkdtempSync(join(tmpdir(), "argus-containment-test-"));
		const gateway: ContainmentGateway = {
			pause: () => undefined,
			processIdentity: () => ({ executable: "/bin/other", pid: 42, startTimeTicks: "11" }),
			runNft: () => undefined,
			terminate: () => undefined,
		};
		expect(() => applyContainment(
			root,
			policy("approval-required"),
			{ ...processPlan, target: "pid=42" },
			0,
			gateway,
		)).toThrow("pid=N");
		expect(() => applyContainment(
			root,
			policy("approval-required"),
			{ ...processPlan, target: "pid=42,start=10,path=/bin/test" },
			0,
			gateway,
		)).toThrow("identity changed");
		expect(() => applyContainment(
			root,
			policy("autonomous-action"),
			{
				action: "pause-process",
				evidence: ["event-1"],
				reason: "confirmed agent policy violation",
				target: "pid=42,start=10,path=/bin/test",
			},
			0,
			gateway,
		)).toThrow("identity changed");
		expect(() => applyContainment(
			root,
			policy("autonomous-action"),
			{
				action: "block-destination",
				evidence: ["event-1"],
				reason: "test",
				target: "2001:db8::1",
			},
			0,
			gateway,
		)).toThrow("IPv4");
	});

	test("prevents execution in report-only mode", () => {
		const gateway: ContainmentGateway = {
			pause: () => undefined,
			processIdentity: () => ({ executable: "/bin/test", pid: 42, startTimeTicks: "10" }),
			runNft: () => undefined,
			terminate: () => undefined,
		};
		expect(() => applyContainment(
			mkdtempSync(join(tmpdir(), "argus-containment-test-")),
			policy("report-only"),
			processPlan,
			0,
			gateway,
		)).toThrow("permits reports only");
	});
	test("requires approval for process termination by default", () => {
		expect(authorizeContainment(policy("autonomous-action"), processPlan)).toBe(
			"approval-required",
		);
	});

	test("allows process termination when setup grants it", () => {
		expect(authorizeContainment(
			policy("autonomous-action", true),
			processPlan,
		)).toBe("allowed");
	});

	test("allows a reversible block in autonomous mode", () => {
		expect(
			authorizeContainment(policy("autonomous-action"), {
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
