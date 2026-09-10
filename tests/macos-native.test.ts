import { once } from "node:events";
import { spawn } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "vitest";

import { applyContainment } from "../src/containment.js";
import type { OnboardingPolicy } from "../src/contracts.js";
import {
	nativeMacosContainmentGateway,
	nativeMacosProcessIdentity,
	nativeMacosProcessSnapshot,
	parseMacosProcessSnapshot,
} from "../src/macos-containment-native.js";
import { collectMacosConnections } from "../src/macos-native.js";

describe("macOS native inspection", () => {
	const policy: OnboardingPolicy = {
		adminContact: "local-only",
		automaticProcessTermination: true,
		approvedAgentRuntimes: [],
		createdAt: "2026-01-01T00:00:00.000Z",
		criticalPaths: [],
		devicePurpose: "test Mac",
		expectedServices: [],
		maintenanceWindow: "Sunday 02:00",
		responseMode: "autonomous-action",
		retentionDays: 30,
		reviewSchedule: "daily",
	};

	test("parses one macOS process table snapshot", () => {
		const output = [
			"  42 Mon Sep  7 14:30:00 2026 /usr/bin/example process",
			"invalid",
		].join("\n");
		expect(parseMacosProcessSnapshot(output)).toEqual([{
			executable: "/usr/bin/example process",
			pid: 42,
			startTimeTicks: String(Date.parse("Mon Sep 7 14:30:00 2026")),
		}]);
	});

	test.skipIf(process.platform !== "darwin")("reads a stable identity for the current process", () => {
		const identity = nativeMacosProcessIdentity(process.pid);
		expect(identity.pid).toBe(process.pid);
		expect(identity.executable.startsWith("/")).toBe(true);
		expect(identity.startTimeTicks).toMatch(/^\d+$/u);
	});

	test.skipIf(process.platform !== "darwin")("reads the process table in one snapshot", () => {
		const identity = nativeMacosProcessSnapshot().find((item) => item.pid === process.pid);
		expect(identity?.executable.startsWith("/")).toBe(true);
		expect(identity?.startTimeTicks).toMatch(/^\d+$/u);
	});

	test.skipIf(process.platform !== "darwin")("collects a bounded connection snapshot", () => {
		const evidence = collectMacosConnections();
		expect(evidence.records.length).toBeLessThanOrEqual(200);
	});

	test.skipIf(process.platform !== "darwin")("pauses and terminates one exact child process", async () => {
		const child = spawn("/bin/sleep", ["30"]);
		await once(child, "spawn");
		try {
			const identity = nativeMacosProcessIdentity(child.pid ?? 0);
			const target = `pid=${identity.pid},start=${identity.startTimeTicks},path=${identity.executable}`;
			const gateway = nativeMacosContainmentGateway();
			expect(applyContainment(
				mkdtempSync(join(tmpdir(), "argus-mac-containment-test-")),
				policy,
				{
					action: "pause-process",
					evidence: ["test child"],
					reason: "safe integration test",
					target,
				},
				0,
				gateway,
			).action).toBe("pause-process");
			process.kill(identity.pid, "SIGCONT");
			gateway.terminate(identity.pid);
			await once(child, "exit");
		} finally {
			if (child.exitCode === null) {
				child.kill("SIGKILL");
			}
		}
	});
});
