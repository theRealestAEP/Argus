import { mkdtempSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "vitest";

import { bootstrap } from "../src/bootstrap.js";
import {
	macosProcessSource,
	readPrivilegedProcessIdentity,
	refreshPrivilegedProcessSnapshot,
} from "../src/privileged-inspection.js";
import { statePaths } from "../src/paths.js";

describe("privileged process inspection", () => {
	test("serves one captured macOS process table", () => {
		const identity = { executable: "/usr/bin/node", pid: 42, startTimeTicks: "91" };
		const source = macosProcessSource([identity]);
		expect(source.processNames()).toEqual(["42"]);
		expect(source.identity(42)).toEqual(identity);
		expect(() => source.identity(43)).toThrow("absent");
	});

	test("publishes exact process identities to the service account", () => {
		const root = mkdtempSync(join(tmpdir(), "argus-process-snapshot-test-"));
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
		refreshPrivilegedProcessSnapshot(
			root,
			new Date("2026-01-01T00:00:00.000Z"),
			{
				identity(pid) {
					if (pid === 43) {
						throw new Error("process exited");
					}
					return { executable: "/usr/bin/node", pid, startTimeTicks: "91" };
				},
				processNames: () => ["self", "42", "43"],
			},
		);

		expect(readPrivilegedProcessIdentity(root, 42)).toEqual({
			executable: "/usr/bin/node",
			pid: 42,
			startTimeTicks: "91",
		});
		expect(statSync(statePaths(root).processSnapshot).mode & 0o777).toBe(0o644);
		expect(() => readPrivilegedProcessIdentity(root, 43)).toThrow("absent");
	});
});
