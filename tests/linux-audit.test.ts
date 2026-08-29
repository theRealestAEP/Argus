import {
	appendFileSync,
	mkdtempSync,
	readdirSync,
	unlinkSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "vitest";

import { bootstrap } from "../src/bootstrap.js";
import type { OnboardingAnswers } from "../src/contracts.js";
import {
	collectLinuxAuditAlerts,
	initializeLinuxAuditCursor,
	watchLinuxAudit,
} from "../src/linux-audit.js";
import { statePaths } from "../src/paths.js";

function answers(responseMode: OnboardingAnswers["responseMode"]): OnboardingAnswers {
	return {
		adminContact: "local-only",
		automaticProcessTermination: true,
		approvedAgentRuntimes: [],
		criticalPaths: [],
		devicePurpose: "test server",
		expectedServices: ["web"],
		maintenanceWindow: "Sunday 02:00",
		responseMode,
		retentionDays: 30,
		reviewSchedule: "daily",
	};
}

const auditLine = "type=SYSCALL msg=audit(1788027378.861:8121): arch=c00000b7 syscall=221 success=yes ppid=12005 pid=12025 auid=4294967295 uid=999 euid=999 comm=\"sh\" exe=\"/usr/bin/dash\" key=\"argus_exec\"\n";
const auditArguments = "type=EXECVE msg=audit(1788027378.861:8121): argc=3 a0=\"/bin/sh\" a1=\"-c\" a2=\"getent example.com; cat /etc/service.conf\"\n";

describe("Linux Audit collection", () => {
	test("watches the audit log after writes settle", async () => {
		const root = mkdtempSync(join(tmpdir(), "argus-audit-watch-test-"));
		const auditPath = join(root, "audit.log");
		writeFileSync(auditPath, "start\n");
		let resolveChange: () => void = () => undefined;
		const changed = new Promise<void>((resolve) => { resolveChange = resolve; });
		const watcher = watchLinuxAudit(resolveChange, auditPath);
		setTimeout(() => appendFileSync(auditPath, "event\n"), 20);
		await changed;
		watcher?.close();
		expect(watchLinuxAudit(() => undefined, join(root, "missing"))).toBeNull();
	});

	test("attributes a service shell and requests policy-approved containment", () => {
		const root = mkdtempSync(join(tmpdir(), "argus-audit-test-"));
		const auditPath = join(root, "audit.log");
		appendFileSync(auditPath, "type=DAEMON_START msg=audit(1.0:1)\n");
		bootstrap(root, answers("autonomous-action"));
		initializeLinuxAuditCursor(root, auditPath);
		appendFileSync(auditPath, `${auditLine}${auditArguments}`);

		const alerts = collectLinuxAuditAlerts(
			root,
			{ ...answers("autonomous-action"), createdAt: "2026-01-01T00:00:00.000Z" },
			new Date("2026-01-01T00:00:01.000Z"),
			auditPath,
			{
				identity: () => ({
					executable: "/usr/local/bin/node",
					pid: 12005,
					startTimeTicks: "55",
				}),
			},
		);

		expect(alerts).toHaveLength(1);
		expect(alerts[0]).toMatchObject({
			kind: "service-command-shell",
			severity: "critical",
		});
		expect(alerts[0]?.evidence).toContain("child-pid:12025");
		expect(alerts[0]?.evidence).toContain("parent-pid:12005");
		expect(alerts[0]?.evidence).toContain("arguments:/bin/sh -c getent example.com; cat /etc/service.conf");
		expect(readdirSync(statePaths(root).brokerRequests)).toHaveLength(4);
	});

	test("accepts a simple commissioned service command", () => {
		const root = mkdtempSync(join(tmpdir(), "argus-audit-test-"));
		const auditPath = join(root, "audit.log");
		appendFileSync(auditPath, "type=DAEMON_START msg=audit(1.0:1)\n");
		bootstrap(root, answers("autonomous-action"));
		initializeLinuxAuditCursor(root, auditPath);
		appendFileSync(auditPath, auditLine);
		appendFileSync(auditPath, auditArguments.replace(
			"getent example.com; cat /etc/service.conf",
			"getent ahosts example.com",
		));

		expect(collectLinuxAuditAlerts(
			root,
			{ ...answers("autonomous-action"), createdAt: "2026-01-01T00:00:00.000Z" },
			new Date(),
			auditPath,
			{ identity: () => ({ executable: "/usr/bin/node", pid: 12005, startTimeTicks: "5" }) },
		)).toEqual([]);
	});

	test("ignores prior records, non-shell executions, and missing parents", () => {
		const root = mkdtempSync(join(tmpdir(), "argus-audit-test-"));
		const auditPath = join(root, "audit.log");
		appendFileSync(auditPath, auditLine);
		bootstrap(root, answers("report-only"));
		initializeLinuxAuditCursor(root, auditPath);

		expect(collectLinuxAuditAlerts(
			root,
			{ ...answers("report-only"), createdAt: "2026-01-01T00:00:00.000Z" },
			new Date(),
			auditPath,
		)).toEqual([]);

		appendFileSync(auditPath, auditLine.replace("/usr/bin/dash", "/usr/bin/getent"));
		appendFileSync(auditPath, auditLine.replace("ppid=12005", "ppid=12006"));
		expect(collectLinuxAuditAlerts(
			root,
			{ ...answers("report-only"), createdAt: "2026-01-01T00:00:00.000Z" },
			new Date(),
			auditPath,
			{ identity: () => { throw new Error("process exited"); } },
		)).toEqual([]);
	});

	test("recovers the audit cursor and handles unavailable native process identity", () => {
		const root = mkdtempSync(join(tmpdir(), "argus-audit-test-"));
		const auditPath = join(root, "audit.log");
		appendFileSync(auditPath, auditLine);
		bootstrap(root, answers("report-only"));

		expect(collectLinuxAuditAlerts(
			root,
			{ ...answers("report-only"), createdAt: "2026-01-01T00:00:00.000Z" },
			new Date(),
			auditPath,
		)).toEqual([]);
		writeFileSync(statePaths(root).auditCursor, "invalid");
		expect(collectLinuxAuditAlerts(
			root,
			{ ...answers("report-only"), createdAt: "2026-01-01T00:00:00.000Z" },
			new Date(),
			auditPath,
		)).toEqual([]);
		appendFileSync(auditPath, `${auditLine}${auditArguments}`);
		expect(collectLinuxAuditAlerts(
			root,
			{ ...answers("report-only"), createdAt: "2026-01-01T00:00:00.000Z" },
			new Date(),
			auditPath,
		)).toEqual([]);
	});

	test("keeps the alert when policy or broker state prevents containment", () => {
		for (const responseMode of ["report-only", "autonomous-action"] as const) {
			const root = mkdtempSync(join(tmpdir(), "argus-audit-policy-test-"));
			const auditPath = join(root, "audit.log");
			appendFileSync(auditPath, "start\n");
			bootstrap(root, answers(responseMode));
			initializeLinuxAuditCursor(root, auditPath);
			if (responseMode === "autonomous-action") {
				unlinkSync(statePaths(root).privateKey);
			}
			appendFileSync(auditPath, `${auditLine}${auditArguments}`);
			const alerts = collectLinuxAuditAlerts(
				root,
				{ ...answers(responseMode), createdAt: "2026-01-01T00:00:00.000Z" },
				new Date(),
				auditPath,
				{ identity: () => ({ executable: "/usr/bin/node", pid: 12005, startTimeTicks: "5" }) },
			);
			expect(alerts).toHaveLength(1);
			expect(readdirSync(statePaths(root).brokerRequests)).toHaveLength(0);
		}
	});
});
