import {
	appendFileSync,
	existsSync,
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

function securityRecord(key: string, path: string): string {
	return `type=SYSCALL msg=audit(1788027379.000:8122): arch=c000003e syscall=257 success=yes ppid=12005 pid=12026 auid=4294967295 uid=999 euid=999 comm="cat" exe="/usr/bin/cat" key="${key}"\n` +
		`type=PATH msg=audit(1788027379.000:8122): item=0 name="${path}" mode=0100644 nametype=NORMAL\n`;
}

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

	test("reports a missing Audit log once and reports recovery", () => {
		const root = mkdtempSync(join(tmpdir(), "argus-audit-health-test-"));
		const auditPath = join(root, "audit.log");
		bootstrap(root, answers("report-only"));

		expect(collectLinuxAuditAlerts(
			root,
			{ ...answers("report-only"), createdAt: "2026-01-01T00:00:00.000Z" },
			new Date(),
			auditPath,
		).at(0)).toMatchObject({
			kind: "kernel-integrity-change",
			summary: "Linux Audit health failed.",
		});
		expect(collectLinuxAuditAlerts(
			root,
			{ ...answers("report-only"), createdAt: "2026-01-01T00:00:00.000Z" },
			new Date(),
			auditPath,
		)).toEqual([]);
		writeFileSync(auditPath, "start\n");
		expect(collectLinuxAuditAlerts(
			root,
			{ ...answers("report-only"), createdAt: "2026-01-01T00:00:00.000Z" },
			new Date(),
			auditPath,
		)).toEqual([]);
		expect(existsSync(statePaths(root).auditIntegrityState)).toBe(false);
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

	test("detects credential access for direct investigation", () => {
		const root = mkdtempSync(join(tmpdir(), "argus-audit-credential-test-"));
		const auditPath = join(root, "audit.log");
		writeFileSync(auditPath, "start\n");
		bootstrap(root, answers("autonomous-action"));
		initializeLinuxAuditCursor(root, auditPath);
		appendFileSync(auditPath, securityRecord("argus_credential", "/home/app/.ssh/id_ed25519"));

		const alerts = collectLinuxAuditAlerts(
			root,
			{ ...answers("autonomous-action"), createdAt: "2026-01-01T00:00:00.000Z" },
			new Date("2026-01-01T00:00:01.000Z"),
			auditPath,
			{ identity: () => ({ executable: "/usr/bin/node", pid: 12005, startTimeTicks: "8" }) },
		);

		expect(alerts[0]).toMatchObject({ kind: "credential-access", severity: "high" });
		expect(alerts[0]?.evidence).toContain("audit-path:/home/app/.ssh/id_ed25519");
		expect(readdirSync(statePaths(root).brokerRequests)).toHaveLength(0);
	});

	test("detects persistence and kernel security changes", () => {
		const root = mkdtempSync(join(tmpdir(), "argus-audit-integrity-test-"));
		const auditPath = join(root, "audit.log");
		writeFileSync(auditPath, "start\n");
		bootstrap(root, answers("report-only"));
		initializeLinuxAuditCursor(root, auditPath);
		appendFileSync(auditPath, securityRecord("argus_persistence", "/etc/cron.d/update"));
		appendFileSync(
			auditPath,
			securityRecord("argus_kernel", "/etc/modules-load.d/hidden.conf")
				.replaceAll("8122", "8123"),
		);

		const alerts = collectLinuxAuditAlerts(
			root,
			{ ...answers("report-only"), createdAt: "2026-01-01T00:00:00.000Z" },
			new Date(),
			auditPath,
			{ identity: () => ({ executable: "/bin/sh", pid: 12005, startTimeTicks: "9" }) },
		);

		expect(alerts.map((item) => item.kind)).toEqual([
			"persistence-change",
			"kernel-integrity-change",
		]);
	});

	test("requests quarantine for new service persistence", () => {
		const root = mkdtempSync(join(tmpdir(), "argus-audit-persistence-test-"));
		const auditPath = join(root, "audit.log");
		writeFileSync(auditPath, "start\n");
		bootstrap(root, answers("autonomous-action"));
		initializeLinuxAuditCursor(root, auditPath);
		appendFileSync(
			auditPath,
			securityRecord("argus_persistence", "/etc/cron.d/quiet-update")
				.replace("nametype=NORMAL", "nametype=CREATE"),
		);

		const alert = collectLinuxAuditAlerts(
			root,
			{ ...answers("autonomous-action"), createdAt: "2026-01-01T00:00:00.000Z" },
			new Date(),
			auditPath,
			{ identity: () => ({ executable: "/usr/bin/node", pid: 12005, startTimeTicks: "9" }) },
		).at(0);

		expect(alert?.evidence).toContain(
			"containment-requested:quarantine-persistence:/etc/cron.d/quiet-update",
		);
		expect(readdirSync(statePaths(root).brokerRequests)).toHaveLength(4);
	});

	test("requests removal of new privileged executable bits", () => {
		const root = mkdtempSync(join(tmpdir(), "argus-audit-privilege-test-"));
		const auditPath = join(root, "audit.log");
		writeFileSync(auditPath, "start\n");
		bootstrap(root, answers("autonomous-action"));
		initializeLinuxAuditCursor(root, auditPath);
		appendFileSync(
			auditPath,
			securityRecord("argus_persistence", "/usr/lib/syscore")
				.replace("mode=0100644", "mode=0104755")
				.replace("euid=999", "euid=0"),
		);

		const alert = collectLinuxAuditAlerts(
			root,
			{ ...answers("autonomous-action"), createdAt: "2026-01-01T00:00:00.000Z" },
			new Date(),
			auditPath,
		).at(0);

		expect(alert?.evidence).toContain(
			"containment-requested:strip-file-privileges:/usr/lib/syscore",
		);
		expect(readdirSync(statePaths(root).brokerRequests)).toHaveLength(2);
	});

	test("keeps a persistence alert when its containment request fails", () => {
		const root = mkdtempSync(join(tmpdir(), "argus-audit-persistence-failure-test-"));
		const auditPath = join(root, "audit.log");
		writeFileSync(auditPath, "start\n");
		bootstrap(root, answers("autonomous-action"));
		initializeLinuxAuditCursor(root, auditPath);
		unlinkSync(statePaths(root).privateKey);
		appendFileSync(
			auditPath,
			securityRecord("argus_persistence", "/etc/cron.d/quiet-update")
				.replace("nametype=NORMAL", "nametype=CREATE"),
		);

		expect(collectLinuxAuditAlerts(
			root,
			{ ...answers("autonomous-action"), createdAt: "2026-01-01T00:00:00.000Z" },
			new Date(),
			auditPath,
			{ identity: () => ({ executable: "/usr/bin/node", pid: 12005, startTimeTicks: "9" }) },
		).at(0)?.kind).toBe("persistence-change");
		expect(readdirSync(statePaths(root).brokerRequests)).toHaveLength(0);
	});

	test("detects a successful remote login and Audit shutdown", () => {
		const root = mkdtempSync(join(tmpdir(), "argus-audit-login-test-"));
		const auditPath = join(root, "audit.log");
		writeFileSync(auditPath, "start\n");
		bootstrap(root, answers("report-only"));
		initializeLinuxAuditCursor(root, auditPath);
		appendFileSync(auditPath, "type=USER_LOGIN msg=audit(1788027380.000:8124): pid=500 uid=0 auid=1000 acct=\"ops\" addr=203.0.113.7 terminal=ssh res=success\n");
		appendFileSync(auditPath, "type=DAEMON_END msg=audit(1788027381.000:8125): op=terminate res=success\n");

		const alerts = collectLinuxAuditAlerts(
			root,
			{ ...answers("report-only"), createdAt: "2026-01-01T00:00:00.000Z" },
			new Date(),
			auditPath,
		);

		expect(alerts.map((item) => item.kind)).toEqual([
			"remote-login",
			"kernel-integrity-change",
		]);
		expect(alerts[0]?.evidence).toContain("remote-address:203.0.113.7");
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
