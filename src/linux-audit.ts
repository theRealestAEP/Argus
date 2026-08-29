import { randomUUID } from "node:crypto";
import {
	closeSync,
	existsSync,
	openSync,
	readFileSync,
	readSync,
	statSync,
	watch,
	type FSWatcher,
} from "node:fs";
import { basename } from "node:path";
import { z } from "zod";

import { requestAutomaticContainment } from "./containment-broker.js";
import type { ProcessIdentity } from "./containment.js";
import type { Alert, OnboardingPolicy } from "./contracts.js";
import { jsonText, writePrivate } from "./files.js";
import { recordEvidence } from "./evidence-store.js";
import { nativeContainmentGateway } from "./linux-containment-native.js";
import { statePaths } from "./paths.js";
import { readPrivilegedProcessIdentity } from "./privileged-inspection.js";

const DEFAULT_AUDIT_LOG = "/var/log/audit/audit.log";
const SHELLS = new Set(["bash", "dash", "sh", "zsh"]);
const MAX_READ_BYTES = 1_048_576;

type AuditCursor = {
	inode: number;
	offset: number;
};

const auditCursorSchema = z.object({
	inode: z.number().int().nonnegative(),
	offset: z.number().int().nonnegative(),
});

type AuditExecution = {
	arguments: string;
	childExecutable: string;
	childPid: number;
	effectiveUserId: number;
	parentPid: number;
	serial: string;
	time: string;
};

export interface AuditProcessInspector {
	identity(pid: number): ProcessIdentity;
}

function nativeInspector(root: string): AuditProcessInspector {
	return {
		identity(pid) {
			try {
				return readPrivilegedProcessIdentity(root, pid);
			} catch {
				return nativeContainmentGateway().processIdentity(pid);
			}
		},
	};
}

function auditCursor(path: string): AuditCursor | null {
	try {
		const stat = statSync(path);
		return { inode: stat.ino, offset: stat.size };
	} catch {
		return null;
	}
}

export function initializeLinuxAuditCursor(
	root: string,
	path = DEFAULT_AUDIT_LOG,
): void {
	const cursor = auditCursor(path);
	if (cursor !== null) {
		writePrivate(statePaths(root).auditCursor, jsonText(cursor));
	}
}

export function watchLinuxAudit(
	onChange: () => void,
	path = DEFAULT_AUDIT_LOG,
): FSWatcher | null {
	if (!existsSync(path)) {
		return null;
	}
	let pending: NodeJS.Timeout | undefined;
	const watcher = watch(path, { persistent: false }, () => {
		clearTimeout(pending);
		pending = setTimeout(onChange, 50);
	});
	watcher.on("close", () => clearTimeout(pending));
	return watcher;
}

function readCursor(root: string, path: string): AuditCursor | null {
	const cursorPath = statePaths(root).auditCursor;
	if (!existsSync(cursorPath)) {
		initializeLinuxAuditCursor(root, path);
		return null;
	}
	try {
		return auditCursorSchema.parse(JSON.parse(readFileSync(cursorPath, "utf8")));
	} catch {
		initializeLinuxAuditCursor(root, path);
		return null;
	}
}

function appendedAuditText(root: string, path: string): string {
	const cursor = readCursor(root, path);
	const current = auditCursor(path);
	if (cursor === null || current === null) {
		return "";
	}
	const offset = cursor.inode === current.inode && current.offset >= cursor.offset
		? cursor.offset
		: 0;
	const length = Math.min(current.offset - offset, MAX_READ_BYTES);
	if (length <= 0) {
		return "";
	}
	const start = current.offset - length;
	const buffer = Buffer.alloc(length);
	const descriptor = openSync(path, "r");
	try {
		readSync(descriptor, buffer, 0, length, start);
	} finally {
		closeSync(descriptor);
	}
	writePrivate(statePaths(root).auditCursor, jsonText(current));
	return buffer.toString("utf8");
}

function field(line: string, name: string): string | null {
	const match = new RegExp(`(?:^|\\s)${name}=(?:"([^"]*)"|(\\S+))`, "u").exec(line);
	return match?.[1] ?? match?.[2] ?? null;
}

function executionNumbers(line: string): {
	childPid: number;
	effectiveUserId: number;
	parentPid: number;
} | null {
	const numbers = {
		childPid: Number.parseInt(field(line, "pid") ?? "", 10),
		effectiveUserId: Number.parseInt(field(line, "euid") ?? "", 10),
		parentPid: Number.parseInt(field(line, "ppid") ?? "", 10),
	};
	return Object.values(numbers).every(Number.isInteger) ? numbers : null;
}

function trackedAuditExecution(line: string): boolean {
	const auditKey = field(line, "key") ?? "";
	const auditUser = field(line, "auid") ?? "";
	return line.startsWith("type=SYSCALL ") && field(line, "success") === "yes" &&
		auditKey.startsWith("argus_") && ["4294967295", "unset"].includes(auditUser);
}

function auditArgument(value: string): string {
	const decoded = /^[a-f\d]+$/iu.test(value) && value.length % 2 === 0
		? Buffer.from(value, "hex").toString("utf8")
		: value;
	return decoded.replace(/[a-f\d]{24,}/giu, "[redacted]").slice(0, 500);
}

function executionArguments(lines: string[]): string {
	const line = lines.find((item) => item.startsWith("type=EXECVE "));
	const count = Math.min(20, Number.parseInt(field(line ?? "", "argc") ?? "0", 10));
	return Array.from({ length: count }, (_, index) => field(line ?? "", `a${index}`))
		.filter((value) => value !== null)
		.map(auditArgument)
		.join(" ");
}

function hostileShellArguments(argumentsText: string): boolean {
	return /[;&|`$<>\n\r]/u.test(argumentsText) || /\s-(?:i|s)(?:\s|$)/u.test(argumentsText);
}

function actionableExecution(
	childExecutable: string | null,
	effectiveUserId: number,
	argumentsText: string,
): childExecutable is string {
	return childExecutable !== null && effectiveUserId !== 0 &&
		SHELLS.has(basename(childExecutable)) &&
		hostileShellArguments(argumentsText);
}

function execution(lines: string[]): AuditExecution | null {
	const line = lines.find((item) => item.startsWith("type=SYSCALL ")) ?? "";
	if (!trackedAuditExecution(line)) {
		return null;
	}
	const childExecutable = field(line, "exe");
	const message = /msg=audit\(([^:]+):(\d+)\)/u.exec(line);
	const numbers = executionNumbers(line);
	const argumentsText = executionArguments(lines);
	if (message === null || numbers === null) {
		return null;
	}
	if (!actionableExecution(childExecutable, numbers.effectiveUserId, argumentsText)) {
		return null;
	}
	return {
		arguments: argumentsText,
		childExecutable,
		...numbers,
		serial: message[2] ?? "",
		time: new Date(Number.parseFloat(message[1] ?? "0") * 1_000).toISOString(),
	};
}

function auditRecordGroups(text: string): string[][] {
	const groups = new Map<string, string[]>();
	for (const line of text.split("\n")) {
		const serial = /msg=audit\([^:]+:(\d+)\)/u.exec(line)?.[1];
		if (serial !== undefined) {
			groups.set(serial, [...(groups.get(serial) ?? []), line]);
		}
	}
	return [...groups.values()];
}

function containmentTarget(
	executionEvent: AuditExecution,
	inspector: AuditProcessInspector,
): { evidence: string[]; target: string } | null {
	try {
		const parent = inspector.identity(executionEvent.parentPid);
		return {
			evidence: [
				`audit-serial:${executionEvent.serial}`,
				`arguments:${executionEvent.arguments || "unavailable"}`,
				`child-pid:${executionEvent.childPid}`,
				`child-executable:${executionEvent.childExecutable}`,
				`parent-pid:${parent.pid}`,
				`parent-executable:${parent.executable}`,
				`effective-user:${executionEvent.effectiveUserId}`,
				`observed-at:${executionEvent.time}`,
			],
			target: `pid=${parent.pid},start=${parent.startTimeTicks},path=${parent.executable}`,
		};
	} catch {
		return null;
	}
}

function requestContainment(
	root: string,
	policy: OnboardingPolicy,
	alert: Alert,
	target: string,
): void {
	if (policy.responseMode !== "autonomous-action") {
		return;
	}
	const action = policy.automaticProcessTermination === true
		? "terminate-process"
		: "pause-process";
	try {
		requestAutomaticContainment(root, {
			action: "block-user-egress",
			evidence: alert.evidence,
			reason: "Stop outbound traffic from the service account during investigation.",
			target: alert.evidence.find((item) => item.startsWith("effective-user:"))?.split(":")[1] ?? "",
		});
		requestAutomaticContainment(root, {
			action,
			evidence: alert.evidence,
			reason: "Linux Audit confirmed that a service process launched a command shell.",
			target,
		});
		alert.evidence.push(`containment-requested:block-user-egress:${executionUser(alert)}`);
		alert.evidence.push(`containment-requested:${action}:${target}`);
		recordEvidence(root, "containment.requested", `${alert.id}:${target}`);
	} catch (error) {
		const detail = error instanceof Error ? error.message : "Containment request failed.";
		recordEvidence(root, "containment.request.failed", detail);
	}
}

function executionUser(alert: Alert): string {
	return alert.evidence.find((item) => item.startsWith("effective-user:"))?.split(":")[1] ?? "";
}

export function collectLinuxAuditAlerts(
	root: string,
	policy: OnboardingPolicy,
	now = new Date(),
	path = DEFAULT_AUDIT_LOG,
	inspector: AuditProcessInspector = nativeInspector(root),
): Alert[] {
	if (process.platform !== "linux" && path === DEFAULT_AUDIT_LOG) {
		return [];
	}
	const alerts: Alert[] = [];
	const seenParents = new Set<number>();
	for (const records of auditRecordGroups(appendedAuditText(root, path))) {
		const observed = execution(records);
		if (observed === null || seenParents.has(observed.parentPid)) {
			continue;
		}
		const attributed = containmentTarget(observed, inspector);
		if (attributed === null) {
			continue;
		}
		const alert: Alert = {
			createdAt: now.toISOString(),
			evidence: attributed.evidence,
			id: randomUUID(),
			kind: "service-command-shell",
			severity: "critical",
			summary: "Linux Audit confirmed that a service process launched a command shell.",
		};
		recordEvidence(root, "host.audit.exec", alert.evidence.join(","), now);
		requestContainment(root, policy, alert, attributed.target);
		seenParents.add(observed.parentPid);
		alerts.push(alert);
	}
	return alerts;
}
