import { randomUUID } from "node:crypto";
import {
	closeSync,
	existsSync,
	openSync,
	readFileSync,
	readSync,
	statSync,
	unlinkSync,
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

type ClassifiedAuditRecord = {
	automaticContainment: boolean;
	kind: Alert["kind"];
	severity: Alert["severity"];
	summary: string;
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
		auditKey.startsWith("argus_") && auditKey.endsWith("exec") &&
		["4294967295", "unset"].includes(auditUser);
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

function recordField(lines: string[], name: string): string | null {
	for (const line of lines) {
		const value = field(line, name);
		if (value !== null) {
			return value;
		}
	}
	return null;
}

function successfulRemoteLogin(lines: string[]): boolean {
	const login = lines.find((line) => line.startsWith("type=USER_LOGIN "));
	const address = field(login ?? "", "addr") ?? "";
	return login !== undefined && field(login, "res") === "success" &&
		!["", "?", "127.0.0.1", "::1", "localhost"].includes(address);
}

function loginClassification(lines: string[]): ClassifiedAuditRecord | null {
	if (successfulRemoteLogin(lines)) {
		return {
			automaticContainment: false,
			kind: "remote-login",
			severity: "high",
			summary: "A remote account login succeeded.",
		};
	}
	return null;
}

function keyedClassification(lines: string[]): ClassifiedAuditRecord | null {
	const key = recordField(lines, "key") ?? "";
	const syscall = lines.find((line) => line.startsWith("type=SYSCALL ")) ?? "";
	const succeeded = field(syscall, "success") === "yes";
	if (key.endsWith("credential") && succeeded) {
		return {
			automaticContainment: false,
			kind: "credential-access",
			severity: "high",
			summary: "A process accessed protected credential material.",
		};
	}
	if (key.endsWith("persistence") && succeeded) {
		return {
			automaticContainment: true,
			kind: "persistence-change",
			severity: "critical",
			summary: "A process changed a persistent execution location.",
		};
	}
	return null;
}

function kernelClassification(lines: string[]): ClassifiedAuditRecord | null {
	const key = recordField(lines, "key") ?? "";
	const syscall = lines.find((line) => line.startsWith("type=SYSCALL ")) ?? "";
	const succeeded = field(syscall, "success") === "yes";
	const auditControlChanged = lines.some((line) =>
		line.startsWith("type=CONFIG_CHANGE ") || line.startsWith("type=DAEMON_END ")
	);
	if ((key.endsWith("kernel") && succeeded) || auditControlChanged) {
		return {
			automaticContainment: false,
			kind: "kernel-integrity-change",
			severity: "critical",
			summary: "A kernel or Audit security control changed.",
		};
	}
	return null;
}

function classifyAuditRecord(lines: string[]): ClassifiedAuditRecord | null {
	return loginClassification(lines) ?? keyedClassification(lines) ?? kernelClassification(lines);
}

function recordTime(lines: string[], fallback: Date): string {
	const value = /msg=audit\(([^:]+):/u.exec(lines[0] ?? "")?.[1];
	const seconds = Number.parseFloat(value ?? "");
	return Number.isFinite(seconds) ? new Date(seconds * 1_000).toISOString() : fallback.toISOString();
}

function evidenceValue(value: string | null, fallback = "unknown"): string {
	return value === null ? fallback : value;
}

function auditSerial(lines: string[]): string {
	const match = /msg=audit\([^:]+:(\d+)\)/u.exec(evidenceValue(lines.at(0) ?? null, ""));
	return evidenceValue(match?.[1] ?? null, "unknown");
}

function recordEvidenceItems(lines: string[], now: Date): string[] {
	const syscall = lines.find((line) => line.startsWith("type=SYSCALL ")) ?? "";
	const names = lines
		.filter((line) => line.startsWith("type=PATH "))
		.map((line) => field(line, "name"))
		.filter((name) => name !== null);
	const values = [
		`audit-serial:${auditSerial(lines)}`,
		`audit-key:${evidenceValue(recordField(lines, "key"), "none")}`,
		`observed-at:${recordTime(lines, now)}`,
		`account:${evidenceValue(recordField(lines, "acct"))}`,
		`remote-address:${evidenceValue(recordField(lines, "addr"))}`,
		`audit-user:${evidenceValue(field(syscall, "auid"))}`,
		`effective-user:${evidenceValue(field(syscall, "euid"))}`,
		`child-pid:${evidenceValue(field(syscall, "pid"))}`,
		`parent-pid:${evidenceValue(field(syscall, "ppid"))}`,
		`child-executable:${evidenceValue(field(syscall, "exe"))}`,
		`arguments:${evidenceValue(executionArguments(lines) || null, "unavailable")}`,
	];
	return [...values, ...names.map((name) => `audit-path:${auditArgument(name)}`)];
}

function serviceProcessTarget(
	lines: string[],
	inspector: AuditProcessInspector,
): string | null {
	const syscall = lines.find((line) => line.startsWith("type=SYSCALL ")) ?? "";
	const childPid = Number.parseInt(field(syscall, "pid") ?? "", 10);
	const auditUser = field(syscall, "auid") ?? "";
	const effectiveUser = Number.parseInt(field(syscall, "euid") ?? "", 10);
	if (!["4294967295", "unset"].includes(auditUser) || effectiveUser === 0 || childPid <= 1) {
		return null;
	}
	try {
		const child = inspector.identity(childPid);
		return `pid=${child.pid},start=${child.startTimeTicks},path=${child.executable}`;
	} catch {
		return null;
	}
}

function requestSuspiciousProcessPause(
	root: string,
	policy: OnboardingPolicy,
	alert: Alert,
	target: string | null,
): void {
	if (policy.responseMode !== "autonomous-action" || target === null) {
		return;
	}
	try {
		requestAutomaticContainment(root, {
			action: "pause-process",
			evidence: alert.evidence,
			reason: "Pause the responsible service while Argus investigates the security change.",
			target,
		});
		alert.evidence.push(`containment-requested:pause-process:${target}`);
		recordEvidence(root, "containment.requested", `${alert.id}:${target}`);
	} catch (error) {
		const detail = error instanceof Error ? error.message : "Containment request failed.";
		recordEvidence(root, "containment.request.failed", detail);
	}
}

function newPersistencePath(lines: string[]): string | null {
	const syscall = lines.find((line) => line.startsWith("type=SYSCALL ")) ?? "";
	if (!["4294967295", "unset"].includes(field(syscall, "auid") ?? "")) {
		return null;
	}
	const created = lines.find((line) =>
		line.startsWith("type=PATH ") && field(line, "nametype") === "CREATE"
	);
	return field(created ?? "", "name");
}

function requestPersistenceQuarantine(
	root: string,
	policy: OnboardingPolicy,
	alert: Alert,
	lines: string[],
): void {
	const path = newPersistencePath(lines);
	if (policy.responseMode !== "autonomous-action" || path === null) {
		return;
	}
	try {
		requestAutomaticContainment(root, {
			action: "quarantine-persistence",
			evidence: alert.evidence,
			reason: "Quarantine a new persistent execution file created by a service.",
			target: path,
		});
		alert.evidence.push(`containment-requested:quarantine-persistence:${path}`);
		recordEvidence(root, "containment.requested", `${alert.id}:${path}`);
	} catch (error) {
		const detail = error instanceof Error ? error.message : "Containment request failed.";
		recordEvidence(root, "containment.request.failed", detail);
	}
}

function privilegedFilePath(lines: string[]): string | null {
	const syscall = lines.find((line) => line.startsWith("type=SYSCALL ")) ?? "";
	if (!["4294967295", "unset"].includes(field(syscall, "auid") ?? "")) {
		return null;
	}
	const path = lines.find((line) => {
		if (!line.startsWith("type=PATH ")) {
			return false;
		}
		const mode = Number.parseInt(field(line, "mode") ?? "", 8);
		return Number.isFinite(mode) && (mode & 0o6000) !== 0;
	});
	return field(path ?? "", "name");
}

function requestPrivilegeRemoval(
	root: string,
	policy: OnboardingPolicy,
	alert: Alert,
	lines: string[],
): void {
	const path = privilegedFilePath(lines);
	if (policy.responseMode !== "autonomous-action" || path === null) {
		return;
	}
	try {
		requestAutomaticContainment(root, {
			action: "strip-file-privileges",
			evidence: alert.evidence,
			reason: "Remove new set-user-ID or set-group-ID privileges created by a service.",
			target: path,
		});
		alert.evidence.push(`containment-requested:strip-file-privileges:${path}`);
		recordEvidence(root, "containment.requested", `${alert.id}:${path}`);
	} catch (error) {
		const detail = error instanceof Error ? error.message : "Containment request failed.";
		recordEvidence(root, "containment.request.failed", detail);
	}
}

function classifiedAlert(
	root: string,
	policy: OnboardingPolicy,
	lines: string[],
	now: Date,
	inspector: AuditProcessInspector,
): Alert | null {
	const classification = classifyAuditRecord(lines);
	if (classification === null) {
		return null;
	}
	const alert: Alert = {
		createdAt: now.toISOString(),
		evidence: recordEvidenceItems(lines, now),
		id: randomUUID(),
		kind: classification.kind,
		severity: classification.severity,
		summary: classification.summary,
	};
	recordEvidence(root, `host.audit.${alert.kind}`, alert.evidence.join(","), now);
	if (classification.automaticContainment) {
		requestSuspiciousProcessPause(root, policy, alert, serviceProcessTarget(lines, inspector));
	}
	if (alert.kind === "persistence-change") {
		requestPersistenceQuarantine(root, policy, alert, lines);
		requestPrivilegeRemoval(root, policy, alert, lines);
	}
	return alert;
}

function auditHealthIssue(path: string): string | null {
	if (!existsSync(path)) {
		return `The Linux Audit log is unavailable: ${path}`;
	}
	return null;
}

function auditHealthAlert(root: string, path: string, now: Date): Alert | null {
	const state = statePaths(root).auditIntegrityState;
	const issue = auditHealthIssue(path);
	if (issue === null) {
		if (existsSync(state)) {
			unlinkSync(state);
		}
		return null;
	}
	if (existsSync(state)) {
		return null;
	}
	writePrivate(state, jsonText({ detail: issue, observedAt: now.toISOString() }));
	return {
		createdAt: now.toISOString(),
		evidence: [issue],
		id: randomUUID(),
		kind: "kernel-integrity-change",
		severity: "critical",
		summary: "Linux Audit health failed.",
	};
}

function serviceShellAlert(
	root: string,
	policy: OnboardingPolicy,
	records: string[],
	now: Date,
	inspector: AuditProcessInspector,
	seenParents: Set<number>,
): Alert | null {
	const observed = execution(records);
	if (observed === null || seenParents.has(observed.parentPid)) {
		return null;
	}
	const attributed = containmentTarget(observed, inspector);
	if (attributed === null) {
		return null;
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
	return alert;
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
	const healthAlert = auditHealthAlert(root, path, now);
	if (healthAlert !== null) {
		recordEvidence(root, "host.audit.health", healthAlert.evidence.join(","), now);
		return [healthAlert];
	}
	const alerts: Alert[] = [];
	const seenParents = new Set<number>();
	for (const records of auditRecordGroups(appendedAuditText(root, path))) {
		const alert = serviceShellAlert(root, policy, records, now, inspector, seenParents) ??
			classifiedAlert(root, policy, records, now, inspector);
		if (alert !== null) {
			alerts.push(alert);
		}
	}
	return alerts;
}
