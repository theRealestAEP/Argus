import { createHash, randomUUID } from "node:crypto";
import { appendFileSync, existsSync, readFileSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { z } from "zod";

import type { Alert, OnboardingPolicy } from "./contracts.js";
import { requestAutomaticContainment } from "./containment-broker.js";
import { isPersistencePathAllowed } from "./containment.js";
import { recordEvidence } from "./evidence-store.js";
import { jsonText, writePrivate } from "./files.js";
import { nativeMacosEventSource } from "./macos-eslogger-native.js";
import { statePaths } from "./paths.js";
import { macosServiceActive } from "./macos-native.js";

export const MACOS_ESLOGGER_EVENTS = [
	"authentication",
	"btm_launch_item_add",
	"btm_launch_item_remove",
	"copyfile",
	"create",
	"cs_invalidated",
	"exec",
	"gatekeeper_user_override",
	"kextload",
	"kextunload",
	"login_login",
	"login_logout",
	"od_create_user",
	"od_delete_user",
	"od_disable_user",
	"od_enable_user",
	"od_group_add",
	"od_group_remove",
	"od_modify_password",
	"openssh_login",
	"openssh_logout",
	"profile_add",
	"profile_remove",
	"remote_thread_create",
	"remount",
	"rename",
	"screensharing_attach",
	"screensharing_detach",
	"setmode",
	"setowner",
	"setuid",
	"su",
	"sudo",
	"tcc_modify",
	"trace",
	"truncate",
	"unlink",
	"xp_malware_detected",
	"xp_malware_remediated",
] as const;

const SPOOL_LIMIT_BYTES = 64 * 1024 * 1024;
const PERSISTENCE_EVENTS = new Set([
	"btm_launch_item_add",
	"od_create_user",
	"od_enable_user",
	"od_group_add",
	"profile_add",
]);
const FILE_CHANGE_EVENTS = new Set([
	"close",
	"copyfile",
	"create",
	"rename",
	"setmode",
	"setowner",
	"truncate",
	"unlink",
	"write",
]);
const PROCESS_TAMPERING_EVENTS = new Set([
	"get_task",
	"get_task_inspect",
	"get_task_read",
	"remote_thread_create",
	"trace",
]);
const KERNEL_EVENTS = new Set([
	"cs_invalidated",
	"gatekeeper_user_override",
	"kextload",
	"kextunload",
	"remount",
	"tcc_modify",
]);

const jsonValueSchema = z.json();
const jsonRecordSchema = z.record(z.string(), jsonValueSchema);
const nonemptyStringSchema = z.string().min(1);
const finiteNumberSchema = z.number().finite();
const booleanSchema = z.boolean();
const macosEventEnvelopeSchema = z.object({
	event: jsonRecordSchema.optional(),
	event_type: z.union([z.string(), z.number()]).optional(),
	eventType: z.string().optional(),
	process: jsonRecordSchema.optional(),
});

type JsonValue = z.infer<typeof jsonValueSchema>;
type JsonRecord = z.infer<typeof jsonRecordSchema>;
type MacosEventEnvelope = z.infer<typeof macosEventEnvelopeSchema>;

type NormalizedMacosEvent = {
	account: string | null;
	eventType: string;
	executable: string | null;
	paths: string[];
	pid: number | null;
	remoteAddress: string | null;
	startToken: string | null;
	success: boolean | null;
	userId: number | null;
};

const sensorStatusSchema = z.object({
	connected: z.boolean(),
	error: z.string().nullable(),
	eventCount: z.number().int().nonnegative(),
	events: z.array(z.string()),
	lastEventAt: z.iso.datetime().nullable(),
	startedAt: z.iso.datetime(),
});
export type SensorStatus = z.infer<typeof sensorStatusSchema>;

const cursorSchema = z.object({ offset: z.number().int().nonnegative() });
const serviceStateSchema = z.object({ inactive: z.array(z.string()) });
const parserStatusSchema = z.object({
	invalidRecords: z.number().int().nonnegative(),
	lastParsedAt: z.iso.datetime(),
	validRecords: z.number().int().nonnegative(),
});
const daemonStartSchema = z.object({ startedAt: z.iso.datetime() });
const eventDedupSchema = z.object({ fingerprints: z.array(z.string().length(64)).max(5_000) });
const evidenceRecordSchema = z.object({ detail: z.string(), event: z.string() });

type ReadMacosLines = {
	invalid: number;
	previousOffset: number;
	values: JsonValue[];
};

export interface MacosEventSource {
	availableEvents(): string[];
	start(
		events: string[],
		onLine: (line: string) => void,
		onFailure: (detail: string) => void,
	): () => void;
}

export type MacosServiceStatusReader = (target: string) => boolean;

function recordValue(value: JsonValue | undefined): JsonRecord | null {
	// SAFETY: The JSON boundary validates every object member as JsonValue.
	return Object(value) === value && !Array.isArray(value)
		? value as JsonRecord
		: null;
}

function nested(record: JsonRecord, keys: string[]): JsonValue | undefined {
	let value: JsonValue = record;
	for (const key of keys) {
		const parsed = recordValue(value);
		if (parsed === null) {
			return undefined;
		}
		value = parsed[key] ?? null;
	}
	return value;
}

function numberValue(value: JsonValue | undefined): number | null {
	const parsed = finiteNumberSchema.safeParse(value);
	return parsed.success ? parsed.data : null;
}

function stringValue(value: JsonValue | undefined): string | null {
	const parsed = nonemptyStringSchema.safeParse(value);
	return parsed.success ? parsed.data : null;
}

function eventType(record: MacosEventEnvelope): string {
	const explicit = stringValue(record.event_type) ?? stringValue(record.eventType);
	const event = record.event ?? {};
	const raw = explicit ?? Object.keys(event).at(0) ?? "unknown";
	return raw.toLowerCase().replace(/^es_event_type_notify_/u, "");
}

function collectNamedStrings(value: JsonValue | undefined, keyName: string, found: string[]): void {
	if (found.length >= 100) {
		return;
	}
	const record = recordValue(value);
	if (record !== null) {
		for (const [key, child] of Object.entries(record)) {
			if (key === keyName) {
				const text = stringValue(child);
				if (text !== null) {
					found.push(text);
				}
			}
			collectNamedStrings(child, keyName, found);
		}
		return;
	}
	if (Array.isArray(value)) {
		for (const child of value) {
			collectNamedStrings(child, keyName, found);
		}
	}
}

function eventPaths(record: MacosEventEnvelope): string[] {
	const paths: string[] = [];
	collectNamedStrings(record.event, "path", paths);
	return [...new Set(paths.filter((path) => path.startsWith("/")))];
}

function actor(record: MacosEventEnvelope): JsonRecord {
	return record.process ?? {};
}

function processStartToken(processRecord: JsonRecord): string | null {
	const start = processRecord.start_time ?? processRecord.startTime;
	const startRecord = recordValue(start);
	if (startRecord !== null) {
		const seconds = numberValue(startRecord.sec) ??
			numberValue(startRecord.tv_sec) ?? numberValue(startRecord.seconds);
		return seconds === null ? null : String(Math.trunc(seconds * 1_000));
	}
	const startText = stringValue(start);
	if (startText !== null) {
		const milliseconds = Date.parse(startText);
		return Number.isFinite(milliseconds) ? String(milliseconds) : null;
	}
	return null;
}

function remoteAddress(record: MacosEventEnvelope): string | null {
	for (const key of ["source_address", "remote_address", "address", "sourceAddress"]) {
		const values: string[] = [];
		collectNamedStrings(record.event, key, values);
		if (values[0] !== undefined) {
			return values[0];
		}
	}
	return null;
}

function namedString(record: MacosEventEnvelope, names: string[]): string | null {
	for (const name of names) {
		const values: string[] = [];
		collectNamedStrings(record.event, name, values);
		if (values[0] !== undefined) {
			return values[0];
		}
	}
	return null;
}

function eventSuccess(record: MacosEventEnvelope): boolean | null {
	const event = recordValue(record.event);
	if (event === null) {
		return null;
	}
	const member = recordValue(Object.values(event).at(0));
	if (member === null) {
		return null;
	}
	const parsed = booleanSchema.safeParse(member.success);
	return parsed.success ? parsed.data : null;
}

export function normalizeMacosEvent(value: JsonValue): NormalizedMacosEvent | null {
	const parsed = macosEventEnvelopeSchema.safeParse(value);
	if (!parsed.success) {
		return null;
	}
	const processRecord = actor(parsed.data);
	const token = recordValue(processRecord.audit_token) ?? {};
	return {
		account: namedString(parsed.data, ["username", "account_name"]),
		eventType: eventType(parsed.data),
		executable: stringValue(nested(processRecord, ["executable", "path"])),
		paths: eventPaths(parsed.data),
		pid: numberValue(token.pid),
		remoteAddress: remoteAddress(parsed.data),
		startToken: processStartToken(processRecord),
		success: eventSuccess(parsed.data),
		userId: numberValue(token.euid) ?? numberValue(token.uid),
	};
}

export function isMacosCredentialPath(path: string): boolean {
	return /(?:\/Library\/Keychains\/|\/\.ssh\/(?:id_[^/]+|config)$|\/\.aws\/credentials$|\/\.kube\/config$|\/Login Data$|\/etc\/master\.passwd$)/u.test(path);
}

type MacosClassification = Pick<Alert, "kind" | "severity" | "summary">;

function fixedClassification(event: NormalizedMacosEvent): MacosClassification | null {
	if (event.eventType === "xp_malware_detected") {
		return { kind: "malware-detected", severity: "critical", summary: "macOS detected malware on this host." };
	}
	if (PROCESS_TAMPERING_EVENTS.has(event.eventType)) {
		return { kind: "process-tampering", severity: "critical", summary: "A process attempted to inspect or control another process." };
	}
	if (KERNEL_EVENTS.has(event.eventType)) {
		return { kind: "kernel-integrity-change", severity: "critical", summary: "A macOS security or kernel control changed." };
	}
	if ((event.eventType === "openssh_login" && event.success === true) ||
		event.eventType === "screensharing_attach") {
		return { kind: "remote-login", severity: "high", summary: "A remote macOS login succeeded." };
	}
	return null;
}

function persistenceClassification(event: NormalizedMacosEvent): MacosClassification | null {
	if (PERSISTENCE_EVENTS.has(event.eventType) ||
		(FILE_CHANGE_EVENTS.has(event.eventType) && event.paths.some(isPersistencePathAllowed))) {
		return { kind: "persistence-change", severity: "critical", summary: "A macOS persistent execution mechanism changed." };
	}
	return null;
}

function classification(event: NormalizedMacosEvent): MacosClassification | null {
	const fixed = fixedClassification(event) ?? persistenceClassification(event);
	if (fixed !== null) {
		return fixed;
	}
	if (["access", "open"].includes(event.eventType) && event.paths.some(isMacosCredentialPath)) {
		return { kind: "credential-access", severity: "high", summary: "A process accessed protected credential material." };
	}
	return null;
}

function eventEvidence(event: NormalizedMacosEvent): string[] {
	return [
		`macos-event:${event.eventType}`,
		`account:${event.account ?? "unknown"}`,
		`child-pid:${event.pid ?? "unknown"}`,
		`effective-user:${event.userId ?? "unknown"}`,
		`child-executable:${event.executable ?? "unknown"}`,
		`process-start:${event.startToken ?? "unknown"}`,
		`remote-address:${event.remoteAddress ?? "unknown"}`,
		...event.paths.map((path) => `macos-path:${path}`),
	];
}

function alertFingerprint(event: NormalizedMacosEvent): string {
	return createHash("sha256").update(eventEvidence(event).join(",")).digest("hex");
}

function historicalAlertFingerprints(root: string, endOffset: number): string[] {
	if (endOffset === 0) {
		return [];
	}
	const content = readFileSync(statePaths(root).macosSensorLog).subarray(0, endOffset).toString("utf8");
	return content.split("\n").flatMap((line) => {
		try {
			const event = normalizeMacosEvent(jsonValueSchema.parse(JSON.parse(line)));
			return event === null || classification(event) === null ? [] : [alertFingerprint(event)];
		} catch {
			return [];
		}
	});
}

function historicalEvidenceFingerprints(root: string): string[] {
	const path = statePaths(root).eventLog;
	if (!existsSync(path)) {
		return [];
	}
	return readFileSync(path, "utf8").split("\n").flatMap((line) => {
		try {
			const record = evidenceRecordSchema.parse(JSON.parse(line));
			return record.event.startsWith("host.macos.")
				? [createHash("sha256").update(record.detail).digest("hex")]
				: [];
		} catch {
			return [];
		}
	});
}

function deduplicateAlertEvents(
	root: string,
	events: NormalizedMacosEvent[],
	previousOffset: number,
): NormalizedMacosEvent[] {
	const path = statePaths(root).macosEventDedup;
	const saved = existsSync(path)
		? eventDedupSchema.parse(JSON.parse(readFileSync(path, "utf8"))).fingerprints
		: [];
	const initial = saved.length === 0
		? [...historicalAlertFingerprints(root, previousOffset), ...historicalEvidenceFingerprints(root)]
		: saved;
	const fingerprints = new Set(initial);
	const fresh = events.filter((event) => {
		if (classification(event) === null) {
			return true;
		}
		const fingerprint = alertFingerprint(event);
		if (fingerprints.has(fingerprint)) {
			return false;
		}
		fingerprints.add(fingerprint);
		return true;
	});
	writePrivate(path, jsonText({ fingerprints: [...fingerprints].slice(-5_000) }));
	return fresh;
}

function processTarget(event: NormalizedMacosEvent): string | null {
	if (event.pid === null || event.pid <= 1 || event.executable === null || event.startToken === null) {
		return null;
	}
	return `pid=${event.pid},start=${event.startToken},path=${event.executable}`;
}

function requestMacosContainment(
	root: string,
	policy: OnboardingPolicy,
	alert: Alert,
	event: NormalizedMacosEvent,
): void {
	if (policy.responseMode !== "autonomous-action" || alert.kind !== "persistence-change") {
		return;
	}
	const path = event.paths.find(isPersistencePathAllowed);
	const target = processTarget(event);
	const plans = [
		...(target === null ? [] : [{ action: "pause-process" as const, target }]),
		...(path === undefined ? [] : [{ action: "quarantine-persistence" as const, target: path }]),
	];
	for (const plan of plans) {
		try {
			requestAutomaticContainment(root, {
				...plan,
				evidence: alert.evidence,
				reason: "Contain a new macOS persistence mechanism while Argus investigates.",
			});
			alert.evidence.push(`containment-requested:${plan.action}:${plan.target}`);
		} catch (error) {
			const detail = error instanceof Error ? error.message : "Containment request failed.";
			recordEvidence(root, "containment.request.failed", detail);
		}
	}
}

function alertFromMacosEvent(
	root: string,
	policy: OnboardingPolicy,
	event: NormalizedMacosEvent,
	now = new Date(),
): Alert | null {
	const result = classification(event);
	if (result === null) {
		return null;
	}
	const alert: Alert = {
		createdAt: now.toISOString(),
		evidence: eventEvidence(event),
		id: randomUUID(),
		...result,
	};
	recordEvidence(root, `host.macos.${alert.kind}`, alert.evidence.join(","), now);
	requestMacosContainment(root, policy, alert, event);
	return alert;
}

export function classifyMacosEvent(
	root: string,
	policy: OnboardingPolicy,
	value: JsonValue,
	now = new Date(),
): Alert | null {
	const event = normalizeMacosEvent(value);
	return event === null ? null : alertFromMacosEvent(root, policy, event, now);
}

function readNewLines(root: string): ReadMacosLines {
	const paths = statePaths(root);
	if (!existsSync(paths.macosSensorLog)) {
		return { invalid: 0, previousOffset: 0, values: [] };
	}
	const content = readFileSync(paths.macosSensorLog);
	let offset = 0;
	if (existsSync(paths.macosCursor)) {
		const saved = cursorSchema.safeParse(JSON.parse(readFileSync(paths.macosCursor, "utf8")));
		offset = saved.success && saved.data.offset <= content.length ? saved.data.offset : 0;
	}
	const appended = content.subarray(offset);
	const newline = appended.lastIndexOf(10);
	if (newline < 0) {
		return { invalid: 0, previousOffset: offset, values: [] };
	}
	writePrivate(paths.macosCursor, jsonText({ offset: offset + newline + 1 }));
	let invalid = 0;
	const values = appended.subarray(0, newline).toString("utf8").split("\n").flatMap((line) => {
		try {
			return line.length === 0 ? [] : [jsonValueSchema.parse(JSON.parse(line))];
		} catch {
			invalid += 1;
			return [];
		}
	});
	return { invalid, previousOffset: offset, values };
}

function integrityAlert(summary: string, evidence: string, now: Date): Alert {
	return {
		createdAt: now.toISOString(),
		evidence: [evidence],
		id: randomUUID(),
		kind: "sensor-integrity-failure",
		severity: "critical",
		summary,
	};
}

function requestServiceStart(root: string, policy: OnboardingPolicy, alert: Alert, target: string): void {
	if (policy.responseMode !== "autonomous-action") {
		return;
	}
	try {
		requestAutomaticContainment(root, {
			action: "start-service",
			evidence: alert.evidence,
			reason: "Restore an expected macOS service that stopped.",
			target,
		});
		alert.evidence.push(`containment-requested:start-service:${target}`);
	} catch (error) {
		const detail = error instanceof Error ? error.message : "Containment request failed.";
		recordEvidence(root, "containment.request.failed", detail);
	}
}

export function detectStoppedMacosServices(
	root: string,
	policy: OnboardingPolicy,
	now = new Date(),
	isActive: MacosServiceStatusReader = macosServiceActive,
): Alert[] {
	const path = statePaths(root).macosServiceState;
	const previous = existsSync(path)
		? serviceStateSchema.parse(JSON.parse(readFileSync(path, "utf8"))).inactive
		: [];
	const targets = policy.expectedServices.filter((target) =>
		/^(?:system|gui\/\d+)\/[A-Za-z0-9_.@-]+$/u.test(target)
	);
	const inactive = targets.filter((target) => !isActive(target));
	writePrivate(path, jsonText({ inactive }));
	return inactive.filter((target) => !previous.includes(target)).map((target) => {
		const alert: Alert = {
			createdAt: now.toISOString(),
			evidence: [`service-unit:${target}`, "launchd-state:inactive"],
			id: randomUUID(),
			kind: "service-stopped",
			severity: "critical",
			summary: `An expected macOS service stopped: ${target}`,
		};
		requestServiceStart(root, policy, alert, target);
		return alert;
	});
}

function sensorHealthIssue(root: string, now: Date): string | null {
	const paths = statePaths(root);
	if (!existsSync(paths.macosSensorLog) || !existsSync(paths.macosSensorStatus)) {
		return "The macOS event sensor has not produced its event stream and status files.";
	}
	try {
		const status = sensorStatusSchema.parse(JSON.parse(readFileSync(paths.macosSensorStatus, "utf8")));
		if (!status.connected) {
			return status.error ?? "The macOS event sensor stopped.";
		}
		if (status.lastEventAt === null || now.getTime() - Date.parse(status.lastEventAt) > 120_000) {
			return "The macOS event stream has been silent for more than two minutes.";
		}
		return null;
	} catch {
		return "The macOS event sensor status is invalid.";
	}
}

export function macosSensorReady(root: string, now = new Date()): boolean {
	return sensorHealthIssue(root, now) === null;
}

export function macosPipelineReady(root: string, now = new Date()): boolean {
	if (!macosSensorReady(root, now) || !existsSync(statePaths(root).macosParserStatus)) {
		return false;
	}
	try {
		const status = parserStatusSchema.parse(
			JSON.parse(readFileSync(statePaths(root).macosParserStatus, "utf8")),
		);
		return status.validRecords > 0 && now.getTime() - Date.parse(status.lastParsedAt) <= 120_000;
	} catch {
		return false;
	}
}

export function readMacosSensorStatus(root: string): SensorStatus {
	return sensorStatusSchema.parse(
		JSON.parse(readFileSync(statePaths(root).macosSensorStatus, "utf8")),
	);
}

function updateParserStatus(root: string, valid: number, invalid: number, now: Date): void {
	if (valid + invalid === 0) {
		return;
	}
	const path = statePaths(root).macosParserStatus;
	const previous = existsSync(path)
		? parserStatusSchema.parse(JSON.parse(readFileSync(path, "utf8")))
		: { invalidRecords: 0, lastParsedAt: now.toISOString(), validRecords: 0 };
	writePrivate(path, jsonText({
		invalidRecords: previous.invalidRecords + invalid,
		lastParsedAt: now.toISOString(),
		validRecords: previous.validRecords + valid,
	}));
}

function sensorHealthAlert(root: string, now: Date): Alert | null {
	const state = statePaths(root).macosIntegrityState;
	const issue = sensorHealthIssue(root, now);
	if (issue === null) {
		if (existsSync(state)) {
			unlinkSync(state);
		}
		return null;
	}
	const heartbeat = statePaths(root).heartbeat;
	if (existsSync(heartbeat)) {
		const started = daemonStartSchema.safeParse(JSON.parse(readFileSync(heartbeat, "utf8")));
		if (started.success && now.getTime() - Date.parse(started.data.startedAt) < 10_000) {
			return null;
		}
	}
	if (existsSync(state)) {
		return null;
	}
	writePrivate(state, jsonText({ issue, observedAt: now.toISOString() }));
	return integrityAlert("The macOS event sensor needs attention.", issue, now);
}

export function collectMacosAlerts(
	root: string,
	policy: OnboardingPolicy,
	now = new Date(),
	isServiceActive: MacosServiceStatusReader = macosServiceActive,
): Alert[] {
	const paths = statePaths(root);
	const health = sensorHealthAlert(root, now);
	if (!existsSync(paths.macosSensorLog)) {
		return health === null ? [] : [health];
	}
	const read = readNewLines(root);
	const values = read.values.flatMap((value) => {
		const event = normalizeMacosEvent(value);
		return event === null ? [] : [event];
	});
	const invalidCount = read.invalid + read.values.length - values.length;
	updateParserStatus(root, values.length, invalidCount, now);
	const alerts = deduplicateAlertEvents(root, values, read.previousOffset)
		.map((event) => alertFromMacosEvent(root, policy, event, now))
		.filter((alert) => alert !== null);
	const invalid = invalidCount === 0
		? []
		: [integrityAlert("The macOS event stream contained invalid data.", `invalid-records:${invalidCount}`, now)];
	const services = detectStoppedMacosServices(root, policy, now, isServiceActive);
	return [...(health === null ? [] : [health]), ...invalid, ...alerts, ...services];
}

export function trimMacosSensorSpool(path: string, limitBytes = SPOOL_LIMIT_BYTES): void {
	if (!existsSync(path) || statSync(path).size < limitBytes) {
		return;
	}
	const content = readFileSync(path);
	const retained = content.subarray(Math.floor(content.length / 2));
	const newline = retained.indexOf(10);
	writeFileSync(path, newline < 0 ? "" : retained.subarray(newline + 1), { mode: 0o644 });
}

function writeSensorStatus(root: string, status: SensorStatus): void {
	writePrivate(statePaths(root).macosSensorStatus, jsonText(status), 0o644);
}

export async function runMacosSensor(
	root: string,
	wait: () => Promise<void>,
	source: MacosEventSource = nativeMacosEventSource(),
	now: () => Date = () => new Date(),
): Promise<void> {
	const available = new Set(source.availableEvents());
	const events = MACOS_ESLOGGER_EVENTS.filter((event) => available.has(event));
	const startedAt = now().toISOString();
	const status: SensorStatus = {
		connected: events.length > 0,
		error: events.length > 0 ? null : "This macOS version supplied no supported eslogger events.",
		eventCount: 0,
		events,
		lastEventAt: null,
		startedAt,
	};
	writeSensorStatus(root, status);
	if (events.length === 0) {
		throw new Error(status.error ?? "The macOS event sensor cannot start.");
	}
	let rejectFailure: (error: Error) => void = () => undefined;
	const failure = new Promise<never>((_resolve, reject) => { rejectFailure = reject; });
	let stopping = false;
	let lastStatusWriteAt = 0;
	const stop = source.start(
		events,
		(line) => {
			trimMacosSensorSpool(statePaths(root).macosSensorLog);
			appendFileSync(statePaths(root).macosSensorLog, `${line}\n`, { encoding: "utf8", mode: 0o644 });
			status.eventCount += 1;
			const observedAt = now();
			status.lastEventAt = observedAt.toISOString();
			if (observedAt.getTime() - lastStatusWriteAt >= 1_000) {
				writeSensorStatus(root, status);
				lastStatusWriteAt = observedAt.getTime();
			}
		},
		(detail) => {
			if (stopping) {
				return;
			}
			status.connected = false;
			status.error = detail;
			writeSensorStatus(root, status);
			rejectFailure(new Error(detail));
		},
	);
	try {
		await Promise.race([wait(), failure]);
	} finally {
		stopping = true;
		writeSensorStatus(root, status);
		stop();
	}
}
