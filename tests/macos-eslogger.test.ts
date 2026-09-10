import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "vitest";

import { bootstrap } from "../src/bootstrap.js";
import type { OnboardingAnswers } from "../src/contracts.js";
import {
	classifyMacosEvent,
	collectMacosAlerts,
	detectStoppedMacosServices,
	isMacosCredentialPath,
	macosPipelineReady,
	macosSensorReady,
	normalizeMacosEvent,
	readMacosSensorStatus,
	runMacosSensor,
	trimMacosSensorSpool,
	type MacosEventSource,
	type SensorStatus,
} from "../src/macos-eslogger.js";
import { statePaths } from "../src/paths.js";

function answers(): OnboardingAnswers {
	return {
		adminContact: "local-only",
		automaticProcessTermination: true,
		approvedAgentRuntimes: [],
		criticalPaths: [],
		devicePurpose: "Mac workstation",
		expectedServices: [],
		maintenanceWindow: "Sunday 02:00",
		responseMode: "autonomous-action",
		retentionDays: 30,
		reviewSchedule: "daily",
	};
}

function state() {
	const root = mkdtempSync(join(tmpdir(), "argus-macos-events-test-"));
	const manifest = bootstrap(root, answers(), new Date("2026-01-01T00:00:00.000Z"));
	mkdirSync(statePaths(root).macosSensor, { mode: 0o700 });
	return { policy: { ...answers(), createdAt: manifest.createdAt }, root };
}

function event(type: string, path?: string) {
	return {
		event: {
			[type]: path === undefined ? { success: true } : { success: true, target: { path } },
		},
		event_type: `ES_EVENT_TYPE_NOTIFY_${type.toUpperCase()}`,
		process: {
			audit_token: { euid: 501, pid: 904 },
			executable: { path: "/bin/zsh" },
			start_time: { sec: 1_788_000_000 },
		},
	};
}

function writeSensorHealth(root: string, now: Date, change: Partial<SensorStatus> = {}): void {
	writeFileSync(statePaths(root).macosSensorLog, "");
	writeFileSync(statePaths(root).macosSensorStatus, JSON.stringify({
		connected: true,
		error: null,
		eventCount: 1,
		events: ["open"],
		lastEventAt: now.toISOString(),
		startedAt: now.toISOString(),
		...change,
	}));
}

describe("macOS Endpoint Security collection", () => {
	test("normalizes eslogger process and path evidence", () => {
		expect(normalizeMacosEvent(event("create", "/Users/alex/Library/LaunchAgents/com.test.plist")))
			.toEqual({
				account: null,
				eventType: "create",
				executable: "/bin/zsh",
				paths: ["/Users/alex/Library/LaunchAgents/com.test.plist"],
				pid: 904,
				remoteAddress: null,
				startToken: "1788000000000",
				success: true,
				userId: 501,
			});
		expect(normalizeMacosEvent("bad")).toBeNull();
	});

	test("normalizes alternate eslogger fields", () => {
		const start = "2026-08-31T12:00:00.000Z";
		expect(normalizeMacosEvent({
			event: {
				openssh_login: {
					success: true,
					user: { username: "alex" },
					connections: [{ sourceAddress: "192.0.2.8" }],
					files: [{ path: "relative" }, { path: "/Users/alex/.ssh/config" }],
				},
			},
			process: {
				audit_token: { pid: 44, uid: 502 },
				executable: { path: "/usr/sbin/sshd" },
				startTime: start,
			},
		})).toEqual({
			account: "alex",
			eventType: "openssh_login",
			executable: "/usr/sbin/sshd",
			paths: ["/Users/alex/.ssh/config"],
			pid: 44,
			remoteAddress: "192.0.2.8",
			startToken: String(Date.parse(start)),
			success: true,
			userId: 502,
		});
		expect(normalizeMacosEvent({ eventType: "EXEC", event: {}, process: {} }))
			.toMatchObject({ eventType: "exec", pid: null, startToken: null });
	});

	test("normalizes the macOS 26 numeric event envelope", () => {
		expect(normalizeMacosEvent({
			event: { close: { target: { path: "/Users/alex/notes.txt" } } },
			event_type: 12,
			process: {
				audit_token: { euid: 501, pid: 966 },
				executable: { path: "/usr/bin/textedit" },
				start_time: { sec: 1_788_000_000 },
			},
		})).toMatchObject({
			eventType: "close",
			executable: "/usr/bin/textedit",
			paths: ["/Users/alex/notes.txt"],
			pid: 966,
			userId: 501,
		});
	});

	test("classifies important macOS security events", () => {
		const { policy, root } = state();
		const samples = [
			[event("open", "/Users/alex/.ssh/id_ed25519"), "credential-access"],
			[event("remote_thread_create"), "process-tampering"],
			[event("kextload"), "kernel-integrity-change"],
			[event("openssh_login"), "remote-login"],
			[event("xp_malware_detected"), "malware-detected"],
		] as const;

		expect(samples.map(([value]) => classifyMacosEvent(root, policy, value)?.kind))
			.toEqual(samples.map(([, kind]) => kind));
		expect(isMacosCredentialPath("/Users/alex/.aws/credentials")).toBe(true);
		expect(isMacosCredentialPath("/Users/alex/notes.txt")).toBe(false);
		expect(classifyMacosEvent(root, policy, event("screensharing_attach"))?.kind)
			.toBe("remote-login");
		expect(classifyMacosEvent(root, policy, {
			...event("openssh_login"),
			event: { openssh_login: { success: false } },
		})).toBeNull();
		expect(classifyMacosEvent(root, policy, event("exec"))).toBeNull();
	});

	test("requests bounded containment for new persistence", () => {
		const { policy, root } = state();
		const alert = classifyMacosEvent(
			root,
			policy,
			event("create", "/Users/alex/Library/LaunchAgents/com.test.plist"),
		);

		expect(alert?.kind).toBe("persistence-change");
		expect(alert?.evidence).toContain(
			"containment-requested:quarantine-persistence:/Users/alex/Library/LaunchAgents/com.test.plist",
		);
		expect(readdirSync(statePaths(root).brokerRequests)).toHaveLength(4);
	});

	test("reads complete JSON lines once and reports stream damage", () => {
		const { policy, root } = state();
		const paths = statePaths(root);
		const now = new Date("2026-08-31T12:00:00.000Z");
		writeFileSync(paths.macosSensorStatus, JSON.stringify({
			connected: true,
			error: null,
			eventCount: 2,
			events: ["open"],
			lastEventAt: now.toISOString(),
			startedAt: now.toISOString(),
		}));
		writeFileSync(
			paths.macosSensorLog,
			`${JSON.stringify(event("open", "/Users/alex/.aws/credentials"))}\ninvalid\npartial`,
		);

		expect(collectMacosAlerts(root, policy, now).map((alert) => alert.kind)).toEqual([
			"sensor-integrity-failure",
			"credential-access",
		]);
		expect(collectMacosAlerts(root, policy, now)).toEqual([]);
	});

	test("deduplicates replayed security events across collection cycles", () => {
		const { policy, root } = state();
		const paths = statePaths(root);
		const now = new Date("2026-08-31T12:00:00.000Z");
		writeSensorHealth(root, now);
		const login = event("openssh_login");
		writeFileSync(paths.macosSensorLog, `${JSON.stringify(login)}\n${JSON.stringify(login)}\n`);

		expect(collectMacosAlerts(root, policy, now).map((alert) => alert.kind))
			.toEqual(["remote-login"]);
		writeFileSync(paths.macosSensorLog, `${readFileSync(paths.macosSensorLog, "utf8")}${JSON.stringify(login)}\n`);
		expect(collectMacosAlerts(root, policy, now)).toEqual([]);

		const nextLogin = {
			...login,
			process: { ...login.process, audit_token: { euid: 501, pid: 905 } },
		};
		writeFileSync(
			paths.macosSensorLog,
			`${readFileSync(paths.macosSensorLog, "utf8")}${JSON.stringify(nextLogin)}\n`,
		);
		expect(collectMacosAlerts(root, policy, now).map((alert) => alert.kind))
			.toEqual(["remote-login"]);
	});

	test("seeds event deduplication from an existing sensor cursor", () => {
		const { policy, root } = state();
		const paths = statePaths(root);
		const now = new Date("2026-08-31T12:00:00.000Z");
		writeSensorHealth(root, now);
		const line = `${JSON.stringify(event("openssh_login"))}\n`;
		writeFileSync(paths.macosSensorLog, `${line}${line}`);
		writeFileSync(paths.macosCursor, JSON.stringify({ offset: Buffer.byteLength(line) }));

		expect(collectMacosAlerts(root, policy, now)).toEqual([]);
		expect(existsSync(paths.macosEventDedup)).toBe(true);
	});

	test("seeds event deduplication from prior evidence after spool rotation", () => {
		const { policy, root } = state();
		const paths = statePaths(root);
		const now = new Date("2026-08-31T12:00:00.000Z");
		writeSensorHealth(root, now);
		writeFileSync(paths.eventLog, `${JSON.stringify({
			detail: "macos-event:openssh_login,account:unknown,child-pid:904,effective-user:501,child-executable:/bin/zsh,process-start:1788000000000,remote-address:unknown",
			event: "host.macos.remote-login",
			recordedAt: now.toISOString(),
		})}\n`);
		writeFileSync(paths.macosSensorLog, `${JSON.stringify(event("openssh_login"))}\n`);

		expect(collectMacosAlerts(root, policy, now)).toEqual([]);
	});

	test("reports a missing sensor once", () => {
		const { policy, root } = state();
		expect(collectMacosAlerts(root, policy)).toHaveLength(1);
		expect(collectMacosAlerts(root, policy)).toEqual([]);
	});

	test("allows the sensor ten seconds to start with the daemon", () => {
		const { policy, root } = state();
		const now = new Date("2026-08-31T12:00:00.000Z");
		writeFileSync(statePaths(root).heartbeat, JSON.stringify({ startedAt: now.toISOString() }));
		expect(collectMacosAlerts(root, policy, now)).toEqual([]);
	});

	test("requests recovery for a stopped expected launchd service once", () => {
		const { policy, root } = state();
		const launchdPolicy = {
			...policy,
			expectedServices: ["system/com.example.web"],
		};
		const alerts = detectStoppedMacosServices(
			root,
			launchdPolicy,
			new Date("2026-08-31T12:00:00.000Z"),
			() => false,
		);

		expect(alerts[0]).toMatchObject({ kind: "service-stopped", severity: "critical" });
		expect(alerts[0]?.evidence).toContain(
			"containment-requested:start-service:system/com.example.web",
		);
		expect(detectStoppedMacosServices(root, launchdPolicy, new Date(), () => false)).toEqual([]);
	});

	test("filters launchd targets and follows report-only policy", () => {
		const { policy, root } = state();
		const reportOnly = {
			...policy,
			expectedServices: ["nginx.service", "gui/501/com.example.agent"],
			responseMode: "report-only" as const,
		};
		const alerts = detectStoppedMacosServices(root, reportOnly, new Date(), () => false);
		expect(alerts).toHaveLength(1);
		expect(alerts[0]?.evidence.some((item) => item.startsWith("containment-requested:")))
			.toBe(false);
		const { policy: activePolicy, root: activeRoot } = state();
		expect(detectStoppedMacosServices(
			activeRoot,
			{ ...activePolicy, expectedServices: ["system/com.example.web"] },
			new Date(),
			() => true,
		)).toEqual([]);
	});

	test("reports sensor health and parser readiness", () => {
		const { policy, root } = state();
		const now = new Date("2026-08-31T12:00:00.000Z");
		writeSensorHealth(root, now);
		expect(macosSensorReady(root, now)).toBe(true);
		expect(macosPipelineReady(root, now)).toBe(false);
		writeFileSync(statePaths(root).macosSensorLog, `${JSON.stringify(event("exec"))}\n`);
		expect(collectMacosAlerts(root, policy, now)).toEqual([]);
		expect(macosPipelineReady(root, now)).toBe(true);
		expect(readMacosSensorStatus(root).connected).toBe(true);

		writeFileSync(statePaths(root).macosParserStatus, "invalid");
		expect(macosPipelineReady(root, now)).toBe(false);
		writeSensorHealth(root, now, { lastEventAt: null });
		expect(macosSensorReady(root, now)).toBe(false);
		writeSensorHealth(root, now, { lastEventAt: "2026-08-31T11:00:00.000Z" });
		expect(macosSensorReady(root, now)).toBe(false);
		writeSensorHealth(root, now, { connected: false, error: "permission denied" });
		expect(collectMacosAlerts(root, policy, now)[0]?.evidence).toEqual(["permission denied"]);
		expect(collectMacosAlerts(root, policy, now)).toEqual([]);

		writeSensorHealth(root, now);
		expect(collectMacosAlerts(root, policy, now)).toEqual([]);
		expect(existsSync(statePaths(root).macosIntegrityState)).toBe(false);
		writeFileSync(statePaths(root).macosSensorStatus, "invalid");
		expect(macosSensorReady(root, now)).toBe(false);
	});

	test("runs the root sensor through a bounded source adapter", async () => {
		const { root } = state();
		let stopped = false;
		const source: MacosEventSource = {
			availableEvents: () => ["exec", "open"],
			start(events, onLine) {
				expect(events).toEqual(["exec"]);
				onLine(JSON.stringify(event("exec")));
				return () => { stopped = true; };
			},
		};

		await runMacosSensor(
			root,
			() => Promise.resolve(),
			source,
			() => new Date("2026-08-31T12:00:00.000Z"),
		);

		expect(stopped).toBe(true);
		expect(readFileSync(statePaths(root).macosSensorLog, "utf8")).toContain("event_type");
		expect(JSON.parse(readFileSync(statePaths(root).macosSensorStatus, "utf8")))
			.toMatchObject({ connected: true, eventCount: 1 });
	});

	test("stops when eslogger has no supported events", async () => {
		const { root } = state();
		const source: MacosEventSource = {
			availableEvents: () => ["future_event"],
			start: () => () => undefined,
		};
		await expect(runMacosSensor(root, () => Promise.resolve(), source)).rejects.toThrow(
			"no supported eslogger events",
		);
		expect(readMacosSensorStatus(root)).toMatchObject({ connected: false, eventCount: 0 });
	});

	test("records an eslogger failure", async () => {
		const { root } = state();
		let stop: (() => void) | undefined;
		const source: MacosEventSource = {
			availableEvents: () => ["exec"],
			start(_events, _onLine, onFailure) {
				queueMicrotask(() => onFailure("eslogger lost access"));
				stop = () => onFailure("normal stop");
				return stop;
			},
		};
		await expect(runMacosSensor(root, () => new Promise(() => undefined), source))
			.rejects.toThrow("eslogger lost access");
		expect(readMacosSensorStatus(root)).toMatchObject({
			connected: false,
			error: "eslogger lost access",
		});
	});

	test("bounds the local event spool at complete lines", () => {
		const { root } = state();
		const path = statePaths(root).macosSensorLog;
		trimMacosSensorSpool(path, 5);
		writeFileSync(path, "alpha\nbeta\ngamma\n");
		trimMacosSensorSpool(path, 5);
		expect(readFileSync(path, "utf8")).toBe("gamma\n");
	});
});
