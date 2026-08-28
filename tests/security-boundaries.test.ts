import { chmodSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "vitest";

import { bootstrap, readInstallManifest } from "../src/bootstrap.js";
import {
	canRead,
	canRun,
	commandExists,
	inspectCapabilities,
	saveCapabilityReport,
} from "../src/capabilities.js";
import type { OnboardingAnswers } from "../src/contracts.js";
import { runDoctor } from "../src/doctor.js";
import { detectHost, validateLocalScope } from "../src/host.js";
import { buildMemoryPack, verifyMemoryPack } from "../src/memory-pack.js";
import { statePaths } from "../src/paths.js";

function newRoot(): string {
	return mkdtempSync(join(tmpdir(), "ids-security-test-"));
}

function policy(): OnboardingAnswers {
	return {
		adminContact: "security@example.test",
		approvedAgentRuntimes: ["codex"],
		criticalPaths: ["/etc"],
		devicePurpose: "test host",
		expectedServices: ["sshd"],
		maintenanceWindow: "Sunday 02:00",
		responseMode: "approval-required",
		retentionDays: 30,
		reviewSchedule: "every 2 days",
	};
}

function readyReport(root: string): void {
	const host = detectHost();
	saveCapabilityReport(root, {
		checkedAt: "2026-01-02T03:04:05.000Z",
		hostFingerprint: host.fingerprint,
		platform: host.platform,
		probes: [],
		ready: true,
		schemaVersion: 1,
	});
}

describe("security boundaries", () => {
	test("checks command, file, and process access", () => {
		const directory = newRoot();
		const command = join(directory, "test-command");
		writeFileSync(command, "test\n");

		expect(commandExists("test-command", directory)).toBe(true);
		expect(commandExists("missing-command", directory)).toBe(false);
		expect(canRead(command)).toBe(true);
		expect(canRead(join(directory, "missing"))).toBe(false);
		expect(canRun(process.execPath, ["--version"])).toBe(true);
		expect(canRun(process.execPath, ["-e", "process.exit(2)"])).toBe(false);
	});

	test("reports every required file when setup is absent", () => {
		const report = runDoctor(newRoot());

		expect(report.ok).toBe(false);
		expect(report.checks).toHaveLength(8);
		expect(report.checks.every((check) => !check.ok)).toBe(true);
	});

	test("keeps the existing identity and key on repeated bootstrap", () => {
		const root = newRoot();
		const first = bootstrap(root, policy());
		const key = readFileSync(statePaths(root).privateKey, "utf8");
		const second = bootstrap(root, policy());

		expect(second.agentId).toBe(first.agentId);
		expect(readFileSync(statePaths(root).privateKey, "utf8")).toBe(key);
	});

	test("rejects broad private-key permissions", () => {
		const root = newRoot();
		bootstrap(root, policy());
		readyReport(root);
		chmodSync(statePaths(root).privateKey, 0o644);

		const check = runDoctor(root).checks.find(
			(item) => item.name === "private key permissions",
		);
		expect(check?.ok).toBe(false);
	});

	test("rejects a capability report copied from another host", () => {
		const root = newRoot();
		const host = detectHost();
		bootstrap(root, policy());
		saveCapabilityReport(root, {
			checkedAt: "2026-01-02T03:04:05.000Z",
			hostFingerprint: "0".repeat(64),
			platform: host.platform,
			probes: [],
			ready: true,
			schemaVersion: 1,
		});

		const check = runDoctor(root).checks.find((item) => item.name === "host binding");
		expect(check?.ok).toBe(false);
	});

	test("rejects remote execution in the local scope", () => {
		const host = detectHost();
		const scope = JSON.stringify({
			collectionLocalOnly: true,
			hostFingerprint: host.fingerprint,
			remoteExecution: true,
			schemaVersion: 1,
		});

		expect(() => validateLocalScope(scope, host)).toThrow();
	});

	test("rejects a malformed install manifest", () => {
		const root = newRoot();
		bootstrap(root, policy());
		writeFileSync(statePaths(root).installManifest, "{}\n");

		expect(() => readInstallManifest(root)).toThrow();
	});

	test("detects changed memory content", () => {
		const root = newRoot();
		bootstrap(root, policy());
		const packRoot = buildMemoryPack(root);
		writeFileSync(join(packRoot, "assets", "assets.jsonl"), "changed\n");

		expect(verifyMemoryPack(root, packRoot)).toBe(false);
	});

	test("detects a changed memory signature", () => {
		const root = newRoot();
		bootstrap(root, policy());
		const packRoot = buildMemoryPack(root);
		writeFileSync(join(packRoot, "MANIFEST.sig"), `${Buffer.alloc(64).toString("base64")}\n`);

		expect(verifyMemoryPack(root, packRoot)).toBe(false);
	});

	test("creates a host-bound capability report", () => {
		const report = inspectCapabilities(new Date("2026-01-02T03:04:05.000Z"));

		expect(report.hostFingerprint).toBe(detectHost().fingerprint);
		expect(report.checkedAt).toBe("2026-01-02T03:04:05.000Z");
		expect(report.ready).toBe(report.probes.every((probe) => probe.status === "ready"));
	});
});
