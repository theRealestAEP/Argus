import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "vitest";

import { bootstrap } from "../src/bootstrap.js";
import { platformProbes, saveCapabilityReport } from "../src/capabilities.js";
import type { OnboardingAnswers } from "../src/contracts.js";
import { runDoctor } from "../src/doctor.js";
import { detectHost, validateLocalScope } from "../src/host.js";
import { uninstallPlan } from "../src/lifecycle.js";
import { buildMemoryPack, verifyMemoryPack } from "../src/memory-pack.js";
import { readPolicy } from "../src/onboarding.js";
import { statePaths } from "../src/paths.js";

function temporaryState(): string {
	return mkdtempSync(join(tmpdir(), "ids-agent-test-"));
}

function onboarding(devicePurpose: string): OnboardingAnswers {
	return {
		adminContact: "security@example.test",
		approvedAgentRuntimes: [],
		criticalPaths: [],
		devicePurpose,
		expectedServices: [],
		maintenanceWindow: "Sunday 02:00 local time",
		responseMode: "approval-required",
		retentionDays: 30,
		reviewSchedule: "every 2 days",
	};
}

function saveReadyCapabilities(root: string): void {
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

describe("on-device foundation", () => {
	test("defines setup probes for macOS and Linux", () => {
		expect(platformProbes("darwin").map((probe) => probe.id)).toEqual([
			"macos-unified-log",
			"macos-full-disk-access",
			"macos-endpoint-events",
			"macos-mitigation-broker",
		]);
		expect(platformProbes("linux").map((probe) => probe.id)).toEqual([
			"linux-journal",
			"linux-audit",
			"linux-process-state",
			"linux-firewall-tool",
			"linux-mitigation-broker",
		]);
	});

	test("creates signed host-bound state and passes doctor", () => {
		const root = temporaryState();
		const manifest = bootstrap(
			root,
			onboarding("developer workstation"),
			new Date("2026-01-02T03:04:05.000Z"),
		);
		saveReadyCapabilities(root);

		expect(manifest.host.fingerprint).toBe(detectHost().fingerprint);
		expect(runDoctor(root).ok).toBe(true);
	});

	test("rejects a scope manifest for another host", () => {
		const host = detectHost();
		const otherFingerprint = createHash("sha256").update("other host").digest("hex");
		const scope = JSON.stringify({
			collectionLocalOnly: true,
			hostFingerprint: otherFingerprint,
			remoteExecution: false,
			schemaVersion: 1,
		});

		expect(() => validateLocalScope(scope, host)).toThrow(
			"The scope manifest belongs to a different host.",
		);
	});

	test("detects a changed install manifest", () => {
		const root = temporaryState();
		bootstrap(root, onboarding("server"));
		saveReadyCapabilities(root);
		const paths = statePaths(root);
		const text = readFileSync(paths.installManifest, "utf8");
		writeFileSync(
			paths.installManifest,
			text.replace('"schemaVersion": 1', '"schemaVersion":  1'),
		);

		expect(runDoctor(root).ok).toBe(false);
	});

	test("rejects a changed operating policy", () => {
		const root = temporaryState();
		bootstrap(root, onboarding("server"));
		saveReadyCapabilities(root);
		const paths = statePaths(root);
		const text = readFileSync(paths.policy, "utf8");
		writeFileSync(paths.policy, text.replace("server", "workstation"));

		expect(runDoctor(root).ok).toBe(false);
		expect(() => readPolicy(root)).toThrow("policy signature is invalid");
	});

	test("keeps doctor incomplete while required access is missing", () => {
		const root = temporaryState();
		const host = detectHost();
		bootstrap(root, onboarding("server"));
		saveCapabilityReport(root, {
			checkedAt: "2026-01-02T03:04:05.000Z",
			hostFingerprint: host.fingerprint,
			platform: host.platform,
			probes: [
				{
					category: "mitigate",
					detail: "Perform an approved local mitigation.",
					id: "test-broker",
					instruction: "Install the privileged broker.",
					required: true,
					status: "action-required",
				},
			],
			ready: false,
			schemaVersion: 1,
		});

		const report = runDoctor(root);
		expect(report.ok).toBe(false);
		expect(report.checks).toContainEqual({
			detail: "Install the privileged broker.",
			name: "access test-broker",
			ok: false,
		});
	});

	test("builds a stable and verifiable memory pack", () => {
		const root = temporaryState();
		bootstrap(
			root,
			onboarding("workstation"),
			new Date("2026-01-02T03:04:05.000Z"),
		);
		const packRoot = buildMemoryPack(root);
		const firstManifest = readFileSync(join(packRoot, "MANIFEST.json"), "utf8");
		const firstSignature = readFileSync(join(packRoot, "MANIFEST.sig"), "utf8");

		buildMemoryPack(root);

		expect(readFileSync(join(packRoot, "MANIFEST.json"), "utf8")).toBe(firstManifest);
		expect(readFileSync(join(packRoot, "MANIFEST.sig"), "utf8")).toBe(firstSignature);
		expect(verifyMemoryPack(root, packRoot)).toBe(true);
	});

	test("lists every owned resource for removal", () => {
		const root = temporaryState();
		const manifest = bootstrap(root, onboarding("laptop"));
		const plan = uninstallPlan(root);

		expect(plan.toSorted()).toEqual(manifest.resources.toSorted());
		expect(plan.at(-1)).toBe(root);
		expect(plan).toContain(statePaths(root).keys);
	});
});
