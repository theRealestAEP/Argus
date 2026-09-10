import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";

import { describe, expect, test } from "vitest";

import { saveIncidentReport } from "../src/alert-queue.js";
import { bootstrap } from "../src/bootstrap.js";
import type { Alert, OnboardingAnswers, OnboardingPolicy } from "../src/contracts.js";
import {
	archiveIncidentReports,
	type ArchiveGateway,
	type ArchiveUpload,
} from "../src/s3-archive.js";

function answers(bucket: string | null): OnboardingAnswers {
	return {
		adminContact: "local-only",
		approvedAgentRuntimes: [],
		criticalPaths: [],
		devicePurpose: "test host",
		expectedServices: [],
		maintenanceWindow: "Sunday 02:00",
		responseMode: "approval-required",
		retentionDays: 30,
		reviewSchedule: "daily",
		s3ArchiveBucket: bucket,
	};
}

describe("S3 report archive", () => {
	test("uploads a compressed content-addressed report once", async () => {
		const root = mkdtempSync(join(tmpdir(), "argus-archive-test-"));
		const setup = answers("security-archive");
		const manifest = bootstrap(root, setup);
		const policy: OnboardingPolicy = { ...setup, createdAt: manifest.createdAt };
		saveIncidentReport(
			root,
			{
				createdAt: "2026-01-02T00:00:00.000Z",
				evidence: ["event:test"],
				id: "123e4567-e89b-42d3-a456-426614174000",
				kind: "new-listener",
				severity: "high",
				summary: "A listener opened.",
			} satisfies Alert,
			"model",
			"report text",
			new Date("2026-01-02T00:00:00.000Z"),
		);
		let upload: ArchiveUpload | undefined;
		const gateway: ArchiveGateway = {
			put(item) {
				upload = item;
				return Promise.resolve("etag");
			},
		};

		expect(await archiveIncidentReports(root, policy, gateway, "host-reports")).toBe(1);
		expect(upload?.bucket).toBe("security-archive");
		expect(upload?.key).toContain("host-reports/2026-01-02/");
		expect(gunzipSync(upload?.body ?? new Uint8Array()).toString()).toContain("report text");
		expect(await archiveIncidentReports(root, policy, gateway, "host-reports")).toBe(0);
	});

	test("skips upload when no bucket is configured", async () => {
		const root = mkdtempSync(join(tmpdir(), "argus-archive-test-"));
		const setup = answers(null);
		const manifest = bootstrap(root, setup);
		const policy: OnboardingPolicy = { ...setup, createdAt: manifest.createdAt };
		const gateway: ArchiveGateway = {
			put: () => Promise.reject(new Error("unexpected upload")),
		};

		expect(await archiveIncidentReports(root, policy, gateway)).toBe(0);
	});
});
