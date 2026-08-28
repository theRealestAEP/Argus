import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "vitest";

import { appendEvidence, pruneEvidence } from "../src/evidence-store.js";
import { statePaths } from "../src/paths.js";

function temporaryState(): string {
	return mkdtempSync(join(tmpdir(), "argus-evidence-test-"));
}

describe("evidence store", () => {
	test("accepts an empty store", () => {
		expect(pruneEvidence(temporaryState(), 30, 10_000)).toBe(0);
	});

	test("removes events outside the retention period", () => {
		const root = temporaryState();
		appendEvidence(root, {
			detail: "old",
			event: "test.old",
			recordedAt: "2026-01-01T00:00:00.000Z",
		});
		appendEvidence(root, {
			detail: "current",
			event: "test.current",
			recordedAt: "2026-01-10T00:00:00.000Z",
		});

		expect(
			pruneEvidence(root, 2, 10_000, new Date("2026-01-11T00:00:00.000Z")),
		).toBe(1);
		const content = readFileSync(statePaths(root).eventLog, "utf8");
		expect(content).toContain("test.current");
		expect(content).not.toContain("test.old");
	});

	test("removes the oldest event to enforce the size limit", () => {
		const root = temporaryState();
		const newest = {
			detail: "newest event",
			event: "test.newest",
			recordedAt: "2026-01-11T00:00:00.000Z",
		};
		appendEvidence(root, {
			detail: "older event",
			event: "test.older",
			recordedAt: "2026-01-10T00:00:00.000Z",
		});
		appendEvidence(root, newest);
		const newestBytes = Buffer.byteLength(`${JSON.stringify(newest)}\n`);

		expect(
			pruneEvidence(root, 30, newestBytes, new Date("2026-01-11T00:00:00.000Z")),
		).toBe(1);
		expect(readFileSync(statePaths(root).eventLog, "utf8")).toContain("test.newest");
	});
});
