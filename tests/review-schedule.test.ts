import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "vitest";

import {
	dueReviewAlert,
	initializeReviewSchedule,
	reviewIntervalMs,
} from "../src/review-schedule.js";

describe("review schedule", () => {
	test("parses supported schedules", () => {
		expect(reviewIntervalMs("daily")).toBe(86_400_000);
		expect(reviewIntervalMs("weekly")).toBe(604_800_000);
		expect(reviewIntervalMs("every 2 hours")).toBe(7_200_000);
		expect(reviewIntervalMs("every 2 days")).toBe(172_800_000);
		expect(() => reviewIntervalMs("often")).toThrow("Use daily, weekly");
	});

	test("emits one alert when a review becomes due", () => {
		const root = mkdtempSync(join(tmpdir(), "argus-review-test-"));
		const start = new Date("2026-01-01T00:00:00.000Z");
		expect(dueReviewAlert(root, "daily", start)).toBeNull();
		initializeReviewSchedule(root, "daily", start);
		expect(dueReviewAlert(root, "daily", new Date("2026-01-01T12:00:00.000Z"))).toBeNull();
		expect(
			dueReviewAlert(root, "daily", new Date("2026-01-02T00:00:00.000Z"))?.kind,
		).toBe("scheduled-review");
	});
});
