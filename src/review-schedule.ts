import { existsSync, readFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { z } from "zod";

import type { Alert } from "./contracts.js";
import { jsonText, writePrivate } from "./files.js";
import { statePaths } from "./paths.js";

const reviewStateSchema = z.object({ nextReviewAt: z.iso.datetime() });

export function reviewIntervalMs(schedule: string): number {
	const normalized = schedule.trim().toLowerCase();
	if (normalized === "daily") {
		return 86_400_000;
	}
	if (normalized === "weekly") {
		return 604_800_000;
	}
	const match = /^every (\d+) (hour|hours|day|days)$/u.exec(normalized);
	if (match === null) {
		throw new Error("Use daily, weekly, or every N hours or days for the review schedule.");
	}
	const count = Number.parseInt(match[1] ?? "", 10);
	const unitMs = match[2]?.startsWith("hour") === true ? 3_600_000 : 86_400_000;
	return count * unitMs;
}

export function initializeReviewSchedule(
	root: string,
	schedule: string,
	now = new Date(),
): void {
	const nextReviewAt = new Date(now.getTime() + reviewIntervalMs(schedule)).toISOString();
	writePrivate(statePaths(root).reviewState, jsonText({ nextReviewAt }));
}

export function dueReviewAlert(
	root: string,
	schedule: string,
	now = new Date(),
): Alert | null {
	const path = statePaths(root).reviewState;
	if (!existsSync(path)) {
		initializeReviewSchedule(root, schedule, now);
		return null;
	}
	const state = reviewStateSchema.parse(JSON.parse(readFileSync(path, "utf8")));
	if (Date.parse(state.nextReviewAt) > now.getTime()) {
		return null;
	}
	initializeReviewSchedule(root, schedule, now);
	return {
		createdAt: now.toISOString(),
		evidence: [`scheduled-review:${state.nextReviewAt}`],
		id: randomUUID(),
		kind: "scheduled-review",
		severity: "low",
		summary: "Run the scheduled host security review.",
	};
}
