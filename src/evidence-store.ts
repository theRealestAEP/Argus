import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";

import type { EvidenceEvent } from "./contracts.js";
import { evidenceEventSchema } from "./contracts.js";
import { writePrivate } from "./files.js";
import { readPolicy } from "./onboarding.js";
import { statePaths } from "./paths.js";

function encoded(event: EvidenceEvent): string {
	return `${JSON.stringify(event)}\n`;
}

export function appendEvidence(root: string, event: EvidenceEvent): void {
	const path = statePaths(root).eventLog;
	mkdirSync(statePaths(root).logs, { mode: 0o700, recursive: true });
	appendFileSync(path, encoded(evidenceEventSchema.parse(event)), {
		encoding: "utf8",
		mode: 0o600,
	});
}

export function pruneEvidence(
	root: string,
	retentionDays: number,
	maxBytes: number,
	now = new Date(),
): number {
	const path = statePaths(root).eventLog;
	if (!existsSync(path)) {
		return 0;
	}
	const cutoff = now.getTime() - retentionDays * 86_400_000;
	const retained = readFileSync(path, "utf8")
		.trimEnd()
		.split("\n")
		.filter((line) => line.length > 0)
		.map((line) => evidenceEventSchema.parse(JSON.parse(line)))
		.filter((event) => Date.parse(event.recordedAt) >= cutoff)
		.map(encoded);
	while (retained.reduce((size, line) => size + Buffer.byteLength(line), 0) > maxBytes) {
		retained.shift();
	}
	writePrivate(path, retained.join(""));
	return retained.length;
}

export function recordEvidence(
	root: string,
	event: string,
	detail: string,
	now = new Date(),
): void {
	appendEvidence(root, { detail, event, recordedAt: now.toISOString() });
	const policy = readPolicy(root);
	pruneEvidence(
		root,
		policy.retentionDays,
		policy.logCacheMaxBytes ?? 1_073_741_824,
		now,
	);
}
