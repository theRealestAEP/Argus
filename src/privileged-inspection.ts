import { readdirSync, readFileSync } from "node:fs";
import { z } from "zod";

import type { ProcessIdentity } from "./containment.js";
import { jsonText, writePrivate } from "./files.js";
import { nativeProcessIdentity } from "./linux-containment-native.js";
import { statePaths } from "./paths.js";

const processIdentitySchema = z.object({
	executable: z.string().min(1),
	pid: z.number().int().positive(),
	startTimeTicks: z.string().regex(/^\d+$/u),
});

const processSnapshotSchema = z.object({
	capturedAt: z.iso.datetime(),
	processes: z.array(processIdentitySchema),
});

export interface PrivilegedProcessSource {
	identity(pid: number): ProcessIdentity;
	processNames(): string[];
}

function nativeSource(): PrivilegedProcessSource {
	return {
		identity: nativeProcessIdentity,
		processNames: () => readdirSync("/proc"),
	};
}

function observedIdentity(name: string, source: PrivilegedProcessSource): ProcessIdentity | null {
	try {
		return source.identity(Number.parseInt(name, 10));
	} catch {
		return null;
	}
}

export function refreshPrivilegedProcessSnapshot(
	root: string,
	now = new Date(),
	source: PrivilegedProcessSource = nativeSource(),
): void {
	const processes = source.processNames()
		.filter((name) => /^\d+$/u.test(name))
		.map((name) => observedIdentity(name, source))
		.filter((identity) => identity !== null);
	const path = statePaths(root).processSnapshot;
	writePrivate(path, jsonText({ capturedAt: now.toISOString(), processes }), 0o644);
}

export function readPrivilegedProcessIdentity(
	root: string,
	pid: number,
): ProcessIdentity {
	const snapshot = processSnapshotSchema.parse(
		JSON.parse(readFileSync(statePaths(root).processSnapshot, "utf8")),
	);
	const identity = snapshot.processes.find((item) => item.pid === pid);
	if (identity === undefined) {
		throw new Error(`Process ${pid} is absent from the privileged snapshot.`);
	}
	return identity;
}

export function readPrivilegedProcessSnapshot(root: string): ProcessIdentity[] {
	return processSnapshotSchema.parse(
		JSON.parse(readFileSync(statePaths(root).processSnapshot, "utf8")),
	).processes;
}
