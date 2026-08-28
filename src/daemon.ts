import { platform } from "node:os";

import { jsonText, writePrivate } from "./files.js";
import { recordEvidence } from "./evidence-store.js";
import { statePaths } from "./paths.js";

export interface DaemonHeartbeat {
	pid: number;
	platform: string;
	startedAt: string;
	updatedAt: string;
}

export type DaemonWait = () => Promise<void>;

export function writeHeartbeat(
	root: string,
	startedAt: Date,
	now = new Date(),
): DaemonHeartbeat {
	const heartbeat = {
		pid: process.pid,
		platform: platform(),
		startedAt: startedAt.toISOString(),
		updatedAt: now.toISOString(),
	};
	writePrivate(statePaths(root).heartbeat, jsonText(heartbeat));
	return heartbeat;
}

export function waitForStop(): Promise<void> {
	return new Promise((resolve) => {
		const stop = () => {
			process.off("SIGINT", stop);
			process.off("SIGTERM", stop);
			resolve();
		};
		process.once("SIGINT", stop);
		process.once("SIGTERM", stop);
	});
}

export async function runDaemon(
	root: string,
	wait: DaemonWait = waitForStop,
): Promise<void> {
	const startedAt = new Date();
	writeHeartbeat(root, startedAt);
	recordEvidence(root, "daemon.started", `PID ${process.pid}`, startedAt);
	const timer = setInterval(() => writeHeartbeat(root, startedAt), 30_000);
	try {
		await wait();
	} finally {
		clearInterval(timer);
		writeHeartbeat(root, startedAt);
		recordEvidence(root, "daemon.stopped", `PID ${process.pid}`);
	}
}
