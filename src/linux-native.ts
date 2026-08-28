import {
	existsSync,
	lstatSync,
	readdirSync,
	readFileSync,
	readlinkSync,
} from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

import type {
	FileObservation,
	LinuxSnapshot,
	ListenerObservation,
	ProcessObservation,
} from "./contracts.js";
import { linuxSnapshotSchema } from "./contracts.js";

const MAX_CRITICAL_FILES = 10_000;

function processObservation(pid: number): ProcessObservation | null {
	try {
		const status = readFileSync(`/proc/${pid}/status`, "utf8");
		const uidLine = status.split("\n").find((line) => line.startsWith("Uid:"));
		const userId = Number.parseInt(uidLine?.split(/\s+/u).at(1) ?? "", 10);
		if (!Number.isInteger(userId)) {
			return null;
		}
		return {
			command: readFileSync(`/proc/${pid}/cmdline`, "utf8").replaceAll("\0", " ").trim(),
			executable: readlinkSync(`/proc/${pid}/exe`),
			pid,
			userId,
		};
	} catch {
		return null;
	}
}

function collectProcesses(): ProcessObservation[] {
	return readdirSync("/proc")
		.filter((name) => /^\d+$/u.test(name))
		.map((name) => processObservation(Number.parseInt(name, 10)))
		.filter((item) => item !== null)
		.toSorted((left, right) => left.pid - right.pid);
}

type NetworkTable = {
	establishedCount: number;
	listeners: ListenerObservation[];
};

function readNetworkTable(path: string, protocol: "tcp" | "udp"): NetworkTable {
	if (!existsSync(path)) {
		return { establishedCount: 0, listeners: [] };
	}
	let establishedCount = 0;
	const listeners: ListenerObservation[] = [];
	for (const line of readFileSync(path, "utf8").split("\n").slice(1)) {
		const fields = line.trim().split(/\s+/u);
		const local = fields.at(1);
		const state = fields.at(3);
		if (state === "01") {
			establishedCount += 1;
		}
		if (state !== "0A" || local === undefined) {
			continue;
		}
		const [address, portText] = local.split(":");
		const port = Number.parseInt(portText ?? "", 16);
		if (address !== undefined && Number.isInteger(port)) {
			listeners.push({ address, port, protocol });
		}
	}
	return { establishedCount, listeners };
}

function collectNetwork(): NetworkTable {
	const tables = [
		readNetworkTable("/proc/net/tcp", "tcp"),
		readNetworkTable("/proc/net/tcp6", "tcp"),
		readNetworkTable("/proc/net/udp", "udp"),
		readNetworkTable("/proc/net/udp6", "udp"),
	];
	return {
		establishedCount: tables.reduce((count, item) => count + item.establishedCount, 0),
		listeners: tables.flatMap((item) => item.listeners),
	};
}

function addCriticalPath(path: string, files: FileObservation[]): void {
	if (files.length >= MAX_CRITICAL_FILES) {
		return;
	}
	try {
		const stat = lstatSync(path);
		if (stat.isSymbolicLink()) {
			return;
		}
		if (stat.isFile()) {
			files.push({ modifiedAtMs: stat.mtimeMs, path, size: stat.size });
			return;
		}
		if (stat.isDirectory()) {
			for (const entry of readdirSync(path)) {
				addCriticalPath(join(path, entry), files);
			}
		}
	} catch {
		return;
	}
}

function collectCriticalFiles(paths: string[]): FileObservation[] {
	const files: FileObservation[] = [];
	for (const path of paths) {
		addCriticalPath(path, files);
	}
	return files.toSorted((left, right) => left.path.localeCompare(right.path));
}

function authenticationFailureCount(): number {
	const result = spawnSync(
		"journalctl",
		["--no-pager", "--since", "30 seconds ago", "-o", "cat"],
		{ encoding: "utf8", timeout: 5_000 },
	);
	if (result.status !== 0) {
		return 0;
	}
	return result.stdout
		.split("\n")
		.filter((line) => /authentication failure|failed password|invalid user/iu.test(line))
		.length;
}

export function collectLinuxSnapshot(
	criticalPaths: string[],
	now = new Date(),
): LinuxSnapshot {
	const network = collectNetwork();
	return linuxSnapshotSchema.parse({
		authFailureCount: authenticationFailureCount(),
		criticalFiles: collectCriticalFiles(criticalPaths),
		establishedConnectionCount: network.establishedCount,
		listeners: network.listeners,
		observedAt: now.toISOString(),
		processes: collectProcesses(),
	});
}
