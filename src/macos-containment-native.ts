import { chmodSync, renameSync, statSync } from "node:fs";
import { spawnSync } from "node:child_process";

import type { ContainmentGateway, ProcessIdentity } from "./containment.js";

type MacosProcessLine = {
	executable: string;
	startedAt: string;
};

function processLine(pid: number): MacosProcessLine {
	const result = spawnSync(
		"/bin/ps",
		["-p", String(pid), "-o", "lstart=", "-o", "comm="],
		{ encoding: "utf8", timeout: 5_000 },
	);
	if (result.status !== 0) {
		throw new Error(`Process ${pid} is absent.`);
	}
	const match = /^\s*(\S+\s+\S+\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+(.+)$/u.exec(result.stdout.trim());
	if (match === null) {
		throw new Error(`Process ${pid} has an invalid identity.`);
	}
	return { executable: match[2] ?? "", startedAt: match[1] ?? "" };
}

export function nativeMacosProcessIdentity(pid: number): ProcessIdentity {
	const observed = processLine(pid);
	const milliseconds = Date.parse(observed.startedAt);
	if (!Number.isFinite(milliseconds)) {
		throw new Error(`Process ${pid} has an invalid start time.`);
	}
	return { executable: observed.executable, pid, startTimeTicks: String(milliseconds) };
}

export function parseMacosProcessSnapshot(output: string): ProcessIdentity[] {
	return output.split("\n").flatMap((line) => {
		const match = /^\s*(\d+)\s+(\S+\s+\S+\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+(.+)$/u.exec(line);
		const milliseconds = match === null ? Number.NaN : Date.parse(match[2] ?? "");
		if (match === null || !Number.isFinite(milliseconds)) {
			return [];
		}
		return [{
			executable: match[3] ?? "",
			pid: Number.parseInt(match[1] ?? "", 10),
			startTimeTicks: String(milliseconds),
		}];
	});
}

export function nativeMacosProcessSnapshot(): ProcessIdentity[] {
	const result = spawnSync(
		"/bin/ps",
		["-axo", "pid=,lstart=,comm="],
		{ encoding: "utf8", timeout: 5_000 },
	);
	if (result.status !== 0) {
		throw new Error("The macOS process snapshot failed.");
	}
	return parseMacosProcessSnapshot(result.stdout);
}

export function nativeMacosContainmentGateway(): ContainmentGateway {
	return {
		fileMode(path) {
			const stat = statSync(path);
			if (!stat.isFile()) {
				throw new Error("The privileged target is not a regular file.");
			}
			return stat.mode;
		},
		pause(pid) {
			process.kill(pid, "SIGSTOP");
		},
		processIdentity: nativeMacosProcessIdentity,
		quarantine(source, destination) {
			renameSync(source, destination);
		},
		runNft() {
			throw new Error("The macOS PF containment backend is not configured.");
		},
		setFileMode(path, mode) {
			chmodSync(path, mode);
		},
		startService(unit) {
			const result = spawnSync("/bin/launchctl", ["kickstart", "-k", unit], {
				encoding: "utf8",
				timeout: 10_000,
			});
			if (result.status !== 0) {
				throw new Error(`launchctl failed: ${result.stderr.trim()}`);
			}
			return `launchctl kill SIGTERM ${unit}`;
		},
		terminate(pid) {
			process.kill(pid, "SIGTERM");
		},
	};
}
