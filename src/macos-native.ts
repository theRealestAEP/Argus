import { spawnSync } from "node:child_process";

export type MacosConnectionEvidence = {
	records: string[];
	unavailable?: string;
};

export function collectMacosConnections(): MacosConnectionEvidence {
	const result = spawnSync(
		"/usr/sbin/lsof",
		["-nP", "-iTCP", "-sTCP:LISTEN,ESTABLISHED"],
		{ encoding: "utf8", timeout: 5_000 },
	);
	if (result.error !== undefined || ![0, 1].includes(result.status ?? -1)) {
		return { records: [], unavailable: "macOS connection inspection failed." };
	}
	return { records: result.stdout.trim().split("\n").filter(Boolean).slice(0, 200) };
}

export function macosServiceActive(target: string): boolean {
	const result = spawnSync("/bin/launchctl", ["print", target], {
		stdio: "ignore",
		timeout: 5_000,
	});
	return result.status === 0;
}
