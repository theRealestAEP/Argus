import { chmodSync, readFileSync, readlinkSync, renameSync, statSync } from "node:fs";
import { spawnSync } from "node:child_process";

import type { ContainmentGateway, ProcessIdentity } from "./containment.js";

export function nativeProcessIdentity(pid: number): ProcessIdentity {
	const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
	const fields = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
	return {
		executable: readlinkSync(`/proc/${pid}/exe`),
		pid,
		startTimeTicks: fields.at(19) ?? "",
	};
}

export function nativeContainmentGateway(): ContainmentGateway {
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
		processIdentity: nativeProcessIdentity,
		quarantine(source, destination) {
			renameSync(source, destination);
		},
		runNft(args, ignoreFailure) {
			const result = spawnSync("nft", args, { encoding: "utf8" });
			if (result.status !== 0 && !ignoreFailure) {
				throw new Error(`nft failed: ${result.stderr.trim()}`);
			}
		},
		setFileMode(path, mode) {
			chmodSync(path, mode);
		},
		startService(unit) {
			const result = spawnSync("systemctl", ["start", unit], {
				encoding: "utf8",
				timeout: 10_000,
			});
			if (result.status !== 0) {
				throw new Error(`systemctl failed: ${result.stderr.trim()}`);
			}
		},
		terminate(pid) {
			process.kill(pid, "SIGTERM");
		},
	};
}
