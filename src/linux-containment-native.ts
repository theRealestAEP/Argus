import { readFileSync, readlinkSync } from "node:fs";
import { spawnSync } from "node:child_process";

import type { ContainmentGateway, ProcessIdentity } from "./containment.js";

function nativeProcessIdentity(pid: number): ProcessIdentity {
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
		pause(pid) {
			process.kill(pid, "SIGSTOP");
		},
		processIdentity: nativeProcessIdentity,
		runNft(args, ignoreFailure) {
			const result = spawnSync("nft", args, { encoding: "utf8" });
			if (result.status !== 0 && !ignoreFailure) {
				throw new Error(`nft failed: ${result.stderr.trim()}`);
			}
		},
		terminate(pid) {
			process.kill(pid, "SIGTERM");
		},
	};
}
