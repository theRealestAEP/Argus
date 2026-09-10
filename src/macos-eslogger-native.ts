import { spawn, spawnSync } from "node:child_process";

import type { MacosEventSource } from "./macos-eslogger.js";

export function nativeMacosEventSource(): MacosEventSource {
	return {
		availableEvents() {
			const result = spawnSync("/usr/bin/eslogger", ["--list-events"], { encoding: "utf8" });
			return result.status === 0 ? result.stdout.trim().split("\n") : [];
		},
		start(events, onLine, onFailure) {
			const child = spawn("/usr/bin/eslogger", events, { stdio: ["ignore", "pipe", "pipe"] });
			let buffer = "";
			child.stdout.setEncoding("utf8");
			child.stdout.on("data", (chunk: string) => {
				buffer += chunk;
				const lines = buffer.split("\n");
				buffer = lines.pop() ?? "";
				for (const line of lines.filter((item) => item.length > 0)) {
					onLine(line);
				}
			});
			let errorText = "";
			child.stderr.setEncoding("utf8");
			child.stderr.on("data", (chunk: string) => { errorText += chunk; });
			child.once("error", (error) => onFailure(error.message));
			child.once("exit", (code) => {
				onFailure(errorText.trim() || `eslogger exited with status ${code ?? "unknown"}.`);
			});
			return () => child.kill("SIGTERM");
		},
	};
}
