import { spawnSync } from "node:child_process";

export function send(response, status, value, headers = {}) {
	response.writeHead(status, { "content-type": "application/json", ...headers });
	response.end(JSON.stringify(value));
}

export function runDiagnostic(host) {
	const result = spawnSync("/bin/sh", ["-c", `getent hosts ${host}`], {
		encoding: "utf8",
		timeout: 10_000,
	});
	return {
		exitCode: result.status,
		stderr: result.stderr,
		stdout: result.stdout,
	};
}
