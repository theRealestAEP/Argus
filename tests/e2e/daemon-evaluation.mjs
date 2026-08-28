import { once } from "node:events";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";

import { bootstrap } from "../../dist/bootstrap.js";

const stateDirectory = mkdtempSync(join(tmpdir(), "argus-daemon-eval-"));
bootstrap(stateDirectory, {
	adminContact: "local-only",
	agentMailInbox: null,
	approvedAgentRuntimes: [],
	criticalPaths: [],
	devicePurpose: "Linux daemon evaluation",
	expectedServices: [],
	maintenanceWindow: "Sunday 02:00",
	responseMode: "approval-required",
	retentionDays: 30,
	reviewSchedule: "every 2 days",
});

const heartbeatPath = join(stateDirectory, "runtime", "heartbeat.json");
const child = spawn(
	process.execPath,
	[
		join(process.cwd(), "dist", "cli.js"),
		"daemon",
		`--state-dir=${stateDirectory}`,
	],
	{ stdio: "inherit" },
);
const completion = once(child, "exit");

for (let attempt = 0; attempt < 40 && !existsSync(heartbeatPath); attempt += 1) {
	await new Promise((resolve) => setTimeout(resolve, 50));
}

child.kill("SIGTERM");
const [exitCode, signal] = await completion;
const heartbeat = existsSync(heartbeatPath)
	? JSON.parse(readFileSync(heartbeatPath, "utf8"))
	: null;
const passed = exitCode === 0 && signal === null && heartbeat?.pid === child.pid;

console.log(
	JSON.stringify(
		{
			exitCode,
			heartbeat,
			passed,
			schemaVersion: 1,
			signal,
		},
		null,
		2,
	),
);

if (!passed) {
	process.exitCode = 1;
}
