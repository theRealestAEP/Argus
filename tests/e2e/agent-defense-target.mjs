import { spawn } from "node:child_process";
import { chmodSync, chownSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { bootstrap } from "../../dist/bootstrap.js";
import { runContainmentBroker } from "../../dist/containment-broker.js";
import { runDaemon, waitForStop } from "../../dist/daemon.js";
import {
	collectLinuxSnapshot,
	commissionLinuxSensors,
} from "../../dist/linux-sensors.js";
import { statePaths } from "../../dist/paths.js";
import { securityScenario } from "./security-scenarios.mjs";

const root = "/state/argus-red-team";
const scenario = securityScenario(process.argv[2] ?? "prompt-injection");
const runtime = "vulnerable-scenario.mjs";
const answers = {
	adminContact: "local-only",
	agentMailInbox: null,
	approvedAgentRuntimes: [runtime],
	criticalPaths: [dirname(scenario.marker)],
	devicePurpose: scenario.purpose,
	expectedServices: [`vulnerable-${scenario.id}:8090`],
	maintenanceWindow: "Sunday 02:00",
	responseMode: "autonomous-action",
	retentionDays: 1,
	reviewSchedule: "weekly",
};
const manifest = bootstrap(root, answers);
const policy = { ...answers, createdAt: manifest.createdAt };
const directory = dirname(fileURLToPath(import.meta.url));
const paths = statePaths(root);
const workloadUserId = 65_534;
const runtimeDirectory = dirname(scenario.marker);

mkdirSync(runtimeDirectory, { recursive: true });
chownSync(runtimeDirectory, workloadUserId, workloadUserId);
chmodSync(runtimeDirectory, 0o700);
chownSync(dirname(root), 0, workloadUserId);
chmodSync(dirname(root), 0o710);
chownSync(root, 0, workloadUserId);
chmodSync(root, 0o710);
chownSync(dirname(paths.agentEvents), 0, workloadUserId);
chmodSync(dirname(paths.agentEvents), 0o710);
chownSync(paths.agentEvents, 0, workloadUserId);
chmodSync(paths.agentEvents, 0o730);

spawn(process.execPath, [join(directory, "workload", runtime), scenario.id], {
	env: {
		ARGUS_AGENT_EVENT_DIR: paths.agentEvents,
		PATH: process.env.PATH ?? "",
	},
	gid: workloadUserId,
	stdio: "inherit",
	uid: workloadUserId,
});

for (let attempt = 0; attempt < 30; attempt += 1) {
	try {
		const response = await fetch("http://127.0.0.1:8090/status");
		if (response.ok) {
			break;
		}
	} catch {
		await new Promise((resolve) => setTimeout(resolve, 100));
	}
}

commissionLinuxSensors(
	root,
	policy,
	{
		authentication: false,
		criticalFiles: true,
		listeners: false,
		networkConnections: false,
		processes: false,
		reason: "Watch the protected service runtime directory.",
		thresholds: {
			authFailureBurst: 5,
			establishedConnectionBurst: 10,
			processStartBurst: 10,
		},
	},
	collectLinuxSnapshot(answers.criticalPaths),
);

runContainmentBroker(root, waitForStop).catch((error) => console.error(error));
runDaemon(root).catch((error) => console.error(error));
console.log(JSON.stringify({ marker: scenario.marker, scenario: scenario.id, service: "ready" }));
