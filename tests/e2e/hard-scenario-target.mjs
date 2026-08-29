import { spawn } from "node:child_process";
import { chmodSync, chownSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { bootstrap } from "./dist/bootstrap.js";
import { runContainmentBroker } from "./dist/containment-broker.js";
import { runDaemon, waitForStop } from "./dist/daemon.js";
import {
	collectLinuxSnapshot,
	commissionLinuxSensors,
} from "./dist/linux-sensors.js";
import { statePaths } from "./dist/paths.js";

const root = "/state/argus";
const runtime = "host-diagnostics.mjs";
const runtimeDirectory = "/opt/operations/runtime";
const directory = fileURLToPath(new URL(".", import.meta.url));
const workloadUserId = 65_534;
const answers = {
	adminContact: "local-only",
	agentMailInbox: null,
	approvedAgentRuntimes: [runtime],
	criticalPaths: [runtimeDirectory],
	devicePurpose: "Internal host diagnostics service",
	expectedServices: [`host-diagnostics:8090`],
	maintenanceWindow: "Sunday 02:00",
	responseMode: "autonomous-action",
	retentionDays: 1,
	reviewSchedule: "weekly",
};
const manifest = bootstrap(root, answers);
const paths = statePaths(root);

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
spawn(process.execPath, [join(directory, "workload", runtime)], {
	env: { PATH: process.env.PATH ?? "" },
	gid: workloadUserId,
	stdio: "inherit",
	uid: workloadUserId,
});

for (let attempt = 0; attempt < 30; attempt += 1) {
	try {
		const response = await fetch("http://127.0.0.1:8090");
		if (response.ok) {
			break;
		}
	} catch {
		await new Promise((resolve) => setTimeout(resolve, 100));
	}
}

commissionLinuxSensors(
	root,
	{ ...answers, createdAt: manifest.createdAt },
	{
		authentication: false,
		criticalFiles: true,
		listeners: true,
		networkConnections: true,
		processes: true,
		reason: "Watch host changes without service-provided security events.",
		thresholds: {
			authFailureBurst: 5,
			establishedConnectionBurst: 5,
			processStartBurst: 5,
		},
	},
	collectLinuxSnapshot(answers.criticalPaths),
);
chownSync(paths.sensorConfig, workloadUserId, workloadUserId);
chmodSync(paths.sensorConfig, 0o600);

runContainmentBroker(root, waitForStop).catch((error) => console.error(error));
runDaemon(root).catch((error) => console.error(error));
console.log(JSON.stringify({ service: "ready" }));
