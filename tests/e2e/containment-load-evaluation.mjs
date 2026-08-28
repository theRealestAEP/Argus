import { spawn } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { collectAgentRuntimeAlerts } from "../../dist/agent-events.js";
import { bootstrap } from "../../dist/bootstrap.js";
import { processBrokerRequests } from "../../dist/containment-broker.js";
import {
	collectLinuxSnapshot,
	collectSensorAlerts,
	commissionLinuxSensors,
} from "../../dist/linux-sensors.js";
import { statePaths } from "../../dist/paths.js";

const root = "/state/argus-containment-load";
const runtimeDirectory = "/opt/operations/containment-load";
const workerCount = 32;
const runtime = "containment-load-worker.mjs";
const directory = fileURLToPath(new URL(".", import.meta.url));
const answers = {
	adminContact: "local-only",
	agentMailInbox: null,
	approvedAgentRuntimes: [runtime],
	criticalPaths: [runtimeDirectory],
	devicePurpose: "Containment load evaluation",
	emailAllowedSenders: [],
	emailReportRecipients: [],
	expectedServices: [],
	logCacheMaxBytes: 10_485_760,
	maintenanceWindow: "Sunday 02:00",
	responseMode: "autonomous-action",
	retentionDays: 1,
	reviewSchedule: "weekly",
	s3ArchiveBucket: null,
};
const manifest = bootstrap(root, answers);
const policy = { ...answers, createdAt: manifest.createdAt };

commissionLinuxSensors(
	root,
	policy,
	{
		authentication: false,
		criticalFiles: true,
		listeners: false,
		networkConnections: false,
		processes: false,
		reason: "Watch concurrent protected-agent file changes.",
		thresholds: {
			authFailureBurst: 5,
			establishedConnectionBurst: 5,
			processStartBurst: 5,
		},
	},
	collectLinuxSnapshot(answers.criticalPaths),
);

const paths = statePaths(root);
const children = Array.from({ length: workerCount }, (_, index) => {
	const target = join(runtimeDirectory, `worker-${index}.json`);
	return spawn(process.execPath, [
		join(directory, "workload", runtime),
		paths.agentEvents,
		target,
		String(index),
	], { stdio: "ignore" });
});

for (let attempt = 0; attempt < 100; attempt += 1) {
	if (readdirSync(paths.agentEvents).length === workerCount) {
		break;
	}
	await new Promise((resolve) => setTimeout(resolve, 50));
}

const sensorAlerts = collectSensorAlerts(root);
const agentAlerts = collectAgentRuntimeAlerts(root, policy, sensorAlerts);
const requestCount = readdirSync(paths.brokerRequests)
	.filter((name) => name.endsWith(".json")).length;
const startedAt = performance.now();
const receipts = processBrokerRequests(root, 0);
const elapsedMs = Math.round(performance.now() - startedAt);
const pausedCount = children.filter((child) => {
	const status = readFileSync(`/proc/${child.pid}/status`, "utf8");
	return /^State:\s+T/mu.test(status);
}).length;

for (const child of children) {
	child.kill("SIGCONT");
	child.kill("SIGTERM");
}

const passed =
	agentAlerts.length === workerCount &&
	pausedCount === workerCount &&
	receipts.length === workerCount &&
	requestCount === workerCount;
console.log(JSON.stringify({
	agentAlertCount: agentAlerts.length,
	brokerElapsedMs: elapsedMs,
	passed,
	pausedCount,
	requestCount,
	workerCount,
}));
if (!passed) {
	process.exitCode = 1;
}
