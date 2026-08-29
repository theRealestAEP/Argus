import { spawn } from "node:child_process";
import { chmodSync, chownSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { bootstrap } from "./dist/bootstrap.js";
import { runContainmentBroker } from "./dist/containment-broker.js";
import { runDaemon, waitForStop } from "./dist/daemon.js";
import {
	collectLinuxSnapshot,
	commissionLinuxSensors,
} from "./dist/linux-sensors.js";

const root = "/state/argus";
const runtimeDirectory = "/opt/operations/runtime";
const service = process.env.APPLICATION_SERVICE ?? "router";
const services = new Set(["identity", "renderer", "router"]);
const directory = fileURLToPath(new URL(".", import.meta.url));

if (!services.has(service)) {
	throw new Error("Unknown application service.");
}

mkdirSync(runtimeDirectory, { recursive: true });
chownSync(runtimeDirectory, 65_534, 65_534);
chmodSync(runtimeDirectory, 0o700);
spawn(process.execPath, [join(directory, "services", `${service}.mjs`)], {
	env: { PATH: process.env.PATH ?? "" },
	gid: 65_534,
	stdio: "inherit",
	uid: 65_534,
});

let ready = false;
for (let attempt = 0; attempt < 30; attempt += 1) {
	try {
		const response = await fetch("http://127.0.0.1:8090");
		if (response.ok) {
			ready = true;
			break;
		}
	} catch {
		await new Promise((resolve) => setTimeout(resolve, 100));
	}
}
if (!ready) {
	throw new Error("The application service did not start.");
}

const answers = {
	adminContact: "local-only",
	agentMailInbox: null,
	approvedAgentRuntimes: [`${service}.mjs`],
	criticalPaths: [runtimeDirectory],
	devicePurpose: "Internal application gateway",
	emailAllowedSenders: [],
	emailReportRecipients: [],
	expectedServices: ["application-gateway:8090"],
	logCacheMaxBytes: 10_485_760,
	maintenanceWindow: "Sunday 02:00",
	responseMode: "autonomous-action",
	retentionDays: 1,
	reviewSchedule: "weekly",
	s3ArchiveBucket: null,
};
const manifest = bootstrap(root, answers);
commissionLinuxSensors(
	root,
	{ ...answers, createdAt: manifest.createdAt },
	{
		authentication: false,
		criticalFiles: true,
		listeners: true,
		networkConnections: true,
		processes: true,
		reason: "Watch application and host changes.",
		thresholds: {
			authFailureBurst: 5,
			establishedConnectionBurst: 5,
			processStartBurst: 5,
		},
	},
	collectLinuxSnapshot(answers.criticalPaths),
);

runContainmentBroker(root, waitForStop).catch((error) => console.error(error));
runDaemon(root).catch((error) => console.error(error));
console.log(JSON.stringify({ service: "ready" }));
