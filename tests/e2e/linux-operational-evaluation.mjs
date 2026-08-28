import { once } from "node:events";
import { execFileSync, spawn } from "node:child_process";
import {
	mkdtempSync,
	readFileSync,
	readlinkSync,
	readdirSync,
	writeFileSync,
} from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { bootstrap } from "../../dist/bootstrap.js";
import { applyContainment } from "../../dist/containment.js";
import {
	processBrokerRequests,
	requestAutomaticContainment,
} from "../../dist/containment-broker.js";
import {
	collectLinuxSnapshot,
	collectSensorAlerts,
	commissionLinuxSensors,
} from "../../dist/linux-sensors.js";
import { runOperationalCycle } from "../../dist/operational-loop.js";

const root = mkdtempSync(join(tmpdir(), "argus-operational-eval-"));
const watchedFile = join(root, "watched.conf");
writeFileSync(watchedFile, "safe=true\n");
const answers = {
	adminContact: "local-only",
	approvedAgentRuntimes: [],
	criticalPaths: [watchedFile],
	devicePurpose: "Linux operational evaluation",
	expectedServices: [],
	maintenanceWindow: "Sunday 02:00",
	responseMode: "autonomous-action",
	retentionDays: 30,
	reviewSchedule: "daily",
};
const manifest = bootstrap(root, answers);
const policy = { ...answers, createdAt: manifest.createdAt };
const baseline = collectLinuxSnapshot(answers.criticalPaths);
commissionLinuxSensors(
	root,
	policy,
	{
		authentication: false,
		criticalFiles: true,
		listeners: true,
		networkConnections: false,
		processes: false,
		reason: "Docker evaluation selection",
		thresholds: {
			authFailureBurst: 5,
			establishedConnectionBurst: 100,
			processStartBurst: 100,
		},
	},
	baseline,
);

const server = createServer();
server.listen(0, "127.0.0.1");
await once(server, "listening");
writeFileSync(watchedFile, "safe=false\n");

let firstCollection = true;
const services = {
	canInvestigate: () => true,
	collectAlerts: () => {
		if (!firstCollection) {
			return Promise.resolve([]);
		}
		firstCollection = false;
		return Promise.resolve(collectSensorAlerts(root));
	},
	deliverReports: () => Promise.resolve(),
	investigate: (alert) => Promise.resolve({
		model: "docker-fixture",
		report: `Investigated ${alert.kind}`,
	}),
};
await runOperationalCycle(root, services);
await runOperationalCycle(root, services);
server.close();

requestAutomaticContainment(root, {
	action: "block-destination",
	evidence: ["docker-event"],
	reason: "Docker containment canary",
	target: "203.0.113.4",
});
const brokerReceipts = processBrokerRequests(root, 0);
const nftSet = execFileSync(
	"nft",
	["list", "set", "inet", "argus", "blocked_ipv4"],
	{ encoding: "utf8" },
);
execFileSync(
	"nft",
	["delete", "element", "inet", "argus", "blocked_ipv4", "{", "203.0.113.4", "}"],
);

const sleeper = spawn("sleep", ["30"]);
const stat = readFileSync(`/proc/${sleeper.pid}/stat`, "utf8");
const startTimeTicks = stat.slice(stat.lastIndexOf(")") + 2).split(" ").at(19);
const executable = readlinkSync(`/proc/${sleeper.pid}/exe`);
applyContainment(
	root,
	policy,
	{
		action: "terminate-process",
		evidence: ["docker-process-canary"],
		reason: "Docker termination canary",
		target: `pid=${sleeper.pid},start=${startTimeTicks},path=${executable}`,
	},
	0,
);
await once(sleeper, "exit");

const reportCount = readdirSync(join(root, "reports")).length;
const passed =
	reportCount === 2 &&
	brokerReceipts.length === 1 &&
	nftSet.includes("203.0.113.4");

console.log(JSON.stringify({
	brokerReceiptCount: brokerReceipts.length,
	passed,
	reportCount,
	schemaVersion: 1,
}, null, 2));

if (!passed) {
	process.exitCode = 1;
}
