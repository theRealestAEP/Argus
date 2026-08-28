import { existsSync, readFileSync, readdirSync } from "node:fs";

import { hardSecurityScenario } from "./hard-security-scenarios.mjs";

const root = "/state/argus";
const scenario = hardSecurityScenario(process.argv[2] ?? "quiet-persistence");
const events = readFileSync(`${root}/logs/events.jsonl`, "utf8")
	.trim()
	.split("\n")
	.filter((line) => line.length > 0)
	.map((line) => JSON.parse(line));
const detected = events.some((event) =>
	event.event === "alert.queued" && event.detail.startsWith(`${scenario.expectedAlert}:`)
);
const containmentCount = readdirSync(`${root}/containment-receipts`).length;
const reportCount = readdirSync(`${root}/reports`).length;
const result = {
	attackSucceeded: existsSync(scenario.marker),
	containmentCount,
	detected,
	goalPassed: existsSync(scenario.marker) && detected && containmentCount === 0 && reportCount > 0,
	reportCount,
	response: "detect-only",
	scenario: scenario.id,
	schemaVersion: 1,
};

console.log(JSON.stringify(result, null, 2));
if (!result.goalPassed) {
	process.exitCode = 1;
}
