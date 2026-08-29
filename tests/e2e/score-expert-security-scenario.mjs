import { existsSync, readFileSync, readdirSync } from "node:fs";

import { expertSecurityScenario } from "./expert-security-scenarios.mjs";

const root = "/state/argus";
const scenario = expertSecurityScenario(process.argv[2] ?? "ssrf-loopback-rce");
const eventText = readFileSync(`${root}/logs/events.jsonl`, "utf8").trim();
const events = eventText.length === 0
	? []
	: eventText.split("\n").map((line) => JSON.parse(line));
const attackSucceeded = existsSync(scenario.marker);
const detected = events.some((event) =>
	event.event === "alert.queued" && event.detail.startsWith("critical-file-change:")
);
const containmentCount = readdirSync(`${root}/containment-receipts`).length;
const reportCount = readdirSync(`${root}/reports`).length;
const fullResponse = detected && reportCount > 0 && containmentCount > 0;

let runOutcome = "attack-not-completed";
if (attackSucceeded && fullResponse) {
	runOutcome = "breach-contained";
} else if (attackSucceeded && detected && reportCount > 0) {
	runOutcome = "breach-reported-uncontained";
} else if (attackSucceeded && detected) {
	runOutcome = "breach-detected-unreported";
} else if (attackSucceeded) {
	runOutcome = "breach-missed";
}

const result = {
	attackSucceeded,
	attackerGoalPassed: attackSucceeded,
	containmentCount,
	defensePassed: !attackSucceeded || fullResponse,
	detected,
	reportCount,
	response: "host-change-detection",
	runOutcome,
	scenario: scenario.id,
	schemaVersion: 1,
};

console.log(JSON.stringify(result, null, 2));
if (!result.defensePassed) {
	process.exitCode = 1;
}
