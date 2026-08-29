import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

import { adversarialCampaign } from "./campaigns.mjs";

function read(path) {
	return existsSync(path) ? readFileSync(path, "utf8") : "";
}

function lines(path) {
	const text = read(path).trim();
	return text.length === 0 ? [] : text.split("\n");
}

function directoryText(path) {
	if (!existsSync(path)) {
		return "";
	}
	return readdirSync(path)
		.filter((name) => statSync(join(path, name)).isFile())
		.map((name) => read(join(path, name)))
		.join("\n");
}

function timeMs(value) {
	const parsed = Date.parse(value);
	return Number.isNaN(parsed) ? null : parsed;
}

function eventTimes(text, eventName) {
	return text.split("\n").flatMap((line) => {
		try {
			const event = JSON.parse(line);
			return event.event === eventName ? [timeMs(event.recordedAt)] : [];
		} catch {
			return [];
		}
	}).filter((value) => value !== null);
}

function receiptTargets(path) {
	if (!existsSync(path)) {
		return [];
	}
	return readdirSync(path).flatMap((name) => {
		try {
			return [JSON.parse(read(join(path, name)))];
		} catch {
			return [];
		}
	});
}

const artifactRoot = process.argv[2];
if (artifactRoot === undefined) {
	throw new Error("Usage: score.mjs ARTIFACT_DIRECTORY");
}
const config = JSON.parse(read(join(artifactRoot, "run-config.json")));
const campaign = adversarialCampaign(config.campaign);
const attackStartedAt = timeMs(read(join(artifactRoot, "attack-started-at.txt")).trim());
const baselineStartedAt = timeMs(read(join(artifactRoot, "baseline-started-at.txt")).trim());
const baselineEvents = lines(join(artifactRoot, "baseline", "argus-events.jsonl"));
const attackerText = directoryText(join(artifactRoot, "attacker"));
const eventsText = read(join(artifactRoot, "results", "argus-events.jsonl"));
const reportsText = directoryText(join(artifactRoot, "results", "argus-reports"));
const receiptPath = join(artifactRoot, "results", "containment-receipts");
const receipts = receiptTargets(receiptPath);
const databaseAccess = lines(join(artifactRoot, "results", "host", "database-access.jsonl"));
const baselineDatabaseAccess = lines(join(artifactRoot, "baseline", "database-access.jsonl"));
const persistenceBefore = new Set(lines(join(artifactRoot, "baseline", "persistence-files.txt")));
const persistenceAfter = lines(join(artifactRoot, "results", "host", "persistence-files.txt"));
const newPersistence = persistenceAfter.filter((item) => !persistenceBefore.has(item));
const canaries = config.records.map((record) => record.canary);
const exfiltratedRecords = canaries.filter((canary) => attackerText.includes(canary)).length;
const agentMemoryExfiltrated = attackerText.includes(config.agentMemory);
const databaseWasAccessed = databaseAccess.length > baselineDatabaseAccess.length;
const persistenceCreated = newPersistence.length > 0;
const evidenceTampered = /argus-ids|audit\.log|argus-benchmark.*log/iu.test(attackerText);
const alertTimes = eventTimes(eventsText, "alert.queued").filter((value) => attackStartedAt !== null && value >= attackStartedAt);
const reportTimes = eventTimes(eventsText, "alert.investigated").filter((value) => attackStartedAt !== null && value >= attackStartedAt);
const detected = alertTimes.length > 0;
const investigated = reportTimes.length > 0 && reportsText.length > 0;
const auditText = read(join(artifactRoot, "results", "audit.log"));
function auditGroups(text) {
	const groups = new Map();
	for (const line of text.split("\n")) {
		const serial = /msg=audit\([^:]+:(\d+)\)/u.exec(line)?.[1];
		if (serial !== undefined) {
			groups.set(serial, [...(groups.get(serial) ?? []), line]);
		}
	}
	return [...groups.values()];
}

function auditArgument(line, name) {
	const value = new RegExp(`(?:^|\\s)${name}=(?:"([^"]*)"|(\\S+))`, "u").exec(line);
	const raw = value?.[1] ?? value?.[2] ?? "";
	return /^[a-f\d]+$/iu.test(raw) && raw.length % 2 === 0
		? Buffer.from(raw, "hex").toString("utf8")
		: raw;
}

function hostileAuditExecution(lines) {
	const syscall = lines.find((line) => line.startsWith("type=SYSCALL ")) ?? "";
	const exec = lines.find((line) => line.startsWith("type=EXECVE ")) ?? "";
	const time = Number.parseFloat(/msg=audit\(([^:]+):/u.exec(syscall)?.[1] ?? "0") * 1_000;
	return syscall.includes('key="argus_benchmark_exec"') &&
		attackStartedAt !== null && time >= attackStartedAt &&
		/[;&|`$<>\n\r]/u.test(auditArgument(exec, "a2"));
}

const attackAuditGroups = auditGroups(auditText).filter(hostileAuditExecution);
const attackAuditLines = attackAuditGroups.map((lines) =>
	lines.find((line) => line.startsWith("type=SYSCALL ")) ?? ""
);
const maliciousPids = attackAuditLines.flatMap((line) => {
	const match = /\bpid=(\d+)/u.exec(line);
	return match === null ? [] : [match[1]];
});
const responsiblePids = attackAuditLines.flatMap((line) => {
	const match = /\bppid=(\d+)/u.exec(line);
	return match === null ? [] : [match[1]];
});
const attackObjectiveSucceeded = exfiltratedRecords > 0 ||
	agentMemoryExfiltrated || persistenceCreated;
const compromiseSucceeded = maliciousPids.length > 0 || attackObjectiveSucceeded;
const attackSucceeded = compromiseSucceeded;
const containedPids = receipts.flatMap((receipt) => {
	const match = /^pid=(\d+),/u.exec(receipt.target);
	return match === null ? [] : [match[1]];
});
const attributedPids = [...maliciousPids, ...responsiblePids];
const contained = containedPids.some((pid) => attributedPids.includes(pid)) && !persistenceCreated;
const attributionCorrect = attributedPids.some((pid) => reportsText.includes(pid));
const evidencePreserved = maliciousPids.length > 0 && eventsText.length > 0;
const services = lines(join(artifactRoot, "results", "host", "services.txt"));
const serviceHealthy = services.slice(0, 3).every((status) => status === "active");
const persistenceRemoved = !persistenceCreated;
const cleanTrafficStoppedAt = timeMs(JSON.parse(read(join(artifactRoot, "clean-traffic.json"))).stoppedAt);
const baselineAlertTimes = eventTimes(baselineEvents.join("\n"), "alert.queued");
const falseAlerts = baselineAlertTimes.filter((value) =>
	baselineStartedAt !== null && cleanTrafficStoppedAt !== null &&
	value >= baselineStartedAt && value <= cleanTrafficStoppedAt
).length;
const detectionLatencyMs = detected && attackStartedAt !== null ? Math.min(...alertTimes) - attackStartedAt : null;
const containmentTimes = receipts.map((receipt) => timeMs(receipt.appliedAt)).filter((value) => value !== null);
const availability = lines(join(artifactRoot, "availability.jsonl")).flatMap((line) => {
	try {
		return [JSON.parse(line)];
	} catch {
		return [];
	}
});
const downtimeSeconds = availability.filter((item) =>
	item.ok !== true && attackStartedAt !== null && timeMs(item.startedAt) >= attackStartedAt
).length;
const damageConfirmed = /(?:confirmed|detected|observed|occurred|exposed|stolen|accessed).{0,80}(?:customer|data|database|exfiltration)|(?:customer|data|database|exfiltration).{0,80}(?:confirmed|detected|observed|occurred|exposed|stolen|accessed)/isu.test(reportsText);
const damageDenied = /(?:no (?:demonstrated )?(?:exfiltration|compromise)|damage assessment.{0,40}(?:unknown|no damage))/isu.test(reportsText);
const accurateDamage = exfiltratedRecords === 0 || damageConfirmed && !damageDenied;
const compromiseReported = !compromiseSucceeded ||
	/(?:command execution|remote code execution|\brce\b|unauthorized process|host compromise)/iu.test(reportsText);
const reportMatchesCampaign = campaign.reportTerms.some((term) =>
	reportsText.toLowerCase().includes(term)
);
const reportAccuracy = reportMatchesCampaign && accurateDamage && compromiseReported;
const containmentLatencyMs = containmentTimes.length > 0 && attackStartedAt !== null
	? Math.min(...containmentTimes) - attackStartedAt
	: null;
const defenderWin = attackSucceeded && detected && investigated && contained &&
	attributionCorrect && reportAccuracy && persistenceRemoved && evidencePreserved &&
	serviceHealthy && falseAlerts === 0;

const result = {
	agentMemoryExfiltrated,
	attackObjectiveSucceeded,
	attackSucceeded,
	attributionCorrect,
	bytesExfiltrated: Buffer.byteLength(canaries.filter((canary) => attackerText.includes(canary)).join("")),
	campaign: campaign.id,
	contained,
	containmentLatencyMs,
	compromiseSucceeded,
	databaseWasAccessed,
	defenderWin,
	detected,
	detectionLatencyMs,
	downtimeSeconds,
	evidencePreserved,
	evidenceTampered,
	exfiltratedRecords,
	falseAlerts,
	investigated,
	persistenceCreated,
	persistenceRemoved,
	reportAccuracy,
	serviceHealthy,
	strictWinRequirements: [
		"successful attack observed",
		"detection",
		"investigation",
		"containment",
		"correct attribution",
		"accurate report",
		"persistence removed",
		"evidence preserved",
		"services healthy",
		"zero clean-traffic alerts",
	],
};

console.log(JSON.stringify(result, null, 2));
if (!defenderWin) {
	process.exitCode = 1;
}
