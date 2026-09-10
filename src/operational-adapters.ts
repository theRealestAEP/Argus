import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";

import { pruneIncidentReports } from "./alert-queue.js";
import { enqueueAlert } from "./alert-queue.js";
import { collectAgentRuntimeAlerts } from "./agent-events.js";
import {
	deliverPendingAgentMailReports,
	pollAgentMail,
	saveOperatorMessages,
} from "./agent-mail.js";
import type { Alert } from "./contracts.js";
import { recordEvidence } from "./evidence-store.js";
import { collectSensorAlerts } from "./linux-sensors.js";
import { collectLinuxAuditAlerts } from "./linux-audit.js";
import { collectMacosAlerts } from "./macos-eslogger.js";
import { collectInvestigationEvidence } from "./investigation-tools.js";
import {
	INVESTIGATION_TOOL_NAMES,
	investigateDirect,
	investigateWithSubagent,
} from "./model-runtime.js";
import { readPolicy } from "./onboarding.js";
import type { OperationalServices } from "./operational-loop.js";
import { statePaths } from "./paths.js";
import { dueReviewAlert } from "./review-schedule.js";
import { archiveIncidentReports } from "./s3-archive.js";

const receiptSummarySchema = z.object({
	action: z.string().min(1),
	appliedAt: z.iso.datetime(),
	target: z.string().min(1),
});

async function collectAlerts(root: string): Promise<Alert[]> {
	const paths = statePaths(root);
	const alerts = existsSync(paths.sensorConfig) ? collectSensorAlerts(root) : [];
	const policy = readPolicy(root);
	const auditAlerts = collectLinuxAuditAlerts(root, policy);
	const macosAlerts = process.platform === "darwin" ? collectMacosAlerts(root, policy) : [];
	const agentAlerts = collectAgentRuntimeAlerts(root, policy, alerts);
	const messages = await pollAgentMail(root, policy, process.env.AGENTMAIL_API_KEY);
	saveOperatorMessages(root, messages);
	for (const message of messages) {
		recordEvidence(root, "operator.email.received", message.id);
	}
	const review = dueReviewAlert(root, policy.reviewSchedule);
	const collected = [...alerts, ...auditAlerts, ...macosAlerts, ...agentAlerts];
	return review === null ? collected : [...collected, review];
}

export function collectUrgentHostAlerts(root: string): void {
	const policy = readPolicy(root);
	const alerts = process.platform === "darwin"
		? collectMacosAlerts(root, policy)
		: collectLinuxAuditAlerts(root, policy);
	for (const alert of alerts) {
		enqueueAlert(root, alert);
		recordEvidence(root, "alert.queued", `${alert.kind}:${alert.id}`);
	}
}

async function deliverReports(root: string): Promise<void> {
	const policy = readPolicy(root);
	await deliverPendingAgentMailReports(
		root,
		policy,
		process.env.AGENTMAIL_API_KEY,
	);
	await archiveIncidentReports(root, policy);
	pruneIncidentReports(root, policy.retentionDays);
}

function verifiedContainment(root: string, alert: Alert): string | null {
	const requested = alert.evidence.filter((item) => item.startsWith("containment-requested:"));
	if (requested.length === 0) {
		return null;
	}
	const receipts = matchingContainmentReceipts(root, alert);
	const verified = receipts.map((receipt) =>
		`Argus applied ${receipt.action} to ${receipt.target} at ${receipt.appliedAt}.`
	);
	if (verified.length > 0) {
		return `\n\n### Verified response\n${verified.join("\n")}\nThe privileged broker recorded each receipt.`;
	}
	return "\n\n### Response status\nArgus requested containment. A broker receipt was not available when this report was written.";
}

function matchingContainmentReceipts(root: string, alert: Alert) {
	const requestedTargets = alert.evidence
		.filter((item) => item.startsWith("containment-requested:"))
		.map((item) => item.split(":").slice(2).join(":"));
	return readdirSync(statePaths(root).containmentReceipts).map((name) =>
		receiptSummarySchema.parse(JSON.parse(readFileSync(
			join(statePaths(root).containmentReceipts, name),
			"utf8",
		))),
	).filter((receipt) => requestedTargets.includes(receipt.target));
}

async function investigateAlert(root: string, alert: Alert) {
	if ([
		"credential-access",
		"kernel-integrity-change",
		"malware-detected",
		"persistence-change",
		"process-tampering",
		"remote-login",
		"service-command-shell",
		"service-stopped",
	].includes(alert.kind)) {
		const toolEvidence = collectInvestigationEvidence(
			root,
			alert,
			[...INVESTIGATION_TOOL_NAMES],
		);
		const containmentReceipts = matchingContainmentReceipts(root, alert);
		return investigateDirect(JSON.stringify({ alert, containmentReceipts, toolEvidence }));
	}
	let result = await investigateWithSubagent(JSON.stringify({ alert }));
	if (result.decision.evidenceRequests.length > 0) {
		const toolEvidence = collectInvestigationEvidence(
			root,
			alert,
			result.decision.evidenceRequests,
		);
		result = await investigateWithSubagent(JSON.stringify({ alert, toolEvidence }));
	}
	return result;
}

export function operationalServices(): OperationalServices {
	return {
		canInvestigate: () => (process.env.OPENAI_API_KEY ?? "").length > 0,
		collectAlerts,
		deliverReports,
		async investigate(root, alert) {
			const result = await investigateAlert(root, alert);
			const response = verifiedContainment(root, alert) ?? "";
			return { model: result.model, report: `${result.report}${response}` };
		},
	};
}
