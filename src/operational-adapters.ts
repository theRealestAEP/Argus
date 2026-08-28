import { existsSync } from "node:fs";

import { pruneIncidentReports } from "./alert-queue.js";
import { collectAgentRuntimeAlerts } from "./agent-events.js";
import {
	deliverPendingAgentMailReports,
	pollAgentMail,
	saveOperatorMessages,
} from "./agent-mail.js";
import type { Alert } from "./contracts.js";
import { recordEvidence } from "./evidence-store.js";
import { collectSensorAlerts } from "./linux-sensors.js";
import { investigateWithSubagent } from "./model-runtime.js";
import { readPolicy } from "./onboarding.js";
import type { OperationalServices } from "./operational-loop.js";
import { statePaths } from "./paths.js";
import { dueReviewAlert } from "./review-schedule.js";
import { archiveIncidentReports } from "./s3-archive.js";

async function collectAlerts(root: string): Promise<Alert[]> {
	const paths = statePaths(root);
	const alerts = existsSync(paths.sensorConfig) ? collectSensorAlerts(root) : [];
	const policy = readPolicy(root);
	const agentAlerts = collectAgentRuntimeAlerts(root, policy, alerts);
	const messages = await pollAgentMail(root, policy, process.env.AGENTMAIL_API_KEY);
	saveOperatorMessages(root, messages);
	for (const message of messages) {
		recordEvidence(root, "operator.email.received", message.id);
	}
	const review = dueReviewAlert(root, policy.reviewSchedule);
	const collected = [...alerts, ...agentAlerts];
	return review === null ? collected : [...collected, review];
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

export function operationalServices(): OperationalServices {
	return {
		canInvestigate: () => (process.env.OPENAI_API_KEY ?? "").length > 0,
		collectAlerts,
		deliverReports,
		async investigate(alert) {
			const result = await investigateWithSubagent(JSON.stringify(alert));
			return { model: result.model, report: result.report };
		},
	};
}
