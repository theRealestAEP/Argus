import { completeAlert, claimAlert, enqueueAlert, retryAlert, saveIncidentReport } from "./alert-queue.js";
import type { Alert } from "./contracts.js";
import { recordEvidence } from "./evidence-store.js";
import { operationalServices } from "./operational-adapters.js";

export type InvestigationOutput = {
	model: string;
	report: string;
};

export interface OperationalServices {
	canInvestigate(): boolean;
	collectAlerts(root: string): Promise<Alert[]>;
	deliverReports(root: string): Promise<void>;
	investigate(root: string, alert: Alert): Promise<InvestigationOutput>;
}

async function stage(root: string, name: string, action: () => Promise<void>): Promise<void> {
	try {
		await action();
	} catch (error) {
		const detail = error instanceof Error ? error.message : "Invalid stage error";
		recordEvidence(root, `stage.${name}.failed`, detail);
	}
}

function queueAlerts(root: string, alerts: Alert[]): void {
	for (const alert of alerts) {
		enqueueAlert(root, alert);
		recordEvidence(root, "alert.queued", `${alert.kind}:${alert.id}`);
	}
}

async function investigateNext(
	root: string,
	services: OperationalServices,
): Promise<void> {
	if (!services.canInvestigate()) {
		return;
	}
	const claimed = claimAlert(root);
	if (claimed === null) {
		return;
	}
	try {
		const result = await services.investigate(root, claimed.alert);
		saveIncidentReport(root, claimed.alert.id, result.model, result.report);
		completeAlert(claimed);
		recordEvidence(root, "alert.investigated", claimed.alert.id);
	} catch (error) {
		retryAlert(root, claimed);
		throw error;
	}
}

export async function runOperationalCycle(
	root: string,
	services: OperationalServices = operationalServices(),
): Promise<void> {
	await stage(root, "collect", async () => queueAlerts(root, await services.collectAlerts(root)));
	await stage(root, "investigate", () => investigateNext(root, services));
	await stage(root, "deliver", () => services.deliverReports(root));
}
