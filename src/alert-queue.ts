import { randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, renameSync, unlinkSync } from "node:fs";
import { basename, join } from "node:path";

import type { Alert, IncidentReport } from "./contracts.js";
import { alertSchema, incidentReportSchema } from "./contracts.js";
import { jsonText, writePrivate } from "./files.js";
import { statePaths } from "./paths.js";

export type ClaimedAlert = {
	alert: Alert;
	path: string;
};

export function enqueueAlert(root: string, alert: Alert): string {
	const parsed = alertSchema.parse(alert);
	const path = join(statePaths(root).alerts, `${parsed.createdAt}-${parsed.id}.json`);
	writePrivate(path, jsonText(parsed));
	return path;
}

export function claimAlert(root: string): ClaimedAlert | null {
	const paths = statePaths(root);
	mkdirSync(paths.alerts, { mode: 0o700, recursive: true });
	mkdirSync(paths.alertWorking, { mode: 0o700, recursive: true });
	const name = readdirSync(paths.alerts).toSorted().at(0);
	if (name === undefined) {
		return null;
	}
	const pendingPath = join(paths.alerts, name);
	const workingPath = join(paths.alertWorking, name);
	renameSync(pendingPath, workingPath);
	return {
		alert: alertSchema.parse(JSON.parse(readFileSync(workingPath, "utf8"))),
		path: workingPath,
	};
}

export function retryAlert(root: string, claimed: ClaimedAlert): void {
	renameSync(claimed.path, join(statePaths(root).alerts, basename(claimed.path)));
}

export function completeAlert(claimed: ClaimedAlert): void {
	unlinkSync(claimed.path);
}

export function saveIncidentReport(
	root: string,
	alert: Alert,
	model: string,
	report: string,
	now = new Date(),
): IncidentReport {
	const incident = incidentReportSchema.parse({
		alertId: alert.id,
		alertKind: alert.kind,
		createdAt: now.toISOString(),
		id: randomUUID(),
		model,
		report,
		severity: alert.severity,
	});
	writePrivate(join(statePaths(root).reports, `${incident.createdAt}-${incident.id}.json`), jsonText(incident));
	return incident;
}

function removeIfPresent(path: string): void {
	if (existsSync(path)) {
		unlinkSync(path);
	}
}

export function pruneIncidentReports(
	root: string,
	retentionDays: number,
	now = new Date(),
): number {
	const paths = statePaths(root);
	const cutoff = now.getTime() - retentionDays * 86_400_000;
	let removed = 0;
	for (const name of readdirSync(paths.reports)) {
		const reportPath = join(paths.reports, name);
		const report = incidentReportSchema.parse(JSON.parse(readFileSync(reportPath, "utf8")));
		if (Date.parse(report.createdAt) >= cutoff) {
			continue;
		}
		unlinkSync(reportPath);
		removeIfPresent(join(paths.mailReceipts, `${name}.json`));
		removeIfPresent(join(paths.archiveReceipts, `${name}.json`));
		removed += 1;
	}
	return removed;
}
