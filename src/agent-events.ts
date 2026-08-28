import { randomUUID } from "node:crypto";
import { mkdirSync, readFileSync, readdirSync, renameSync } from "node:fs";
import { basename, join } from "node:path";

import { requestAutomaticContainment } from "./containment-broker.js";
import type { ProcessIdentity } from "./containment.js";
import type { Alert, AgentRuntimeEvent, OnboardingPolicy } from "./contracts.js";
import { agentRuntimeEventSchema } from "./contracts.js";
import { recordEvidence } from "./evidence-store.js";
import { nativeContainmentGateway } from "./linux-containment-native.js";
import { statePaths } from "./paths.js";

export interface AgentProcessInspector {
	command(pid: number): string;
	identity(pid: number): ProcessIdentity;
}

function nativeProcessInspector(): AgentProcessInspector {
	return {
		command: (pid) => readFileSync(`/proc/${pid}/cmdline`, "utf8"),
		identity: (pid) => nativeContainmentGateway().processIdentity(pid),
	};
}

function confirmsTarget(alerts: Alert[], target: string): boolean {
	return alerts.some((alert) =>
		alert.kind === "critical-file-change" &&
		alert.evidence.some((item) => item.startsWith(`${target}:`))
	);
}

function approvedRuntime(
	policy: OnboardingPolicy,
	event: AgentRuntimeEvent,
	inspector: AgentProcessInspector,
): boolean {
	if (!policy.approvedAgentRuntimes.includes(event.runtime)) {
		return false;
	}
	try {
		const command = inspector.command(event.pid);
		return command.includes(event.runtime);
	} catch {
		return false;
	}
}

function pauseTarget(event: AgentRuntimeEvent, inspector: AgentProcessInspector): string {
	const identity = inspector.identity(event.pid);
	return `pid=${identity.pid},start=${identity.startTimeTicks},path=${identity.executable}`;
}

function processAction(policy: OnboardingPolicy): "pause-process" | "terminate-process" {
	return policy.automaticProcessTermination === true
		? "terminate-process"
		: "pause-process";
}

function requestProcessContainment(
	root: string,
	policy: OnboardingPolicy,
	event: AgentRuntimeEvent,
	sensorAlerts: Alert[],
	inspector: AgentProcessInspector,
): void {
	if (
		policy.responseMode !== "autonomous-action" ||
		!approvedRuntime(policy, event, inspector) ||
		!confirmsTarget(sensorAlerts, event.target)
	) {
		return;
	}
	try {
		requestAutomaticContainment(root, {
			action: processAction(policy),
			evidence: [event.id, event.action, event.target],
			reason: "An approved agent recorded an independently confirmed unauthorized action.",
			target: pauseTarget(event, inspector),
		});
		recordEvidence(root, "containment.requested", event.id);
	} catch (error) {
		const detail = error instanceof Error ? error.message : "Containment request failed.";
		recordEvidence(root, "containment.request.failed", detail);
	}
}

function eventAlert(event: AgentRuntimeEvent, now: Date): Alert {
	return {
		createdAt: now.toISOString(),
		evidence: [
			`runtime:${event.runtime}`,
			`pid:${event.pid}`,
			`action:${event.action}`,
			`target:${event.target}`,
		],
		id: randomUUID(),
		kind: "agent-policy-violation",
		severity: "high",
		summary: `The approved agent ${event.runtime} recorded an unauthorized action.`,
	};
}

function rejectedEventAlert(name: string, detail: string, now: Date): Alert {
	return {
		createdAt: now.toISOString(),
		evidence: [`file:${name}`, detail],
		id: randomUUID(),
		kind: "agent-event-integrity-failure",
		severity: "critical",
		summary: "Argus rejected a malformed agent runtime event.",
	};
}

export function collectAgentRuntimeAlerts(
	root: string,
	policy: OnboardingPolicy,
	sensorAlerts: Alert[],
	now = new Date(),
	inspector: AgentProcessInspector = nativeProcessInspector(),
): Alert[] {
	const paths = statePaths(root);
	mkdirSync(paths.agentEvents, { mode: 0o700, recursive: true });
	mkdirSync(paths.agentEventsProcessed, { mode: 0o700, recursive: true });
	mkdirSync(paths.agentEventsRejected, { mode: 0o700, recursive: true });
	const alerts: Alert[] = [];
	const handled = new Set<string>();
	for (const name of readdirSync(paths.agentEvents).filter((item) => item.endsWith(".json"))) {
		const path = join(paths.agentEvents, name);
		let event: AgentRuntimeEvent;
		try {
			event = agentRuntimeEventSchema.parse(JSON.parse(readFileSync(path, "utf8")));
		} catch (error) {
			const detail = error instanceof Error ? error.message : "Invalid agent event.";
			renameSync(path, join(paths.agentEventsRejected, basename(path)));
			recordEvidence(root, "agent.event.rejected", `${name}:${detail}`);
			alerts.push(rejectedEventAlert(name, detail, now));
			continue;
		}
		const key = `${event.runtime}:${event.pid}:${event.action}:${event.target}`;
		if (!handled.has(key)) {
			handled.add(key);
			requestProcessContainment(root, policy, event, sensorAlerts, inspector);
			alerts.push(eventAlert(event, now));
		}
		renameSync(path, join(paths.agentEventsProcessed, basename(path)));
	}
	return alerts;
}
