import { randomUUID } from "node:crypto";
import { mkdtempSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "vitest";

import { collectAgentRuntimeAlerts } from "../src/agent-events.js";
import { bootstrap } from "../src/bootstrap.js";
import { processBrokerRequests } from "../src/containment-broker.js";
import type { ContainmentGateway } from "../src/containment.js";
import type { Alert, OnboardingAnswers } from "../src/contracts.js";
import { statePaths } from "../src/paths.js";

function agentState(runtime: string, automaticProcessTermination = false) {
	const root = mkdtempSync(join(tmpdir(), "argus-agent-event-test-"));
	const answers: OnboardingAnswers = {
		adminContact: "local-only",
		agentMailInbox: null,
		automaticProcessTermination,
		approvedAgentRuntimes: [runtime],
		criticalPaths: ["/opt/protected"],
		devicePurpose: "agent event test",
		expectedServices: [],
		maintenanceWindow: "Sunday 02:00",
		responseMode: "autonomous-action",
		retentionDays: 30,
		reviewSchedule: "weekly",
	};
	bootstrap(root, answers);
	return { answers, root };
}

function fileAlert(target: string): Alert {
	return {
		createdAt: "2026-01-01T00:00:00.000Z",
		evidence: [`${target}:12:1000`],
		id: randomUUID(),
		kind: "critical-file-change",
		severity: "high",
		summary: "A critical file changed.",
	};
}

describe("agent runtime events", () => {
	test("requests and applies a reversible process pause after independent confirmation", () => {
		const runtime = "test-agent";
		const { answers, root } = agentState(runtime);
		const paths = statePaths(root);
		const target = "/opt/protected/changed.json";
		const event = {
			action: "unauthorized-file-write",
			id: randomUUID(),
			observedAt: "2026-01-01T00:00:00.000Z",
			pid: process.pid,
			runtime,
			target,
		};
		writeFileSync(join(paths.agentEvents, `${event.id}.json`), JSON.stringify(event));
		const duplicate = { ...event, id: randomUUID() };
		writeFileSync(join(paths.agentEvents, `${duplicate.id}.json`), JSON.stringify(duplicate));
		const manifest = bootstrap(root, answers);
		const policy = { ...answers, createdAt: manifest.createdAt };

		const identity = { executable: "/bin/test-agent", pid: process.pid, startTimeTicks: "10" };
		const inspector = {
			command: () => "/bin/test-agent --serve",
			identity: () => identity,
		};
		const alerts = collectAgentRuntimeAlerts(
			root,
			policy,
			[fileAlert(target)],
			new Date("2026-01-01T00:00:00.000Z"),
			inspector,
		);
		expect(alerts).toHaveLength(1);
		expect(readdirSync(paths.brokerRequests)).toHaveLength(2);
		expect(readdirSync(paths.agentEventsProcessed)).toHaveLength(2);

		let paused = 0;
		const gateway: ContainmentGateway = {
			pause: (pid) => {
				paused = pid;
			},
			processIdentity: () => identity,
			runNft: () => undefined,
			terminate: () => undefined,
		};
		expect(processBrokerRequests(root, 0, gateway)).toHaveLength(1);
		expect(paused).toBe(process.pid);
	});

	test("keeps unconfirmed events out of automatic containment", () => {
		const { answers, root } = agentState("node");
		const paths = statePaths(root);
		const event = {
			action: "unauthorized-file-write",
			id: randomUUID(),
			observedAt: "2026-01-01T00:00:00.000Z",
			pid: process.pid,
			runtime: "node",
			target: "/opt/protected/changed.json",
		};
		writeFileSync(join(paths.agentEvents, `${event.id}.json`), JSON.stringify(event));
		const manifest = bootstrap(root, answers);
		const policy = { ...answers, createdAt: manifest.createdAt };

		expect(collectAgentRuntimeAlerts(root, policy, [])).toHaveLength(1);
		expect(readdirSync(paths.brokerRequests)).toEqual([]);
	});

	test("terminates a confirmed process when setup permits it", () => {
		const runtime = "test-agent";
		const { answers, root } = agentState(runtime, true);
		const paths = statePaths(root);
		const target = "/opt/protected/changed.json";
		const event = {
			action: "unauthorized-file-write",
			id: randomUUID(),
			observedAt: "2026-01-01T00:00:00.000Z",
			pid: process.pid,
			runtime,
			target,
		};
		writeFileSync(join(paths.agentEvents, `${event.id}.json`), JSON.stringify(event));
		const manifest = bootstrap(root, answers);
		const policy = { ...answers, createdAt: manifest.createdAt };
		const identity = { executable: "/bin/test-agent", pid: process.pid, startTimeTicks: "10" };
		const inspector = {
			command: () => "/bin/test-agent --serve",
			identity: () => identity,
		};
		collectAgentRuntimeAlerts(root, policy, [fileAlert(target)], new Date(), inspector);

		let terminated = 0;
		const gateway: ContainmentGateway = {
			pause: () => undefined,
			processIdentity: () => identity,
			runNft: () => undefined,
			terminate: (pid) => {
				terminated = pid;
			},
		};
		expect(processBrokerRequests(root, 0, gateway)).toHaveLength(1);
		expect(terminated).toBe(process.pid);
	});

	test("records a failed process identity check", () => {
		const runtime = "test-agent";
		const { answers, root } = agentState(runtime);
		const paths = statePaths(root);
		const target = "/opt/protected/changed.json";
		const event = {
			action: "unauthorized-file-write",
			id: randomUUID(),
			observedAt: "2026-01-01T00:00:00.000Z",
			pid: 42,
			runtime,
			target,
		};
		writeFileSync(join(paths.agentEvents, `${event.id}.json`), JSON.stringify(event));
		const manifest = bootstrap(root, answers);
		const policy = { ...answers, createdAt: manifest.createdAt };

		collectAgentRuntimeAlerts(
			root,
			policy,
			[fileAlert(target)],
			new Date("2026-01-01T00:00:00.000Z"),
			{
				command: () => "/bin/test-agent --serve",
				identity: () => {
					throw new Error("process exited");
				},
			},
		);
		expect(readdirSync(paths.brokerRequests)).toEqual([]);
	});

	test("quarantines a malformed event and continues collection", () => {
		const { answers, root } = agentState("test-agent");
		const paths = statePaths(root);
		writeFileSync(join(paths.agentEvents, "malformed.json"), "{\"id\":\"bad\"}\nextra");
		const manifest = bootstrap(root, answers);
		const policy = { ...answers, createdAt: manifest.createdAt };

		expect(collectAgentRuntimeAlerts(root, policy, [])).toMatchObject([{
			kind: "agent-event-integrity-failure",
			severity: "critical",
		}]);
		expect(readdirSync(paths.agentEvents)).toEqual([]);
		expect(readdirSync(paths.agentEventsRejected)).toEqual(["malformed.json"]);
		expect(readdirSync(paths.brokerRequests)).toEqual([]);
	});
});
