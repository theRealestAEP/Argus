import { isIP } from "node:net";
import { randomUUID } from "node:crypto";
import { join } from "node:path";

import type { ContainmentPlan, OnboardingPolicy } from "./contracts.js";
import { containmentPlanSchema } from "./contracts.js";
import { jsonText, writePrivate } from "./files.js";
import { statePaths } from "./paths.js";
import { nativeContainmentGateway } from "./linux-containment-native.js";

export type ContainmentDecision = "allowed" | "approval-required" | "report-only";

export interface ProcessIdentity {
	executable: string;
	pid: number;
	startTimeTicks: string;
}

export interface ContainmentGateway {
	pause(pid: number): void;
	processIdentity(pid: number): ProcessIdentity;
	runNft(args: string[], ignoreFailure: boolean): void;
	terminate(pid: number): void;
}

export interface ContainmentReceipt {
	action: ContainmentPlan["action"];
	appliedAt: string;
	id: string;
	rollback: string;
	target: string;
}

export function authorizeContainment(
	policy: OnboardingPolicy,
	plan: ContainmentPlan,
): ContainmentDecision {
	containmentPlanSchema.parse(plan);
	if (policy.responseMode === "report-only") {
		return "report-only";
	}
	if (plan.action === "terminate-process") {
		return policy.responseMode === "autonomous-action" &&
			policy.automaticProcessTermination === true
			? "allowed"
			: "approval-required";
	}
	return policy.responseMode === "autonomous-action"
		? "allowed"
		: "approval-required";
}

function processTarget(target: string): ProcessIdentity {
	const match = /^pid=(\d+),start=(\d+),path=(.+)$/u.exec(target);
	if (match === null) {
		throw new Error("Use pid=N,start=TICKS,path=PATH for a process target.");
	}
	return {
		executable: match[3] ?? "",
		pid: Number.parseInt(match[1] ?? "", 10),
		startTimeTicks: match[2] ?? "",
	};
}

function ensureNftables(gateway: ContainmentGateway): void {
	gateway.runNft(["add", "table", "inet", "argus"], true);
	gateway.runNft(
		["add", "set", "inet", "argus", "blocked_ipv4", "{", "type", "ipv4_addr", ";", "}"],
		true,
	);
	gateway.runNft(
		[
			"add", "chain", "inet", "argus", "output", "{", "type", "filter", "hook",
			"output", "priority", "-10", ";", "policy", "accept", ";", "}",
		],
		true,
	);
	gateway.runNft(
		["add", "rule", "inet", "argus", "output", "ip", "daddr", "@blocked_ipv4", "reject"],
		true,
	);
	gateway.runNft(["list", "chain", "inet", "argus", "output"], false);
}

function blockDestination(
	target: string,
	gateway: ContainmentGateway,
): string {
	if (isIP(target) !== 4) {
		throw new Error("The first containment backend accepts one IPv4 address.");
	}
	ensureNftables(gateway);
	gateway.runNft(
		["add", "element", "inet", "argus", "blocked_ipv4", "{", target, "}"],
		false,
	);
	return `nft delete element inet argus blocked_ipv4 { ${target} }`;
}

function terminateProcess(
	targetText: string,
	gateway: ContainmentGateway,
): string {
	const target = processTarget(targetText);
	const current = gateway.processIdentity(target.pid);
	if (
		current.startTimeTicks !== target.startTimeTicks ||
		current.executable !== target.executable
	) {
		throw new Error("The process identity changed. Containment stopped.");
	}
	gateway.terminate(target.pid);
	return "Process termination has no rollback command.";
}

function pauseProcess(
	targetText: string,
	gateway: ContainmentGateway,
): string {
	const target = processTarget(targetText);
	const current = gateway.processIdentity(target.pid);
	if (
		current.startTimeTicks !== target.startTimeTicks ||
		current.executable !== target.executable
	) {
		throw new Error("The process identity changed. Containment stopped.");
	}
	gateway.pause(target.pid);
	return `kill -CONT ${target.pid}`;
}

export function applyContainment(
	root: string,
	policy: OnboardingPolicy,
	plan: ContainmentPlan,
	effectiveUserId: number,
	gateway: ContainmentGateway = nativeContainmentGateway(),
	now = new Date(),
): ContainmentReceipt {
	const parsed = containmentPlanSchema.parse(plan);
	const decision = authorizeContainment(policy, parsed);
	if (decision === "report-only") {
		throw new Error("The operating policy permits reports only.");
	}
	if (effectiveUserId !== 0) {
		throw new Error("Native administrator authorization is required for containment.");
	}
	let rollback: string;
	if (parsed.action === "block-destination") {
		rollback = blockDestination(parsed.target, gateway);
	} else if (parsed.action === "pause-process") {
		rollback = pauseProcess(parsed.target, gateway);
	} else {
		rollback = terminateProcess(parsed.target, gateway);
	}
	const receipt: ContainmentReceipt = {
		action: parsed.action,
		appliedAt: now.toISOString(),
		id: randomUUID(),
		rollback,
		target: parsed.target,
	};
	writePrivate(
		join(statePaths(root).containmentReceipts, `${receipt.appliedAt}-${receipt.id}.json`),
		jsonText(receipt),
	);
	return receipt;
}
