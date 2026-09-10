import { isIP } from "node:net";
import { randomUUID } from "node:crypto";
import { basename, join } from "node:path";

import type { ContainmentPlan, OnboardingPolicy } from "./contracts.js";
import { containmentPlanSchema } from "./contracts.js";
import { jsonText, writePrivate } from "./files.js";
import { statePaths } from "./paths.js";
import { nativeContainmentGateway } from "./native-containment.js";

export type ContainmentDecision = "allowed" | "approval-required" | "report-only";

export interface ProcessIdentity {
	executable: string;
	pid: number;
	startTimeTicks: string;
}

export interface ContainmentGateway {
	fileMode?(path: string): number;
	pause(pid: number): void;
	processIdentity(pid: number): ProcessIdentity;
	quarantine?(source: string, destination: string): void;
	runNft(args: string[], ignoreFailure: boolean): void;
	setFileMode?(path: string, mode: number): void;
	startService?(unit: string): string | void;
	terminate(pid: number): void;
}

const PERSISTENCE_PATHS = [
	/^\/etc\/cron\.d\/[A-Za-z0-9_.@-]+$/u,
	/^\/etc\/profile\.d\/[A-Za-z0-9_.@-]+\.sh$/u,
	/^\/etc\/systemd\/system\/[A-Za-z0-9_.@-]+\.(?:path|service|socket|target|timer)$/u,
	/^\/(?:root|home\/[A-Za-z0-9_.@-]+)\/(?:\.bashrc|\.profile|\.ssh\/authorized_keys)$/u,
	/^\/Library\/LaunchAgents\/[A-Za-z0-9_.@-]+\.plist$/u,
	/^\/Library\/LaunchDaemons\/[A-Za-z0-9_.@-]+\.plist$/u,
	/^\/Library\/PrivilegedHelperTools\/[A-Za-z0-9_.@-]+$/u,
	/^\/Users\/[A-Za-z0-9_.@-]+\/Library\/LaunchAgents\/[A-Za-z0-9_.@-]+\.plist$/u,
	/^\/Users\/[A-Za-z0-9_.@-]+\/(?:\.bash_profile|\.bashrc|\.profile|\.zprofile|\.zshrc|\.ssh\/authorized_keys)$/u,
];

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
	const identity = {
		executable: match[3] ?? "",
		pid: Number.parseInt(match[1] ?? "", 10),
		startTimeTicks: match[2] ?? "",
	};
	if (identity.pid === 1) {
		throw new Error("Argus will not pause or terminate the init process.");
	}
	return identity;
}

function ensureNftables(gateway: ContainmentGateway): void {
	gateway.runNft(["add", "table", "inet", "argus"], true);
	gateway.runNft(
		["add", "set", "inet", "argus", "blocked_ipv4", "{", "type", "ipv4_addr", ";", "}"],
		true,
	);
	gateway.runNft(
		["add", "set", "inet", "argus", "blocked_uids", "{", "type", "uid", ";", "}"],
		true,
	);
	gateway.runNft(
		[
			"add", "chain", "inet", "argus", "output", "{", "type", "filter", "hook",
			"output", "priority", "-10", ";", "policy", "accept", ";", "}",
		],
		true,
	);
	gateway.runNft(["flush", "chain", "inet", "argus", "output"], false);
	gateway.runNft(
		["add", "rule", "inet", "argus", "output", "ct", "direction", "reply", "accept"],
		true,
	);
	gateway.runNft(
		["add", "rule", "inet", "argus", "output", "ip", "daddr", "@blocked_ipv4", "reject"],
		true,
	);
	gateway.runNft(
		["add", "rule", "inet", "argus", "output", "meta", "skuid", "@blocked_uids", "reject"],
		true,
	);
	gateway.runNft(["list", "chain", "inet", "argus", "output"], false);
}

function blockUserEgress(target: string, gateway: ContainmentGateway): string {
	if (!/^\d+$/u.test(target)) {
		throw new Error("A user egress block requires one numeric user ID.");
	}
	ensureNftables(gateway);
	gateway.runNft(
		["add", "element", "inet", "argus", "blocked_uids", "{", target, "}"],
		false,
	);
	return `nft delete element inet argus blocked_uids { ${target} }`;
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

export function isPersistencePathAllowed(path: string): boolean {
	return path === "/etc/crontab" || path === "/etc/ld.so.preload" ||
		PERSISTENCE_PATHS.some((pattern) => pattern.test(path));
}

function shellQuote(value: string): string {
	return `'${value.replaceAll("'", `'"'"'`)}'`;
}

function quarantinePersistence(
	root: string,
	target: string,
	gateway: ContainmentGateway,
): string {
	if (!isPersistencePathAllowed(target)) {
		throw new Error("The persistence path is outside the broker allowlist.");
	}
	if (gateway.quarantine === undefined) {
		throw new Error("The containment backend cannot quarantine persistence.");
	}
	const destination = join(statePaths(root).quarantine, `${randomUUID()}-${basename(target)}`);
	gateway.quarantine(target, destination);
	return `mv -- ${shellQuote(destination)} ${shellQuote(target)}`;
}

function stripFilePrivileges(target: string, gateway: ContainmentGateway): string {
	if (!target.startsWith("/") || /[\n\r]/u.test(target)) {
		throw new Error("A privileged file target must be an absolute path.");
	}
	if (gateway.fileMode === undefined || gateway.setFileMode === undefined) {
		throw new Error("The containment backend cannot change file privileges.");
	}
	const oldMode = gateway.fileMode(target) & 0o7777;
	if ((oldMode & 0o6000) === 0) {
		throw new Error("The target has no set-user-ID or set-group-ID bit.");
	}
	gateway.setFileMode(target, oldMode & ~0o6000);
	return `chmod ${oldMode.toString(8).padStart(4, "0")} -- ${shellQuote(target)}`;
}

function startExpectedService(
	policy: OnboardingPolicy,
	target: string,
	gateway: ContainmentGateway,
): string {
	const safeTarget = /^[A-Za-z0-9_.@-]+\.service$/u.test(target) ||
		/^(?:system|gui\/\d+)\/[A-Za-z0-9_.@-]+$/u.test(target);
	if (!policy.expectedServices.includes(target) || !safeTarget) {
		throw new Error("The service is absent from the signed expected-service policy.");
	}
	if (gateway.startService === undefined) {
		throw new Error("The containment backend cannot start a service.");
	}
	const rollback = gateway.startService(target);
	return rollback ?? `systemctl stop -- ${shellQuote(target)}`;
}

function executePlan(
	root: string,
	policy: OnboardingPolicy,
	plan: ContainmentPlan,
	gateway: ContainmentGateway,
): string {
	const actions = {
		"block-destination": () => blockDestination(plan.target, gateway),
		"block-user-egress": () => blockUserEgress(plan.target, gateway),
		"pause-process": () => pauseProcess(plan.target, gateway),
		"quarantine-persistence": () => quarantinePersistence(root, plan.target, gateway),
		"start-service": () => startExpectedService(policy, plan.target, gateway),
		"strip-file-privileges": () => stripFilePrivileges(plan.target, gateway),
		"terminate-process": () => terminateProcess(plan.target, gateway),
	} satisfies Record<ContainmentPlan["action"], () => string>;
	return actions[plan.action]();
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
	const rollback = executePlan(root, policy, parsed, gateway);
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
		0o644,
	);
	return receipt;
}
