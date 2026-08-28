#!/usr/bin/env node

import { existsSync } from "node:fs";
import { join } from "node:path";
import { parseArgs } from "node:util";

import { checkAgentMail, configureAgentMailAllowlist } from "./agent-mail.js";
import { bootstrap, readInstallManifest } from "./bootstrap.js";
import { inspectCapabilities, saveCapabilityReport } from "./capabilities.js";
import type { CapabilityReport, OnboardingAnswers } from "./contracts.js";
import { onboardingPolicySchema } from "./contracts.js";
import { runDoctor } from "./doctor.js";
import { runDaemon } from "./daemon.js";
import { uninstallPlan } from "./lifecycle.js";
import { buildMemoryPack, verifyMemoryPack } from "./memory-pack.js";
import { askOnboardingQuestions, readPolicy, updatePolicy } from "./onboarding.js";
import { statePaths } from "./paths.js";
import {
	buildServicePlan,
	installService,
	uninstallService,
} from "./service.js";

const command = process.argv.at(2) ?? "help";
const parsedArguments = parseArgs({
	allowPositionals: false,
	args: process.argv.slice(3),
	options: {
		"admin-contact": { type: "string" },
		"agent-mail-inbox": { type: "string" },
		"approved-agent-runtimes": { type: "string", default: "none" },
		"critical-paths": { type: "string", default: "none" },
		"device-purpose": { type: "string" },
		"expected-services": { type: "string", default: "none" },
		"email-allowed-senders": { type: "string" },
		"email-report-recipients": { type: "string" },
		"log-cache-mb": { type: "string", default: "1024" },
		"maintenance-window": { type: "string" },
		"response-mode": { type: "string", default: "approval-required" },
		"retention-days": { type: "string", default: "30" },
		"review-schedule": { type: "string", default: "every 2 days" },
		"s3-archive-bucket": { type: "string", default: "none" },
		"service-group": { type: "string" },
		"service-user": { type: "string" },
		"state-dir": { type: "string" },
	},
	strict: true,
});
const root =
	parsedArguments.values["state-dir"] ??
	process.env.IDS_AGENT_STATE_DIR ??
	join(process.cwd(), ".ids-agent");

function showHelp(): void {
	console.log(`Usage: ids-agent <command>

Commands:
  setup          Run first-time setup
  re-onboard     Update the local operating policy
  daemon         Run the background agent process
  install-service Install and start the boot service
  uninstall-service Stop and remove the boot service
  access         Probe collection and mitigation access
  status         Show the local agent identity
  doctor         Check local state and host binding
  memory-pack    Build and verify the current memory pack
  uninstall-plan List agent-owned resources in removal order
  help           Show this help`);
}

function optionList(value: string): string[] {
	return value === "none"
		? []
		: value.split(",").map((item) => item.trim()).filter((item) => item.length > 0);
}

async function onboardingAnswers(): Promise<OnboardingAnswers> {
	const purpose = parsedArguments.values["device-purpose"];
	const contact = parsedArguments.values["admin-contact"];
	const window = parsedArguments.values["maintenance-window"];
	if (purpose !== undefined && window !== undefined) {
		return nonInteractiveAnswers(purpose, contact, window);
	}
	if (purpose !== undefined || contact !== undefined || window !== undefined) {
		throw new Error("Provide device purpose and maintenance window or answer the prompts.");
	}
	return askOnboardingQuestions();
}

function nonInteractiveAnswers(
	purpose: string,
	contact: string | undefined,
	window: string,
): OnboardingAnswers {
	const inbox = parsedArguments.values["agent-mail-inbox"] ??
		process.env.IDS_AGENT_AGENTMAIL_INBOX_ID ?? "skip";
	const bucket = parsedArguments.values["s3-archive-bucket"];
	return onboardingPolicySchema.omit({ createdAt: true }).parse({
		adminContact: contact ?? "local-only",
		agentMailInbox: inbox === "skip" ? null : inbox,
		approvedAgentRuntimes: optionList(parsedArguments.values["approved-agent-runtimes"]),
		criticalPaths: optionList(parsedArguments.values["critical-paths"]),
		devicePurpose: purpose,
		emailAllowedSenders: optionList(parsedArguments.values["email-allowed-senders"] ?? "none"),
		emailReportRecipients: optionList(parsedArguments.values["email-report-recipients"] ?? "none"),
		expectedServices: optionList(parsedArguments.values["expected-services"]),
		logCacheMaxBytes: Number.parseInt(parsedArguments.values["log-cache-mb"], 10) * 1_048_576,
		maintenanceWindow: window,
		responseMode: parsedArguments.values["response-mode"],
		retentionDays: Number.parseInt(parsedArguments.values["retention-days"], 10),
		reviewSchedule: parsedArguments.values["review-schedule"],
		s3ArchiveBucket: bucket === "none" ? null : bucket,
	});
}

function showCapabilities(report: CapabilityReport): void {
	console.log(`\nPlatform access: ${report.ready ? "READY" : "ACTION REQUIRED"}`);
	for (const item of report.probes) {
		console.log(`${item.status === "ready" ? "PASS" : "TODO"} ${item.id}`);
		console.log(`  Purpose: ${item.detail}`);
		if (item.status !== "ready") {
			console.log(`  Action: ${item.instruction}`);
		}
	}
}

function refreshCapabilities(): CapabilityReport {
	const report = inspectCapabilities();
	saveCapabilityReport(root, report);
	showCapabilities(report);
	return report;
}

function requireSetup(): void {
	if (!existsSync(statePaths(root).installManifest)) {
		throw new Error("Setup is incomplete. Run: ids-agent setup");
	}
}

async function showAgentMail(
	inbox: string | null | undefined,
	allowedSenders: string[] = [],
	reportRecipients: string[] = [],
): Promise<void> {
	const apiKey = process.env.AGENTMAIL_API_KEY;
	const result = await checkAgentMail(
		inbox,
		apiKey,
	);
	console.log(`Agent Mail: ${result.detail}`);
	if (result.ready && inbox !== undefined && inbox !== null && apiKey !== undefined) {
		try {
			await configureAgentMailAllowlist(
				inbox,
				apiKey,
				allowedSenders,
				reportRecipients,
			);
			console.log("Agent Mail: email allowlists are active.");
		} catch {
			console.log("Agent Mail: allow-list setup failed. Local reports remain active.");
		}
	}
}

async function setup(): Promise<void> {
	if (existsSync(statePaths(root).installManifest)) {
		console.log("Setup is already complete. Run re-onboard to update policy.");
		return;
	}
	const answers = await onboardingAnswers();
	const manifest = bootstrap(root, answers);
	const capabilityReport = refreshCapabilities();
	await showAgentMail(
		answers.agentMailInbox,
		answers.emailAllowedSenders,
		answers.emailReportRecipients,
	);
	console.log(`Local setup saved for ${manifest.host.hostname}.`);
	console.log(`State directory: ${root}`);
	if (answers.adminContact === "local-only") {
		console.log("External alert delivery is deferred. Reports will remain in local state.");
		console.log("Use the local CLI to review status and reports.");
	}
	if (capabilityReport.ready) {
		console.log("Host commissioning is complete.");
	} else {
		console.log("Complete each TODO action, then run: ids-agent access");
	}
	doctor();
}

async function reOnboard(): Promise<void> {
	requireSetup();
	const answers = await onboardingAnswers();
	updatePolicy(root, answers);
	refreshCapabilities();
	await showAgentMail(
		answers.agentMailInbox,
		answers.emailAllowedSenders,
		answers.emailReportRecipients,
	);
	console.log("The local operating policy is updated.");
}

function status(): void {
	requireSetup();
	const manifest = readInstallManifest(root);
	console.log(`Agent: ${manifest.agentId}`);
	console.log(`Host: ${manifest.host.hostname}`);
	console.log(`Platform: ${manifest.host.platform}/${manifest.host.arch}`);
	console.log("Scope: this host only");
	const inbox = readPolicy(root).agentMailInbox;
	console.log(`Agent Mail: ${inbox ?? "local-only"}`);
}

function doctor(): void {
	const report = runDoctor(root);
	for (const check of report.checks) {
		console.log(`${check.ok ? "PASS" : "FAIL"} ${check.name}: ${check.detail}`);
	}
	process.exitCode = report.ok ? 0 : 1;
}

function memoryPack(): void {
	requireSetup();
	const packRoot = buildMemoryPack(root);
	if (!verifyMemoryPack(root, packRoot)) {
		throw new Error("Memory pack verification failed.");
	}
	console.log(`Verified memory pack: ${packRoot}`);
}

function showUninstallPlan(): void {
	requireSetup();
	console.log("Native administrator authorization is required before removal.");
	for (const resource of uninstallPlan(root)) {
		console.log(resource);
	}
}

function serviceOption(name: "service-group" | "service-user"): string {
	const value = parsedArguments.values[name];
	if (value === undefined || value.length === 0) {
		throw new Error(`Provide --${name}.`);
	}
	return value;
}

function servicePlan() {
	const manifest = readInstallManifest(root);
	return buildServicePlan(
		manifest.host.platform,
		root,
		process.cwd(),
		process.execPath,
		serviceOption("service-user"),
		serviceOption("service-group"),
	);
}

function installBootService(): void {
	requireSetup();
	const plan = servicePlan();
	installService(plan, process.geteuid?.() ?? -1);
	console.log(`Installed and started ${plan.label}.`);
}

function uninstallBootService(): void {
	requireSetup();
	const plan = servicePlan();
	uninstallService(plan, process.geteuid?.() ?? -1);
	console.log(`Stopped and removed ${plan.label}.`);
}

async function runServiceCommand(): Promise<boolean> {
	switch (command) {
		case "daemon":
			requireSetup();
			await runDaemon(root);
			return true;
		case "install-service":
			installBootService();
			return true;
		case "uninstall-service":
			uninstallBootService();
			return true;
		default:
			return false;
	}
}

async function main(): Promise<void> {
	if (await runServiceCommand()) {
		return;
	}
	switch (command) {
		case "setup":
			await setup();
			break;
		case "re-onboard":
			await reOnboard();
			break;
		case "access":
			requireSetup();
			refreshCapabilities();
			break;
		case "status":
			status();
			break;
		case "doctor":
			doctor();
			break;
		case "memory-pack":
			memoryPack();
			break;
		case "uninstall-plan":
			showUninstallPlan();
			break;
		case "help":
			showHelp();
			break;
		default:
			showHelp();
			process.exitCode = 2;
	}
}

await main().catch((error: Error) => {
	console.error(error.message);
	process.exitCode = 1;
});
