#!/usr/bin/env node

import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";

import { checkAgentMail, configureAgentMailAllowlist } from "./agent-mail.js";
import { initializeAgentMailCursor } from "./agent-mail.js";
import { addInstallResources, bootstrap, readInstallManifest } from "./bootstrap.js";
import { inspectCapabilities, saveCapabilityReport } from "./capabilities.js";
import type { CapabilityReport, OnboardingAnswers } from "./contracts.js";
import { evidenceEventSchema, onboardingPolicySchema } from "./contracts.js";
import { runDoctor } from "./doctor.js";
import { runDaemon, waitForStop } from "./daemon.js";
import {
	conductGuidedOnboarding,
	conductSensorPlanReview,
} from "./guided-onboarding.js";
import { detectHost } from "./host.js";
import { applyContainment } from "./containment.js";
import { runContainmentBroker } from "./containment-broker.js";
import { readMacosSensorStatus, runMacosSensor } from "./macos-eslogger.js";
import { containmentPlanSchema } from "./contracts.js";
import { uninstallPlan } from "./lifecycle.js";
import { buildMemoryPack, verifyMemoryPack } from "./memory-pack.js";
import { readPolicy, updatePolicy } from "./onboarding.js";
import { statePaths } from "./paths.js";
import { initializeReviewSchedule } from "./review-schedule.js";
import { collectLinuxSnapshot, commissionLinuxSensors } from "./linux-sensors.js";
import { readSensorConfig } from "./linux-sensors.js";
import { selectLinuxSensors, type GuidedOnboardingContext } from "./model-runtime.js";
import {
	checkSoftwareUpdate,
	installSoftwareUpdate,
	isGlobalSoftwareInstall,
	readSoftwareVersion,
} from "./software-update.js";
import { z } from "zod";
import {
	buildServicePlan,
	buildBrokerServicePlan,
	buildMacosBrokerServicePlan,
	buildMacosSensorServicePlan,
	installService,
	uninstallService,
	type ServicePlan,
} from "./service.js";

const command = process.argv.at(2) ?? "help";
const parsedArguments = parseArgs({
	allowPositionals: false,
	args: process.argv.slice(3),
	options: {
		"admin-contact": { type: "string" },
		"agent-mail-inbox": { type: "string" },
		"automatic-process-termination": { type: "boolean", default: false },
		"approved-agent-runtimes": { type: "string", default: "none" },
		"critical-paths": { type: "string", default: "none" },
		"device-purpose": { type: "string" },
		"expected-services": { type: "string", default: "none" },
		"env-file": { type: "string" },
		"email-allowed-senders": { type: "string" },
		"email-report-recipients": { type: "string" },
		"log-cache-mb": { type: "string", default: "1024" },
		"maintenance-window": { type: "string" },
		"install-resource": { type: "string", multiple: true },
		"plan-file": { type: "string" },
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
const applicationDirectory = join(dirname(fileURLToPath(import.meta.url)), "..");
const installedEnvironmentFile = process.platform === "darwin"
	? "/Library/Application Support/Argus/config/env"
	: "/etc/argus-ids/env";
const environmentFile = parsedArguments.values["env-file"] ??
	(existsSync(installedEnvironmentFile) ? installedEnvironmentFile : join(process.cwd(), ".env"));
if (existsSync(environmentFile)) {
	process.loadEnvFile(environmentFile);
}
const installedStateDirectory = process.platform === "darwin"
	? "/Library/Application Support/Argus/state"
	: "/var/lib/argus-ids";
const root = parsedArguments.values["state-dir"] ??
	process.env.IDS_AGENT_STATE_DIR ??
	(existsSync(installedStateDirectory) ? installedStateDirectory : join(process.cwd(), ".ids-agent"));

function showHelp(): void {
	console.log(`Usage: ids-agent <command>

Commands:
  setup          Run first-time setup
  re-onboard     Update the local operating policy
  commission     Let the agent configure Linux sensors
  contain        Apply an administrator-approved containment plan
  broker         Run the privileged containment broker
  macos-sensor   Run the privileged macOS event sensor
  register-install-resources Record installer-owned resources
  daemon         Run the background agent process
  install-service Install and start the boot service
  uninstall-service Stop and remove the boot service
  access         Probe collection and mitigation access
  status         Show the local agent identity
  doctor         Check local state and host binding
  memory-pack    Build and verify the current memory pack
  update-check   Check the latest GitHub release
  update         Verify and install the latest GitHub release
  uninstall-plan List agent-owned resources in removal order
  help           Show this help`);
}

function optionList(value: string): string[] {
	return value === "none"
		? []
		: value.split(",").map((item) => item.trim()).filter((item) => item.length > 0);
}

const heartbeatStatusSchema = z.object({
	pid: z.number().int().positive(),
	updatedAt: z.iso.datetime(),
});

function guidedContext(): GuidedOnboardingContext {
	const host = detectHost();
	const baseline = host.platform === "linux" ? collectLinuxSnapshot([]) : null;
	const observed = baseline === null
		? { establishedConnectionCount: 0, listenerCount: 0, processCount: 0 }
		: {
			establishedConnectionCount: baseline.establishedConnectionCount,
			listenerCount: baseline.listeners.length,
			processCount: baseline.processes.length,
		};
	return {
		defaultAgentMailInbox: process.env.IDS_AGENT_AGENTMAIL_INBOX_ID ?? null,
		host: {
			arch: host.arch,
			hostname: host.hostname,
			platform: host.platform,
		},
		observed,
	};
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
	return conductGuidedOnboarding(guidedContext());
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
		automaticProcessTermination: parsedArguments.values["automatic-process-termination"],
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

function refreshCapabilities(showReport = true): CapabilityReport {
	const report = inspectCapabilities(new Date(), root);
	saveCapabilityReport(root, report);
	if (showReport) {
		showCapabilities(report);
	}
	return report;
}

function showSetupSummary(
	hostname: string,
	report: CapabilityReport,
	sensorPlanSaved: boolean,
): void {
	console.log(`\nArgus: Setup saved for ${hostname}.`);
	if (sensorPlanSaved) {
		console.log("Argus: The Linux monitoring plan is ready.");
	}
	if (report.ready) {
		console.log("Argus: Host access is ready.");
	} else {
		const pendingCount = report.probes.filter((probe) => probe.status !== "ready").length;
		console.log(`Argus: Host access is limited. ${pendingCount} administrator actions remain.`);
		console.log("Argus: Run `ids-agent doctor` for the action list.");
	}
	console.log("Argus: Run the daemon or install the boot service to start continuous monitoring.");
}

function requireSetup(): void {
	if (!existsSync(statePaths(root).installManifest)) {
		throw new Error("Setup is incomplete. Run: ids-agent setup");
	}
}

async function commissionLinux(
	answers: OnboardingAnswers,
	createdAt: string,
): Promise<boolean> {
	const baseline = collectLinuxSnapshot(answers.criticalPaths);
	try {
		const policy = { ...answers, createdAt };
		const proposedSelection = await selectLinuxSensors(policy, baseline);
		const selection = process.stdin.isTTY === true
			? await conductSensorPlanReview(policy, baseline, proposedSelection)
			: proposedSelection;
		const sensors = commissionLinuxSensors(root, policy, selection, baseline);
		console.log(`Argus: Monitoring plan saved. Sensor interval: ${sensors.pollIntervalSeconds} seconds.`);
		return true;
	} catch (error) {
		const detail = error instanceof Error ? error.message : "Sensor commissioning failed.";
		console.log(`Linux sensors: action required. ${detail}`);
		return false;
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
		const manifest = readInstallManifest(root);
		if (manifest.host.platform === "linux" && !existsSync(statePaths(root).sensorConfig)) {
			await commissionLinux(readPolicy(root), manifest.createdAt);
			return;
		}
		console.log("Setup is already complete. Run re-onboard to update policy.");
		return;
	}
	const answers = await onboardingAnswers();
	const manifest = bootstrap(root, answers);
	initializeReviewSchedule(root, answers.reviewSchedule);
	initializeAgentMailCursor(root);
	let sensorPlanSaved = false;
	if (manifest.host.platform === "linux") {
		sensorPlanSaved = await commissionLinux(answers, manifest.createdAt);
	}
	const capabilityReport = refreshCapabilities(false);
	await showAgentMail(
		answers.agentMailInbox,
		answers.emailAllowedSenders,
		answers.emailReportRecipients,
	);
	console.log(`State directory: ${root}`);
	if (answers.adminContact === "local-only") {
		console.log("External alert delivery is deferred. Reports will remain in local state.");
		console.log("Use the local CLI to review status and reports.");
	}
	showSetupSummary(manifest.host.hostname, capabilityReport, sensorPlanSaved);
	process.exitCode = runDoctor(root).ok ? 0 : 1;
}

async function reOnboard(): Promise<void> {
	requireSetup();
	const answers = await onboardingAnswers();
	updatePolicy(root, answers);
	initializeReviewSchedule(root, answers.reviewSchedule);
	initializeAgentMailCursor(root);
	const manifest = readInstallManifest(root);
	if (manifest.host.platform === "linux") {
		await commissionLinux(answers, manifest.createdAt);
	}
	refreshCapabilities(false);
	await showAgentMail(
		answers.agentMailInbox,
		answers.emailAllowedSenders,
		answers.emailReportRecipients,
	);
	console.log("The local operating policy is updated.");
}

async function commission(): Promise<void> {
	requireSetup();
	const manifest = readInstallManifest(root);
	if (manifest.host.platform !== "linux") {
		console.log("Linux sensor commissioning applies to Linux hosts.");
		return;
	}
	await commissionLinux(readPolicy(root), manifest.createdAt);
}

function showMacosSensorStatus(manifest: ReturnType<typeof readInstallManifest>, paths: ReturnType<typeof statePaths>): void {
	if (manifest.host.platform !== "darwin" || !existsSync(paths.macosSensorStatus)) {
		return;
	}
	const sensor = readMacosSensorStatus(root);
	console.log(`macOS sensor: ${sensor.connected ? "connected" : "stopped"}`);
	console.log(`macOS events received: ${sensor.eventCount}`);
	console.log(`Last macOS event: ${sensor.lastEventAt ?? "none"}`);
}

function status(): void {
	requireSetup();
	const manifest = readInstallManifest(root);
	const paths = statePaths(root);
	console.log(`Agent: ${manifest.agentId}`);
	console.log(`Host: ${manifest.host.hostname}`);
	console.log(`Platform: ${manifest.host.platform}/${manifest.host.arch}`);
	console.log("Scope: this host only");
	const inbox = readPolicy(root).agentMailInbox;
	console.log(`Agent Mail: ${inbox ?? "local-only"}`);
	if (existsSync(paths.heartbeat)) {
		const heartbeat = heartbeatStatusSchema.parse(
			JSON.parse(readFileSync(paths.heartbeat, "utf8")),
		);
		console.log(`Last daemon heartbeat: ${heartbeat.updatedAt} (PID ${heartbeat.pid})`);
	} else {
		console.log("Daemon: no heartbeat recorded");
	}
	if (manifest.host.platform === "linux" && existsSync(paths.sensorConfig)) {
		const sensors = readSensorConfig(root);
		const selected = [
			["authentication", sensors.selection.authentication],
			["critical files", sensors.selection.criticalFiles],
			["listeners", sensors.selection.listeners],
			["network connections", sensors.selection.networkConnections],
			["processes", sensors.selection.processes],
		]
			.filter(([, enabled]) => enabled)
			.map(([name]) => name);
		console.log(`Sensors: ${selected.join(", ")} (every ${sensors.pollIntervalSeconds} seconds)`);
	}
	showMacosSensorStatus(manifest, paths);
	console.log(`Pending alerts: ${readdirSync(paths.alerts).length}`);
	console.log(`Active investigations: ${readdirSync(paths.alertWorking).length}`);
	console.log(`Local reports: ${readdirSync(paths.reports).length}`);
	const operatorMessageCount = existsSync(paths.operatorMessages)
		? readdirSync(paths.operatorMessages).length
		: 0;
	console.log(`Operator messages: ${operatorMessageCount}`);
	if (existsSync(paths.eventLog)) {
		const latest = readFileSync(paths.eventLog, "utf8").trim().split("\n").at(-1);
		if (latest !== undefined && latest.length > 0) {
			const event = evidenceEventSchema.parse(JSON.parse(latest));
			console.log(`Latest activity: ${event.recordedAt} ${event.event} — ${event.detail}`);
		}
	}
	console.log(`Activity log: ${paths.eventLog}`);
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
		applicationDirectory,
		environmentFile,
		process.execPath,
		serviceOption("service-user"),
		serviceOption("service-group"),
	);
}

function installMacosServices(plan: ServicePlan, effectiveUserId: number): void {
	const sensorPlan = buildMacosSensorServicePlan(
		root,
		applicationDirectory,
		process.execPath,
	);
	uninstallService(sensorPlan, effectiveUserId);
	installService(
		buildMacosBrokerServicePlan(root, applicationDirectory, process.execPath),
		effectiveUserId,
	);
	installService(plan, effectiveUserId);
	installService(sensorPlan, effectiveUserId);
}

function installBootService(): void {
	requireSetup();
	const plan = servicePlan();
	const manifest = readInstallManifest(root);
	const effectiveUserId = process.geteuid?.() ?? -1;
	if (manifest.host.platform === "linux") {
		installService(
			buildBrokerServicePlan(root, applicationDirectory, process.execPath),
			effectiveUserId,
		);
		installService(plan, effectiveUserId);
	} else {
		installMacosServices(plan, effectiveUserId);
	}
	console.log(`Installed and started ${plan.label}.`);
}

function uninstallBootService(): void {
	requireSetup();
	const plan = servicePlan();
	uninstallService(plan, process.geteuid?.() ?? -1);
	const manifest = readInstallManifest(root);
	if (manifest.host.platform === "linux") {
		uninstallService(
			buildBrokerServicePlan(root, applicationDirectory, process.execPath),
			process.geteuid?.() ?? -1,
		);
	} else {
		uninstallService(
			buildMacosBrokerServicePlan(root, applicationDirectory, process.execPath),
			process.geteuid?.() ?? -1,
		);
		uninstallService(
			buildMacosSensorServicePlan(root, applicationDirectory, process.execPath),
			process.geteuid?.() ?? -1,
		);
	}
	console.log(`Stopped and removed ${plan.label}.`);
}

async function showUpdateCheck(): Promise<void> {
	const currentVersion = readSoftwareVersion(applicationDirectory);
	const release = await checkSoftwareUpdate(currentVersion);
	console.log(`Installed version: ${release.currentVersion}`);
	console.log(`Latest version: ${release.latestVersion}`);
	console.log(release.updateAvailable ? "Update available." : "Argus is current.");
	console.log(`Release: ${release.releaseUrl}`);
}

async function updateSoftware(): Promise<void> {
	requireSetup();
	if (!isGlobalSoftwareInstall(applicationDirectory)) {
		throw new Error("This Argus copy uses a source checkout. Update it with git, npm ci, and npm run build.");
	}
	const manifest = readInstallManifest(root);
	const currentVersion = readSoftwareVersion(applicationDirectory);
	const release = await installSoftwareUpdate(
		root,
		currentVersion,
		manifest.host.platform,
		process.geteuid?.() ?? -1,
	);
	if (!release.updateAvailable) {
		console.log(`Argus ${release.currentVersion} is current.`);
		return;
	}
	console.log(`Updated Argus from ${release.currentVersion} to ${release.latestVersion}.`);
	console.log(`Rollback release: https://github.com/theRealestAEP/Argus/releases/tag/v${release.currentVersion}`);
}

function contain(): void {
	requireSetup();
	const planPath = parsedArguments.values["plan-file"];
	if (planPath === undefined) {
		throw new Error("Provide --plan-file.");
	}
	const plan = containmentPlanSchema.parse(JSON.parse(readFileSync(planPath, "utf8")));
	const receipt = applyContainment(
		root,
		readPolicy(root),
		plan,
		process.geteuid?.() ?? -1,
	);
	console.log(`Containment applied: ${receipt.action} ${receipt.target}`);
	console.log(`Rollback: ${receipt.rollback}`);
}

function registerInstallResources(): void {
	requireSetup();
	if ((process.geteuid?.() ?? -1) !== 0) {
		throw new Error("Administrator authorization is required to register install resources.");
	}
	const resources = parsedArguments.values["install-resource"] ?? [];
	if (resources.length === 0) {
		throw new Error("Provide at least one --install-resource.");
	}
	addInstallResources(root, resources);
	console.log(`Recorded ${resources.length} installer resources.`);
}

async function runRuntimeCommand(): Promise<boolean> {
	switch (command) {
		case "daemon":
			requireSetup();
			await runDaemon(root);
			return true;
		case "broker":
			requireSetup();
			await runContainmentBroker(root, waitForStop);
			return true;
		case "macos-sensor":
			requireSetup();
			if (process.platform !== "darwin" || (process.geteuid?.() ?? -1) !== 0) {
				throw new Error("The macOS sensor must run as root on macOS.");
			}
			await runMacosSensor(root, waitForStop);
			return true;
		default:
			return false;
	}
}

async function runServiceCommand(): Promise<boolean> {
	if (await runRuntimeCommand()) {
		return true;
	}
	switch (command) {
		case "install-service":
			installBootService();
			return true;
		case "uninstall-service":
			uninstallBootService();
			return true;
		case "commission":
			await commission();
			return true;
		case "contain":
			contain();
			return true;
		case "register-install-resources":
			registerInstallResources();
			return true;
		default:
			return runUpdateCommand();
	}
}

async function runUpdateCommand(): Promise<boolean> {
	switch (command) {
		case "update-check":
			await showUpdateCheck();
			return true;
		case "update":
			await updateSoftware();
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
