import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import { spawnSync } from "node:child_process";

const stateDirectory = join(mkdtempSync(join(tmpdir(), "ids-setup-eval-")), "state");
const command = join(process.cwd(), "dist", "cli.js");
const environment = { ...process.env, IDS_AGENT_STATE_DIR: stateDirectory };

function runStep(name, args, expectedExitCodes) {
	const startedAt = performance.now();
	const result = spawnSync(process.execPath, [command, ...args], {
		encoding: "utf8",
		env: environment,
	});
	const exitCode = result.status ?? -1;
	return {
		durationMs: Math.round(performance.now() - startedAt),
		errorLines: result.stderr.trim().length === 0 ? [] : result.stderr.trim().split("\n"),
		exitCode,
		name,
		passed: expectedExitCodes.includes(exitCode),
		stdout: result.stdout,
	};
}

const startedAt = performance.now();
const steps = [
	runStep(
		"setup",
		[
			"setup",
			"--automatic-process-termination",
			"--device-purpose=Linux evaluation host",
			"--admin-contact=security@example.test",
			"--approved-agent-runtimes=codex,local-review-agent",
			"--maintenance-window=Sunday 02:00",
			"--critical-paths=/etc,/srv",
			"--expected-services=sshd",
			"--response-mode=approval-required",
			"--review-schedule=every 2 days",
			"--retention-days=30",
		],
		[0, 1],
	),
	runStep("repeat-setup", ["setup"], [0]),
	runStep("status", ["status"], [0]),
	runStep("doctor", ["doctor"], [0, 1]),
	runStep("memory-pack", ["memory-pack"], [0]),
	runStep("uninstall-plan", ["uninstall-plan"], [0]),
];

const requiredArtifacts = [
	"capability-report.json",
	"install-manifest.json",
	"install-manifest.sig",
	"keys/agent-private.pem",
	"keys/agent-public.pem",
	"memory-packs/current/MANIFEST.json",
	"memory-packs/current/MANIFEST.sig",
	"policy.json",
	"policy.sig",
	"scope.json",
];
const artifactResults = requiredArtifacts.map((path) => ({
	exists: existsSync(join(stateDirectory, path)),
	path,
}));
const capabilityReport = JSON.parse(
	readFileSync(join(stateDirectory, "capability-report.json"), "utf8"),
);
const policy = JSON.parse(readFileSync(join(stateDirectory, "policy.json"), "utf8"));
const doctorOutput = steps.find((step) => step.name === "doctor")?.stdout ?? "";
const doctorLines = doctorOutput.split("\n");
const errorCount = steps.reduce((count, step) => count + step.errorLines.length, 0);
const passedSteps = steps.filter((step) => step.passed).length;
const presentArtifacts = artifactResults.filter((artifact) => artifact.exists).length;
const report = {
	artifacts: artifactResults,
	metrics: {
		approvedAgentRuntimeCount: policy.approvedAgentRuntimes.length,
		automaticProcessTermination: policy.automaticProcessTermination === true,
		artifactPassRate: presentArtifacts / artifactResults.length,
		capabilityReadyCount: capabilityReport.probes.filter(
			(probe) => probe.status === "ready",
		).length,
		capabilityTodoCount: capabilityReport.probes.filter(
			(probe) => probe.status !== "ready",
		).length,
		commandPassRate: passedSteps / steps.length,
		doctorFailCount: doctorLines.filter((line) => line.startsWith("FAIL ")).length,
		doctorPassCount: doctorLines.filter((line) => line.startsWith("PASS ")).length,
		errorCount,
		totalDurationMs: Math.round(performance.now() - startedAt),
	},
	platform: capabilityReport.platform,
	schemaVersion: 1,
	steps: steps.map((step) => ({
		durationMs: step.durationMs,
		errorLines: step.errorLines,
		exitCode: step.exitCode,
		name: step.name,
		passed: step.passed,
	})),
};

console.log(JSON.stringify(report, null, 2));

if (
	passedSteps !== steps.length ||
	presentArtifacts !== artifactResults.length ||
	policy.approvedAgentRuntimes.length !== 2 ||
	policy.automaticProcessTermination !== true
) {
	process.exitCode = 1;
}
