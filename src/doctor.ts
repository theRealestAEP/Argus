import { verify } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";

import type { DoctorCheck, DoctorReport } from "./contracts.js";
import { capabilityReportSchema, onboardingPolicySchema } from "./contracts.js";
import { readInstallManifest } from "./bootstrap.js";
import { detectHost, validateLocalScope } from "./host.js";
import { statePaths } from "./paths.js";

function fileCheck(name: string, path: string): DoctorCheck {
	return {
		detail: existsSync(path) ? path : `Missing: ${path}`,
		name,
		ok: existsSync(path),
	};
}

function modeCheck(name: string, path: string, expected: number): DoctorCheck {
	const mode = statSync(path).mode & 0o777;
	return {
		detail: `Mode ${mode.toString(8)}`,
		name,
		ok: mode === expected,
	};
}

function signatureCheck(root: string): DoctorCheck {
	const paths = statePaths(root);
	const manifestText = readFileSync(paths.installManifest, "utf8");
	const signature = Buffer.from(
		readFileSync(paths.installSignature, "utf8").trim(),
		"base64",
	);
	const publicKey = readFileSync(paths.publicKey, "utf8");
	return {
		detail: "Ed25519 signature over install-manifest.json",
		name: "install manifest signature",
		ok: verify(null, Buffer.from(manifestText), publicKey, signature),
	};
}

function policySignatureCheck(root: string): DoctorCheck {
	const paths = statePaths(root);
	const text = readFileSync(paths.policy, "utf8");
	const signature = Buffer.from(
		readFileSync(paths.policySignature, "utf8").trim(),
		"base64",
	);
	return {
		detail: "Ed25519 signature over policy.json",
		name: "onboarding policy signature",
		ok: verify(null, Buffer.from(text), readFileSync(paths.publicKey, "utf8"), signature),
	};
}

function stateChecks(root: string): DoctorCheck[] {
	const paths = statePaths(root);
	return [
		fileCheck("capability report", paths.capabilityReport),
		fileCheck("install manifest", paths.installManifest),
		fileCheck("install signature", paths.installSignature),
		fileCheck("scope manifest", paths.scope),
		fileCheck("onboarding policy", paths.policy),
		fileCheck("onboarding policy signature", paths.policySignature),
		fileCheck("private key", paths.privateKey),
		fileCheck("public key", paths.publicKey),
	];
}

export function runDoctor(root: string): DoctorReport {
	const checks = stateChecks(root);
	if (checks.some((check) => !check.ok)) {
		return { checks, ok: false };
	}

	const paths = statePaths(root);
	const host = detectHost();
	const manifest = readInstallManifest(root);
	const scope = validateLocalScope(readFileSync(paths.scope, "utf8"), host);
	const capabilityReport = capabilityReportSchema.parse(
		JSON.parse(readFileSync(paths.capabilityReport, "utf8")),
	);
	onboardingPolicySchema.parse(JSON.parse(readFileSync(paths.policy, "utf8")));

	checks.push(
		{
			detail: host.fingerprint,
			name: "host binding",
			ok:
				manifest.host.fingerprint === host.fingerprint &&
				scope.hostFingerprint === host.fingerprint &&
				capabilityReport.hostFingerprint === host.fingerprint &&
				capabilityReport.platform === host.platform,
		},
		modeCheck("state directory permissions", paths.root, 0o700),
		modeCheck("private key permissions", paths.privateKey, 0o600),
		signatureCheck(root),
		policySignatureCheck(root),
	);
	checks.push(
		...capabilityReport.probes
			.filter((probe) => probe.required)
			.map((probe) => ({
				detail: probe.status === "ready" ? probe.detail : probe.instruction,
				name: `access ${probe.id}`,
				ok: probe.status === "ready",
			})),
	);
	return { checks, ok: checks.every((check) => check.ok) };
}
