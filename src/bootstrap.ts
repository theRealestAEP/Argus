import { generateKeyPairSync, randomUUID, sign } from "node:crypto";
import { chownSync, existsSync, mkdirSync, readFileSync, statSync } from "node:fs";

import type { InstallManifest, OnboardingAnswers, OnboardingPolicy } from "./contracts.js";
import { installManifestSchema } from "./contracts.js";
import { jsonText, writePrivate } from "./files.js";
import { detectHost, localScope } from "./host.js";
import { statePaths } from "./paths.js";
import { serviceResourcePaths } from "./service.js";

function createKeys(privateKeyPath: string, publicKeyPath: string): void {
	const keys = generateKeyPairSync("ed25519");
	const privateKey = keys.privateKey.export({ format: "pem", type: "pkcs8" });
	const publicKey = keys.publicKey.export({ format: "pem", type: "spki" });
	writePrivate(privateKeyPath, privateKey.toString());
	writePrivate(publicKeyPath, publicKey.toString());
}

export function readInstallManifest(root: string): InstallManifest {
	const paths = statePaths(root);
	return installManifestSchema.parse(
		JSON.parse(readFileSync(paths.installManifest, "utf8")),
	);
}

export function addInstallResources(root: string, resources: string[]): InstallManifest {
	const paths = statePaths(root);
	const manifestOwner = statSync(paths.installManifest);
	const signatureOwner = statSync(paths.installSignature);
	const current = readInstallManifest(root);
	const manifest = installManifestSchema.parse({
		...current,
		resources: [...new Set([...current.resources, ...resources])],
	});
	const text = jsonText(manifest);
	writePrivate(paths.installManifest, text);
	if (process.geteuid?.() === 0) {
		chownSync(paths.installManifest, manifestOwner.uid, manifestOwner.gid);
	}
	const signature = sign(
		null,
		Buffer.from(text),
		readFileSync(paths.privateKey, "utf8"),
	);
	writePrivate(paths.installSignature, `${signature.toString("base64")}\n`);
	if (process.geteuid?.() === 0) {
		chownSync(paths.installSignature, signatureOwner.uid, signatureOwner.gid);
	}
	return manifest;
}

export function bootstrap(
	root: string,
	answers: OnboardingAnswers,
	now = new Date(),
): InstallManifest {
	const paths = statePaths(root);
	if (existsSync(paths.installManifest)) {
		return readInstallManifest(root);
	}

	mkdirSync(paths.root, { mode: 0o700, recursive: true });
	mkdirSync(paths.agentEvents, { mode: 0o700, recursive: true });
	mkdirSync(paths.agentEventsProcessed, { mode: 0o700, recursive: true });
	mkdirSync(paths.agentEventsRejected, { mode: 0o700, recursive: true });
	mkdirSync(paths.memoryPacks, { mode: 0o700, recursive: true });
	mkdirSync(paths.logs, { mode: 0o700, recursive: true });
	mkdirSync(paths.alerts, { mode: 0o700, recursive: true });
	mkdirSync(paths.alertWorking, { mode: 0o700, recursive: true });
	mkdirSync(paths.archiveReceipts, { mode: 0o700, recursive: true });
	mkdirSync(paths.brokerRequests, { mode: 0o700, recursive: true });
	mkdirSync(paths.brokerRejected, { mode: 0o700, recursive: true });
	mkdirSync(paths.containmentReceipts, { mode: 0o700, recursive: true });
	mkdirSync(paths.reports, { mode: 0o700, recursive: true });
	mkdirSync(paths.mailReceipts, { mode: 0o700, recursive: true });
	mkdirSync(paths.operatorMessages, { mode: 0o700, recursive: true });
	mkdirSync(paths.runtime, { mode: 0o700, recursive: true });
	createKeys(paths.privateKey, paths.publicKey);

	const host = detectHost();
	const policy: OnboardingPolicy = {
		...answers,
		createdAt: now.toISOString(),
	};
	const manifest: InstallManifest = {
		agentId: randomUUID(),
		createdAt: now.toISOString(),
		host,
		resources: [
			paths.root,
			paths.agentEvents,
			paths.agentEventsProcessed,
			paths.agentEventsRejected,
			paths.memoryPacks,
			paths.logs,
			paths.eventLog,
			paths.alerts,
			paths.alertWorking,
			paths.archiveReceipts,
			paths.brokerRequests,
			paths.brokerRejected,
			paths.containmentReceipts,
			paths.reports,
			paths.mailReceipts,
			paths.operatorMessages,
			paths.runtime,
			paths.keys,
			paths.capabilityReport,
			paths.scope,
			paths.policy,
			paths.policySignature,
			paths.sensorConfig,
			paths.sensorIntegrityState,
			paths.sensorSignature,
			paths.sensorState,
			paths.emailCursor,
			paths.reviewState,
			paths.auditCursor,
			paths.processSnapshot,
			paths.privateKey,
			paths.publicKey,
			paths.installSignature,
			paths.installManifest,
			...serviceResourcePaths(host.platform),
		],
		schemaVersion: 1,
	};

	writePrivate(paths.scope, jsonText(localScope(host)));
	const policyText = jsonText(policy);
	writePrivate(paths.policy, policyText);
	const privateKey = readFileSync(paths.privateKey, "utf8");
	const policySignature = sign(null, Buffer.from(policyText), privateKey);
	writePrivate(paths.policySignature, `${policySignature.toString("base64")}\n`);
	const manifestText = jsonText(manifest);
	writePrivate(paths.installManifest, manifestText);
	const signature = sign(null, Buffer.from(manifestText), privateKey);
	writePrivate(paths.installSignature, `${signature.toString("base64")}\n`);
	return manifest;
}
