import { generateKeyPairSync, randomUUID, sign } from "node:crypto";
import { existsSync, mkdirSync, readFileSync } from "node:fs";

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
	mkdirSync(paths.memoryPacks, { mode: 0o700, recursive: true });
	mkdirSync(paths.logs, { mode: 0o700, recursive: true });
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
			paths.memoryPacks,
			paths.logs,
			paths.eventLog,
			paths.runtime,
			paths.keys,
			paths.capabilityReport,
			paths.scope,
			paths.policy,
			paths.policySignature,
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
