import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { arch, hostname, platform } from "node:os";

import type { HostIdentity, ScopeManifest } from "./contracts.js";
import { scopeManifestSchema } from "./contracts.js";

function linuxMachineId(): string {
	const path = "/etc/machine-id";
	return existsSync(path) ? readFileSync(path, "utf8").trim() : hostname();
}

function macMachineId(): string {
	const output = execFileSync(
		"/usr/sbin/ioreg",
		["-rd1", "-c", "IOPlatformExpertDevice"],
		{ encoding: "utf8" },
	);
	const match = /"IOPlatformUUID" = "([^"]+)"/u.exec(output);
	return match?.at(1) ?? hostname();
}

function machineId(os: "darwin" | "linux"): string {
	return os === "linux" ? linuxMachineId() : macMachineId();
}

export function detectHost(): HostIdentity {
	const os = platform();
	if (os !== "darwin" && os !== "linux") {
		throw new Error(`Unsupported platform: ${os}`);
	}

	const id = machineId(os);
	const name = hostname();
	const fingerprint = createHash("sha256")
		.update([os, arch(), name, id].join("\0"))
		.digest("hex");

	return {
		arch: arch(),
		fingerprint,
		hostname: name,
		machineId: id,
		platform: os,
	};
}

export function localScope(host: HostIdentity): ScopeManifest {
	return {
		collectionLocalOnly: true,
		hostFingerprint: host.fingerprint,
		remoteExecution: false,
		schemaVersion: 1,
	};
}

export function validateLocalScope(text: string, host: HostIdentity): ScopeManifest {
	const scope = scopeManifestSchema.parse(JSON.parse(text));
	if (scope.hostFingerprint !== host.fingerprint) {
		throw new Error("The scope manifest belongs to a different host.");
	}
	return scope;
}
