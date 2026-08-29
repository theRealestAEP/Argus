import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { chownSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";

import { z } from "zod";

import type { HostIdentity } from "./contracts.js";
import { recordEvidence } from "./evidence-store.js";
import { statePaths } from "./paths.js";

const repository = "theRealestAEP/Argus";
const releaseApi = `https://api.github.com/repos/${repository}/releases/latest`;
const versionSchema = z.string().regex(/^\d+\.\d+\.\d+$/u);
const packageSchema = z.object({ version: versionSchema });
const releaseSchema = z.object({
	assets: z.array(z.object({
		browser_download_url: z.url(),
		name: z.string().min(1),
	})),
	html_url: z.url(),
	tag_name: z.string().min(1),
});

export interface SoftwareRelease {
	archiveName: string;
	archiveUrl: string;
	checksumUrl: string;
	currentVersion: string;
	latestVersion: string;
	releaseUrl: string;
	updateAvailable: boolean;
}

export interface SoftwareUpdateGateway {
	install(archivePath: string): void;
	request(url: string): Promise<Response>;
	restart(platform: HostIdentity["platform"]): void;
}

export type SoftwareCommandRunner = (command: string, args: string[]) => void;

function numericVersion(version: string): number[] {
	return versionSchema.parse(version).split(".").map((part) => Number.parseInt(part, 10));
}

export function compareVersions(left: string, right: string): number {
	const leftParts = numericVersion(left);
	const rightParts = numericVersion(right);
	for (let index = 0; index < leftParts.length; index += 1) {
		const difference = (leftParts[index] ?? 0) - (rightParts[index] ?? 0);
		if (difference !== 0) {
			return difference;
		}
	}
	return 0;
}

export function readSoftwareVersion(projectDirectory: string): string {
	const value = JSON.parse(readFileSync(join(projectDirectory, "package.json"), "utf8"));
	return packageSchema.parse(value).version;
}

export function isGlobalSoftwareInstall(
	projectDirectory: string,
	globalRoot = execFileSync("npm", ["root", "--global"], { encoding: "utf8" }).trim(),
): boolean {
	return resolve(projectDirectory) === resolve(globalRoot, "on-device-ids-agent");
}

async function githubRequest(url: string): Promise<Response> {
	const headers = new Headers({
		accept: "application/vnd.github+json",
		"user-agent": "argus-ids-update-check",
	});
	const token = process.env.GITHUB_TOKEN;
	if (token !== undefined && token.length > 0) {
		headers.set("authorization", `Bearer ${token}`);
	}
	return fetch(url, { headers });
}

async function requiredResponse(response: Response): Promise<Response> {
	if (!response.ok) {
		throw new Error(`GitHub release request failed with HTTP ${response.status}.`);
	}
	return response;
}

export async function checkSoftwareUpdate(
	currentVersion: string,
	request: SoftwareUpdateGateway["request"] = githubRequest,
): Promise<SoftwareRelease> {
	const response = await request(releaseApi);
	if (response.status === 404) {
		throw new Error("No published Argus release was found.");
	}
	await requiredResponse(response);
	const release = releaseSchema.parse(await response.json());
	const latestVersion = versionSchema.parse(release.tag_name.replace(/^v/u, ""));
	const archiveName = `on-device-ids-agent-${latestVersion}.tgz`;
	const archive = release.assets.find((asset) => asset.name === archiveName);
	const checksums = release.assets.find((asset) => asset.name === "SHA256SUMS");
	if (archive === undefined || checksums === undefined) {
		throw new Error("The latest release lacks the Argus archive or SHA256SUMS.");
	}
	return {
		archiveName,
		archiveUrl: archive.browser_download_url,
		checksumUrl: checksums.browser_download_url,
		currentVersion: versionSchema.parse(currentVersion),
		latestVersion,
		releaseUrl: release.html_url,
		updateAvailable: compareVersions(currentVersion, latestVersion) < 0,
	};
}

async function responseBytes(
	url: string,
	request: SoftwareUpdateGateway["request"],
): Promise<Buffer> {
	const response = await requiredResponse(await request(url));
	return Buffer.from(await response.arrayBuffer());
}

function expectedChecksum(text: string, archiveName: string): string {
	for (const line of text.split("\n")) {
		const match = /^([a-f0-9]{64})\s+\*?(.+)$/u.exec(line.trim());
		if (match?.[2] === archiveName) {
			return match[1] ?? "";
		}
	}
	throw new Error(`SHA256SUMS has no entry for ${archiveName}.`);
}

function executeSoftwareCommand(command: string, args: string[]): void {
	execFileSync(command, args, { stdio: "inherit" });
}

function run(
	execute: SoftwareCommandRunner,
	command: string,
	args: string[],
	ignoreFailure = false,
): void {
	try {
		execute(command, args);
	} catch (error) {
		if (!ignoreFailure) {
			throw error;
		}
	}
}

export function nativeSoftwareUpdateGateway(
	execute: SoftwareCommandRunner = executeSoftwareCommand,
): SoftwareUpdateGateway {
	return {
		install: (archivePath) => run(execute, "npm", ["install", "--global", archivePath]),
		request: githubRequest,
		restart(platform) {
			if (platform === "linux") {
				run(execute, "/usr/bin/systemctl", ["restart", "argus-ids-broker.service"]);
				run(execute, "/usr/bin/systemctl", ["restart", "argus-ids.service"]);
				return;
			}
			run(
				execute,
				"/bin/launchctl",
				["kickstart", "-k", "system/com.argus.ids-agent.broker"],
				true,
			);
			run(execute, "/bin/launchctl", ["kickstart", "-k", "system/com.argus.ids-agent"]);
		},
	};
}

export async function installSoftwareUpdate(
	root: string,
	currentVersion: string,
	platform: HostIdentity["platform"],
	effectiveUserId: number,
	gateway: SoftwareUpdateGateway = nativeSoftwareUpdateGateway(),
): Promise<SoftwareRelease> {
	if (effectiveUserId !== 0) {
		throw new Error("Administrator authorization is required to update Argus.");
	}
	const release = await checkSoftwareUpdate(currentVersion, gateway.request);
	if (!release.updateAvailable) {
		return release;
	}
	const directory = mkdtempSync(join(tmpdir(), "argus-update-"));
	try {
		const [archive, checksumFile] = await Promise.all([
			responseBytes(release.archiveUrl, gateway.request),
			responseBytes(release.checksumUrl, gateway.request),
		]);
		const checksum = createHash("sha256").update(archive).digest("hex");
		const expected = expectedChecksum(checksumFile.toString("utf8"), release.archiveName);
		if (checksum !== expected) {
			throw new Error("The Argus release checksum does not match SHA256SUMS.");
		}
		const archivePath = join(directory, basename(release.archiveName));
		writeFileSync(archivePath, archive, { mode: 0o600 });
		gateway.install(archivePath);
		gateway.restart(platform);
		const owner = statSync(root);
		recordEvidence(root, "software.updated", `${currentVersion}:${release.latestVersion}:${checksum}`);
		chownSync(statePaths(root).eventLog, owner.uid, owner.gid);
		return release;
	} finally {
		rmSync(directory, { force: true, recursive: true });
	}
}
