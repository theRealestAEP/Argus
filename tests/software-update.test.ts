import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, test, vi } from "vitest";

import { bootstrap } from "../src/bootstrap.js";
import {
	checkSoftwareUpdate,
	compareVersions,
	installSoftwareUpdate,
	isGlobalSoftwareInstall,
	nativeSoftwareUpdateGateway,
	readSoftwareVersion,
	type SoftwareUpdateGateway,
} from "../src/software-update.js";

const archive = Buffer.from("release archive");
const checksum = createHash("sha256").update(archive).digest("hex");
const release = {
	assets: [
		{
			browser_download_url: "https://example.test/argus.tgz",
			name: "on-device-ids-agent-0.2.0.tgz",
		},
		{
			browser_download_url: "https://example.test/SHA256SUMS",
			name: "SHA256SUMS",
		},
	],
	html_url: "https://example.test/release",
	tag_name: "v0.2.0",
};

function response(value: BodyInit, status = 200): Response {
	return new Response(value, { status });
}

function root(): string {
	const state = mkdtempSync(join(tmpdir(), "argus-update-test-"));
	bootstrap(state, {
		adminContact: "local-only",
		approvedAgentRuntimes: [],
		criticalPaths: [],
		devicePurpose: "update test",
		expectedServices: [],
		maintenanceWindow: "Sunday 02:00",
		responseMode: "approval-required",
		retentionDays: 30,
		reviewSchedule: "weekly",
	});
	return state;
}

describe("software updates", () => {
	afterEach(() => {
		delete process.env.GITHUB_TOKEN;
		vi.clearAllMocks();
		vi.unstubAllGlobals();
	});

	test("compares release versions", () => {
		expect(compareVersions("0.1.0", "0.2.0")).toBeLessThan(0);
		expect(compareVersions("1.0.0", "1.0.0")).toBe(0);
		expect(compareVersions("2.0.0", "1.9.9")).toBeGreaterThan(0);
	});

	test("identifies a global package directory", () => {
		expect(isGlobalSoftwareInstall(
			"/opt/node/lib/node_modules/on-device-ids-agent",
			"/opt/node/lib/node_modules",
		)).toBe(true);
		expect(isGlobalSoftwareInstall("/work/Argus", "/opt/node/lib/node_modules")).toBe(false);
	});

	test("reads the package version and the default global root", () => {
		const globalRoot = execFileSync(
			"npm",
			["root", "--global"],
			{ encoding: "utf8" },
		).trim();
		expect(readSoftwareVersion(process.cwd())).toBe("0.1.0");
		expect(isGlobalSoftwareInstall(
			join(globalRoot, "on-device-ids-agent"),
		)).toBe(true);
	});

	test("finds the latest verified release assets", async () => {
		const result = await checkSoftwareUpdate(
			"0.1.0",
			() => Promise.resolve(response(JSON.stringify(release))),
		);
		expect(result.updateAvailable).toBe(true);
		expect(result.archiveName).toBe("on-device-ids-agent-0.2.0.tgz");
	});

	test("explains when no release exists", async () => {
		await expect(checkSoftwareUpdate(
			"0.1.0",
			() => Promise.resolve(response("missing", 404)),
		)).rejects.toThrow("No published Argus release");
	});

	test("uses an authenticated GitHub request", async () => {
		process.env.GITHUB_TOKEN = "test-token";
		const fetchMock = vi.fn<typeof fetch>();
		fetchMock.mockResolvedValue(response(JSON.stringify(release)));
		vi.stubGlobal("fetch", fetchMock);
		await checkSoftwareUpdate("0.1.0");
		const request = fetchMock.mock.calls[0]?.[1];
		expect(new Headers(request?.headers).get("authorization")).toBe("Bearer test-token");
	});

	test("rejects failed requests and incomplete releases", async () => {
		await expect(checkSoftwareUpdate(
			"0.1.0",
			() => Promise.resolve(response("error", 500)),
		)).rejects.toThrow("HTTP 500");
		await expect(checkSoftwareUpdate(
			"0.1.0",
			() => Promise.resolve(response(JSON.stringify({ ...release, assets: [] }))),
		)).rejects.toThrow("lacks the Argus archive");
	});

	test("runs native install and service restart commands", () => {
		const execute = vi.fn<(command: string, args: string[]) => void>();
		const gateway = nativeSoftwareUpdateGateway(execute);
		gateway.install("/tmp/argus.tgz");
		gateway.restart("linux");
		gateway.restart("darwin");
		expect(execute).toHaveBeenCalledWith(
			"npm",
			["install", "--global", "/tmp/argus.tgz"],
		);
		expect(execute).toHaveBeenCalledWith(
			"/bin/launchctl",
			["kickstart", "-k", "system/com.argus.ids-agent"],
		);
	});

	test("continues when an old macOS broker service is absent", () => {
		const execute = vi.fn<(command: string, args: string[]) => void>();
		execute.mockImplementationOnce(() => {
			throw new Error("service absent");
		});
		nativeSoftwareUpdateGateway(execute).restart("darwin");
		expect(execute).toHaveBeenCalledTimes(3);
	});

	test("installs a matching archive and restarts the service", async () => {
		const install = vi.fn();
		const restart = vi.fn();
		const gateway: SoftwareUpdateGateway = {
			install,
			request(url) {
				if (url.endsWith("argus.tgz")) {
					return Promise.resolve(response(archive));
				}
				if (url.endsWith("SHA256SUMS")) {
					return Promise.resolve(response(`${checksum}  on-device-ids-agent-0.2.0.tgz\n`));
				}
				return Promise.resolve(response(JSON.stringify(release)));
			},
			restart,
		};
		const result = await installSoftwareUpdate(root(), "0.1.0", "darwin", 0, gateway);
		expect(result.latestVersion).toBe("0.2.0");
		expect(install).toHaveBeenCalledOnce();
		expect(restart).toHaveBeenCalledWith("darwin");
	});

	test("rejects checksum changes and unprivileged updates", async () => {
		const gateway: SoftwareUpdateGateway = {
			install: vi.fn(),
			request(url) {
				if (url.endsWith("argus.tgz")) {
					return Promise.resolve(response(archive));
				}
				if (url.endsWith("SHA256SUMS")) {
					return Promise.resolve(response(`${"0".repeat(64)}  on-device-ids-agent-0.2.0.tgz\n`));
				}
				return Promise.resolve(response(JSON.stringify(release)));
			},
			restart: vi.fn(),
		};
		await expect(installSoftwareUpdate(root(), "0.1.0", "linux", 0, gateway))
			.rejects.toThrow("checksum");
		await expect(installSoftwareUpdate(root(), "0.1.0", "linux", 501, gateway))
			.rejects.toThrow("Administrator authorization");
	});

	test("returns without installation when the current release is installed", async () => {
		const install = vi.fn();
		const gateway: SoftwareUpdateGateway = {
			install,
			request: () => Promise.resolve(response(JSON.stringify({
				...release,
				tag_name: "v0.1.0",
				assets: release.assets.map((asset) => ({
					...asset,
					name: asset.name.replace("0.2.0", "0.1.0"),
				})),
			}))),
			restart: vi.fn(),
		};
		const result = await installSoftwareUpdate(root(), "0.1.0", "linux", 0, gateway);
		expect(result.updateAvailable).toBe(false);
		expect(install).not.toHaveBeenCalled();
	});

	test("rejects a checksum file without the archive", async () => {
		const gateway: SoftwareUpdateGateway = {
			install: vi.fn(),
			request(url) {
				if (url.endsWith("argus.tgz")) {
					return Promise.resolve(response(archive));
				}
				if (url.endsWith("SHA256SUMS")) {
					return Promise.resolve(response(`${checksum}  another-file.tgz\n`));
				}
				return Promise.resolve(response(JSON.stringify(release)));
			},
			restart: vi.fn(),
		};
		await expect(installSoftwareUpdate(root(), "0.1.0", "linux", 0, gateway))
			.rejects.toThrow("has no entry");
	});
});
