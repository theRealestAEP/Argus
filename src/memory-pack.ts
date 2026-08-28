import { createHash, sign, verify } from "node:crypto";
import { mkdirSync, readFileSync, readdirSync } from "node:fs";
import { join, relative } from "node:path";

import type { MemoryPackManifest } from "./contracts.js";
import { memoryPackManifestSchema } from "./contracts.js";
import { readInstallManifest } from "./bootstrap.js";
import { jsonText, writePrivate } from "./files.js";
import { statePaths } from "./paths.js";

function sha256(content: string): string {
	return createHash("sha256").update(content).digest("hex");
}

function packFiles(packRoot: string): string[] {
	const directories = [
		"actions",
		"assets",
		"baselines",
		"cases",
		"detections",
		"indexes",
		"operations",
		"operator",
		"timeline",
	];
	return directories.flatMap((directory) =>
		readdirSync(join(packRoot, directory), { withFileTypes: true })
			.filter((entry) => entry.isFile())
			.map((entry) => join(packRoot, directory, entry.name)),
	);
}

export function buildMemoryPack(root: string): string {
	const paths = statePaths(root);
	const manifest = readInstallManifest(root);
	const packRoot = join(paths.memoryPacks, "current");
	const directories = [
		"actions",
		"assets",
		"baselines",
		"cases",
		"detections",
		"indexes",
		"operations",
		"operator",
		"timeline",
	];
	for (const directory of directories) {
		mkdirSync(join(packRoot, directory), { mode: 0o700, recursive: true });
	}

	writePrivate(
		join(packRoot, "GUIDE.md"),
		"# Agent Memory Pack\n\nSearch this directory with `grep -R`. Verify `MANIFEST.json` before use.\n",
	);
	writePrivate(join(packRoot, "actions", "receipts.jsonl"), "");
	writePrivate(join(packRoot, "assets", "assets.jsonl"), jsonText(manifest.host));
	writePrivate(join(packRoot, "baselines", "baselines.jsonl"), "");
	writePrivate(join(packRoot, "cases", "cases.jsonl"), "");
	writePrivate(join(packRoot, "detections", "history.jsonl"), "");
	writePrivate(join(packRoot, "indexes", "terms.tsv"), "");
	writePrivate(join(packRoot, "indexes", "time.tsv"), "");
	writePrivate(
		join(packRoot, "operations", "install-state.md"),
		`# Install State\n\nAgent: ${manifest.agentId}\n\nHost: ${manifest.host.hostname}\n`,
	);
	writePrivate(
		join(packRoot, "operator", "decisions.jsonl"),
		`${readFileSync(paths.policy, "utf8").replace(/\n/gu, "")}\n`,
	);
	writePrivate(join(packRoot, "timeline", "events.jsonl"), "");

	const files = [join(packRoot, "GUIDE.md"), ...packFiles(packRoot)]
		.toSorted()
		.map((path) => ({
			path: relative(packRoot, path),
			sha256: sha256(readFileSync(path, "utf8")),
		}));
	const packManifest: MemoryPackManifest = {
		files,
		hostFingerprint: manifest.host.fingerprint,
		schemaVersion: 1,
	};
	const manifestText = jsonText(packManifest);
	writePrivate(join(packRoot, "MANIFEST.json"), manifestText);
	const signature = sign(
		null,
		Buffer.from(manifestText),
		readFileSync(paths.privateKey, "utf8"),
	);
	writePrivate(join(packRoot, "MANIFEST.sig"), `${signature.toString("base64")}\n`);
	return packRoot;
}

export function verifyMemoryPack(root: string, packRoot: string): boolean {
	const paths = statePaths(root);
	const manifestText = readFileSync(join(packRoot, "MANIFEST.json"), "utf8");
	const manifest = memoryPackManifestSchema.parse(JSON.parse(manifestText));
	const filesMatch = manifest.files.every((file) => {
		const content = readFileSync(join(packRoot, file.path), "utf8");
		return sha256(content) === file.sha256;
	});
	const signature = Buffer.from(
		readFileSync(join(packRoot, "MANIFEST.sig"), "utf8").trim(),
		"base64",
	);
	const signatureMatches = verify(
		null,
		Buffer.from(manifestText),
		readFileSync(paths.publicKey, "utf8"),
		signature,
	);
	return filesMatch && signatureMatches;
}
