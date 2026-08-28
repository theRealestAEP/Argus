import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { gzipSync } from "node:zlib";

import type { IncidentReport, OnboardingPolicy } from "./contracts.js";
import { incidentReportSchema } from "./contracts.js";
import { readInstallManifest } from "./bootstrap.js";
import { jsonText, writePrivate } from "./files.js";
import { statePaths } from "./paths.js";
import { s3ArchiveGateway } from "./s3-native.js";

export interface ArchiveUpload {
	body: Uint8Array;
	bucket: string;
	checksumSha256: string;
	hostFingerprint: string;
	key: string;
	kmsKeyId: string | undefined;
	reportId: string;
}

export interface ArchiveGateway {
	put(upload: ArchiveUpload): Promise<string>;
}

function archiveKey(prefix: string, report: IncidentReport, digest: string): string {
	const day = report.createdAt.slice(0, 10);
	const cleanPrefix = prefix.replace(/^\/+|\/+$/gu, "");
	return `${cleanPrefix}/${day}/${report.id}-${digest}.json.gz`;
}

export async function archiveIncidentReports(
	root: string,
	policy: OnboardingPolicy,
	gateway: ArchiveGateway = s3ArchiveGateway(),
	prefix = process.env.IDS_AGENT_S3_PREFIX ?? "argus",
	kmsKeyId = process.env.IDS_AGENT_S3_KMS_KEY_ID,
): Promise<number> {
	const bucket = policy.s3ArchiveBucket;
	if (bucket === undefined || bucket === null) {
		return 0;
	}
	const paths = statePaths(root);
	const hostFingerprint = readInstallManifest(root).host.fingerprint;
	let uploaded = 0;
	for (const name of readdirSync(paths.reports).toSorted()) {
		const receiptPath = join(paths.archiveReceipts, `${name}.json`);
		if (existsSync(receiptPath)) {
			continue;
		}
		const text = readFileSync(join(paths.reports, name), "utf8");
		const report = incidentReportSchema.parse(JSON.parse(text));
		const body = gzipSync(text, { level: 9 });
		const digest = createHash("sha256").update(body).digest();
		const key = archiveKey(prefix, report, digest.toString("hex"));
		const etag = await gateway.put({
			body,
			bucket,
			checksumSha256: digest.toString("base64"),
			hostFingerprint,
			key,
			kmsKeyId,
			reportId: report.id,
		});
		writePrivate(receiptPath, jsonText({ archivedAt: new Date().toISOString(), etag, key }));
		uploaded += 1;
	}
	return uploaded;
}
