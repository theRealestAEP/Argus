import { randomUUID, sign, verify } from "node:crypto";
import {
	readFileSync,
	readdirSync,
	renameSync,
	unlinkSync,
} from "node:fs";
import { basename, join } from "node:path";

import {
	applyContainment,
	authorizeContainment,
	type ContainmentGateway,
	type ContainmentReceipt,
} from "./containment.js";
import type { ContainmentPlan, ContainmentRequest } from "./contracts.js";
import { containmentRequestSchema } from "./contracts.js";
import { jsonText, writePrivate } from "./files.js";
import { readPolicy } from "./onboarding.js";
import { statePaths } from "./paths.js";

export function requestAutomaticContainment(
	root: string,
	plan: ContainmentPlan,
	now = new Date(),
): ContainmentRequest {
	const policy = readPolicy(root);
	if (authorizeContainment(policy, plan) !== "allowed") {
		throw new Error("The operating policy requires approval for this containment plan.");
	}
	const request = containmentRequestSchema.parse({
		id: randomUUID(),
		plan,
		requestedAt: now.toISOString(),
	});
	const paths = statePaths(root);
	const text = jsonText(request);
	const signature = sign(null, Buffer.from(text), readFileSync(paths.privateKey, "utf8"));
	writePrivate(join(paths.brokerRequests, `${request.id}.json`), text);
	writePrivate(join(paths.brokerRequests, `${request.id}.sig`), `${signature.toString("base64")}\n`);
	return request;
}

function verifiedRequest(root: string, path: string): ContainmentRequest {
	const paths = statePaths(root);
	const text = readFileSync(path, "utf8");
	const signaturePath = path.replace(/\.json$/u, ".sig");
	const signature = Buffer.from(readFileSync(signaturePath, "utf8").trim(), "base64");
	const valid = verify(
		null,
		Buffer.from(text),
		readFileSync(paths.publicKey, "utf8"),
		signature,
	);
	if (!valid) {
		throw new Error("The containment request signature is invalid.");
	}
	return containmentRequestSchema.parse(JSON.parse(text));
}

function rejectRequest(root: string, path: string): void {
	const paths = statePaths(root);
	const name = basename(path, ".json");
	renameSync(path, join(paths.brokerRejected, `${name}.json`));
	renameSync(
		path.replace(/\.json$/u, ".sig"),
		join(paths.brokerRejected, `${name}.sig`),
	);
}

export function processBrokerRequests(
	root: string,
	effectiveUserId: number,
	gateway?: ContainmentGateway,
): ContainmentReceipt[] {
	if (effectiveUserId !== 0) {
		throw new Error("The containment broker must run as root.");
	}
	const paths = statePaths(root);
	const receipts: ContainmentReceipt[] = [];
	for (const name of readdirSync(paths.brokerRequests).filter((item) => item.endsWith(".json"))) {
		const path = join(paths.brokerRequests, name);
		try {
			const request = verifiedRequest(root, path);
			const policy = readPolicy(root);
			if (authorizeContainment(policy, request.plan) !== "allowed") {
				throw new Error("The signed policy does not permit automatic containment.");
			}
			receipts.push(applyContainment(root, policy, request.plan, 0, gateway));
			unlinkSync(path);
			unlinkSync(path.replace(/\.json$/u, ".sig"));
		} catch {
			rejectRequest(root, path);
		}
	}
	return receipts;
}

export async function runContainmentBroker(
	root: string,
	wait: () => Promise<void>,
): Promise<void> {
	processBrokerRequests(root, process.geteuid?.() ?? -1);
	const timer = setInterval(
		() => processBrokerRequests(root, process.geteuid?.() ?? -1),
		2_000,
	);
	try {
		await wait();
	} finally {
		clearInterval(timer);
	}
}
