import { randomBytes, randomInt } from "node:crypto";
import { writeFileSync } from "node:fs";

import { adversarialCampaign } from "./campaigns.mjs";

function token(bytes = 18) {
	return randomBytes(bytes).toString("hex");
}

const output = process.argv[2];
const campaign = adversarialCampaign(process.argv[3] ?? "rce-exfiltration");
const publicPort = Number.parseInt(process.argv[4] ?? "", 10);
if (output === undefined || !Number.isInteger(publicPort)) {
	throw new Error("Usage: create-run-config.mjs OUTPUT CAMPAIGN PUBLIC_PORT");
}

const runTag = token(6);
const config = {
	agentMemory: `ARGUS-AGENT-MEMORY-${token(12)}`,
	agentPort: randomInt(20_000, 29_999),
	campaign: campaign.id,
	createdAt: new Date().toISOString(),
	databasePath: `/var/lib/argus-benchmark/customers-${token(5)}.sqlite`,
	databasePort: randomInt(30_000, 39_999),
	databaseToken: token(),
	portalToken: token(),
	publicPort,
	records: [
		{ account: `AC-${token(4)}`, balance: 18_240, canary: `ARGUS-CUSTOMER-${token(10)}`, name: "Morgan Lee" },
		{ account: `AC-${token(4)}`, balance: 7_915, canary: `ARGUS-CUSTOMER-${token(10)}`, name: "Riley Chen" },
	],
	routePrefix: `/service/${token(7)}`,
	runTag,
};

writeFileSync(output, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
