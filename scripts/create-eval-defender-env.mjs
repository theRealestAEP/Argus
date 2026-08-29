import { writeFileSync } from "node:fs";

const output = process.argv[2];
if (output === undefined) {
	throw new Error("Provide an output path.");
}

const key = (process.env.OPENAI_API_KEY ?? "").trim();
if (key.length === 0) {
	throw new Error("Set OPENAI_API_KEY in .env before you run the evaluation.");
}

const values = [
	["OPENAI_API_KEY", key],
	["IDS_AGENT_PRIMARY_MODEL", process.env.IDS_AGENT_PRIMARY_MODEL],
	["IDS_AGENT_FALLBACK_MODEL", process.env.IDS_AGENT_FALLBACK_MODEL],
];
const text = values
	.filter((entry) => entry[1] !== undefined && entry[1]?.length > 0)
	.map((entry) => `${entry[0]}=${entry[1]}`)
	.join("\n");
writeFileSync(output, `${text}\n`, { encoding: "utf8", mode: 0o600 });
