import { readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { extname, join } from "node:path";

const root = process.argv[2];
if (root === undefined) {
	throw new Error("Provide an artifact directory.");
}

const secretNames = [
	"OPENAI_API_KEY",
	"AGENTMAIL_API_KEY",
	"AWS_ACCESS_KEY_ID",
	"AWS_SECRET_ACCESS_KEY",
	"AWS_SESSION_TOKEN",
	"GITHUB_TOKEN",
	"ZAI_API_KEY",
];
const secrets = secretNames
	.map((name) => ({ name, value: process.env[name] ?? "" }))
	.filter((item) => item.value.length > 0);
const textExtensions = new Set([".json", ".jsonl", ".log", ".txt"]);

function artifactFiles(directory) {
	return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
		const path = join(directory, entry.name);
		return entry.isDirectory() ? artifactFiles(path) : [path];
	});
}

for (const path of artifactFiles(root)) {
	if (!textExtensions.has(extname(path))) {
		continue;
	}
	const original = readFileSync(path, "utf8");
	const redacted = secrets.reduce(
		(text, secret) => text.replaceAll(secret.value, `[REDACTED:${secret.name}]`),
		original,
	);
	if (redacted !== original) {
		const mode = statSync(path).mode;
		writeFileSync(path, redacted, { encoding: "utf8", mode });
	}
}
