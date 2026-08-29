import { appendFileSync } from "node:fs";

const target = process.argv[2];
const output = process.argv[3];
if (target === undefined || output === undefined) {
	throw new Error("Usage: availability-monitor.mjs TARGET OUTPUT");
}

let stopping = false;
process.on("SIGTERM", () => {
	stopping = true;
});
process.on("SIGINT", () => {
	stopping = true;
});

while (!stopping) {
	const startedAt = new Date().toISOString();
	let ok = false;
	try {
		const response = await fetch(target, { signal: AbortSignal.timeout(2_000) });
		ok = response.ok;
	} catch {
		ok = false;
	}
	appendFileSync(output, `${JSON.stringify({ ok, startedAt })}\n`);
	await new Promise((resolve) => setTimeout(resolve, 1_000));
}
