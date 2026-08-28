import { randomUUID } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

const eventDirectory = process.argv[2];
const target = process.argv[3];
const worker = process.argv[4];
const observedAt = new Date().toISOString();
const event = {
	action: "unauthorized-file-write",
	id: randomUUID(),
	observedAt,
	pid: process.pid,
	runtime: "containment-load-worker.mjs",
	target,
};

mkdirSync(dirname(target), { recursive: true });
writeFileSync(target, `${JSON.stringify({ worker })}\n`);
writeFileSync(join(eventDirectory, `${observedAt}-${event.id}.json`), JSON.stringify(event));
setInterval(() => undefined, 60_000);
