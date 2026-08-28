import { randomUUID } from "node:crypto";
import { mkdirSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

export function jsonText<Value extends object>(value: Value): string {
	return `${JSON.stringify(value, null, 2)}\n`;
}

export function writePrivate(path: string, content: string): void {
	mkdirSync(dirname(path), { mode: 0o700, recursive: true });
	const temporaryPath = `${path}.${randomUUID()}.tmp`;
	writeFileSync(temporaryPath, content, { encoding: "utf8", mode: 0o600 });
	renameSync(temporaryPath, path);
}
