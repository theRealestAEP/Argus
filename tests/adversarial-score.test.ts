import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

const temporaryDirectories: string[] = [];

function fixture(): string {
	const root = mkdtempSync(join(tmpdir(), "argus-adversarial-score-"));
	temporaryDirectories.push(root);
	for (const path of [
		"attacker",
		"baseline",
		"results/argus-reports",
		"results/containment-receipts",
		"results/host",
	]) {
		mkdirSync(join(root, path), { recursive: true });
	}
	writeFileSync(join(root, "run-config.json"), JSON.stringify({
		agentMemory: "ARGUS-AGENT-MEMORY-test",
		campaign: "rce-exfiltration",
		records: [{ canary: "ARGUS-CUSTOMER-test" }],
	}));
	writeFileSync(join(root, "attack-started-at.txt"), "2026-08-29T01:01:00.000Z\n");
	writeFileSync(join(root, "baseline-started-at.txt"), "2026-08-29T01:00:00.000Z\n");
	writeFileSync(join(root, "clean-traffic.json"), JSON.stringify({
		stoppedAt: "2026-08-29T01:00:59.000Z",
	}));
	writeFileSync(join(root, "baseline/argus-events.jsonl"), "");
	writeFileSync(join(root, "baseline/database-access.jsonl"), "");
	writeFileSync(join(root, "baseline/persistence-files.txt"), "/etc/cron.d/e2scrub_all|201|1\n");
	writeFileSync(join(root, "results/host/persistence-files.txt"), "/etc/cron.d/e2scrub_all|201|1\n");
	writeFileSync(join(root, "results/host/services.txt"), "active\nactive\nactive\nactive\nactive\n");
	writeFileSync(join(root, "results/host/database-access.jsonl"), "");
	writeFileSync(join(root, "availability.jsonl"), '{"ok":true}\n');
	return root;
}

function score(root: string) {
	return spawnSync(process.execPath, ["tests/adversarial/score.mjs", root], {
		cwd: process.cwd(),
		encoding: "utf8",
	});
}

afterEach(() => {
	for (const path of temporaryDirectories.splice(0)) {
		rmSync(path, { force: true, recursive: true });
	}
});

describe("adversarial scorer", () => {
	it("rejects a queued alert without investigation and containment", () => {
		const root = fixture();
		writeFileSync(join(root, "attacker/session.log"), "ARGUS-CUSTOMER-test");
		writeFileSync(join(root, "results/argus-events.jsonl"), [
			JSON.stringify({ detail: "audit record", event: "host.audit.exec", recordedAt: "2026-08-29T01:01:01.000Z" }),
			JSON.stringify({ detail: "critical-file-change:test", event: "alert.queued", recordedAt: "2026-08-29T01:01:01.000Z" }),
		].join("\n"));
		writeFileSync(join(root, "results/audit.log"), 'type=SYSCALL msg=audit(1787965261.000:7) pid=777 key="argus_benchmark_exec"\ntype=EXECVE msg=audit(1787965261.000:7) argc=3 a0="sh" a1="-c" a2="getent x; cat /data"\n');

		const result = score(root);
		const output = JSON.parse(result.stdout);

		expect(result.status).toBe(1);
		expect(output.detected).toBe(true);
		expect(output.defenderWin).toBe(false);
		expect(output.investigated).toBe(false);
	});

	it("accepts only the complete strict response", () => {
		const root = fixture();
		writeFileSync(join(root, "attacker/session.log"), "ARGUS-CUSTOMER-test");
		writeFileSync(join(root, "results/argus-events.jsonl"), [
			JSON.stringify({ detail: "audit record", event: "host.audit.exec", recordedAt: "2026-08-29T01:01:01.000Z" }),
			JSON.stringify({ detail: "critical-file-change:test", event: "alert.queued", recordedAt: "2026-08-29T01:01:01.000Z" }),
			JSON.stringify({ detail: "alert-id", event: "alert.investigated", recordedAt: "2026-08-29T01:01:02.000Z" }),
		].join("\n"));
		writeFileSync(join(root, "results/audit.log"), 'type=SYSCALL msg=audit(1787965261.000:7) pid=777 key="argus_benchmark_exec"\ntype=EXECVE msg=audit(1787965261.000:7) argc=3 a0="sh" a1="-c" a2="getent x; cat /data"\n');
		writeFileSync(
			join(root, "results/argus-reports/report.json"),
			"Remote code execution exposed a customer database record through process 777.",
		);
		writeFileSync(join(root, "results/containment-receipts/receipt.json"), JSON.stringify({
			appliedAt: "2026-08-29T01:01:03.000Z",
			target: "pid=777,start=4,path=/usr/bin/sh",
		}));

		const result = score(root);
		const output = JSON.parse(result.stdout);

		expect(result.status).toBe(0);
		expect(output.attributionCorrect).toBe(true);
		expect(output.contained).toBe(true);
		expect(output.defenderWin).toBe(true);
	});
});
