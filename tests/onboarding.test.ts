import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test, vi } from "vitest";

import { bootstrap } from "../src/bootstrap.js";
import type { OnboardingAnswers } from "../src/contracts.js";
import type { Questioner } from "../src/onboarding.js";
import {
	askOnboardingQuestions,
	readPolicy,
	terminalQuestioner,
	updatePolicy,
} from "../src/onboarding.js";

class AnswerQueue implements Questioner {
	closed = false;
	readonly messages: string[] = [];
	readonly prompts: string[] = [];

	constructor(private readonly answers: string[]) {}

	close(): void {
		this.closed = true;
	}

	question(prompt: string): Promise<string> {
		this.prompts.push(prompt);
		return Promise.resolve(this.answers.shift() ?? "");
	}

	write(message: string): void {
		this.messages.push(message);
	}
}

function answers(devicePurpose: string): OnboardingAnswers {
	return {
		adminContact: "security@example.test",
		approvedAgentRuntimes: ["codex"],
		criticalPaths: ["/etc"],
		devicePurpose,
		expectedServices: ["sshd"],
		maintenanceWindow: "Sunday 02:00",
		responseMode: "approval-required",
		retentionDays: 30,
		reviewSchedule: "every 2 days",
	};
}

describe("onboarding", () => {
	test("connects the onboarding flow to terminal input and output", async () => {
		const close = vi.fn();
		const question = vi.fn(() => Promise.resolve("answer"));
		const write = vi.fn();
		const terminal = terminalQuestioner({ close, question }, { write });

		await expect(terminal.question("Prompt: ")).resolves.toBe("answer");
		terminal.write("Message");
		terminal.close();

		expect(question).toHaveBeenCalledWith("Prompt: ");
		expect(write).toHaveBeenCalledWith("Message\n");
		expect(close).toHaveBeenCalledOnce();
	});

	test("collects every policy answer", async () => {
		const terminal = new AnswerQueue([
			"Developer laptop",
			"security@example.test",
			"argus-01@agentmail.to",
			"admin@example.test, operator@example.test",
			"",
			"Sunday 02:00",
			"/etc, /srv/app",
			"sshd, postgresql",
			"codex, local-review-agent",
			"autonomous-action",
			"yes",
			"weekly",
			"45",
			"512",
			"argus-audit",
			"yes",
		]);

		await expect(askOnboardingQuestions(terminal, "skip")).resolves.toEqual({
			adminContact: "security@example.test",
			agentMailInbox: "argus-01@agentmail.to",
			automaticProcessTermination: true,
			approvedAgentRuntimes: ["codex", "local-review-agent"],
			criticalPaths: ["/etc", "/srv/app"],
			devicePurpose: "Developer laptop",
			expectedServices: ["sshd", "postgresql"],
			emailAllowedSenders: ["admin@example.test", "operator@example.test"],
			emailReportRecipients: ["admin@example.test", "operator@example.test"],
			logCacheMaxBytes: 536_870_912,
			maintenanceWindow: "Sunday 02:00",
			responseMode: "autonomous-action",
			retentionDays: 45,
			reviewSchedule: "weekly",
			s3ArchiveBucket: "argus-audit",
		});
		expect(terminal.closed).toBe(true);
		expect(terminal.prompts).toEqual([
			"Device purpose: ",
			"Primary security contact email or local-only [local-only] ",
			"Agent Mail inbox email or skip [skip] ",
			"Allowed email senders (comma-separated) [security@example.test] ",
			"Report recipients (comma-separated) [admin@example.test,operator@example.test] ",
			"Time for planned sensor and configuration changes (example: Sunday 02:00 UTC): ",
			"Critical paths (comma-separated) [none] ",
			"Expected services (comma-separated) [none] ",
			"Approved agents (comma-separated) [none] ",
			"Response mode: report-only, approval-required, or autonomous-action [approval-required] ",
			"Allow automatic termination of a confirmed malicious process? yes or no [no] ",
			"Review schedule [every 2 days] ",
			"Local evidence and report retention days [30] ",
			"Local log limit MB [1024] ",
			"S3 archive bucket or none [none] ",
			"Save this setup? yes or no [yes] ",
		]);
		expect(terminal.messages).toContain("Review this setup:");
	});

	test("applies conservative optional defaults", async () => {
		const terminal = new AnswerQueue([
			"Server",
			"",
			"skip",
			"",
			"",
			"Saturday 01:00",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
		]);

		const result = await askOnboardingQuestions(terminal, "skip");
		expect(result.adminContact).toBe("local-only");
		expect(result.agentMailInbox).toBeNull();
		expect(result.criticalPaths).toEqual([]);
		expect(result.expectedServices).toEqual([]);
		expect(result.approvedAgentRuntimes).toEqual([]);
		expect(result.automaticProcessTermination).toBe(false);
		expect(result.responseMode).toBe("approval-required");
		expect(result.reviewSchedule).toBe("every 2 days");
		expect(result.retentionDays).toBe(30);
		expect(result.emailAllowedSenders).toEqual([]);
		expect(result.emailReportRecipients).toEqual([]);
		expect(result.logCacheMaxBytes).toBe(1_073_741_824);
		expect(result.s3ArchiveBucket).toBeNull();
	});

	test("cancels before save when the operator rejects the summary", async () => {
		const terminal = new AnswerQueue([
			"Server",
			"",
			"skip",
			"",
			"",
			"Saturday 01:00 UTC",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"",
			"no",
		]);

		await expect(askOnboardingQuestions(terminal, "skip"))
			.rejects.toThrow("cancelled before save");
		expect(terminal.closed).toBe(true);
	});

	test("rejects an empty required answer and closes the terminal", async () => {
		const terminal = new AnswerQueue([""]);

		await expect(askOnboardingQuestions(terminal, "skip")).rejects.toThrow(
			"A value is required.",
		);
		expect(terminal.closed).toBe(true);
	});

	test("rejects an invalid response mode", async () => {
		const terminal = new AnswerQueue([
			"Server",
			"admin@example.test",
			"skip",
			"",
			"",
			"Saturday 01:00",
			"none",
			"none",
			"none",
			"unlimited",
			"daily",
			"30",
		]);

		await expect(askOnboardingQuestions(terminal, "skip")).rejects.toThrow();
	});

	test("updates policy fields and keeps the setup time", () => {
		const root = mkdtempSync(join(tmpdir(), "ids-onboarding-test-"));
		bootstrap(root, answers("Old purpose"), new Date("2026-01-02T03:04:05.000Z"));
		updatePolicy(root, answers("New purpose"));

		const policy = readPolicy(root);
		expect(policy.devicePurpose).toBe("New purpose");
		expect(policy.createdAt).toBe("2026-01-02T03:04:05.000Z");
	});
});
