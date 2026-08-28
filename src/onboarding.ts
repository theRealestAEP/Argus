import { sign, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { createInterface } from "node:readline/promises";
import { stdin, stdout } from "node:process";

import type { OnboardingAnswers, OnboardingPolicy } from "./contracts.js";
import { onboardingPolicySchema } from "./contracts.js";
import { jsonText, writePrivate } from "./files.js";
import { statePaths } from "./paths.js";

export type Questioner = {
	close(): void;
	question(prompt: string): Promise<string>;
};

async function requiredAnswer(terminal: Questioner, prompt: string): Promise<string> {
	const answer = (await terminal.question(prompt)).trim();
	if (answer.length === 0) {
		throw new Error("A value is required.");
	}
	return answer;
}

async function answerWithDefault(
	terminal: Questioner,
	prompt: string,
	defaultAnswer: string,
): Promise<string> {
	const answer = (await terminal.question(`${prompt} [${defaultAnswer}] `)).trim();
	return answer.length === 0 ? defaultAnswer : answer;
}

function answerList(answer: string): string[] {
	return answer === "none"
		? []
		: answer.split(",").map((item) => item.trim()).filter((item) => item.length > 0);
}

export async function askOnboardingQuestions(
	terminal: Questioner = createInterface({ input: stdin, output: stdout }),
	defaultAgentMailInbox = process.env.IDS_AGENT_AGENTMAIL_INBOX_ID ?? "skip",
): Promise<OnboardingAnswers> {
	try {
		const devicePurpose = await requiredAnswer(terminal, "Device purpose: ");
		const adminContact = await answerWithDefault(
			terminal,
			"Alert recipient",
			"local-only",
		);
		const inboxAnswer = await answerWithDefault(
			terminal,
			"Agent Mail inbox",
			defaultAgentMailInbox,
		);
		const agentMailInbox = inboxAnswer === "skip" ? null : inboxAnswer;
		const defaultEmail = adminContact === "local-only" ? "none" : adminContact;
		const emailAllowedSenders = answerList(
			await answerWithDefault(terminal, "Allowed email senders", defaultEmail),
		);
		const emailReportRecipients = answerList(
			await answerWithDefault(terminal, "Report recipients", defaultEmail),
		);
		const maintenanceWindow = await requiredAnswer(
			terminal,
			"Change window: ",
		);
		const criticalPaths = answerList(
			await answerWithDefault(terminal, "Critical paths (comma-separated)", "none"),
		);
		const expectedServices = answerList(
			await answerWithDefault(terminal, "Expected services (comma-separated)", "none"),
		);
		const approvedAgentRuntimes = answerList(
			await answerWithDefault(
				terminal,
				"Approved agents (comma-separated)",
				"none",
			),
		);
		const responseMode = await answerWithDefault(
			terminal,
			"Response mode: report-only, approval-required, or autonomous-reversible",
			"approval-required",
		);
		const reviewSchedule = await answerWithDefault(
			terminal,
			"Review schedule",
			"every 2 days",
		);
		const retentionDays = Number.parseInt(
			await answerWithDefault(terminal, "Evidence retention days", "30"),
			10,
		);
		const logCacheMaxBytes =
			Number.parseInt(
				await answerWithDefault(terminal, "Local log limit MB", "1024"),
				10,
			) * 1_048_576;
		const bucketAnswer = await answerWithDefault(
			terminal,
			"S3 archive bucket",
			"none",
		);
		return onboardingPolicySchema.omit({ createdAt: true }).parse({
			adminContact,
			agentMailInbox,
			approvedAgentRuntimes,
			criticalPaths,
			devicePurpose,
			expectedServices,
			emailAllowedSenders,
			emailReportRecipients,
			logCacheMaxBytes,
			maintenanceWindow,
			responseMode,
			retentionDays,
			reviewSchedule,
			s3ArchiveBucket: bucketAnswer === "none" ? null : bucketAnswer,
		});
	} finally {
		terminal.close();
	}
}

export function readPolicy(root: string): OnboardingPolicy {
	const paths = statePaths(root);
	const text = readFileSync(paths.policy, "utf8");
	const signature = Buffer.from(
		readFileSync(paths.policySignature, "utf8").trim(),
		"base64",
	);
	const publicKey = readFileSync(paths.publicKey, "utf8");
	if (!verify(null, Buffer.from(text), publicKey, signature)) {
		throw new Error("The onboarding policy signature is invalid.");
	}
	return onboardingPolicySchema.parse(JSON.parse(text));
}

export function updatePolicy(
	root: string,
	answers: OnboardingAnswers,
): void {
	const oldPolicy = readPolicy(root);
	const paths = statePaths(root);
	const text = jsonText({
		...answers,
		createdAt: oldPolicy.createdAt,
	});
	writePrivate(paths.policy, text);
	const signature = sign(
		null,
		Buffer.from(text),
		readFileSync(paths.privateKey, "utf8"),
	);
	writePrivate(paths.policySignature, `${signature.toString("base64")}\n`);
}
