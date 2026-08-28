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
	write(message: string): void;
};

type LineWriter = {
	write(message: string): boolean | void;
};

export function terminalQuestioner(
	terminal: Pick<Questioner, "close" | "question"> = createInterface({
		input: stdin,
		output: stdout,
	}),
	writer: LineWriter = stdout,
): Questioner {
	return {
		close: () => terminal.close(),
		question: (prompt) => terminal.question(prompt),
		write: (message) => writer.write(`${message}\n`),
	};
}

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

function listText(values: string[]): string {
	return values.length === 0 ? "none" : values.join(", ");
}

function yesOrNo(answer: string): boolean {
	const value = answer.toLowerCase();
	if (value === "yes" || value === "y") {
		return true;
	}
	if (value === "no" || value === "n") {
		return false;
	}
	throw new Error("Enter yes or no.");
}

function showIntroduction(terminal: Questioner): void {
	terminal.write("Argus first-time setup");
	terminal.write("Press Enter to accept a value shown in brackets.");
	terminal.write("Use commas to separate multiple paths, services, agents, or email addresses.");
	terminal.write("The planned change window applies to routine configuration work. Emergency response follows the response mode.");
	terminal.write("");
}

function showSummary(terminal: Questioner, answers: OnboardingAnswers): void {
	terminal.write("");
	terminal.write("Review this setup:");
	terminal.write(`  Device purpose: ${answers.devicePurpose}`);
	terminal.write(`  Primary security contact: ${answers.adminContact}`);
	terminal.write(`  Agent Mail inbox: ${answers.agentMailInbox ?? "local-only"}`);
	terminal.write(`  Allowed email senders: ${listText(answers.emailAllowedSenders ?? [])}`);
	terminal.write(`  Report recipients: ${listText(answers.emailReportRecipients ?? [])}`);
	terminal.write(`  Planned change window: ${answers.maintenanceWindow}`);
	terminal.write(`  Critical paths: ${listText(answers.criticalPaths)}`);
	terminal.write(`  Expected services: ${listText(answers.expectedServices)}`);
	terminal.write(`  Approved agents: ${listText(answers.approvedAgentRuntimes)}`);
	terminal.write(`  Response mode: ${answers.responseMode}`);
	terminal.write(`  Automatic process termination: ${answers.automaticProcessTermination === true ? "allowed" : "approval required"}`);
	terminal.write(`  Review schedule: ${answers.reviewSchedule}`);
	terminal.write(`  Local retention: ${answers.retentionDays} days`);
	terminal.write(`  Local log limit: ${answers.logCacheMaxBytes ?? 1_073_741_824} bytes`);
	terminal.write(`  S3 archive bucket: ${answers.s3ArchiveBucket ?? "none"}`);
}

async function collectAnswers(
	terminal: Questioner,
	defaultAgentMailInbox: string,
): Promise<OnboardingAnswers> {
	const devicePurpose = await requiredAnswer(terminal, "Device purpose: ");
	const adminContact = await answerWithDefault(
		terminal,
		"Primary security contact email or local-only",
		"local-only",
	);
	const inboxAnswer = await answerWithDefault(
		terminal,
		"Agent Mail inbox email or skip",
		defaultAgentMailInbox,
	);
	const agentMailInbox = inboxAnswer === "skip" ? null : inboxAnswer;
	const defaultEmail = adminContact === "local-only" ? "none" : adminContact;
	const emailAllowedSenders = answerList(
		await answerWithDefault(
			terminal,
			"Allowed email senders (comma-separated)",
			defaultEmail,
		),
	);
	const reportRecipientDefault = emailAllowedSenders.length === 0
		? defaultEmail
		: emailAllowedSenders.join(",");
	const emailReportRecipients = answerList(
		await answerWithDefault(
			terminal,
			"Report recipients (comma-separated)",
			reportRecipientDefault,
		),
	);
	const maintenanceWindow = await requiredAnswer(
		terminal,
		"Time for planned sensor and configuration changes (example: Sunday 02:00 UTC): ",
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
		"Response mode: report-only, approval-required, or autonomous-action",
		"approval-required",
	);
	const automaticProcessTermination = yesOrNo(await answerWithDefault(
		terminal,
		"Allow automatic termination of a confirmed malicious process? yes or no",
		"no",
	));
	const reviewSchedule = await answerWithDefault(
		terminal,
		"Review schedule",
		"every 2 days",
	);
	const retentionDays = Number.parseInt(
		await answerWithDefault(terminal, "Local evidence and report retention days", "30"),
		10,
	);
	const logCacheMaxBytes =
		Number.parseInt(
			await answerWithDefault(terminal, "Local log limit MB", "1024"),
			10,
		) * 1_048_576;
	const bucketAnswer = await answerWithDefault(
		terminal,
		"S3 archive bucket or none",
		"none",
	);
	return onboardingPolicySchema.omit({ createdAt: true }).parse({
		adminContact,
		agentMailInbox,
		automaticProcessTermination,
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
}

export async function askOnboardingQuestions(
	terminal: Questioner = terminalQuestioner(),
	defaultAgentMailInbox = process.env.IDS_AGENT_AGENTMAIL_INBOX_ID ?? "skip",
): Promise<OnboardingAnswers> {
	try {
		showIntroduction(terminal);
		const answers = await collectAnswers(terminal, defaultAgentMailInbox);
		showSummary(terminal, answers);
		const confirmation = (
			await answerWithDefault(terminal, "Save this setup? yes or no", "yes")
		).toLowerCase();
		if (confirmation !== "yes" && confirmation !== "y") {
			throw new Error("Setup cancelled before save.");
		}
		return answers;
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
