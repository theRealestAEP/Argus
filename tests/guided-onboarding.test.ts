import { describe, expect, test, vi } from "vitest";

import type { GuidedOnboardingTurn } from "../src/contracts.js";
import {
	conductGuidedOnboarding,
	conductSensorPlanReview,
	type GuidedTurn,
	type SensorReviewTurn,
} from "../src/guided-onboarding.js";
import type { GuidedOnboardingContext } from "../src/model-runtime.js";

const context: GuidedOnboardingContext = {
	defaultAgentMailInbox: "argus@example.test",
	host: { arch: "x64", hostname: "host", platform: "linux" },
	observed: { establishedConnectionCount: 2, listenerCount: 1, processCount: 10 },
};

const policy = {
	adminContact: "security@example.test",
	agentMailInbox: "argus@example.test",
	automaticProcessTermination: false,
	approvedAgentRuntimes: ["local-assistant"],
	criticalPaths: ["/opt/app"],
	devicePurpose: "Internal application server",
	emailAllowedSenders: ["security@example.test"],
	emailReportRecipients: ["security@example.test"],
	expectedServices: ["operations-api"],
	logCacheMaxBytes: 268_435_456,
	maintenanceWindow: "Sunday 02:00 UTC",
	responseMode: "approval-required" as const,
	retentionDays: 30,
	reviewSchedule: "every 2 days",
	s3ArchiveBucket: null,
};

function terminal(answer: string) {
	const close = vi.fn();
	return {
		close,
		questioner: {
			close,
			question: vi.fn(() => Promise.resolve(answer)),
			write: vi.fn(),
		},
	};
}

function terminalAnswers(answers: string[]) {
	const close = vi.fn();
	const write = vi.fn();
	return {
		close,
		questioner: {
			close,
			question: vi.fn(() => Promise.resolve(answers.shift() ?? "")),
			write,
		},
		write,
	};
}

describe("guided onboarding", () => {
	test("lets Argus conduct the conversation and returns the confirmed policy", async () => {
		const turns: GuidedOnboardingTurn[] = [
			{ confirmed: false, message: "What does this host do?", policy: null },
			{ confirmed: true, message: "Setup confirmed.", policy },
		];
		const ask = terminal("It runs our internal operations API.");
		const modelTurn = vi.fn<GuidedTurn>(
			() => Promise.resolve(turns.shift() ?? turns[0]!),
		);

		await expect(conductGuidedOnboarding(context, ask.questioner, modelTurn))
			.resolves.toEqual(policy);
		expect(modelTurn).toHaveBeenCalledTimes(2);
		expect(modelTurn.mock.calls[1]?.[1]).toEqual([
			{
				content: JSON.stringify({
					confirmed: false,
					message: "What does this host do?",
					policy: null,
				}),
				role: "assistant",
			},
			{ content: "It runs our internal operations API.", role: "user" },
		]);
		expect(ask.close).toHaveBeenCalledOnce();
	});

	test("lets the operator cancel before policy creation", async () => {
		const ask = terminal("/cancel");
		const modelTurn = vi.fn<GuidedTurn>(() => Promise.resolve({
			confirmed: false,
			message: "What does this host do?",
			policy: null,
		}));

		await expect(conductGuidedOnboarding(context, ask.questioner, modelTurn))
			.rejects.toThrow("cancelled before save");
		expect(ask.close).toHaveBeenCalledOnce();
	});

	test("rejects a confirmation that has no policy", async () => {
		const ask = terminal("unused");
		const modelTurn = vi.fn<GuidedTurn>(() => Promise.resolve({
			confirmed: true,
			message: "Setup confirmed.",
			policy: null,
		}));

		await expect(conductGuidedOnboarding(context, ask.questioner, modelTurn))
			.rejects.toThrow("without a valid policy");
	});

	test("stops an onboarding conversation at its turn limit", async () => {
		const ask = terminal("");
		const modelTurn = vi.fn<GuidedTurn>(() => Promise.resolve({
			confirmed: false,
			message: "I need one more answer.",
			policy: null,
		}));

		await expect(conductGuidedOnboarding(context, ask.questioner, modelTurn))
			.rejects.toThrow("40-turn conversation limit");
		expect(modelTurn).toHaveBeenCalledTimes(40);
	});

	test("lets the operator discuss and approve the sensor plan", async () => {
		const ask = terminalAnswers(["Why monitor listeners?", "approve"]);
		const baseline = {
			authFailureCount: 0,
			criticalFiles: [],
			establishedConnectionCount: 2,
			listeners: [],
			observedAt: "2026-01-01T00:00:00.000Z",
			processes: [],
		};
		const selection = {
			authentication: true,
			criticalFiles: true,
			listeners: true,
			networkConnections: true,
			processes: true,
			reason: "Protect the application server.",
			thresholds: {
				authFailureBurst: 4,
				establishedConnectionBurst: 10,
				processStartBurst: 8,
			},
		};
		const review = vi.fn<SensorReviewTurn>(() => Promise.resolve({
			reply: "A new listener can expose an undeclared service.",
			selection,
		}));

		await expect(conductSensorPlanReview(
			{ ...policy, createdAt: "2026-01-01T00:00:00.000Z" },
			baseline,
			selection,
			ask.questioner,
			review,
		)).resolves.toEqual(selection);
		expect(review).toHaveBeenCalledOnce();
		expect(ask.write).toHaveBeenCalledWith(
			"Argus: A new listener can expose an undeclared service.",
		);
		expect(ask.close).toHaveBeenCalledOnce();

		const limitAsk = terminalAnswers(Array.from({ length: 20 }, () => "Explain more."));
		await expect(conductSensorPlanReview(
			{ ...policy, createdAt: "2026-01-01T00:00:00.000Z" },
			baseline,
			selection,
			limitAsk.questioner,
			review,
		)).rejects.toThrow("20-turn conversation limit");
	});

	test("lets the operator cancel sensor commissioning", async () => {
		const ask = terminal("/cancel");
		const selection = {
			authentication: true,
			criticalFiles: false,
			listeners: false,
			networkConnections: false,
			processes: false,
			reason: "Watch authentication.",
			thresholds: {
				authFailureBurst: 4,
				establishedConnectionBurst: 10,
				processStartBurst: 8,
			},
		};

		await expect(conductSensorPlanReview(
			{ ...policy, createdAt: "2026-01-01T00:00:00.000Z" },
			{
				authFailureCount: 0,
				criticalFiles: [],
				establishedConnectionCount: 0,
				listeners: [],
				observedAt: "2026-01-01T00:00:00.000Z",
				processes: [],
			},
			selection,
			ask.questioner,
		)).rejects.toThrow("cancelled before activation");
	});
});
