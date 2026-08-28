import type {
	LinuxSnapshot,
	OnboardingAnswers,
	OnboardingPolicy,
	SensorSelection,
} from "./contracts.js";
import { createSensorConfig } from "./linux-sensors.js";
import type {
	GuidedConversationMessage,
	GuidedOnboardingContext,
} from "./model-runtime.js";
import { guidedOnboardingTurn } from "./model-runtime.js";
import { reviewLinuxSensorPlan } from "./model-runtime.js";
import type { Questioner } from "./onboarding.js";
import { terminalQuestioner } from "./onboarding.js";

export type GuidedTurn = typeof guidedOnboardingTurn;
export type SensorReviewTurn = typeof reviewLinuxSensorPlan;

export async function conductGuidedOnboarding(
	context: GuidedOnboardingContext,
	terminal: Questioner = terminalQuestioner(),
	turn: GuidedTurn = guidedOnboardingTurn,
): Promise<OnboardingAnswers> {
	const transcript: GuidedConversationMessage[] = [];
	try {
		for (let count = 0; count < 40; count += 1) {
			const response = await turn(context, [...transcript]);
			terminal.write(`Argus: ${response.message}`);
			transcript.push({ content: JSON.stringify(response), role: "assistant" });
			if (response.confirmed) {
				if (response.policy === null) {
					throw new Error("Argus confirmed setup without a valid policy.");
				}
				return response.policy;
			}
			const answer = (await terminal.question("You: ")).trim();
			if (answer === "/cancel") {
				throw new Error("Setup cancelled before save.");
			}
			transcript.push({ content: answer, role: "user" });
		}
		throw new Error("Setup reached the 40-turn conversation limit.");
	} finally {
		terminal.close();
	}
}

export async function conductSensorPlanReview(
	policy: OnboardingPolicy,
	baseline: LinuxSnapshot,
	initialSelection: SensorSelection,
	terminal: Questioner = terminalQuestioner(),
	review: SensorReviewTurn = reviewLinuxSensorPlan,
): Promise<SensorSelection> {
	let selection = initialSelection;
	terminal.write(`Argus: I inspected this host and prepared its monitoring plan. ${selection.reason}`);
	terminal.write("Argus: Ask a question, request a change, or type approve.");
	try {
		for (let count = 0; count < 20; count += 1) {
			const message = (await terminal.question("You: ")).trim();
			if (message.toLowerCase() === "approve") {
				return selection;
			}
			if (message === "/cancel") {
				throw new Error("Sensor commissioning cancelled before activation.");
			}
			const response = await review(policy, baseline, selection, message);
			createSensorConfig(baseline, policy.criticalPaths, response.selection);
			selection = response.selection;
			terminal.write(`Argus: ${response.reply}`);
		}
		throw new Error("Sensor review reached the 20-turn conversation limit.");
	} finally {
		terminal.close();
	}
}
