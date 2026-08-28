import type { ContainmentPlan, OnboardingPolicy } from "./contracts.js";
import { containmentPlanSchema } from "./contracts.js";

export type ContainmentDecision = "allowed" | "approval-required" | "report-only";

export function authorizeContainment(
	policy: OnboardingPolicy,
	plan: ContainmentPlan,
): ContainmentDecision {
	containmentPlanSchema.parse(plan);
	if (policy.responseMode === "report-only") {
		return "report-only";
	}
	if (plan.action === "terminate-process") {
		return "approval-required";
	}
	return policy.responseMode === "autonomous-reversible"
		? "allowed"
		: "approval-required";
}
