import { APIError } from "openai";
import type { ResponseOutputMessage } from "openai/resources/responses/responses";
import { describe, expect, test } from "vitest";

import {
	DEFAULT_FALLBACK_MODEL,
	DEFAULT_PRIMARY_MODEL,
	INVESTIGATOR_CACHE_KEY,
	buildGuidedOnboardingRequest,
	buildCompactionRequest,
	buildMainRequest,
	buildSensorPlanReviewRequest,
	buildSubagentRequest,
	buildSensorCommissioningRequest,
	guidedOnboardingTurn,
	guidedOnboardingWithGateway,
	investigateDirect,
	investigateDirectWithGateway,
	investigateWithGateway,
	investigateWithSubagent,
	isUnavailableModelError,
	openAIGateway,
	resolveModels,
	reviewLinuxSensorPlan,
	reviewSensorPlanWithGateway,
	selectSensorsWithGateway,
	selectLinuxSensors,
	tokenUsage,
	type ModelGateway,
	type ModelResponse,
	type ResponsesClient,
} from "../src/model-runtime.js";

const usage = {
	input_tokens: 30,
	input_tokens_details: { cache_write_tokens: 20, cached_tokens: 10 },
	output_tokens: 5,
	output_tokens_details: { reasoning_tokens: 2 },
	total_tokens: 35,
};

function response(id: string, outputText: string): ModelResponse {
	return { id, model: "test-model", output: output(outputText), outputText, usage };
}

function output(text: string): ResponseOutputMessage[] {
	return [{
		content: [{ annotations: [], text, type: "output_text" }],
		id: "message-id",
		role: "assistant",
		status: "completed",
		type: "message",
	}];
}

function gatewayFor(responses: ModelResponse[]): ModelGateway {
	let responseIndex = 0;
	return {
		async compact() {
			return { id: "compact-id", usage };
		},
		async create() {
			const item = responses.at(responseIndex);
			responseIndex += 1;
			if (item === undefined) {
				throw new Error("The test response queue is empty.");
			}
			return item;
		},
	};
}

describe("model runtime", () => {
	test("runs structured conversational onboarding", async () => {
		const context = {
			defaultAgentMailInbox: "argus@example.test",
			host: { arch: "x64", hostname: "host", platform: "linux" },
			observed: { establishedConnectionCount: 2, listenerCount: 1, processCount: 10 },
		};
		const turn = { confirmed: false, message: "What does this host do?", policy: null };
		const request = buildGuidedOnboardingRequest("model", context, []);

		expect(request.store).toBe(false);
		expect(request.text?.format?.type).toBe("json_schema");
		await expect(guidedOnboardingWithGateway(
			gatewayFor([response("turn", JSON.stringify(turn))]),
			context,
			[],
			"model",
			"fallback",
		)).resolves.toEqual(turn);

		let calls = 0;
		const fallbackGateway: ModelGateway = {
			compact: () => Promise.resolve({ id: "compact", usage }),
			create: () => {
				calls += 1;
				return calls === 1
					? Promise.reject(new APIError(404, {}, "missing", new Headers()))
					: Promise.resolve(response("turn", JSON.stringify(turn)));
			},
		};
		await expect(guidedOnboardingWithGateway(
			fallbackGateway,
			context,
			[],
			"primary",
			"fallback",
		)).resolves.toEqual(turn);
		await expect(guidedOnboardingTurn(context, [], "")).rejects.toThrow(
			"required for guided setup",
		);
		await expect(guidedOnboardingWithGateway(
			{
				compact: () => Promise.resolve({ id: "compact", usage }),
				create: () => Promise.reject(new Error("network failure")),
			},
			context,
			[],
			"primary",
			"fallback",
		)).rejects.toThrow("network failure");
	});

	test("lets the model select bounded Linux sensors", async () => {
		const policy = {
			adminContact: "local-only",
			approvedAgentRuntimes: [],
			createdAt: "2026-01-01T00:00:00.000Z",
			criticalPaths: ["/etc"],
			devicePurpose: "server",
			expectedServices: ["sshd"],
			maintenanceWindow: "Sunday 02:00",
			responseMode: "approval-required" as const,
			retentionDays: 30,
			reviewSchedule: "daily",
		};
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
			reason: "Server baseline",
			thresholds: {
				authFailureBurst: 4,
				establishedConnectionBurst: 10,
				processStartBurst: 8,
			},
		};
		const request = buildSensorCommissioningRequest("model", policy, baseline);
		expect(request.store).toBe(false);
		expect(request.text?.format?.type).toBe("json_schema");
		await expect(
			selectSensorsWithGateway(
				gatewayFor([response("selection", JSON.stringify(selection))]),
				policy,
				baseline,
				"model",
				"fallback",
			),
		).resolves.toEqual(selection);

		let calls = 0;
		const fallbackGateway: ModelGateway = {
			compact: () => Promise.resolve({ id: "compact", usage }),
			create: () => {
				calls += 1;
				return calls === 1
					? Promise.reject(new APIError(404, {}, "missing", new Headers()))
					: Promise.resolve(response("selection", JSON.stringify(selection)));
			},
		};
		await expect(
			selectSensorsWithGateway(
				fallbackGateway,
				policy,
				baseline,
				"primary",
				"fallback",
			),
		).resolves.toEqual(selection);
		await expect(selectLinuxSensors(policy, baseline, "")).rejects.toThrow(
			"required to commission",
		);
	});

	test("lets the operator ask the model about the sensor plan", async () => {
		const policy = {
			adminContact: "local-only",
			approvedAgentRuntimes: [],
			createdAt: "2026-01-01T00:00:00.000Z",
			criticalPaths: ["/etc"],
			devicePurpose: "server",
			expectedServices: ["sshd"],
			maintenanceWindow: "Sunday 02:00",
			responseMode: "approval-required" as const,
			retentionDays: 30,
			reviewSchedule: "daily",
		};
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
			reason: "Protect the server.",
			thresholds: {
				authFailureBurst: 4,
				establishedConnectionBurst: 10,
				processStartBurst: 8,
			},
		};
		const answer = { reply: "I will watch new listeners.", selection };
		const request = buildSensorPlanReviewRequest(
			"model",
			policy,
			baseline,
			selection,
			"Why watch listeners?",
		);

		expect(request.store).toBe(false);
		expect(request.input).toContain("Why watch listeners?");
		await expect(reviewSensorPlanWithGateway(
			gatewayFor([response("answer", JSON.stringify(answer))]),
			policy,
			baseline,
			selection,
			"Why watch listeners?",
			"model",
			"fallback",
		)).resolves.toEqual(answer);
		let calls = 0;
		const fallbackGateway: ModelGateway = {
			compact: () => Promise.resolve({ id: "compact", usage }),
			create: () => {
				calls += 1;
				return calls === 1
					? Promise.reject(new APIError(404, {}, "missing", new Headers()))
					: Promise.resolve(response("answer", JSON.stringify(answer)));
			},
		};
		await expect(reviewSensorPlanWithGateway(
			fallbackGateway,
			policy,
			baseline,
			selection,
			"Why watch listeners?",
			"primary",
			"fallback",
		)).resolves.toEqual(answer);
		await expect(reviewLinuxSensorPlan(
			policy,
			baseline,
			selection,
			"question",
			"",
		)).rejects.toThrow("required to review");
		await expect(reviewSensorPlanWithGateway(
			{
				compact: () => Promise.resolve({ id: "compact", usage }),
				create: () => Promise.reject(new Error("network failure")),
			},
			policy,
			baseline,
			selection,
			"question",
			"primary",
			"fallback",
		)).rejects.toThrow("network failure");
	});
	test("uses the defensive model and SOL fallback by default", () => {
		expect(resolveModels(undefined, undefined)).toEqual({
			fallbackModel: DEFAULT_FALLBACK_MODEL,
			primaryModel: DEFAULT_PRIMARY_MODEL,
		});
		expect(resolveModels("primary", "fallback")).toEqual({
			fallbackModel: "fallback",
			primaryModel: "primary",
		});
	});

	test("creates a constrained subagent request", () => {
		const request = buildSubagentRequest("model", "alert");

		expect(request.instructions).toContain("You have no tools");
		expect(request.instructions).toContain("You cannot create subagents");
		expect(Object.hasOwn(request, "tools")).toBe(false);
		expect(request.reasoning).toEqual({ context: "all_turns", effort: "high" });
		expect(request.prompt_cache_key).toBe(INVESTIGATOR_CACHE_KEY);
		expect(request.prompt_cache_options).toEqual({ ttl: "30m" });
		expect(request.store).toBe(false);
	});

	test("passes the subagent analysis to the main investigator", () => {
		const request = buildMainRequest("model", "host alert", "evidence review");

		expect(request.input).toContain("host alert");
		expect(request.input).toContain("evidence review");
		expect(request.instructions).toContain("untrusted evidence");
		expect(request.text?.format?.type).toBe("json_schema");
		expect(request.reasoning).toEqual({ context: "all_turns", effort: "high" });
		expect(request.store).toBe(false);
	});

	test("returns a structured investigation decision", async () => {
		const decision = {
			confidence: 95,
			evidenceRequests: ["connections"],
			recommendedAction: "block-user-egress",
			report: "Confirmed hostile service command.",
			verdict: "confirmed-hostile",
		};
		const result = await investigateWithGateway(
			gatewayFor([
				response("subagent-id", "analysis"),
				response("main-id", JSON.stringify(decision)),
			]),
			"alert",
			"primary",
			"fallback",
		);

		expect(result.decision).toEqual(decision);
		expect(result.report).toBe(decision.report);
	});

	test("runs one direct investigator pass for verified host evidence", async () => {
		const decision = {
			confidence: 99,
			evidenceRequests: [],
			recommendedAction: "terminate-process",
			report: "Argus contained the confirmed command execution.",
			verdict: "confirmed-hostile",
		} as const;
		let compacted = false;
		const gateway: ModelGateway = {
			compact() {
				compacted = true;
				return Promise.resolve({ id: "compact", usage });
			},
			create(request) {
				expect(request.reasoning).toEqual({ context: "all_turns", effort: "medium" });
				return Promise.resolve(response("main-id", JSON.stringify(decision)));
			},
		};

		await expect(investigateDirectWithGateway(
			gateway,
			"verified evidence",
			"primary",
			"fallback",
		)).resolves.toMatchObject({ decision, mainResponseId: "main-id" });
		expect(compacted).toBe(false);
	});

	test("handles direct investigator failures and model fallback", async () => {
		const decision = JSON.stringify({
			confidence: 90,
			evidenceRequests: [],
			recommendedAction: "preserve",
			report: "Evidence preserved.",
			verdict: "suspicious",
		});
		let calls = 0;
		const fallbackGateway: ModelGateway = {
			compact: () => Promise.resolve({ id: "compact", usage }),
			create: () => {
				calls += 1;
				return calls === 1
					? Promise.reject(new APIError(404, {}, "missing", new Headers()))
					: Promise.resolve(response("fallback", decision));
			},
		};
		await expect(investigateDirectWithGateway(
			fallbackGateway,
			"evidence",
			"primary",
			"fallback",
		)).resolves.toMatchObject({ fallbackUsed: true, requestedModel: "primary" });
		await expect(investigateDirectWithGateway(
			gatewayFor([response("empty", "")]),
			"evidence",
			"same",
			"same",
		)).rejects.toThrow("main investigator returned an empty response");
		await expect(investigateDirectWithGateway(
			{ ...fallbackGateway, create: () => Promise.reject(7) },
			"evidence",
			"primary",
			"fallback",
		)).rejects.toThrow("model gateway returned an invalid error");
	});

	test("compacts replayed output with the stable cache policy", () => {
		const responseOutput = output("report");
		expect(buildCompactionRequest("model", responseOutput)).toMatchObject({
			input: responseOutput,
			model: "model",
			prompt_cache_key: INVESTIGATOR_CACHE_KEY,
			prompt_cache_options: { ttl: "30m" },
		});
		expect(buildCompactionRequest("model", responseOutput)).not.toHaveProperty(
			"previous_response_id",
		);
	});

	test("extracts cache and token metrics", () => {
		expect(tokenUsage(undefined)).toEqual({
			cacheWriteTokens: 0,
			cachedTokens: 0,
			inputTokens: 0,
			outputTokens: 0,
		});
		expect(
			tokenUsage(usage),
		).toEqual({
			cacheWriteTokens: 20,
			cachedTokens: 10,
			inputTokens: 30,
			outputTokens: 5,
		});
	});

	test("falls back only for model access errors", () => {
		const unavailable = new APIError(
			404,
			{ code: "model_not_found" },
			"Model unavailable",
			new Headers(),
		);
		const rateLimit = new APIError(429, {}, "Rate limit", new Headers());

		expect(isUnavailableModelError(unavailable)).toBe(true);
		expect(isUnavailableModelError(rateLimit)).toBe(false);
		expect(isUnavailableModelError(new Error("network"))).toBe(false);
	});

	test("runs a subagent, main investigator, and compaction pass", async () => {
		const result = await investigateWithGateway(
			gatewayFor([response("subagent-id", "analysis"), response("main-id", "report")]),
			"alert",
			"primary",
			"fallback",
		);

		expect(result).toMatchObject({
			compactionId: "compact-id",
			fallbackUsed: false,
			mainResponseId: "main-id",
			report: "report",
			requestedModel: "primary",
			subagentAnalysis: "analysis",
			subagentResponseId: "subagent-id",
		});
	});

	test("adapts the OpenAI response field names", async () => {
		const client: ResponsesClient = {
			async compact() {
				return { id: "compact-id", usage };
			},
			async create() {
				return {
					id: "response-id",
					model: "test-model",
					output: output("analysis"),
					output_text: "analysis",
					usage,
				};
			},
		};
		const gateway = openAIGateway(client);

			expect(await gateway.create(buildSubagentRequest("model", "alert"))).toEqual({
			id: "response-id",
			model: "test-model",
			output: output("analysis"),
			outputText: "analysis",
			usage,
		});
		expect(await gateway.compact(buildCompactionRequest("model", []))).toEqual({
			id: "compact-id",
			usage,
		});
	});

	test("uses the fallback after a primary model access error", async () => {
		let requestCount = 0;
		const fallbackGateway: ModelGateway = {
			async compact() {
				return { id: "compact-id", usage };
			},
			async create() {
				requestCount += 1;
				if (requestCount === 1) {
					throw new APIError(404, {}, "Model unavailable", new Headers());
				}
				return response(`response-${requestCount}`, requestCount === 2 ? "analysis" : "report");
			},
		};

		const result = await investigateWithGateway(
			fallbackGateway,
			"alert",
			"primary",
			"fallback",
		);

		expect(result.fallbackUsed).toBe(true);
		expect(result.requestedModel).toBe("primary");
	});

	test("rejects empty model output", async () => {
		await expect(
			investigateWithGateway(
				gatewayFor([response("subagent-id", "")]),
				"alert",
				"primary",
				"fallback",
			),
		).rejects.toThrow("subagent returned an empty response");
		await expect(
			investigateWithGateway(
				gatewayFor([response("subagent-id", "analysis"), response("main-id", "")]),
				"alert",
				"primary",
				"fallback",
			),
		).rejects.toThrow("main investigator returned an empty response");
	});

	test("preserves errors that do not permit fallback", async () => {
		const failingGateway: ModelGateway = {
			async compact() {
				return { id: "compact-id", usage };
			},
			async create() {
				throw new Error("network failure");
			},
		};

		await expect(
			investigateWithGateway(failingGateway, "alert", "primary", "fallback"),
		).rejects.toThrow("network failure");
		await expect(
			investigateWithGateway(
				{
					...failingGateway,
					async create() {
						throw new APIError(404, {}, "Model unavailable", new Headers());
					},
				},
				"alert",
				"same",
				"same",
			),
		).rejects.toThrow("404");
	});

	test("normalizes invalid gateway errors", async () => {
		const invalidGateway: ModelGateway = {
			async compact() {
				return { id: "compact-id", usage };
			},
			async create() {
				return Promise.reject(7);
			},
		};

		await expect(
			investigateWithGateway(invalidGateway, "alert", "primary", "fallback"),
		).rejects.toThrow("model gateway returned an invalid error");
	});

	test("requires an API key for a live evaluation", async () => {
		await expect(investigateWithSubagent("alert", "")).rejects.toThrow(
			"OPENAI_API_KEY is required",
		);
		await expect(investigateDirect("alert", "")).rejects.toThrow(
			"OPENAI_API_KEY is required",
		);
	});
});
