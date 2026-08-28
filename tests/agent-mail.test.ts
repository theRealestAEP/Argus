import { describe, expect, test } from "vitest";

import {
	agentMailHttpGateway,
	canAcceptEmail,
	canSendReport,
	checkAgentMail,
	configureAgentMailAllowlist,
	type AgentMailGateway,
} from "../src/agent-mail.js";

describe("Agent Mail setup", () => {
	test("enforces local sender and recipient roles", () => {
		expect(canAcceptEmail(["Admin@Example.test"], "admin@example.test")).toBe(true);
		expect(canAcceptEmail([], "other@example.test")).toBe(false);
		expect(canSendReport(["security@example.test"], "security@example.test")).toBe(
			true,
		);
		expect(canSendReport(undefined, "other@example.test")).toBe(false);
	});
	test("uses local reports when the inbox is skipped", async () => {
		await expect(checkAgentMail(null, undefined)).resolves.toEqual({
			detail: "Local reports are active.",
			inbox: null,
			ready: false,
		});
	});

	test("requests an API key for a selected inbox", async () => {
		await expect(
			checkAgentMail("argus-01@agentmail.to", undefined),
		).resolves.toEqual({
			detail: "Add AGENTMAIL_API_KEY to enable Agent Mail.",
			inbox: "argus-01@agentmail.to",
			ready: false,
		});
	});

	test("checks the encoded inbox without exposing the key", async () => {
		const gateway = agentMailHttpGateway(async (url, init) => {
			expect(url).toContain("argus-01%40agentmail.to/threads?limit=1");
			expect(init.headers).toEqual({ authorization: "Bearer test-key" });
			return { status: 200 };
		});

		await expect(
			checkAgentMail("argus-01@agentmail.to", "test-key", gateway),
		).resolves.toEqual({
			detail: "Connected to argus-01@agentmail.to.",
			inbox: "argus-01@agentmail.to",
			ready: true,
		});
	});

	test("posts an Agent Mail allow-list entry", async () => {
		const gateway = agentMailHttpGateway(async (url, init) => {
			expect(url).toContain(
				"argus-01%40agentmail.to/lists/receive/allow",
			);
			expect(init).toMatchObject({
				body: JSON.stringify({
					entry: "admin@example.test",
					reason: "Argus onboarding email policy",
				}),
				headers: {
					authorization: "Bearer test-key",
					"content-type": "application/json",
				},
				method: "POST",
			});
			return { status: 200 };
		});

		await expect(
			gateway.addAllowEntry(
				"argus-01@agentmail.to",
				"test-key",
				"receive",
				"admin@example.test",
			),
		).resolves.toBe(200);
	});

	test("reports an API rejection", async () => {
		const gateway: AgentMailGateway = {
			addAllowEntry: () => Promise.resolve(200),
			listThreads: () => Promise.resolve(401),
		};

		await expect(
			checkAgentMail("argus-01@agentmail.to", "test-key", gateway),
		).resolves.toMatchObject({ detail: "Agent Mail returned HTTP 401.", ready: false });
	});

	test("reports a connection failure", async () => {
		const gateway: AgentMailGateway = {
			addAllowEntry: () => Promise.resolve(200),
			listThreads: () => Promise.reject(new Error("offline")),
		};

		await expect(
			checkAgentMail("argus-01@agentmail.to", "test-key", gateway),
		).resolves.toMatchObject({ detail: "Agent Mail connection failed.", ready: false });
	});

	test("configures sender and recipient allow lists", async () => {
		const calls: string[] = [];
		const gateway: AgentMailGateway = {
			addAllowEntry(inbox, apiKey, direction, address) {
				calls.push(`${inbox}:${apiKey}:${direction}:${address}`);
				return Promise.resolve(200);
			},
			listThreads: () => Promise.resolve(200),
		};

		await configureAgentMailAllowlist(
			"argus-01@agentmail.to",
			"key",
			["admin@example.test"],
			["security@example.test"],
			gateway,
		);

		expect(calls).toEqual([
			"argus-01@agentmail.to:key:receive:admin@example.test",
			"argus-01@agentmail.to:key:send:security@example.test",
		]);
	});

	test("rejects an allow-list API error", async () => {
		const gateway: AgentMailGateway = {
			addAllowEntry: () => Promise.resolve(403),
			listThreads: () => Promise.resolve(200),
		};

		await expect(
			configureAgentMailAllowlist(
				"argus-01@agentmail.to",
				"key",
				["admin@example.test"],
				[],
				gateway,
			),
		).rejects.toThrow("receive allowlist returned HTTP 403");
	});

	test("rejects an outbound allow-list API error", async () => {
		const gateway: AgentMailGateway = {
			addAllowEntry: () => Promise.resolve(503),
			listThreads: () => Promise.resolve(200),
		};

		await expect(
			configureAgentMailAllowlist(
				"argus-01@agentmail.to",
				"key",
				[],
				["security@example.test"],
				gateway,
			),
		).rejects.toThrow("send allowlist returned HTTP 503");
	});
});
