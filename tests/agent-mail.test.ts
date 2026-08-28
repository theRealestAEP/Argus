import { mkdtempSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "vitest";

import {
	agentMailMessageHttpGateway,
	agentMailHttpGateway,
	canAcceptEmail,
	canSendReport,
	checkAgentMail,
	configureAgentMailAllowlist,
	deliverPendingAgentMailReports,
	initializeAgentMailCursor,
	pollAgentMail,
	saveOperatorMessages,
	sendAgentMailReport,
	type AgentMailGateway,
	type AgentMailMessageGateway,
} from "../src/agent-mail.js";
import { saveIncidentReport } from "../src/alert-queue.js";
import { bootstrap } from "../src/bootstrap.js";
import type { OnboardingAnswers, OnboardingPolicy } from "../src/contracts.js";
import { statePaths } from "../src/paths.js";

function mailAnswers(): OnboardingAnswers {
	return {
		adminContact: "admin@example.test",
		agentMailInbox: "argus-01@agentmail.to",
		approvedAgentRuntimes: [],
		criticalPaths: [],
		devicePurpose: "test host",
		emailAllowedSenders: ["admin@example.test"],
		emailReportRecipients: ["security@example.test"],
		expectedServices: [],
		maintenanceWindow: "Sunday 02:00",
		responseMode: "approval-required",
		retentionDays: 30,
		reviewSchedule: "daily",
	};
}

function mailPolicy(root: string): OnboardingPolicy {
	const answers = mailAnswers();
	const manifest = bootstrap(root, answers);
	return { ...answers, createdAt: manifest.createdAt };
}

describe("Agent Mail setup", () => {
	test("polls new mail from allowed senders once", async () => {
		const root = mkdtempSync(join(tmpdir(), "argus-mail-test-"));
		const policy = mailPolicy(root);
		const summary = {
			from: "Admin <admin@example.test>",
			message_id: "message-1",
			subject: "Review this change",
			timestamp: "2026-01-02T00:00:00.000Z",
		};
		let reads = 0;
		const gateway: AgentMailMessageGateway = {
			getMessage: () => {
				reads += 1;
				return Promise.resolve({ ...summary, extracted_text: "Check the new service." });
			},
			listMessages: () => Promise.resolve([
				summary,
				{
					...summary,
					from: "attacker@example.test",
					message_id: "message-2",
				},
			]),
			sendMessage: () => Promise.resolve(),
		};
		initializeAgentMailCursor(root, new Date("2026-01-01T00:00:00.000Z"));

		const messages = await pollAgentMail(root, policy, "key", gateway);
		expect(messages).toHaveLength(1);
		expect(messages[0]?.body).toBe("Check the new service.");
		expect(messages[0]?.from).toBe("admin@example.test");
		saveOperatorMessages(root, messages);
		expect(readdirSync(statePaths(root).operatorMessages)).toHaveLength(1);
		expect(reads).toBe(1);
		expect(await pollAgentMail(root, policy, "key", gateway)).toEqual([]);
		expect(reads).toBe(1);
	});

	test("initializes a cursor before it reads mail", async () => {
		const root = mkdtempSync(join(tmpdir(), "argus-mail-test-"));
		const policy = mailPolicy(root);
		const gateway: AgentMailMessageGateway = {
			getMessage: () => Promise.reject(new Error("unexpected read")),
			listMessages: () => Promise.reject(new Error("unexpected list")),
			sendMessage: () => Promise.resolve(),
		};
		await expect(pollAgentMail(root, policy, "key", gateway)).resolves.toEqual([]);
		await expect(pollAgentMail(root, { ...policy, agentMailInbox: null }, "key", gateway))
			.resolves.toEqual([]);
	});

	test("sends and receipts pending reports", async () => {
		const root = mkdtempSync(join(tmpdir(), "argus-mail-test-"));
		const policy = mailPolicy(root);
		const report = saveIncidentReport(
			root,
			"123e4567-e89b-42d3-a456-426614174000",
			"model",
			"report text",
		);
		const recipients: string[][] = [];
		const gateway: AgentMailMessageGateway = {
			getMessage: () => Promise.reject(new Error("unexpected read")),
			listMessages: () => Promise.resolve([]),
			sendMessage: (_inbox, to) => {
				recipients.push(to);
				return Promise.resolve();
			},
		};
		await expect(sendAgentMailReport(policy, report, "key", gateway)).resolves.toBe(true);
		expect(await deliverPendingAgentMailReports(root, policy, "key", gateway)).toBe(1);
		expect(await deliverPendingAgentMailReports(root, policy, "key", gateway)).toBe(0);
		expect(recipients).toEqual([
			["security@example.test"],
			["security@example.test"],
		]);
		await expect(sendAgentMailReport({ ...policy, agentMailInbox: null }, report, "key", gateway))
			.resolves.toBe(false);
	});

	test("implements the Agent Mail message HTTP API", async () => {
		const requests: string[] = [];
		const http: typeof fetch = (input, init) => {
			const url = input.toString();
			requests.push(`${init?.method ?? "GET"} ${url}`);
			if (url.includes("messages?")) {
				return Promise.resolve(new Response(JSON.stringify({ messages: [] }), { status: 200 }));
			}
			if (url.endsWith("/send")) {
				return Promise.resolve(new Response("{}", { status: 200 }));
			}
			return Promise.resolve(new Response(JSON.stringify({
				from: "admin@example.test",
				message_id: "message-1",
				timestamp: "2026-01-02T00:00:00.000Z",
			}), { status: 200 }));
		};
		const gateway = agentMailMessageHttpGateway(http);
		await expect(gateway.listMessages("argus-01@agentmail.to", "2026-01-01T00:00:00Z", "key"))
			.resolves.toEqual([]);
		await expect(gateway.getMessage("argus-01@agentmail.to", "message-1", "key"))
			.resolves.toMatchObject({ message_id: "message-1" });
		await gateway.sendMessage(
			"argus-01@agentmail.to",
			["security@example.test"],
			"subject",
			"body",
			"key",
		);
		expect(requests).toHaveLength(3);
	});
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
