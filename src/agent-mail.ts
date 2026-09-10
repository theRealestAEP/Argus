import { randomUUID } from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";

import type { IncidentReport, OnboardingPolicy, OperatorMessage } from "./contracts.js";
import { incidentReportSchema, operatorMessageSchema } from "./contracts.js";
import { jsonText, writePrivate } from "./files.js";
import { statePaths } from "./paths.js";

export interface AgentMailCheck {
	detail: string;
	inbox: string | null;
	ready: boolean;
}

export interface AgentMailGateway {
	addAllowEntry(
		inbox: string,
		apiKey: string,
		direction: "receive" | "send",
		address: string,
	): Promise<number>;
	listThreads(inbox: string, apiKey: string): Promise<number>;
}

export interface HttpResponseStatus {
	status: number;
}

const messageSchema = z.object({
	extracted_text: z.string().optional(),
	from: z.string().min(1),
	message_id: z.string().min(1),
	preview: z.string().optional(),
	subject: z.string().optional(),
	text: z.string().optional(),
	timestamp: z.iso.datetime(),
});

const messageListSchema = z.object({ messages: z.array(messageSchema) });
const mailCursorSchema = z.object({
	after: z.iso.datetime(),
	processedIds: z.array(z.string().min(1)).max(200),
});
type MailCursor = z.infer<typeof mailCursorSchema>;

type MailConnection = {
	apiKey: string;
	inbox: string;
};

export type AgentMailMessage = z.infer<typeof messageSchema>;

export interface AgentMailMessageGateway {
	getMessage(inbox: string, messageId: string, apiKey: string): Promise<AgentMailMessage>;
	listMessages(inbox: string, after: string, apiKey: string): Promise<AgentMailMessage[]>;
	sendMessage(
		inbox: string,
		recipients: string[],
		subject: string,
		text: string,
		apiKey: string,
	): Promise<void>;
}

type PendingReport = {
	name: string;
	report: IncidentReport;
};

type ReportMessage = {
	subject: string;
	text: string;
};

export function agentMailMessageHttpGateway(
	http: typeof fetch = fetch,
): AgentMailMessageGateway {
	return {
		async getMessage(inbox, messageId, apiKey) {
			const response = await http(
				`https://api.agentmail.to/v0/inboxes/${encodeURIComponent(inbox)}/messages/${encodeURIComponent(messageId)}`,
				{
					headers: { authorization: `Bearer ${apiKey}` },
					signal: AbortSignal.timeout(10_000),
				},
			);
			if (response.status !== 200) {
				throw new Error(`Agent Mail message read returned HTTP ${response.status}.`);
			}
			return messageSchema.parse(await response.json());
		},
		async listMessages(inbox, after, apiKey) {
			const query = new URLSearchParams({ after, ascending: "true", limit: "50" });
			const response = await http(
				`https://api.agentmail.to/v0/inboxes/${encodeURIComponent(inbox)}/messages?${query.toString()}`,
				{
					headers: { authorization: `Bearer ${apiKey}` },
					signal: AbortSignal.timeout(10_000),
				},
			);
			if (response.status !== 200) {
				throw new Error(`Agent Mail message list returned HTTP ${response.status}.`);
			}
			return messageListSchema.parse(await response.json()).messages;
		},
		async sendMessage(inbox, recipients, subject, text, apiKey) {
			const response = await http(
				`https://api.agentmail.to/v0/inboxes/${encodeURIComponent(inbox)}/messages/send`,
				{
					body: JSON.stringify({ subject, text, to: recipients, track_opens: false }),
					headers: {
						authorization: `Bearer ${apiKey}`,
						"content-type": "application/json",
					},
					method: "POST",
					signal: AbortSignal.timeout(10_000),
				},
			);
			if (response.status !== 200) {
				throw new Error(`Agent Mail send returned HTTP ${response.status}.`);
			}
		},
	};
}

function includesAddress(addresses: string[] | undefined, address: string): boolean {
	const candidate = address.trim().toLowerCase();
	return addresses?.some((item) => item.toLowerCase() === candidate) ?? false;
}

export function canAcceptEmail(
	allowedSenders: string[] | undefined,
	sender: string,
): boolean {
	return includesAddress(allowedSenders, sender);
}

export function canSendReport(
	reportRecipients: string[] | undefined,
	recipient: string,
): boolean {
	return includesAddress(reportRecipients, recipient);
}

function headerAddress(header: string): string {
	const bracketed = /<([^<>]+)>/u.exec(header);
	return (bracketed?.[1] ?? header).trim().toLowerCase();
}

export function initializeAgentMailCursor(root: string, now = new Date()): void {
	writePrivate(
		statePaths(root).emailCursor,
		jsonText({ after: now.toISOString(), processedIds: [] }),
	);
}

function operatorMessage(
	message: AgentMailMessage,
	body: string,
	now: Date,
): OperatorMessage {
	return operatorMessageSchema.parse({
		body: body.slice(0, 16_384),
		from: headerAddress(message.from),
		id: randomUUID(),
		receivedAt: now.toISOString(),
		remoteMessageId: message.message_id,
		subject: message.subject ?? "",
	});
}

function mailConnection(
	policy: OnboardingPolicy,
	apiKey: string | undefined,
): MailConnection | null {
	const inbox = policy.agentMailInbox;
	if (inbox === undefined || inbox === null || apiKey === undefined || apiKey.length === 0) {
		return null;
	}
	return { apiKey, inbox };
}

function readMailCursor(root: string, now: Date): MailCursor | null {
	const path = statePaths(root).emailCursor;
	if (!existsSync(path)) {
		initializeAgentMailCursor(root, now);
		return null;
	}
	return mailCursorSchema.parse(JSON.parse(readFileSync(path, "utf8")));
}

async function allowedMessageAlerts(
	summaries: AgentMailMessage[],
	connection: MailConnection,
	policy: OnboardingPolicy,
	cursor: MailCursor,
	gateway: AgentMailMessageGateway,
	now: Date,
): Promise<{ messages: OperatorMessage[]; processedIds: string[] }> {
	const processed = new Set(cursor.processedIds);
	const messages: OperatorMessage[] = [];
	for (const summary of summaries) {
		if (processed.has(summary.message_id)) {
			continue;
		}
		processed.add(summary.message_id);
		if (!canAcceptEmail(policy.emailAllowedSenders, headerAddress(summary.from))) {
			continue;
		}
		const message = await gateway.getMessage(
			connection.inbox,
			summary.message_id,
			connection.apiKey,
		);
		const body = message.extracted_text ?? message.text ?? message.preview ?? "";
		messages.push(operatorMessage(message, body, now));
	}
	return { messages, processedIds: [...processed].slice(-200) };
}

export async function pollAgentMail(
	root: string,
	policy: OnboardingPolicy,
	apiKey: string | undefined,
	gateway: AgentMailMessageGateway = agentMailMessageHttpGateway(),
	now = new Date(),
): Promise<OperatorMessage[]> {
	const connection = mailConnection(policy, apiKey);
	if (connection === null) {
		return [];
	}
	const cursor = readMailCursor(root, now);
	if (cursor === null) {
		return [];
	}
	const summaries = await gateway.listMessages(
		connection.inbox,
		cursor.after,
		connection.apiKey,
	);
	const result = await allowedMessageAlerts(
		summaries,
		connection,
		policy,
		cursor,
		gateway,
		now,
	);
	const latest = summaries.at(-1)?.timestamp ?? cursor.after;
	writePrivate(
		statePaths(root).emailCursor,
		jsonText({ after: latest, processedIds: result.processedIds }),
	);
	return result.messages;
}

export function saveOperatorMessages(root: string, messages: OperatorMessage[]): void {
	for (const message of messages) {
		const parsed = operatorMessageSchema.parse(message);
		writePrivate(
			join(statePaths(root).operatorMessages, `${parsed.receivedAt}-${parsed.id}.json`),
			jsonText(parsed),
		);
	}
}

export async function sendAgentMailReport(
	policy: OnboardingPolicy,
	report: IncidentReport,
	apiKey: string | undefined,
	gateway: AgentMailMessageGateway = agentMailMessageHttpGateway(),
): Promise<boolean> {
	return sendAgentMailReports(policy, [report], apiKey, gateway);
}

async function sendAgentMailReports(
	policy: OnboardingPolicy,
	reports: IncidentReport[],
	apiKey: string | undefined,
	gateway: AgentMailMessageGateway,
): Promise<boolean> {
	const connection = mailConnection(policy, apiKey);
	const allowed = (policy.emailReportRecipients ?? []).filter((recipient) =>
		canSendReport(policy.emailReportRecipients, recipient)
	);
	if (connection === null || allowed.length === 0 || reports.length === 0) {
		return false;
	}
	const message = reportMessage(reports);
	await gateway.sendMessage(
		connection.inbox,
		allowed,
		message.subject,
		message.text,
		connection.apiKey,
	);
	return true;
}

function reportMessage(reports: IncidentReport[]): ReportMessage {
	const first = reports[0];
	if (reports.length === 1 && first !== undefined) {
		return { subject: `Argus security report ${first.id}`, text: first.report };
	}
	return {
		subject: `Argus security summary: ${reports.length} reports`,
		text: reports.map((report, index) =>
			`Report ${index + 1} of ${reports.length}\n\n${report.report}`
		).join("\n\n---\n\n"),
	};
}

function pendingReports(root: string): PendingReport[] {
	const paths = statePaths(root);
	return readdirSync(paths.reports).toSorted().flatMap((name) => {
		if (existsSync(join(paths.mailReceipts, `${name}.json`))) {
			return [];
		}
		const report = incidentReportSchema.parse(
			JSON.parse(readFileSync(join(paths.reports, name), "utf8")),
		);
		return [{ name, report }];
	});
}

function isRoutineReport(report: IncidentReport): boolean {
	return report.alertKind === "remote-login" || report.alertKind === "scheduled-review" ||
		report.severity === "low" || report.severity === "medium";
}

function receiptReports(root: string, reports: PendingReport[], now: Date): void {
	for (const item of reports) {
		writePrivate(
			join(statePaths(root).mailReceipts, `${item.name}.json`),
			jsonText({ deliveredAt: now.toISOString(), reportId: item.report.id }),
		);
	}
}

async function deliverReportGroup(
	root: string,
	policy: OnboardingPolicy,
	apiKey: string | undefined,
	reports: PendingReport[],
	gateway: AgentMailMessageGateway,
	now: Date,
): Promise<number> {
	if (!await sendAgentMailReports(policy, reports.map((item) => item.report), apiKey, gateway)) {
		return 0;
	}
	receiptReports(root, reports, now);
	return reports.length;
}

export async function deliverPendingAgentMailReports(
	root: string,
	policy: OnboardingPolicy,
	apiKey: string | undefined,
	gateway: AgentMailMessageGateway = agentMailMessageHttpGateway(),
	now = new Date(),
): Promise<number> {
	const pending = pendingReports(root);
	const urgent = pending.filter((item) => !isRoutineReport(item.report));
	const routine = pending.filter((item) => isRoutineReport(item.report));
	let delivered = await deliverReportGroup(root, policy, apiKey, urgent, gateway, now);
	if (routine.some((item) => item.report.alertKind === "scheduled-review")) {
		delivered += await deliverReportGroup(root, policy, apiKey, routine, gateway, now);
	}
	return delivered;
}

export type HttpGet = (
	url: string,
	init: RequestInit,
) => Promise<HttpResponseStatus>;

export function agentMailHttpGateway(httpGet: HttpGet = fetch): AgentMailGateway {
	return {
		async addAllowEntry(inbox, apiKey, direction, address) {
			const encodedInbox = encodeURIComponent(inbox);
			const response = await httpGet(
				`https://api.agentmail.to/v0/inboxes/${encodedInbox}/lists/${direction}/allow`,
				{
					body: JSON.stringify({
						entry: address,
						reason: "Argus onboarding email policy",
					}),
					headers: {
						authorization: `Bearer ${apiKey}`,
						"content-type": "application/json",
					},
					method: "POST",
					signal: AbortSignal.timeout(5_000),
				},
			);
			return response.status;
		},
		async listThreads(inbox, apiKey) {
			const encodedInbox = encodeURIComponent(inbox);
			const response = await httpGet(
				`https://api.agentmail.to/v0/inboxes/${encodedInbox}/threads?limit=1`,
				{
					headers: { authorization: `Bearer ${apiKey}` },
					method: "GET",
					signal: AbortSignal.timeout(5_000),
				},
			);
			return response.status;
		},
	};
}

export async function configureAgentMailAllowlist(
	inbox: string,
	apiKey: string,
	allowedSenders: string[],
	reportRecipients: string[],
	gateway: AgentMailGateway = agentMailHttpGateway(),
): Promise<void> {
	for (const address of allowedSenders) {
		const status = await gateway.addAllowEntry(inbox, apiKey, "receive", address);
		if (status !== 200) {
			throw new Error(`Agent Mail receive allowlist returned HTTP ${status}.`);
		}
	}
	for (const address of reportRecipients) {
		const status = await gateway.addAllowEntry(inbox, apiKey, "send", address);
		if (status !== 200) {
			throw new Error(`Agent Mail send allowlist returned HTTP ${status}.`);
		}
	}
}

export async function checkAgentMail(
	inbox: string | null | undefined,
	apiKey: string | undefined,
	gateway: AgentMailGateway = agentMailHttpGateway(),
): Promise<AgentMailCheck> {
	if (inbox === undefined || inbox === null) {
		return { detail: "Local reports are active.", inbox: null, ready: false };
	}
	if (apiKey === undefined || apiKey.length === 0) {
		return {
			detail: "Add AGENTMAIL_API_KEY to enable Agent Mail.",
			inbox,
			ready: false,
		};
	}
	try {
		const status = await gateway.listThreads(inbox, apiKey);
		return status === 200
			? { detail: `Connected to ${inbox}.`, inbox, ready: true }
			: { detail: `Agent Mail returned HTTP ${status}.`, inbox, ready: false };
	} catch {
		return { detail: "Agent Mail connection failed.", inbox, ready: false };
	}
}
