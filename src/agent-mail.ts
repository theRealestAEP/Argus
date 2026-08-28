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
