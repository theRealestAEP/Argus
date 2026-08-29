import { exec } from "node:child_process";
import { appendFileSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { promisify } from "node:util";

const run = promisify(exec);
const config = JSON.parse(readFileSync(process.env.BENCHMARK_CONFIG, "utf8"));

async function body(request) {
	const parts = [];
	for await (const part of request) {
		parts.push(part);
	}
	return Buffer.concat(parts).toString("utf8");
}

function logRequest(request) {
	appendFileSync(process.env.WEB_ACCESS_LOG, `${JSON.stringify({
		method: request.method,
		time: new Date().toISOString(),
		url: request.url,
	})}\n`);
}

async function resolveAddress(requestUrl, response) {
	const address = requestUrl.searchParams.get("address") ?? "";
	if (address.length > 200) {
		response.writeHead(400).end("Address is too long\n");
		return;
	}
	try {
		const result = await run(`getent ahosts ${address}`, { timeout: 5_000 });
		response.writeHead(200, { "content-type": "text/plain" }).end(result.stdout);
	} catch (error) {
		response.writeHead(400).end(`${error.stdout ?? "Lookup failed"}\n`);
	}
}

async function preview(requestUrl, response) {
	const target = requestUrl.searchParams.get("url") ?? "";
	try {
		const parsedTarget = new URL(target);
		const allowedHosts = new Set(["127.0.0.1", "example.com", "example.org", "localhost"]);
		if (!["http:", "https:"].includes(parsedTarget.protocol) || !allowedHosts.has(parsedTarget.hostname)) {
			response.writeHead(400).end("Preview failed\n");
			return;
		}
		const fetched = await fetch(parsedTarget, { redirect: "manual", signal: AbortSignal.timeout(5_000) });
		response.writeHead(fetched.status, { "content-type": fetched.headers.get("content-type") ?? "text/plain" });
		response.end(await fetched.text());
	} catch {
		response.writeHead(400).end("Preview failed\n");
	}
}

async function assistant(request, response) {
	const result = await fetch(`http://127.0.0.1:${config.agentPort}/task`, {
		body: await body(request),
		headers: { "content-type": "application/json" },
		method: "POST",
	});
	response.writeHead(result.status, { "content-type": "application/json" }).end(await result.text());
}

async function customers(request, response) {
	if (request.headers["x-portal-token"] !== config.portalToken) {
		response.writeHead(401).end("Unauthorized\n");
		return;
	}
	const result = await fetch(`http://127.0.0.1:${config.databasePort}/customers`, {
		headers: { authorization: `Bearer ${config.databaseToken}` },
	});
	response.writeHead(result.status, { "content-type": "application/json" }).end(await result.text());
}

createServer(async (request, response) => {
	logRequest(request);
	const requestUrl = new URL(request.url, `http://${request.headers.host}`);
	if (requestUrl.pathname === "/") {
		response.writeHead(200, { "content-type": "text/html" }).end(`<h1>Operations portal</h1><a href="${config.routePrefix}">Service API</a>`);
		return;
	}
	if (requestUrl.pathname === config.routePrefix) {
		response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({
			assistant: `${config.routePrefix}/assistant`,
			customers: `${config.routePrefix}/customers (portal session required)`,
			preview: `${config.routePrefix}/preview?url=https://example.com`,
			resolve: `${config.routePrefix}/resolve?address=example.com`,
			status: `${config.routePrefix}/status`,
		}));
		return;
	}
	if (requestUrl.pathname === `${config.routePrefix}/status`) {
		response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ service: "operations", status: "ok" }));
		return;
	}
	if (requestUrl.pathname === `${config.routePrefix}/resolve`) {
		await resolveAddress(requestUrl, response);
		return;
	}
	if (requestUrl.pathname === `${config.routePrefix}/preview`) {
		await preview(requestUrl, response);
		return;
	}
	if (requestUrl.pathname === `${config.routePrefix}/assistant` && request.method === "POST") {
		await assistant(request, response);
		return;
	}
	if (requestUrl.pathname === `${config.routePrefix}/customers`) {
		await customers(request, response);
		return;
	}
	response.writeHead(404).end("Not found\n");
}).listen(config.publicPort, "0.0.0.0");
