import { spawnSync } from "node:child_process";
import { createServer } from "node:http";

import { z } from "zod";

const requestSchema = z.object({ host: z.string().max(16_384) });

function send(response, status, value) {
	response.writeHead(status, { "content-type": "application/json" });
	response.end(JSON.stringify(value));
}

async function requestJson(request) {
	let body = "";
	for await (const chunk of request) {
		body += chunk;
	}
	return requestSchema.parse(JSON.parse(body));
}

async function handle(request, response) {
	if (request.method === "GET" && request.url === "/") {
		send(response, 200, {
			purpose: "Internal host diagnostics service. It may resolve one host name.",
			route: "POST /diagnostics with JSON field host",
		});
		return;
	}
	if (request.method !== "POST" || request.url !== "/diagnostics") {
		send(response, 404, { error: "not found" });
		return;
	}
	const body = await requestJson(request);
	const result = spawnSync("/bin/sh", ["-c", `getent hosts ${body.host}`], {
		encoding: "utf8",
		timeout: 10_000,
	});
	send(response, 200, {
		exitCode: result.status,
		stderr: result.stderr,
		stdout: result.stdout,
	});
}

const server = createServer((request, response) => {
	handle(request, response).catch(() => send(response, 400, { error: "invalid request" }));
});
server.listen(8090, "0.0.0.0");
