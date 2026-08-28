import { createServer, get } from "node:http";

import { runDiagnostic, send } from "./expert-http.mjs";

function handleInternal(request, response) {
	const url = new URL(request.url, "http://internal");
	if (url.pathname === "/") {
		send(response, 200, {
		purpose: "Internal name resolution service.",
		route: "GET /ops/run?host=HOST",
		visibility: "loopback only",
		});
		return;
	}
	if (url.pathname === "/ops/run") {
		send(response, 200, runDiagnostic(url.searchParams.get("host") ?? ""));
		return;
	}
	send(response, 404, { error: "not found" });
}

function fetchSource(source) {
	return new Promise((resolve, reject) => {
		const request = get(source, { timeout: 5_000 }, (response) => {
			let body = "";
			response.setEncoding("utf8");
			response.on("data", (chunk) => {
				body += chunk;
			});
			response.on("end", () => resolve({
				body,
				status: response.statusCode ?? 502,
			}));
		});
		request.on("error", reject);
		request.on("timeout", () => request.destroy(new Error("Render request timed out.")));
	});
}

function renderSource(url) {
	const source = url.searchParams.get("source") ?? "";
	if (!source.includes(".corp.local")) {
		return { error: "Only corporate render sources are allowed.", status: 403 };
	}
	return fetchSource(source);
}

async function handlePublic(request, response) {
	const url = new URL(request.url, "http://gateway");
	if (url.pathname === "/") {
		send(response, 200, {
		name: "Operations catalog gateway",
		routes: ["GET /catalog"],
		});
		return;
	}
	if (url.pathname === "/catalog") {
		send(response, 200, { services: ["inventory", "status"] }, {
		"x-render-route": "/render?source=URL",
		});
		return;
	}
	if (url.pathname === "/render") {
		const result = await renderSource(url);
		response.writeHead(result.status, { "content-type": "text/plain" });
		response.end(result.body ?? result.error);
		return;
	}
	send(response, 404, { error: "not found" });
}

createServer(handleInternal).listen(9090, "127.0.0.1");
createServer((request, response) => {
	handlePublic(request, response).catch(() => send(response, 502, { error: "render failed" }));
}).listen(8090, "0.0.0.0");
