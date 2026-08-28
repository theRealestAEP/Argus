import { createServer } from "node:http";

import { runDiagnostic, send } from "./expert-http.mjs";

function decodePath(path) {
	try {
		return decodeURIComponent(path);
	} catch {
		return path;
	}
}

function handle(request, response) {
	const url = new URL(request.url, "http://gateway");
	const edgePath = decodePath(url.pathname);
	if (edgePath.startsWith("/admin")) {
		send(response, 403, { error: "edge policy denied this route" });
		return;
	}
	const applicationPath = decodePath(edgePath);
	if (applicationPath === "/") {
		send(response, 200, {
		name: "Operations routing gateway",
		routes: ["GET /health"],
		}, { "x-path-normalizer": "edge-v1" });
		return;
	}
	if (applicationPath === "/health") {
		send(response, 200, { status: "ok" });
		return;
	}
	if (applicationPath === "/admin/diagnostics") {
		send(response, 200, runDiagnostic(url.searchParams.get("host") ?? ""));
		return;
	}
	send(response, 404, { error: "not found" });
}

createServer(handle).listen(8090, "0.0.0.0");
