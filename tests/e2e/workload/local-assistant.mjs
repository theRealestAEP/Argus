import { writeFile } from "node:fs/promises";

async function checkService() {
	let serviceStatus = "unavailable";
	try {
		const response = await fetch("http://127.0.0.1:8080/health");
		serviceStatus = response.ok ? "ready" : `http-${response.status}`;
	} catch {
		serviceStatus = "unavailable";
	}
	await writeFile(
		"/var/lib/operations/local-assistant-state.json",
		`${JSON.stringify({ checkedAt: new Date().toISOString(), serviceStatus })}\n`,
		{ mode: 0o600 },
	);
}

await checkService();
setInterval(checkService, 10_000);
