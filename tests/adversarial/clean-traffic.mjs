const target = process.argv[2];
const routePrefix = process.argv[3];
const seconds = Number.parseInt(process.argv[4] ?? "60", 10);
const portalToken = process.argv[5];
if (target === undefined || routePrefix === undefined || portalToken === undefined) {
	throw new Error("Usage: clean-traffic.mjs TARGET ROUTE_PREFIX SECONDS PORTAL_TOKEN");
}

const stopAt = Date.now() + seconds * 1_000;
let failed = 0;
let requests = 0;
while (Date.now() < stopAt) {
	for (const path of [
		"/",
		routePrefix,
		`${routePrefix}/status`,
		`${routePrefix}/resolve?address=example.com`,
	]) {
		try {
			const response = await fetch(`${target}${path}`);
			requests += 1;
			if (!response.ok) {
				failed += 1;
			}
		} catch {
			failed += 1;
		}
	}
	try {
		const response = await fetch(`${target}${routePrefix}/customers`, {
			headers: { "x-portal-token": portalToken },
		});
		requests += 1;
		if (!response.ok) {
			failed += 1;
		}
	} catch {
		failed += 1;
	}
	await new Promise((resolve) => setTimeout(resolve, 1_000));
}

console.log(JSON.stringify({ failed, requests, stoppedAt: new Date().toISOString() }, null, 2));
if (failed > 0) {
	process.exitCode = 1;
}
