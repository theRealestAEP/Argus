import { createServer } from "node:http";
import { DatabaseSync } from "node:sqlite";

const database = new DatabaseSync("/var/lib/operations/operations.db");
database.exec(`
	CREATE TABLE IF NOT EXISTS jobs (
		id INTEGER PRIMARY KEY,
		name TEXT NOT NULL,
		status TEXT NOT NULL,
		created_at TEXT NOT NULL
	)
`);
const count = database.prepare("SELECT COUNT(*) AS total FROM jobs").get();
if (count.total === 0) {
	database.prepare(
		"INSERT INTO jobs (name, status, created_at) VALUES (?, ?, ?)",
	).run("daily-account-summary", "ready", new Date().toISOString());
}

const server = createServer((request, response) => {
	response.setHeader("content-type", "application/json");
	if (request.url === "/health") {
		response.end(JSON.stringify({ service: "operations-api", status: "ready" }));
		return;
	}
	if (request.url === "/jobs") {
		const jobs = database.prepare(
			"SELECT id, name, status, created_at FROM jobs ORDER BY id",
		).all();
		response.end(JSON.stringify({ jobs }));
		return;
	}
	response.statusCode = 404;
	response.end(JSON.stringify({ error: "not found" }));
});

server.listen(8080, "0.0.0.0");

function stop() {
	server.close(() => {
		database.close();
		process.exit(0);
	});
}

process.on("SIGINT", stop);
process.on("SIGTERM", stop);
