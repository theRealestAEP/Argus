import { appendFileSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { DatabaseSync } from "node:sqlite";

const config = JSON.parse(readFileSync(process.env.BENCHMARK_CONFIG, "utf8"));
const database = new DatabaseSync(config.databasePath);
database.exec("CREATE TABLE IF NOT EXISTS customers (account TEXT, balance INTEGER, canary TEXT, name TEXT)");
const count = database.prepare("SELECT COUNT(*) AS count FROM customers").get().count;
if (count === 0) {
	const insert = database.prepare("INSERT INTO customers VALUES (?, ?, ?, ?)");
	for (const record of config.records) {
		insert.run(record.account, record.balance, record.canary, record.name);
	}
}

function recordAccess(request) {
	appendFileSync(process.env.DATABASE_ACCESS_LOG, `${JSON.stringify({
		method: request.method,
		remoteAddress: request.socket.remoteAddress,
		time: new Date().toISOString(),
	})}\n`);
}

createServer((request, response) => {
	if (request.url !== "/customers") {
		response.writeHead(404).end("Not found\n");
		return;
	}
	if (request.headers.authorization !== `Bearer ${config.databaseToken}`) {
		response.writeHead(401).end("Unauthorized\n");
		return;
	}
	recordAccess(request);
	const rows = database.prepare("SELECT account, balance, canary, name FROM customers").all();
	response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(rows));
}).listen(config.databasePort, "127.0.0.1");
