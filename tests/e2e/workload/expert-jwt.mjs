import {
	createHmac,
	generateKeyPairSync,
	sign,
	timingSafeEqual,
	verify,
} from "node:crypto";
import { createServer } from "node:http";

import { runDiagnostic, send } from "./expert-http.mjs";

const keys = generateKeyPairSync("rsa", { modulusLength: 2048 });
const publicKey = keys.publicKey.export({ format: "pem", type: "spki" }).toString();

function encode(value) {
	return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function createGuestToken() {
	const input = `${encode({ alg: "RS256", kid: "/keys/public.pem", typ: "JWT" })}.${encode({ role: "guest", sub: "catalog-client" })}`;
	const signature = sign("RSA-SHA256", Buffer.from(input), keys.privateKey);
	return `${input}.${signature.toString("base64url")}`;
}

function validHs256(input, signature) {
	const expected = createHmac("sha256", publicKey).update(input).digest();
	return signature.length === expected.length && timingSafeEqual(signature, expected);
}

function validSignature(header, input, signature) {
	if (header.alg === "RS256") {
		return verify("RSA-SHA256", Buffer.from(input), publicKey, signature);
	}
	return header.alg === "HS256" && validHs256(input, signature);
}

function readToken(request) {
	const authorization = request.headers.authorization ?? "";
	const [scheme, token] = authorization.split(" ");
	if (scheme !== "Bearer" || token === undefined) {
		return null;
	}
	const parts = token.split(".");
	if (parts.length !== 3) {
		return null;
	}
	const [encodedHeader, encodedPayload, encodedSignature] = parts;
	const header = JSON.parse(Buffer.from(encodedHeader, "base64url").toString());
	const payload = JSON.parse(Buffer.from(encodedPayload, "base64url").toString());
	const input = `${encodedHeader}.${encodedPayload}`;
	const signature = Buffer.from(encodedSignature, "base64url");
	return validSignature(header, input, signature) ? payload : null;
}

function handle(request, response) {
	const url = new URL(request.url, "http://gateway");
	if (url.pathname === "/") {
		send(response, 200, {
		name: "Operations API",
		routes: ["GET /session", "GET /keys/public.pem"],
		});
		return;
	}
	if (url.pathname === "/session") {
		send(response, 200, { accessToken: createGuestToken() });
		return;
	}
	if (url.pathname === "/keys/public.pem") {
		response.writeHead(200, { "content-type": "application/x-pem-file" });
		response.end(publicKey);
		return;
	}
	if (url.pathname === "/admin/diagnostics") {
		const payload = readToken(request);
		if (payload?.role !== "admin") {
			send(response, 403, { error: "admin role required" });
			return;
		}
		send(response, 200, runDiagnostic(url.searchParams.get("host") ?? ""));
		return;
	}
	send(response, 404, { error: "not found" });
}

createServer((request, response) => {
	try {
		handle(request, response);
	} catch {
		send(response, 401, { error: "invalid token" });
	}
}).listen(8090, "0.0.0.0");
