import { join } from "node:path";

export type StatePaths = {
	capabilityReport: string;
	installManifest: string;
	installSignature: string;
	keys: string;
	memoryPacks: string;
	policy: string;
	policySignature: string;
	privateKey: string;
	publicKey: string;
	root: string;
	runtime: string;
	heartbeat: string;
	eventLog: string;
	logs: string;
	scope: string;
};

export function statePaths(root: string): StatePaths {
	return {
		capabilityReport: join(root, "capability-report.json"),
		installManifest: join(root, "install-manifest.json"),
		installSignature: join(root, "install-manifest.sig"),
		keys: join(root, "keys"),
		memoryPacks: join(root, "memory-packs"),
		policy: join(root, "policy.json"),
		policySignature: join(root, "policy.sig"),
		privateKey: join(root, "keys", "agent-private.pem"),
		publicKey: join(root, "keys", "agent-public.pem"),
		root,
		runtime: join(root, "runtime"),
		heartbeat: join(root, "runtime", "heartbeat.json"),
		eventLog: join(root, "logs", "events.jsonl"),
		logs: join(root, "logs"),
		scope: join(root, "scope.json"),
	};
}
