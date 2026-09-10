import { join } from "node:path";

const MACOS_INSTALLED_STATE = "/Library/Application Support/Argus/state";
const MACOS_INSTALLED_SENSOR = "/Library/Application Support/Argus/sensor";

export type StatePaths = {
	agentEvents: string;
	agentEventsProcessed: string;
	agentEventsRejected: string;
	capabilityReport: string;
	installManifest: string;
	installSignature: string;
	keys: string;
	memoryPacks: string;
	policy: string;
	policySignature: string;
	privateKey: string;
	publicKey: string;
	quarantine: string;
	root: string;
	runtime: string;
	heartbeat: string;
	eventLog: string;
	emailCursor: string;
	alerts: string;
	alertWorking: string;
	archiveReceipts: string;
	brokerRequests: string;
	brokerRejected: string;
	containmentReceipts: string;
	logs: string;
	mailReceipts: string;
	operatorMessages: string;
	reports: string;
	reviewState: string;
	auditCursor: string;
	auditIntegrityState: string;
	macosCursor: string;
	macosEventDedup: string;
	macosIntegrityState: string;
	macosParserStatus: string;
	macosSensor: string;
	macosSensorLog: string;
	macosSensorStatus: string;
	macosServiceState: string;
	processSnapshot: string;
	sensorConfig: string;
	sensorIntegrityState: string;
	sensorSignature: string;
	sensorState: string;
	scope: string;
};

export function statePaths(root: string): StatePaths {
	const macosSensor = root === MACOS_INSTALLED_STATE
		? MACOS_INSTALLED_SENSOR
		: join(root, "macos-sensor");
	return {
		agentEvents: join(root, "agent-events", "pending"),
		agentEventsProcessed: join(root, "agent-events", "processed"),
		agentEventsRejected: join(root, "agent-events", "rejected"),
		capabilityReport: join(root, "capability-report.json"),
		alerts: join(root, "alerts", "pending"),
		alertWorking: join(root, "alerts", "working"),
		archiveReceipts: join(root, "archive-receipts"),
		brokerRequests: join(root, "broker-requests"),
		brokerRejected: join(root, "broker-rejected"),
		containmentReceipts: join(root, "containment-receipts"),
		installManifest: join(root, "install-manifest.json"),
		installSignature: join(root, "install-manifest.sig"),
		keys: join(root, "keys"),
		memoryPacks: join(root, "memory-packs"),
		policy: join(root, "policy.json"),
		policySignature: join(root, "policy.sig"),
		privateKey: join(root, "keys", "agent-private.pem"),
		publicKey: join(root, "keys", "agent-public.pem"),
		quarantine: join(root, "quarantine"),
		root,
		runtime: join(root, "runtime"),
		heartbeat: join(root, "runtime", "heartbeat.json"),
		eventLog: join(root, "logs", "events.jsonl"),
		emailCursor: join(root, "runtime", "agent-mail-cursor.json"),
		logs: join(root, "logs"),
		mailReceipts: join(root, "mail-receipts"),
		operatorMessages: join(root, "operator-messages"),
		reports: join(root, "reports"),
		reviewState: join(root, "runtime", "review-state.json"),
		auditCursor: join(root, "runtime", "audit-cursor.json"),
		auditIntegrityState: join(root, "runtime", "audit-integrity.json"),
		macosCursor: join(root, "runtime", "macos-eslogger-cursor.json"),
		macosEventDedup: join(root, "runtime", "macos-event-dedup.json"),
		macosIntegrityState: join(root, "runtime", "macos-eslogger-integrity.json"),
		macosParserStatus: join(root, "runtime", "macos-parser-status.json"),
		macosSensor,
		macosSensorLog: join(macosSensor, "events.jsonl"),
		macosSensorStatus: join(macosSensor, "status.json"),
		macosServiceState: join(root, "runtime", "macos-service-state.json"),
		processSnapshot: join(root, "runtime", "privileged-processes.json"),
		sensorConfig: join(root, "sensor-config.json"),
		sensorIntegrityState: join(root, "runtime", "sensor-integrity.json"),
		sensorSignature: join(root, "sensor-config.sig"),
		sensorState: join(root, "runtime", "sensor-state.json"),
		scope: join(root, "scope.json"),
	};
}
