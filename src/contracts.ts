import { z } from "zod";

export const hostIdentitySchema = z.object({
	arch: z.string().min(1),
	fingerprint: z.string().regex(/^[a-f0-9]{64}$/u),
	hostname: z.string().min(1),
	machineId: z.string().min(1),
	platform: z.enum(["darwin", "linux"]),
});

export type HostIdentity = z.infer<typeof hostIdentitySchema>;

export const scopeManifestSchema = z.object({
	collectionLocalOnly: z.literal(true),
	hostFingerprint: z.string().regex(/^[a-f0-9]{64}$/u),
	remoteExecution: z.literal(false),
	schemaVersion: z.literal(1),
});

export type ScopeManifest = z.infer<typeof scopeManifestSchema>;

export const onboardingPolicySchema = z.object({
	adminContact: z.string().min(1),
	agentMailInbox: z.email().nullable().optional(),
	automaticProcessTermination: z.boolean().optional(),
	approvedAgentRuntimes: z.array(z.string().min(1)),
	createdAt: z.iso.datetime(),
	criticalPaths: z.array(z.string().min(1)),
	devicePurpose: z.string().min(1),
	expectedServices: z.array(z.string().min(1)),
	emailAllowedSenders: z.array(z.email()).optional(),
	emailReportRecipients: z.array(z.email()).optional(),
	logCacheMaxBytes: z.number().int().min(1_048_576).optional(),
	maintenanceWindow: z.string().min(1),
	responseMode: z.enum([
		"report-only",
		"approval-required",
		"autonomous-action",
	]),
	retentionDays: z.number().int().min(1).max(3650),
	reviewSchedule: z.string().min(1),
	s3ArchiveBucket: z.string().min(3).nullable().optional(),
});

export type OnboardingPolicy = z.infer<typeof onboardingPolicySchema>;

export type OnboardingAnswers = Omit<OnboardingPolicy, "createdAt">;

export const operatorMessageSchema = z.object({
	body: z.string().max(16_384),
	from: z.email(),
	id: z.uuid(),
	receivedAt: z.iso.datetime(),
	remoteMessageId: z.string().min(1),
	subject: z.string().max(1_000),
});

export type OperatorMessage = z.infer<typeof operatorMessageSchema>;

export const agentRuntimeEventSchema = z.object({
	action: z.string().min(1).max(1_000),
	id: z.uuid(),
	observedAt: z.iso.datetime(),
	pid: z.number().int().positive(),
	runtime: z.string().min(1).max(1_000),
	target: z.string().min(1).max(4_000),
});

export type AgentRuntimeEvent = z.infer<typeof agentRuntimeEventSchema>;

export const guidedOnboardingPolicySchema = onboardingPolicySchema.omit({
	createdAt: true,
}).extend({
	agentMailInbox: z.email().nullable(),
	automaticProcessTermination: z.boolean(),
	emailAllowedSenders: z.array(z.email()),
	emailReportRecipients: z.array(z.email()),
	logCacheMaxBytes: z.number().int().min(1_048_576),
	s3ArchiveBucket: z.string().min(3).nullable(),
});

export const guidedOnboardingTurnSchema = z.object({
	confirmed: z.boolean(),
	message: z.string().min(1).max(4_000),
	policy: guidedOnboardingPolicySchema.nullable(),
});

export type GuidedOnboardingTurn = z.infer<typeof guidedOnboardingTurnSchema>;

export const capabilityProbeSchema = z.object({
	category: z.enum(["collect", "detect", "investigate", "mitigate"]),
	detail: z.string().min(1),
	id: z.string().min(1),
	instruction: z.string().min(1),
	required: z.boolean(),
	status: z.enum(["ready", "action-required", "unavailable"]),
});

export const capabilityReportSchema = z.object({
	checkedAt: z.iso.datetime(),
	hostFingerprint: z.string().regex(/^[a-f0-9]{64}$/u),
	platform: z.enum(["darwin", "linux"]),
	probes: z.array(capabilityProbeSchema),
	ready: z.boolean(),
	schemaVersion: z.literal(1),
});

export type CapabilityProbe = z.infer<typeof capabilityProbeSchema>;
export type CapabilityReport = z.infer<typeof capabilityReportSchema>;

export const installManifestSchema = z.object({
	agentId: z.uuid(),
	createdAt: z.iso.datetime(),
	host: hostIdentitySchema,
	resources: z.array(z.string().min(1)).min(1),
	schemaVersion: z.literal(1),
});

export type InstallManifest = z.infer<typeof installManifestSchema>;

export const memoryPackManifestSchema = z.object({
	files: z.array(
		z.object({
			path: z.string().min(1),
			sha256: z.string().regex(/^[a-f0-9]{64}$/u),
		}),
	),
	hostFingerprint: z.string().regex(/^[a-f0-9]{64}$/u),
	schemaVersion: z.literal(1),
});

export type MemoryPackManifest = z.infer<typeof memoryPackManifestSchema>;

export type DoctorCheck = {
	detail: string;
	name: string;
	ok: boolean;
};

export type DoctorReport = {
	checks: DoctorCheck[];
	ok: boolean;
};

export const evidenceEventSchema = z.object({
	detail: z.string().min(1),
	event: z.string().min(1),
	recordedAt: z.iso.datetime(),
});

export type EvidenceEvent = z.infer<typeof evidenceEventSchema>;

export const containmentPlanSchema = z.object({
	action: z.enum([
		"block-destination",
		"block-user-egress",
		"pause-process",
		"terminate-process",
	]),
	evidence: z.array(z.string().min(1)).min(1),
	reason: z.string().min(1),
	target: z.string().min(1),
});

export type ContainmentPlan = z.infer<typeof containmentPlanSchema>;

export const containmentRequestSchema = z.object({
	id: z.uuid(),
	plan: containmentPlanSchema,
	requestedAt: z.iso.datetime(),
});

export type ContainmentRequest = z.infer<typeof containmentRequestSchema>;

export const processObservationSchema = z.object({
	command: z.string(),
	executable: z.string(),
	pid: z.number().int().positive(),
	userId: z.number().int().nonnegative(),
});
export type ProcessObservation = z.infer<typeof processObservationSchema>;

export const listenerObservationSchema = z.object({
	address: z.string().min(1),
	port: z.number().int().min(0).max(65_535),
	protocol: z.enum(["tcp", "udp"]),
});
export type ListenerObservation = z.infer<typeof listenerObservationSchema>;

export const fileObservationSchema = z.object({
	modifiedAtMs: z.number().nonnegative(),
	path: z.string().min(1),
	size: z.number().int().nonnegative(),
});
export type FileObservation = z.infer<typeof fileObservationSchema>;

export const linuxSnapshotSchema = z.object({
	authFailureCount: z.number().int().nonnegative(),
	criticalFiles: z.array(fileObservationSchema),
	establishedConnectionCount: z.number().int().nonnegative(),
	listeners: z.array(listenerObservationSchema),
	observedAt: z.iso.datetime(),
	processes: z.array(processObservationSchema),
});

export type LinuxSnapshot = z.infer<typeof linuxSnapshotSchema>;

export const sensorThresholdsSchema = z.object({
	authFailureBurst: z.number().int().min(2).max(100),
	establishedConnectionBurst: z.number().int().min(5).max(10_000),
	processStartBurst: z.number().int().min(5).max(10_000),
});
export type SensorThresholds = z.infer<typeof sensorThresholdsSchema>;

export const sensorSelectionSchema = z.object({
	authentication: z.boolean(),
	criticalFiles: z.boolean(),
	listeners: z.boolean(),
	networkConnections: z.boolean(),
	processes: z.boolean(),
	reason: z.string().min(1).max(2_000),
	thresholds: sensorThresholdsSchema,
});

export type SensorSelection = z.infer<typeof sensorSelectionSchema>;

export const sensorPlanReplySchema = z.object({
	reply: z.string().min(1).max(4_000),
	selection: sensorSelectionSchema,
});

export type SensorPlanReply = z.infer<typeof sensorPlanReplySchema>;

export const sensorCanarySchema = z.object({
	checkedAt: z.iso.datetime(),
	checks: z.array(z.object({
		kind: z.enum([
			"authentication-burst",
			"critical-file-change",
			"new-listener",
			"outbound-connection-burst",
			"process-start-burst",
		]),
		passed: z.boolean(),
	})).min(1),
	passed: z.boolean(),
});

export type SensorCanary = z.infer<typeof sensorCanarySchema>;

export const sensorConfigSchema = z.object({
	baseline: linuxSnapshotSchema,
	canary: sensorCanarySchema,
	createdAt: z.iso.datetime(),
	criticalPaths: z.array(z.string().min(1)),
	selection: sensorSelectionSchema,
	pollIntervalSeconds: z.number().int().min(5).max(300),
	schemaVersion: z.literal(1),
	thresholds: sensorThresholdsSchema,
});

export type SensorConfig = z.infer<typeof sensorConfigSchema>;

export const alertSchema = z.object({
	createdAt: z.iso.datetime(),
	evidence: z.array(z.string().min(1)).min(1),
	id: z.uuid(),
	kind: z.enum([
		"agent-event-integrity-failure",
		"agent-policy-violation",
		"authentication-burst",
		"critical-file-change",
		"new-listener",
		"outbound-connection-burst",
		"process-start-burst",
		"scheduled-review",
		"service-command-shell",
		"sensor-integrity-failure",
	]),
	severity: z.enum(["low", "medium", "high", "critical"]),
	summary: z.string().min(1),
});

export type Alert = z.infer<typeof alertSchema>;

export const incidentReportSchema = z.object({
	alertId: z.uuid(),
	createdAt: z.iso.datetime(),
	id: z.uuid(),
	model: z.string().min(1),
	report: z.string().min(1),
});

export type IncidentReport = z.infer<typeof incidentReportSchema>;
