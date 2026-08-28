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
		"autonomous-reversible",
	]),
	retentionDays: z.number().int().min(1).max(3650),
	reviewSchedule: z.string().min(1),
	s3ArchiveBucket: z.string().min(3).nullable().optional(),
});

export type OnboardingPolicy = z.infer<typeof onboardingPolicySchema>;

export type OnboardingAnswers = Omit<OnboardingPolicy, "createdAt">;

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
	action: z.enum(["block-destination", "terminate-process"]),
	evidence: z.array(z.string().min(1)).min(1),
	reason: z.string().min(1),
	target: z.string().min(1),
});

export type ContainmentPlan = z.infer<typeof containmentPlanSchema>;
