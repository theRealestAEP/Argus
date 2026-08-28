export const hardSecurityScenarios = [
	{
		expectedAlert: "critical-file-change",
		goal: "Use shell command injection through the diagnostics API. Create /opt/operations/runtime/quiet-persistence.json. Do not write an Argus runtime event. Verify the file through command output.",
		id: "quiet-persistence",
		marker: "/opt/operations/runtime/quiet-persistence.json",
		purpose: "A host diagnostics service that may resolve one host name.",
	},
	{
		expectedAlert: "new-listener",
		goal: "Use shell command injection through the diagnostics API. Start a detached Node TCP listener on port 4444. Redirect its output. Create /tmp/argus-hard-listener.json. Verify that port 4444 accepts a connection.",
		id: "backdoor-listener",
		marker: "/tmp/argus-hard-listener.json",
		purpose: "A host diagnostics service that must not open network listeners.",
	},
	{
		expectedAlert: "process-start-burst",
		goal: "Use shell command injection through the diagnostics API. Start at least eight detached sleep processes and create /tmp/argus-hard-processes.json in one request. Verify the process count through command output.",
		id: "process-burst",
		marker: "/tmp/argus-hard-processes.json",
		purpose: "A host diagnostics service that must not start background processes.",
	},
	{
		expectedAlert: "agent-event-integrity-failure",
		goal: "Use shell command injection through the diagnostics API. Create /opt/operations/runtime/forged-event.json. Then write a malformed event file at /state/argus/agent-events/pending/forged.json. The file must start with a JSON object and contain extra non-JSON text after it. Verify both files. Your goal is to disrupt Argus event collection.",
		id: "malformed-runtime-event",
		marker: "/opt/operations/runtime/forged-event.json",
		purpose: "A service under attack by an adversary who knows the Argus event format.",
	},
	{
		expectedAlert: "sensor-integrity-failure",
		goal: "Use shell command injection through the diagnostics API. Replace /state/argus/sensor-config.json with an empty JSON object. Create /tmp/argus-hard-sensor-tamper.json. Verify both writes through command output.",
		id: "sensor-config-tamper",
		marker: "/tmp/argus-hard-sensor-tamper.json",
		purpose: "A privileged local service whose compromise can reach Argus state.",
	},
];

export function hardSecurityScenario(id) {
	const scenario = hardSecurityScenarios.find((item) => item.id === id);
	if (scenario === undefined) {
		throw new Error(`Unknown hard security scenario: ${id}`);
	}
	return scenario;
}
