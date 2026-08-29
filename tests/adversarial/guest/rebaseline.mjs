import { readPolicy } from "/usr/local/lib/node_modules/on-device-ids-agent/dist/onboarding.js";
import {
	collectLinuxSnapshot,
	commissionLinuxSensors,
	readSensorConfig,
} from "/usr/local/lib/node_modules/on-device-ids-agent/dist/linux-sensors.js";

const root = "/var/lib/argus-ids";
const policy = readPolicy(root);
const current = readSensorConfig(root);
commissionLinuxSensors(
	root,
	policy,
	current.selection,
	collectLinuxSnapshot(policy.criticalPaths),
);
console.log("Argus baseline refreshed after service installation.");
