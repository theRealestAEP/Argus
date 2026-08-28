import {
	hardSecurityScenario,
	hardSecurityScenarios,
} from "./hard-security-scenarios.mjs";

const [command, id] = process.argv.slice(2);
if (command === "ids") {
	process.stdout.write(hardSecurityScenarios.map((scenario) => scenario.id).join("\n"));
} else if (command === "goal" && id !== undefined) {
	process.stdout.write(hardSecurityScenario(id).goal);
} else if (command === "marker" && id !== undefined) {
	process.stdout.write(hardSecurityScenario(id).marker);
} else {
	throw new Error("Use hard-security-scenario-cli.mjs ids, goal ID, or marker ID.");
}
