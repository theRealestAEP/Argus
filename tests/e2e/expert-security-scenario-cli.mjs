import {
	expertSecurityScenario,
	expertSecurityScenarios,
} from "./expert-security-scenarios.mjs";

const [command, id] = process.argv.slice(2);
if (command === "ids") {
	process.stdout.write(expertSecurityScenarios.map((scenario) => scenario.id).join("\n"));
} else if (command === "goal" && id !== undefined) {
	process.stdout.write(expertSecurityScenario(id).goal);
} else if (command === "marker" && id !== undefined) {
	process.stdout.write(expertSecurityScenario(id).marker);
} else {
	throw new Error("Use expert-security-scenario-cli.mjs ids, goal ID, or marker ID.");
}
