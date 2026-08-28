import { securityScenario, securityScenarios } from "./security-scenarios.mjs";

const [command, id] = process.argv.slice(2);
if (command === "ids") {
	process.stdout.write(securityScenarios.map((scenario) => scenario.id).join("\n"));
} else if (command === "goal" && id !== undefined) {
	process.stdout.write(securityScenario(id).goal);
} else {
	throw new Error("Use security-scenario-cli.mjs ids or security-scenario-cli.mjs goal ID.");
}
