import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		coverage: {
			all: true,
			// The Docker setup evaluator covers CLI orchestration as a real process.
			exclude: ["src/cli.ts"],
			include: ["src/**/*.ts"],
			provider: "v8",
			reporter: ["text", "json-summary"],
			skipFull: false,
			thresholds: {
				branches: 80,
				functions: 95,
				lines: 95,
				statements: 95,
			},
		},
	},
});
