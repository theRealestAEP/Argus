import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "vitest";

import { bootstrap } from "../src/bootstrap.js";
import { runDaemon, waitForStop } from "../src/daemon.js";
import { statePaths } from "../src/paths.js";
import {
	LINUX_SERVICE_LINK,
	LINUX_SERVICE_PATH,
	LINUX_BROKER_SERVICE_LINK,
	LINUX_BROKER_SERVICE_PATH,
	MACOS_BROKER_SERVICE_PATH,
	MACOS_SERVICE_PATH,
	buildBrokerServicePlan,
	buildMacosBrokerServicePlan,
	buildServicePlan,
	installService,
	nativeServiceGateway,
	serviceResourcePaths,
	uninstallService,
	type ServiceGateway,
} from "../src/service.js";

function temporaryPath(name: string): string {
	return join(mkdtempSync(join(tmpdir(), "argus-service-test-")), name);
}

describe("boot service", () => {
	test("builds a Linux systemd service", () => {
		const plan = buildServicePlan(
			"linux",
			"/var/lib/argus state",
			"/opt/argus app",
			"/etc/argus/env file",
			"/usr/bin/node",
			"argus",
			"argus",
		);

		expect(plan.path).toBe(LINUX_SERVICE_PATH);
		expect(plan.label).toBe("argus-ids.service");
		expect(plan.content).toContain("WantedBy=multi-user.target");
		expect(plan.content).toContain("Restart=on-failure");
		expect(plan.content).toContain(
			'"--env-file-if-exists=/etc/argus/env file"',
		);
		expect(plan.content).toContain('"--state-dir=/var/lib/argus state"');
		expect(plan.content).toContain("WorkingDirectory=/var/lib/argus\\x20state");
		expect(serviceResourcePaths("linux")).toEqual([
			LINUX_SERVICE_PATH,
			LINUX_SERVICE_LINK,
			LINUX_BROKER_SERVICE_PATH,
			LINUX_BROKER_SERVICE_LINK,
		]);
	});

	test("builds a root Linux containment broker", () => {
		const plan = buildBrokerServicePlan("/var/lib/argus", "/opt/argus", "/usr/bin/node");
		expect(plan.path).toBe(LINUX_BROKER_SERVICE_PATH);
		expect(plan.content).toContain(
			"CapabilityBoundingSet=CAP_NET_ADMIN CAP_KILL CAP_DAC_OVERRIDE",
		);
		expect(plan.content).toContain("ReadWritePaths=/var/lib/argus");
		expect(plan.content).toContain("broker");
	});

	test("builds an escaped macOS launch daemon", () => {
		const plan = buildServicePlan(
			"darwin",
			"/var/argus&state",
			"/opt/argus<app>",
			"/etc/argus&env",
			"/usr/local/bin/node",
			"argus-user",
			"staff",
		);

		expect(plan.path).toBe(MACOS_SERVICE_PATH);
		expect(plan.label).toBe("com.argus.ids-agent");
		expect(plan.content).toContain("<key>RunAtLoad</key>");
		expect(plan.content).toContain("<key>KeepAlive</key>");
		expect(plan.content).toContain(
			"--env-file-if-exists=/etc/argus&amp;env",
		);
		expect(plan.content).toContain("/opt/argus&lt;app&gt;");
		expect(plan.content).toContain("/var/argus&amp;state");
		expect(serviceResourcePaths("darwin")).toEqual([
			MACOS_SERVICE_PATH,
			MACOS_BROKER_SERVICE_PATH,
		]);
	});

	test("builds a root macOS containment broker", () => {
		const plan = buildMacosBrokerServicePlan(
			"/Library/Application Support/Argus/state",
			"/usr/local/lib/node_modules/on-device-ids-agent",
			"/opt/homebrew/bin/node",
		);
		expect(plan.path).toBe(MACOS_BROKER_SERVICE_PATH);
		expect(plan.content).toContain("com.argus.ids-agent.broker");
		expect(plan.content).toContain("<string>root</string>");
		expect(plan.content).toContain("<string>broker</string>");
	});

	test("requires administrator authorization", () => {
		const plan = buildServicePlan(
			"linux",
			"/state",
			"/project",
			"/env",
			"/node",
			"argus",
			"argus",
		);
		const gateway: ServiceGateway = {
			remove() {},
			run() {},
			write() {},
		};

		expect(() => installService(plan, 501, gateway)).toThrow(
			"Administrator authorization is required",
		);
		expect(() => uninstallService(plan, 501, gateway)).toThrow(
			"Administrator authorization is required",
		);
	});

	test("rejects unsafe service account names", () => {
		expect(() =>
			buildServicePlan(
				"linux",
				"/state",
				"/project",
				"/env",
				"/node",
				"argus\nUser=root",
				"argus",
			),
		).toThrow("safe account characters");
	});

	test("applies and removes the service plan", () => {
		const events: string[] = [];
		const plan = buildServicePlan(
			"linux",
			"/state",
			"/project",
			"/env",
			"/node",
			"argus",
			"argus",
		);
		const gateway: ServiceGateway = {
			remove(path) {
				events.push(`remove ${path}`);
			},
			run(command) {
				events.push(command.args.join(" "));
			},
			write(path) {
				events.push(`write ${path}`);
			},
		};

		installService(plan, 0, gateway);
		uninstallService(plan, 0, gateway);

		expect(events).toContain(`write ${LINUX_SERVICE_PATH}`);
		expect(events).toContain("enable --now argus-ids.service");
		expect(events).toContain("disable --now argus-ids.service");
		expect(events.at(-1)).toBe(`remove ${LINUX_SERVICE_PATH}`);
	});

	test("writes, runs, and removes through the native gateway", () => {
		const path = temporaryPath("service.unit");
		const gateway = nativeServiceGateway();

		gateway.write(path, "service\n");
		expect(readFileSync(path, "utf8")).toBe("service\n");
		gateway.run({
			args: ["-e", ""],
			command: process.execPath,
			ignoreFailure: false,
		});
		gateway.run({
			args: ["-e", "process.exit(2)"],
			command: process.execPath,
			ignoreFailure: true,
		});
		expect(() =>
			gateway.run({
				args: ["-e", "process.exit(2)"],
				command: process.execPath,
				ignoreFailure: false,
			}),
		).toThrow("failed");
		gateway.remove(path);
		gateway.remove(path);
		expect(existsSync(path)).toBe(false);
	});

	test("writes daemon heartbeats and stops cleanly", async () => {
		const root = temporaryPath("state");
		bootstrap(root, {
			adminContact: "local-only",
			approvedAgentRuntimes: [],
			criticalPaths: [],
			devicePurpose: "test host",
			expectedServices: [],
			maintenanceWindow: "Sunday 02:00",
			responseMode: "approval-required",
			retentionDays: 30,
			reviewSchedule: "weekly",
		});
		await runDaemon(root, () => Promise.resolve());
		const heartbeat = JSON.parse(readFileSync(statePaths(root).heartbeat, "utf8"));

		expect(heartbeat.pid).toBe(process.pid);
		expect(heartbeat.startedAt).toBeTruthy();
		expect(heartbeat.updatedAt).toBeTruthy();
		expect(readFileSync(statePaths(root).eventLog, "utf8")).toContain(
			'"event":"daemon.started"',
		);
	});

	test("accepts the process stop signal", async () => {
		const waiting = waitForStop();
		process.emit("SIGTERM", "SIGTERM");
		await expect(waiting).resolves.toBeUndefined();
	});
});
