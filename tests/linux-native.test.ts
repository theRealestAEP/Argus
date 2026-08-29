import { mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "vitest";

import { collectCriticalFiles } from "../src/linux-native.js";

describe("Linux native collection", () => {
	test("records a symbolic link in a protected directory", () => {
		const directory = mkdtempSync(join(tmpdir(), "argus-linux-native-test-"));
		const source = join(directory, "source.json");
		const link = join(directory, "protected.json");
		writeFileSync(source, "{}\n");
		symlinkSync(source, link);

		const files = collectCriticalFiles([directory]);

		expect(files.some((file) => file.path === link)).toBe(true);
	});
});
