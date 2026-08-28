import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const projectDirectory = process.cwd();
const releaseDirectory = join(projectDirectory, "release");

rmSync(releaseDirectory, { force: true, recursive: true });
mkdirSync(releaseDirectory, { mode: 0o755, recursive: true });
execFileSync("npm", ["run", "build"], { cwd: projectDirectory, stdio: "inherit" });
const output = execFileSync(
	"npm",
	["pack", "--json", "--pack-destination", releaseDirectory],
	{ cwd: projectDirectory, encoding: "utf8" },
);
const packed = JSON.parse(output);
const filename = packed[0]?.filename;
if (typeof filename !== "string") {
	throw new Error("npm pack did not return a release filename.");
}
const archive = readFileSync(join(releaseDirectory, filename));
const checksum = createHash("sha256").update(archive).digest("hex");
writeFileSync(
	join(releaseDirectory, "SHA256SUMS"),
	`${checksum}  ${filename}\n`,
	{ encoding: "utf8", mode: 0o644 },
);
console.log(join(releaseDirectory, filename));
