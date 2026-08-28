import type { InstallManifest } from "./contracts.js";
import { readInstallManifest } from "./bootstrap.js";

export function uninstallPlan(root: string): string[] {
	const manifest: InstallManifest = readInstallManifest(root);
	return manifest.resources.toReversed();
}
