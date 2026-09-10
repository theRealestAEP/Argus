import type { ContainmentGateway, ProcessIdentity } from "./containment.js";
import { nativeMacosContainmentGateway, nativeMacosProcessIdentity } from "./macos-containment-native.js";
import { nativeContainmentGateway as nativeLinuxContainmentGateway } from "./linux-containment-native.js";
import { nativeProcessIdentity as nativeLinuxProcessIdentity } from "./linux-containment-native.js";

export function nativeProcessIdentity(pid: number): ProcessIdentity {
	return process.platform === "darwin"
		? nativeMacosProcessIdentity(pid)
		: nativeLinuxProcessIdentity(pid);
}

export function nativeContainmentGateway(): ContainmentGateway {
	return process.platform === "darwin"
		? nativeMacosContainmentGateway()
		: nativeLinuxContainmentGateway();
}
