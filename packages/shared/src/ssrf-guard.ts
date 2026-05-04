import { isValid, parse } from "ipaddr.js";
import { resolve4, resolve6 } from "node:dns/promises";

const BLOCKED_HOSTNAMES = new Set([
	"localhost",
	"metadata.google.internal",
	"metadata.google",
	"169.254.169.254",
]);

const BLOCKED_SUFFIXES = [".local", ".internal", ".localhost"];

function isPrivateOrReserved(ip: string): boolean {
	try {
		const parsed = parse(ip);
		const range = parsed.range();
		return range !== "unicast";
	} catch {
		return true;
	}
}

export async function validateUrl(url: string): Promise<{
	safe: boolean;
	hostname: string;
	error?: string;
}> {
	let parsed: URL;
	try {
		parsed = new URL(url);
	} catch {
		return { safe: false, hostname: "", error: "Invalid URL" };
	}

	if (!["http:", "https:"].includes(parsed.protocol)) {
		return {
			safe: false,
			hostname: parsed.hostname,
			error: "Invalid protocol",
		};
	}

	const hostname = parsed.hostname.toLowerCase();

	if (BLOCKED_HOSTNAMES.has(hostname)) {
		return { safe: false, hostname, error: "Blocked hostname" };
	}

	for (const suffix of BLOCKED_SUFFIXES) {
		if (hostname.endsWith(suffix)) {
			return { safe: false, hostname, error: "Blocked hostname suffix" };
		}
	}

	if (isValid(hostname)) {
		if (isPrivateOrReserved(hostname)) {
			return { safe: false, hostname, error: "Private IP address" };
		}
		return { safe: true, hostname };
	}

	const v4: string[] = [];
	const v6: string[] = [];
	try {
		v4.push(...(await resolve4(hostname)));
	} catch {
		/* no A records */
	}
	try {
		v6.push(...(await resolve6(hostname)));
	} catch {
		/* no AAAA records */
	}

	const resolved = [...v4, ...v6];
	if (resolved.length === 0) {
		return { safe: false, hostname, error: "DNS resolution failed" };
	}

	for (const addr of resolved) {
		if (isPrivateOrReserved(addr)) {
			return {
				safe: false,
				hostname,
				error: `Resolves to private IP: ${addr}`,
			};
		}
	}

	return { safe: true, hostname };
}
