// Copyright 2026 will Farrell, and sast-json-schema contributors.
// SPDX-License-Identifier: MIT
import { lookup as dnsLookup } from "node:dns/promises";

const DNS_TIMEOUT_MS = 5_000;
const DNS_CONCURRENCY = 10;

// RFC 1918 + loopback + link-local + CGN + TEST-NETs + multicast + reserved.
// Used to block $ref URLs whose hostname resolves to an internal/private IP.
export const isPrivateIP = (ip) => {
	const parts = ip.split(".").map(Number);
	if (
		parts.length === 4 &&
		parts.every((p) => Number.isInteger(p) && p >= 0 && p <= 255)
	) {
		const [a, b] = parts;
		if (a === 0) return true; // 0.0.0.0/8 "this" network
		if (a === 10) return true; // 10.0.0.0/8 private
		if (a === 127) return true; // 127.0.0.0/8 loopback
		if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGN
		if (a === 169 && b === 254) return true; // 169.254.0.0/16 link-local
		if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12 private
		if (a === 192 && b === 0 && parts[2] === 0) return true; // 192.0.0.0/24 IETF
		if (a === 192 && b === 0 && parts[2] === 2) return true; // 192.0.2.0/24 TEST-NET-1
		if (a === 192 && b === 168) return true; // 192.168.0.0/16 private
		if (a === 198 && (b === 18 || b === 19)) return true; // 198.18.0.0/15 benchmark
		if (a === 198 && b === 51 && parts[2] === 100) return true; // 198.51.100.0/24 TEST-NET-2
		if (a === 203 && b === 0 && parts[2] === 113) return true; // 203.0.113.0/24 TEST-NET-3
		if (a >= 224 && a <= 239) return true; // 224.0.0.0/4 multicast
		if (a >= 240) return true; // 240.0.0.0/4 reserved + 255.255.255.255 broadcast
	}

	// Normalize IPv6: expand :: and remove leading zeros for consistent matching
	const lower = ip.toLowerCase();
	if (lower.includes(":")) {
		// Handle IPv4-mapped forms with dotted notation (e.g. ::ffff:127.0.0.1)
		// before general expansion since the dotted part counts as 2 groups
		const lastColon = lower.lastIndexOf(":");
		const tail = lower.slice(lastColon + 1);
		if (tail.includes(".")) {
			// Recursively check the IPv4 portion
			return isPrivateIP(tail);
		}

		// Expand :: notation to full 8-group form
		let groups;
		if (lower.includes("::")) {
			const [left, right] = lower.split("::");
			const leftGroups = left ? left.split(":") : [];
			const rightGroups = right ? right.split(":") : [];
			const missing = 8 - leftGroups.length - rightGroups.length;
			groups = [...leftGroups, ...Array(missing).fill("0"), ...rightGroups].map(
				(g) => g.replace(/^0+(?=.)/, ""),
			);
		} else {
			groups = lower.split(":").map((g) => g.replace(/^0+(?=.)/, ""));
		}
		if (groups.length === 8) {
			const normalized = groups.join(":");
			if (normalized === "0:0:0:0:0:0:0:0" || normalized === "0:0:0:0:0:0:0:1")
				return true;
			if (groups[0].startsWith("fc") || groups[0].startsWith("fd")) return true; // unique local
			if (groups[0].startsWith("fe80")) return true; // link-local
			if (groups[0].startsWith("ff")) return true; // multicast
			// IPv4-mapped with hex groups (e.g. 0:0:0:0:0:ffff:7f00:1)
			if (normalized.startsWith("0:0:0:0:0:ffff:")) {
				const hi = Number.parseInt(groups[6], 16);
				const lo = Number.parseInt(groups[7], 16);
				const mappedIP = `${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`;
				return isPrivateIP(mappedIP);
			}
		}
	}
	return false;
};

const lookupHostname = async (hostname, entries) => {
	try {
		const results = await dnsLookup(hostname, {
			all: true,
			signal: AbortSignal.timeout(DNS_TIMEOUT_MS),
		});
		const privateAddr = results.find((r) => isPrivateIP(r.address));
		if (!privateAddr) return [];
		return entries.map(({ ref, path }) => ({
			instancePath: path,
			schemaPath: "#/ssrf",
			keyword: "ssrf",
			params: { ref, hostname, resolvedIP: privateAddr.address },
			message: `$ref hostname "${hostname}" resolves to private IP ${privateAddr.address}`,
		}));
	} catch {
		return entries.map(({ ref, path }) => ({
			instancePath: path,
			schemaPath: "#/ssrf",
			keyword: "ssrf",
			params: { ref, hostname },
			message: `$ref hostname "${hostname}" does not resolve`,
		}));
	}
};

export const resolveSSRFRefs = async (refs) => {
	const hostnameMap = new Map();
	for (const entry of refs) {
		if (!hostnameMap.has(entry.hostname)) {
			hostnameMap.set(entry.hostname, []);
		}
		hostnameMap.get(entry.hostname).push(entry);
	}

	const results = [];
	const batches = [...hostnameMap.entries()];
	for (let i = 0; i < batches.length; i += DNS_CONCURRENCY) {
		const batch = batches.slice(i, i + DNS_CONCURRENCY);
		const batchResults = await Promise.all(
			batch.map(([hostname, entries]) => lookupHostname(hostname, entries)),
		);
		results.push(...batchResults);
	}
	return results.flat();
};
