import { strictEqual } from "node:assert";
import { describe, test } from "node:test";
import { isPrivateIP } from "../cli.js";

describe("isPrivateIP", () => {
	const privateCases = [
		["127.0.0.1", "IPv4 loopback"],
		["10.0.0.1", "IPv4 private 10.x"],
		["172.16.0.1", "IPv4 private 172.16.x"],
		["192.168.1.1", "IPv4 private 192.168.x"],
		["169.254.1.1", "IPv4 link-local"],
		["0.0.0.0", "IPv4 this-network"],
		["100.64.0.1", "IPv4 CGN"],
		["192.0.0.1", "IPv4 IETF Protocol Assignments 192.0.0.0/24"],
		["192.0.2.1", "IPv4 TEST-NET-1 192.0.2.0/24"],
		["198.18.0.1", "IPv4 benchmark 198.18.0.0/15 (b=18)"],
		["198.19.0.1", "IPv4 benchmark 198.18.0.0/15 (b=19)"],
		["198.51.100.1", "IPv4 TEST-NET-2 198.51.100.0/24"],
		["203.0.113.1", "IPv4 TEST-NET-3 203.0.113.0/24"],
		["224.0.0.1", "IPv4 multicast 224.0.0.0/4"],
		["239.255.255.255", "IPv4 multicast upper bound"],
		["240.0.0.1", "IPv4 reserved"],
		["255.255.255.255", "IPv4 broadcast"],
		["::1", "IPv6 loopback compressed"],
		["0:0:0:0:0:0:0:1", "IPv6 loopback expanded"],
		["0000:0000:0000:0000:0000:0000:0000:0001", "IPv6 loopback full"],
		["::", "IPv6 all-zeros"],
		["fc00::1", "IPv6 unique local fc"],
		["fd12::1", "IPv6 unique local fd"],
		["fe80::1", "IPv6 link-local"],
		["ff02::1", "IPv6 multicast"],
		["::ffff:127.0.0.1", "IPv4-mapped loopback dotted"],
		["::ffff:10.0.0.1", "IPv4-mapped private dotted"],
		["::ffff:192.168.1.1", "IPv4-mapped private dotted"],
		["0:0:0:0:0:ffff:7f00:1", "IPv4-mapped loopback hex"],
	];

	for (const [ip, desc] of privateCases) {
		test(`should detect private: ${desc} (${ip})`, () => {
			strictEqual(isPrivateIP(ip), true);
		});
	}

	const publicCases = [
		["8.8.8.8", "Google DNS"],
		["1.1.1.1", "Cloudflare DNS"],
		["2607:f8b0:4004:800::200e", "Google IPv6"],
		["not-an-ip", "non-IP string"],
	];

	for (const [ip, desc] of publicCases) {
		test(`should allow public: ${desc} (${ip})`, () => {
			strictEqual(isPrivateIP(ip), false);
		});
	}
});

describe("isPrivateIP IPv6 extended", () => {
	test("fe80-prefixed malformed groups still classified link-local (fail-closed)", () => {
		strictEqual(isPrivateIP("fe80::gggg"), true);
	});

	test("IPv6 zone id (fe80::1%eth0) classified link-local (fail-closed)", () => {
		strictEqual(isPrivateIP("fe80::1%eth0"), true);
	});

	test("compressed IPv4-mapped mixed (::ffff:10.0.0.1) is private", () => {
		strictEqual(isPrivateIP("::ffff:10.0.0.1"), true);
	});

	test("compressed IPv4-mapped public (::ffff:8.8.8.8) is public", () => {
		strictEqual(isPrivateIP("::ffff:8.8.8.8"), false);
	});

	test("empty and single-colon strings are not private", () => {
		strictEqual(isPrivateIP(""), false);
		strictEqual(isPrivateIP(":"), false);
	});

	test("NAT64 well-known prefix 64:ff9b:: not treated as private", () => {
		strictEqual(isPrivateIP("64:ff9b::8.8.8.8"), false);
	});

	// Zone ID must be stripped before classification
	test("IPv6 loopback with zone ID (::1%lo0) classified private", () => {
		strictEqual(isPrivateIP("::1%lo0"), true);
	});

	test("IPv6 all-zeros with zone ID (::%eth0) classified private", () => {
		strictEqual(isPrivateIP("::%eth0"), true);
	});

	test("IPv6 unique local with zone ID (fc00::1%eth0) classified private", () => {
		strictEqual(isPrivateIP("fc00::1%eth0"), true);
	});

	test("IPv4-mapped hex with zone ID classified private", () => {
		strictEqual(isPrivateIP("0:0:0:0:0:ffff:7f00:1%eth0"), true);
	});

	test("IPv4-mapped dotted with zone ID classified private", () => {
		strictEqual(isPrivateIP("::ffff:192.168.1.1%eth0"), true);
	});
});
