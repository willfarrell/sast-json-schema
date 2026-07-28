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

	test("empty string is not private (no colon, not an address)", () => {
		strictEqual(isPrivateIP(""), false);
	});

	// Malformed colon-containing strings are fail-closed: they look like IPv6
	// but do not parse, so they are blocked rather than allowed through.
	test("single-colon string classified private (fail-closed)", () => {
		strictEqual(isPrivateIP(":"), true);
	});

	test("two-group malformed IPv6 (fc00:1) classified private (fail-closed)", () => {
		strictEqual(isPrivateIP("fc00:1"), true);
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

	test("IPv4-mapped hex with invalid hex groups classified private (fail-closed)", () => {
		strictEqual(isPrivateIP("0:0:0:0:0:ffff:0808:gggg"), true);
	});

	test("IPv4-mapped hex with valid hex still classified private", () => {
		strictEqual(isPrivateIP("0:0:0:0:0:ffff:7f00:1"), true);
	});
});

// Each address sits just outside one reserved range, so it is public only while
// that range's CIDR bounds are intact. Broadening any range (a corrupted subnet
// entry, a malformed-input gate flipped to always-block) would misclassify one
// of these as private, which is an SSRF allow-list hole.
describe("isPrivateIP near-miss public addresses", () => {
	const nearMissPublic = [
		["10.2.3.999", "octet above 255 voids the dotted-quad match"],
		["10.2.3.-5", "negative octet voids the dotted-quad match"],
		["100.0.0.1", "100.x below CGN b>=64"],
		["100.200.0.1", "100.x above CGN b<=127"],
		["1.254.0.1", "b=254 but a!=169 (not link-local)"],
		["169.0.0.1", "a=169 but b!=254 (not link-local)"],
		["172.0.0.1", "172.x below private b>=16"],
		["172.200.0.1", "172.x above private b<=31"],
		["192.5.0.1", "a=192 but b not 0/168"],
		["192.0.5.1", "192.0.x with third octet not 0/2"],
		["192.5.2.1", "third octet 2 but b!=0 (not TEST-NET-1)"],
		["198.0.0.1", "a=198 but b not 18/19/51"],
		["198.0.100.1", "third octet 100 but b!=51 (not TEST-NET-2)"],
		["198.51.5.1", "a=198 b=51 but third octet!=100"],
		["203.5.113.1", "third octet 113 but b!=0 (not TEST-NET-3)"],
		["203.0.5.1", "a=203 b=0 but third octet!=113"],
		// Wrong first octet but otherwise-matching range: the leading `a === N`
		// check must hold, or the whole range collapses to "any IP whose other
		// octets match" (e.g. a CGN match for any b in 64..127).
		["8.100.0.1", "b in CGN range but a!=100"],
		["8.20.0.1", "b in 172-private range but a!=172"],
		["8.0.2.1", "b=0 third=2 but a!=192 (not TEST-NET-1)"],
		["8.0.0.1", "b=0 third=0 but a!=192 (not IETF 192.0.0.0/24)"],
		["8.168.0.1", "b=168 but a!=192 (not 192.168/16)"],
		["8.18.0.1", "b in benchmark range but a!=198"],
		["8.51.100.1", "b=51 third=100 but a!=198 (not TEST-NET-2)"],
		["8.0.113.1", "b=0 third=113 but a!=203 (not TEST-NET-3)"],
		["::ffff:0808:0808", "IPv4-mapped hex resolving to public 8.8.8.8"],
	];
	for (const [ip, desc] of nearMissPublic) {
		test(`should allow public: ${ip} (${desc})`, () => {
			strictEqual(isPrivateIP(ip), false);
		});
	}
});

// Addresses sitting exactly on an inclusive CIDR edge, plus IPv6 forms whose
// classification depends on leading-zero/`::` canonicalization. Narrowing a
// subnet or breaking canonicalization would drop them from the private set.
describe("isPrivateIP inclusive boundaries and IPv6 normalization", () => {
	const boundaryPrivate = [
		["100.127.0.1", "CGN upper bound b<=127"],
		["172.31.0.1", "172.16.0.0/12 upper bound b<=31"],
		["::0001", "compressed loopback with leading-zero group"],
		["::0:1", "compressed loopback via right-hand groups"],
		// Compressed IPv4-mapped loopback in hex-group form: must decode the
		// embedded 7f00:1 as 127.0.0.1, not match it as a plain IPv6 address.
		["::ffff:7f00:1", "compressed IPv4-mapped loopback (::ffff:7f00:1)"],
		// Malformed 5-hex-digit link-local group: over-long groups make the
		// address invalid IPv6, which is fail-closed to private.
		["fe800::1", "malformed fe80-prefixed group still private (fail-closed)"],
	];
	for (const [ip, desc] of boundaryPrivate) {
		test(`should detect private: ${ip} (${desc})`, () => {
			strictEqual(isPrivateIP(ip), true);
		});
	}
});

// IPv6 ranges added: NAT64 64:ff9b::/96, 6to4 2002::/16, link-local fe80::/10,
// site-local fec0::/10, documentation 2001:db8::/32. Each row pins one boundary
// edge so broadening a prefix/range conjunct misclassifies it as a SSRF hole.
describe("isPrivateIP IPv6 extended ranges", () => {
	const privateRows = [
		// NAT64 64:ff9b::/96 embeds an IPv4 in the last two hex groups.
		["64:ff9b::7f00:1", "NAT64 embeds 127.0.0.1 (private)"],
		// 6to4 2002::/16 embeds an IPv4 in groups 1 and 2.
		["2002:7f00:1::", "6to4 embeds 127.0.0.1 (private)"],
		// Link-local fe80::/10 spans fe80-febf, not just literal fe80.
		["fe80::", "link-local lower edge fe80"],
		["febf::", "link-local upper edge febf"],
		// Site-local fec0::/10 spans fec0-feff.
		["fec0::", "site-local lower edge fec0"],
		["feff::", "site-local upper edge feff"],
		["ff00::", "multicast lower edge (existing)"],
		// Documentation 2001:db8::/32.
		["2001:db8::", "documentation 2001:db8::/32"],
	];
	for (const [ip, desc] of privateRows) {
		test(`should detect private: ${ip} (${desc})`, () => {
			strictEqual(isPrivateIP(ip), true);
		});
	}

	const publicRows = [
		["64:ff9b::808:808", "NAT64 embeds 8.8.8.8 (public)"],
		["64:ff9a::7f00:1", "wrong NAT64 prefix (group1 != ff9b)"],
		["2002:808:808::", "6to4 embeds 8.8.8.8 (public)"],
		["fe7f::", "just below link-local fe80"],
		["2001:db7::", "just below documentation db8"],
		["2001:db9::", "just above documentation db8"],
	];
	for (const [ip, desc] of publicRows) {
		test(`should allow public: ${ip} (${desc})`, () => {
			strictEqual(isPrivateIP(ip), false);
		});
	}

	// Fail-closed: malformed hex in the embedded NAT64/6to4 IPv4 groups makes
	// the whole address invalid IPv6, which is blocked instead of decoded.
	test("NAT64 with malformed embedded hex is private (fail-closed)", () => {
		strictEqual(isPrivateIP("64:ff9b::zzzz:1"), true);
	});

	test("6to4 with malformed embedded hex is private (fail-closed)", () => {
		strictEqual(isPrivateIP("2002:zzzz:1::"), true);
	});

	// Full-form (no `::`) addresses with leading-zero groups: classification
	// must be canonical-form-insensitive, so "2001:0db8" still matches the
	// 2001:db8::/32 documentation range.
	test("full-form 2001:0db8 documentation address (no ::) is private", () => {
		strictEqual(isPrivateIP("2001:0db8:0000:0000:0000:0000:0000:0001"), true);
	});

	// Full-form PUBLIC addresses near the documentation range must stay public:
	// neither a non-2001 first group nor a db8 second group alone may match.
	test("full-form public IPv6 (2606:4700:..) is not private", () => {
		strictEqual(isPrivateIP("2606:4700:4700:0000:0000:0000:0000:1111"), false);
	});

	test("full-form db8 second group but non-2001 first group stays public", () => {
		strictEqual(isPrivateIP("2003:0db8:0000:0000:0000:0000:0000:0001"), false);
	});

	// Non-hex first group is invalid IPv6; fail-closed to private.
	test("malformed non-hex first group is private (fail-closed)", () => {
		strictEqual(isPrivateIP("gggg::1"), true);
	});

	// Over-long first group (> 0xffff) is malformed IPv6; fail-closed to private.
	test("over-long first group is private (fail-closed)", () => {
		strictEqual(isPrivateIP("10000::1"), true);
	});
});
