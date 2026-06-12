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

	test("IPv4-mapped hex with invalid hex groups classified private (fail-closed)", () => {
		strictEqual(isPrivateIP("0:0:0:0:0:ffff:0808:gggg"), true);
	});

	test("IPv4-mapped hex with valid hex still classified private", () => {
		strictEqual(isPrivateIP("0:0:0:0:0:ffff:7f00:1"), true);
	});
});

// Each address sits just outside one reserved range, so it is public only while
// that range's bounds are intact. They lock the exact CIDR edges: broadening any
// single conjunct (an octet test flipped to always-true) would misclassify one of
// these as private, which is an SSRF allow-list hole.
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
		["fc00:1", "two-group malformed IPv6 is not expanded to a ULA"],
		["::ffff:0808:0808", "IPv4-mapped hex resolving to public 8.8.8.8"],
	];
	for (const [ip, desc] of nearMissPublic) {
		test(`should allow public: ${ip} (${desc})`, () => {
			strictEqual(isPrivateIP(ip), false);
		});
	}
});

// Addresses sitting exactly on an inclusive CIDR edge: tightening a `<=`/`>=` to a
// strict comparison, or breaking IPv6 leading-zero/`::` normalization, would drop
// them from the private set.
describe("isPrivateIP inclusive boundaries and IPv6 normalization", () => {
	const boundaryPrivate = [
		["100.127.0.1", "CGN upper bound b<=127"],
		["172.31.0.1", "172.16.0.0/12 upper bound b<=31"],
		["::0001", "compressed loopback with leading-zero group"],
		["::0:1", "compressed loopback via right-hand groups"],
		// Compressed IPv4-mapped loopback: the per-group zero strip in the `::`
		// branch must be anchored (^), or "7f00" loses an interior zero and the
		// mapped IPv4 decodes to a public address.
		["::ffff:7f00:1", "compressed IPv4-mapped loopback (::ffff:7f00:1)"],
		// Malformed 5-hex-digit link-local group: an over-long group parses to a
		// value > 0xffff, which the first-group guard rejects fail-closed.
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

	// Fail-closed: malformed hex in the embedded NAT64/6to4 IPv4 groups parses to
	// NaN; bit-math on NaN would forge a public-looking IPv4, so block instead.
	test("NAT64 with malformed embedded hex is private (fail-closed)", () => {
		strictEqual(isPrivateIP("64:ff9b::zzzz:1"), true);
	});

	test("6to4 with malformed embedded hex is private (fail-closed)", () => {
		strictEqual(isPrivateIP("2002:zzzz:1::"), true);
	});

	// Full-form (no `::`) addresses with leading-zero groups exercise the non-`::`
	// per-group leading-zero strip. The strip must be anchored `^0+(?=.)` (keep at
	// least one digit) so an interior group like "0db8" normalizes to "db8":
	//   - mutating the regex to `^0+(?!.)` or the replacement to a literal leaves
	//     "0db8" intact, so the 2001:db8 documentation match fails and the address
	//     is misclassified as PUBLIC. Asserting it is PRIVATE kills both mutants.
	test("full-form 2001:0db8 documentation address (no ::) is private after leading-zero strip", () => {
		strictEqual(isPrivateIP("2001:0db8:0000:0000:0000:0000:0000:0001"), true);
	});

	// A full-form PUBLIC address whose first group is NOT 2001 (and second not db8)
	// must stay public. Forcing the `groups[0] === "2001" && groups[1] === "db8"`
	// documentation conjunct to `true` would misclassify it as private; asserting
	// public kills that ConditionalExpression mutant.
	test("full-form public IPv6 (2606:4700:..) is not private (kills 2001/db8 conditional)", () => {
		strictEqual(isPrivateIP("2606:4700:4700:0000:0000:0000:0000:1111"), false);
	});

	// The documentation match requires BOTH conjuncts: a public address whose
	// SECOND group is "db8" but whose FIRST group is NOT 2001 (here 2003) must stay
	// public. Mutating the left conjunct `groups[0] === "2001"` to `true` would
	// classify it private on the db8 second group alone; asserting public kills it.
	test("full-form db8 second group but non-2001 first group stays public (kills left conjunct)", () => {
		strictEqual(isPrivateIP("2003:0db8:0000:0000:0000:0000:0000:0001"), false);
	});

	// Non-hex first group (not fc/fd/ff) parses to NaN; fail-closed to private.
	test("malformed non-hex first group is private (fail-closed)", () => {
		strictEqual(isPrivateIP("gggg::1"), true);
	});

	// Over-long first group (> 0xffff) is malformed IPv6; fail-closed to private.
	test("over-long first group is private (fail-closed)", () => {
		strictEqual(isPrivateIP("10000::1"), true);
	});
});
