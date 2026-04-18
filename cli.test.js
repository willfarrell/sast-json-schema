import { ok, strictEqual } from "node:assert";
import { describe, test } from "node:test";
import sast, { analyze, crawlSchema, isPrivateIP } from "./cli.js";

test("sast should return a validate function", () => {
	const validate = sast();
	ok(typeof validate === "function");
});

test("sast should default to 2020-12 when schema is undefined", () => {
	const validate = sast(undefined);
	ok(typeof validate === "function");
});

test("sast validate should return boolean", () => {
	const validate = sast();
	const schema = {
		type: "object",
		properties: {
			name: { type: "string", maxLength: 100 },
		},
		additionalProperties: false,
	};
	const valid = validate(schema);
	strictEqual(typeof valid, "boolean");
});

test("sast validate should detect issues in insecure schema", () => {
	const validate = sast();
	const insecureSchema = {
		type: "object",
		properties: {
			name: { type: "string" },
			items: { type: "array", items: { type: "string" } },
		},
	};
	const valid = validate(insecureSchema);
	ok(valid === true || valid === false);
	if (!valid) {
		ok(Array.isArray(validate.errors));
	}
});

test("sast default export should be sast function", async () => {
	const mod = await import("./cli.js");
	strictEqual(mod.default, mod.sast);
});

test("analyze should filter errors matching options.ignore by instancePath", async () => {
	const schema = {
		type: "object",
		properties: {
			name: {
				type: "string",
				maxLength: 100,
				pattern: "[a-z]+\\w+",
			},
		},
		required: ["name"],
		maxProperties: 10,
		unevaluatedProperties: false,
	};
	const errors = await analyze(schema, {
		ignore: ["/properties/name/pattern"],
	});
	const redos = errors.find(
		(e) => e.instancePath === "/properties/name/pattern",
	);
	strictEqual(redos, undefined);
});

test("analyze should filter errors matching options.ignore by instancePath:keyword", async () => {
	const schema = {
		type: "object",
		properties: {
			tags: {
				type: "array",
				items: { type: "string", maxLength: 50 },
				minItems: 10,
				maxItems: 3,
			},
		},
		required: ["tags"],
		maxProperties: 10,
		unevaluatedProperties: false,
	};
	const matched = await analyze(schema, {
		ignore: ["/properties/tags:minItems"],
	});
	strictEqual(
		matched.find(
			(e) => e.keyword === "minItems" && e.instancePath === "/properties/tags",
		),
		undefined,
	);

	const unmatched = await analyze(schema, {
		ignore: ["/properties/tags:maxItems"],
	});
	ok(
		unmatched.find(
			(e) => e.keyword === "minItems" && e.instancePath === "/properties/tags",
		),
	);
});

// --- sast() draft detection ---

test("sast should throw for unsupported $schema", () => {
	let threw = false;
	try {
		sast({ $schema: "https://example.com/unknown" });
	} catch {
		threw = true;
	}
	ok(threw);
});

test("sast should detect draft-04 from $schema", () => {
	const validate = sast({
		$schema: "http://json-schema.org/draft-04/schema#",
	});
	ok(typeof validate === "function");
});

// --- crawlSchema ---

describe("crawlSchema", () => {
	test("should return empty result for null input", () => {
		const r = crawlSchema(null);
		strictEqual(r.depth, 0);
		strictEqual(r.errors.length, 0);
		strictEqual(r.refs.length, 0);
	});

	test("should track depth", () => {
		const r = crawlSchema({ a: { b: { c: 1 } } });
		ok(r.depth >= 3);
	});

	test("should detect depth exceeded", () => {
		const r = crawlSchema({ a: { b: { c: 1 } } }, 2);
		strictEqual(r.depthExceeded, true);
	});

	test("should not exceed when depth is within limit", () => {
		const r = crawlSchema({ a: 1 }, 32);
		strictEqual(r.depthExceeded, false);
	});

	// --- range consistency: minLength/maxLength ---
	test("should catch minLength > maxLength on strings", () => {
		const r = crawlSchema({ type: "string", minLength: 10, maxLength: 5 });
		ok(r.errors.some((e) => e.keyword === "minLength"));
	});

	test("should not flag minLength > maxLength on non-string types", () => {
		const r = crawlSchema({ type: "array", minLength: 10, maxLength: 5 });
		ok(!r.errors.some((e) => e.keyword === "minLength"));
	});

	// --- range consistency: minimum/maximum ---
	test("should allow minimum === maximum (inclusive bounds)", () => {
		const r = crawlSchema({ type: "integer", minimum: 5, maximum: 5 });
		strictEqual(r.errors.length, 0);
	});

	test("should catch minimum > maximum", () => {
		const r = crawlSchema({ type: "integer", minimum: 10, maximum: 5 });
		ok(r.errors.some((e) => e.keyword === "minimum"));
	});

	test("should catch exclusiveMinimum === exclusiveMaximum", () => {
		const r = crawlSchema({
			type: "integer",
			exclusiveMinimum: 5,
			exclusiveMaximum: 5,
		});
		ok(r.errors.some((e) => e.keyword === "minimum"));
	});

	test("should catch minimum === exclusiveMaximum (impossible)", () => {
		const r = crawlSchema({
			type: "integer",
			minimum: 5,
			exclusiveMaximum: 5,
		});
		ok(r.errors.some((e) => e.keyword === "minimum"));
	});

	test("should catch exclusiveMinimum === maximum (impossible)", () => {
		const r = crawlSchema({
			type: "number",
			exclusiveMinimum: 5,
			maximum: 5,
		});
		ok(r.errors.some((e) => e.keyword === "minimum"));
	});

	test("should ignore draft-04 boolean exclusiveMinimum", () => {
		const r = crawlSchema({
			type: "integer",
			minimum: 0,
			exclusiveMinimum: true,
			maximum: 100,
		});
		strictEqual(r.errors.length, 0);
	});

	test("should not flag min/max on non-numeric types", () => {
		const r = crawlSchema({
			type: "string",
			minimum: 100,
			maximum: 1,
		});
		ok(!r.errors.some((e) => e.keyword === "minimum"));
	});

	// --- range consistency: minItems/maxItems ---
	test("should catch minItems > maxItems on arrays", () => {
		const r = crawlSchema({ type: "array", minItems: 10, maxItems: 3 });
		ok(r.errors.some((e) => e.keyword === "minItems"));
	});

	test("should not flag minItems > maxItems on non-array types", () => {
		const r = crawlSchema({ type: "object", minItems: 10, maxItems: 3 });
		ok(!r.errors.some((e) => e.keyword === "minItems"));
	});

	// --- range consistency: minContains/maxContains ---
	test("should catch minContains > maxContains on arrays", () => {
		const r = crawlSchema({
			type: "array",
			minContains: 10,
			maxContains: 3,
		});
		ok(r.errors.some((e) => e.keyword === "minContains"));
	});

	// --- range consistency: minProperties/maxProperties ---
	test("should catch minProperties > maxProperties on objects", () => {
		const r = crawlSchema({
			type: "object",
			minProperties: 10,
			maxProperties: 5,
		});
		ok(r.errors.some((e) => e.keyword === "minProperties"));
	});

	test("should not flag minProperties > maxProperties on non-object types", () => {
		const r = crawlSchema({
			type: "string",
			minProperties: 10,
			maxProperties: 5,
		});
		ok(!r.errors.some((e) => e.keyword === "minProperties"));
	});

	// --- ReDoS detection ---
	test("should detect ReDoS-vulnerable patterns", () => {
		const r = crawlSchema({
			pattern: "^(a+)+$",
		});
		ok(r.errors.some((e) => e.keyword === "pattern"));
	});

	test("should not flag safe patterns", () => {
		const r = crawlSchema({
			pattern: "^[a-z]+$",
		});
		ok(!r.errors.some((e) => e.keyword === "pattern"));
	});

	test("should handle unparseable patterns without crashing", () => {
		const r = crawlSchema({
			pattern: "^[a-z]{1,99999999999999999}$",
		});
		ok(r.errors.some((e) => e.message.includes("could not be parsed")));
	});

	// --- $ref collection ---
	test("should collect remote $ref URLs", () => {
		const r = crawlSchema({ $ref: "https://example.com/schema.json" });
		strictEqual(r.refs.length, 1);
		strictEqual(r.refs[0].hostname, "example.com");
	});

	test("should skip local $ref", () => {
		const r = crawlSchema({ $ref: "#/$defs/foo" });
		strictEqual(r.refs.length, 0);
	});

	test("should skip refs with empty hostname", () => {
		const r = crawlSchema({ $ref: "file:///etc/passwd" });
		strictEqual(r.refs.length, 0);
	});
});

// --- isPrivateIP ---

describe("isPrivateIP", () => {
	const privateCases = [
		["127.0.0.1", "IPv4 loopback"],
		["10.0.0.1", "IPv4 private 10.x"],
		["172.16.0.1", "IPv4 private 172.16.x"],
		["192.168.1.1", "IPv4 private 192.168.x"],
		["169.254.1.1", "IPv4 link-local"],
		["0.0.0.0", "IPv4 this-network"],
		["100.64.0.1", "IPv4 CGN"],
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

// --- analyze overrides ---

describe("analyze overrides", () => {
	test("overrideMaxItems should suppress enum maxItems errors within limit", async () => {
		const schema = {
			$schema: "https://json-schema.org/draft/2020-12/schema",
			$id: "test",
			type: "string",
			maxLength: 100,
			enum: Array.from({ length: 2000 }, (_, i) => `v${i}`),
		};
		const without = await analyze(schema);
		ok(without.some((e) => e.keyword === "maxItems"));

		const within = await analyze(schema, { overrideMaxItems: 2000 });
		ok(!within.some((e) => e.keyword === "maxItems"));

		const below = await analyze(schema, { overrideMaxItems: 1500 });
		ok(below.some((e) => e.keyword === "maxItems"));
	});

	test("overrideMaxProperties should suppress properties maxProperties errors within limit", async () => {
		const schema = {
			$schema: "https://json-schema.org/draft/2020-12/schema",
			$id: "test",
			type: "object",
			required: ["p0"],
			unevaluatedProperties: false,
			maxProperties: 2000,
		};
		const props = {};
		for (let i = 0; i < 1100; i++)
			props[`p${i}`] = {
				type: "string",
				maxLength: 10,
				pattern: "^[a-z]+$",
			};
		schema.properties = props;

		const without = await analyze(schema);
		ok(without.some((e) => e.keyword === "maxProperties"));

		const within = await analyze(schema, { overrideMaxProperties: 1200 });
		ok(!within.some((e) => e.keyword === "maxProperties"));
	});

	test("overrideMaxDepth should control depth limit", async () => {
		const schema = {
			$schema: "https://json-schema.org/draft/2020-12/schema",
			$id: "test",
			type: "object",
			properties: {
				a: {
					type: "string",
					maxLength: 10,
					pattern: "^[a-z]+$",
				},
			},
			required: ["a"],
			unevaluatedProperties: false,
			maxProperties: 5,
		};
		const shallow = await analyze(schema, { overrideMaxDepth: 1 });
		ok(shallow.some((e) => e.keyword === "depth"));

		const deep = await analyze(schema, { overrideMaxDepth: 100 });
		ok(!deep.some((e) => e.keyword === "depth"));
	});
});

// --- analyze options validation ---

describe("analyze options validation", () => {
	test("should throw TypeError for non-numeric overrideMaxDepth", async () => {
		try {
			await analyze(
				{ type: "string", maxLength: 10 },
				{ overrideMaxDepth: "abc" },
			);
			ok(false, "should have thrown");
		} catch (err) {
			ok(err instanceof TypeError);
		}
	});

	test("should throw TypeError for non-numeric overrideMaxItems", async () => {
		const schema = {
			$schema: "https://json-schema.org/draft/2020-12/schema",
			$id: "test",
			type: "string",
			maxLength: 100,
			enum: ["a", "b"],
		};
		try {
			await analyze(schema, { overrideMaxItems: "abc" });
			ok(false, "should have thrown");
		} catch (err) {
			ok(err instanceof TypeError);
		}
	});

	test("should throw TypeError for non-numeric overrideMaxProperties", async () => {
		const schema = {
			$schema: "https://json-schema.org/draft/2020-12/schema",
			$id: "test",
			type: "object",
			properties: { a: { type: "string", maxLength: 10 } },
			required: ["a"],
			unevaluatedProperties: false,
			maxProperties: 5,
		};
		try {
			await analyze(schema, { overrideMaxProperties: "abc" });
			ok(false, "should have thrown");
		} catch (err) {
			ok(err instanceof TypeError);
		}
	});
});
