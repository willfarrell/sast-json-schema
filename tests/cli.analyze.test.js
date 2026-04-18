import { ok, strictEqual } from "node:assert";
import { describe, test } from "node:test";
import schema202012 from "../2020-12.json" with { type: "json" };
import { analyze, resolveSSRFRefs } from "../cli.js";

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

	test("should throw TypeError for negative overrideMaxDepth", async () => {
		try {
			await analyze(
				{ type: "string", maxLength: 10 },
				{ overrideMaxDepth: -1 },
			);
			ok(false, "should have thrown");
		} catch (err) {
			ok(err instanceof TypeError);
			ok(err.message.includes("non-negative integer"));
		}
	});

	test("should throw TypeError for Infinity overrideMaxDepth", async () => {
		try {
			await analyze(
				{ type: "string", maxLength: 10 },
				{ overrideMaxDepth: Infinity },
			);
			ok(false, "should have thrown");
		} catch (err) {
			ok(err instanceof TypeError);
		}
	});

	test("should throw TypeError for non-integer overrideMaxItems", async () => {
		try {
			await analyze(
				{ type: "string", maxLength: 10 },
				{ overrideMaxItems: 3.5 },
			);
			ok(false, "should have thrown");
		} catch (err) {
			ok(err instanceof TypeError);
			ok(err.message.includes("non-negative integer"));
		}
	});

	test("should throw TypeError for negative overrideMaxProperties", async () => {
		try {
			await analyze(
				{ type: "string", maxLength: 10 },
				{ overrideMaxProperties: -100 },
			);
			ok(false, "should have thrown");
		} catch (err) {
			ok(err instanceof TypeError);
			ok(err.message.includes("non-negative integer"));
		}
	});
});

// --- regression: filter schemaPaths must match what AJV actually emits ---

describe("override filter schemaPath regression", () => {
	test("maxItems filter target matches AJV-emitted schemaPath", async () => {
		const schema = {
			$schema: "https://json-schema.org/draft/2020-12/schema",
			$id: "test",
			type: "string",
			maxLength: 100,
			enum: Array.from({ length: 2000 }, (_, i) => `v${i}`),
		};
		const errors = await analyze(schema, { offline: true });
		const maxItemsErr = errors.find((e) => e.keyword === "maxItems");
		ok(maxItemsErr, "should report maxItems violation");
		strictEqual(
			maxItemsErr.schemaPath,
			"#/$defs/safeArrayItemsLimits/maxItems",
			"AJV schemaPath must match the literal the override filter checks in cli.js",
		);
	});

	test("maxProperties filter target matches AJV-emitted schemaPath", async () => {
		const props = {};
		for (let i = 0; i < 1100; i++)
			props[`p${i}`] = { type: "string", maxLength: 10, pattern: "^[a-z]+$" };
		const schema = {
			$schema: "https://json-schema.org/draft/2020-12/schema",
			$id: "test",
			type: "object",
			properties: props,
			required: ["p0"],
			unevaluatedProperties: false,
			maxProperties: 2000,
		};
		const errors = await analyze(schema, { offline: true });
		const maxPropErr = errors.find((e) => e.keyword === "maxProperties");
		ok(maxPropErr, "should report maxProperties violation");
		strictEqual(
			maxPropErr.schemaPath,
			"#/$defs/safeObjectPropertiesLimits/maxProperties",
			"AJV schemaPath must match the literal the override filter checks in cli.js",
		);
	});

	test("built meta-schema still contains the override anchor defs", () => {
		ok(
			schema202012.$defs.safeArrayItemsLimits,
			"safeArrayItemsLimits must exist for override filter",
		);
		ok(
			schema202012.$defs.safeObjectPropertiesLimits,
			"safeObjectPropertiesLimits must exist for override filter",
		);
	});
});

// --- analyze offline/DNS option plumbing ---

describe("analyze DNS options", () => {
	test("offline mode should not emit ssrf errors for remote $ref", async () => {
		const schema = {
			$schema: "https://json-schema.org/draft/2020-12/schema",
			$id: "test",
			$ref: "https://example.com/schema.json",
		};
		const offline = await analyze(schema, { offline: true });
		strictEqual(
			offline.filter((e) => e.keyword === "ssrf").length,
			0,
			"offline mode must skip DNS lookup entirely",
		);
	});

	test("dnsTimeoutMs=1 should fail fast when offline is unset", async () => {
		const schema = {
			$schema: "https://json-schema.org/draft/2020-12/schema",
			$id: "test",
			$ref: "https://definitely-not-a-real-tld-xyz-12345.invalid/schema.json",
		};
		const start = Date.now();
		await analyze(schema, { dnsTimeoutMs: 1, dnsConcurrency: 1 });
		const elapsed = Date.now() - start;
		ok(
			elapsed < 10_000,
			`should fail fast with short timeout, took ${elapsed}ms`,
		);
	});

	test("public hostname $ref should not produce ssrf errors", async () => {
		const refs = [
			{
				hostname: "dns.google",
				ref: "https://dns.google/schema.json",
				path: "/$ref",
			},
		];
		const errors = await resolveSSRFRefs(refs, { dnsTimeoutMs: 5_000 });
		strictEqual(
			errors.filter((e) => e.params.resolvedIP).length,
			0,
			"public hostname must not be flagged as private",
		);
	});
});

// --- resolveSSRFRefs direct tests ---

describe("resolveSSRFRefs", () => {
	test("should return empty array for empty refs", async () => {
		const errors = await resolveSSRFRefs([]);
		strictEqual(errors.length, 0);
	});

	test("should report errors for unresolvable hostnames", async () => {
		const refs = [
			{
				hostname: "definitely-not-a-real-tld-xyz-99999.invalid",
				ref: "https://definitely-not-a-real-tld-xyz-99999.invalid/schema.json",
				path: "/$ref",
			},
		];
		const errors = await resolveSSRFRefs(refs, { dnsTimeoutMs: 100 });
		strictEqual(errors.length, 1);
		strictEqual(errors[0].keyword, "ssrf");
		ok(errors[0].message.includes("does not resolve"));
	});

	test("should group multiple refs by hostname", async () => {
		const refs = [
			{
				hostname: "no-such-host-abc123.invalid",
				ref: "https://no-such-host-abc123.invalid/a.json",
				path: "/a/$ref",
			},
			{
				hostname: "no-such-host-abc123.invalid",
				ref: "https://no-such-host-abc123.invalid/b.json",
				path: "/b/$ref",
			},
		];
		const errors = await resolveSSRFRefs(refs, { dnsTimeoutMs: 100 });
		strictEqual(errors.length, 2);
	});

	test("should respect concurrency option", async () => {
		const refs = [
			{
				hostname: "no-such-host-1.invalid",
				ref: "https://no-such-host-1.invalid/a.json",
				path: "/a/$ref",
			},
			{
				hostname: "no-such-host-2.invalid",
				ref: "https://no-such-host-2.invalid/b.json",
				path: "/b/$ref",
			},
		];
		const errors = await resolveSSRFRefs(refs, {
			dnsTimeoutMs: 100,
			dnsConcurrency: 1,
		});
		strictEqual(errors.length, 2);
	});
});

// --- resolveInstancePath (via analyze overrides) ---

describe("resolveInstancePath via overrides", () => {
	test("overrideMaxItems resolves nested enum path", async () => {
		const schema = {
			$schema: "https://json-schema.org/draft/2020-12/schema",
			$id: "test",
			type: "object",
			properties: {
				status: {
					type: "string",
					maxLength: 50,
					enum: Array.from({ length: 2000 }, (_, i) => `s${i}`),
				},
			},
			required: ["status"],
			unevaluatedProperties: false,
			maxProperties: 5,
		};
		const errors = await analyze(schema, {
			overrideMaxItems: 2000,
			offline: true,
		});
		ok(!errors.some((e) => e.keyword === "maxItems"));
	});

	test("overrideMaxDepth 0 rejects schemas with nested objects", async () => {
		const schema = {
			$schema: "https://json-schema.org/draft/2020-12/schema",
			$id: "test",
			type: "object",
			properties: {
				a: { type: "string", maxLength: 10, pattern: "^[a-z]+$" },
			},
			required: ["a"],
			unevaluatedProperties: false,
			maxProperties: 5,
		};
		const errors = await analyze(schema, { overrideMaxDepth: 0 });
		ok(errors.some((e) => e.keyword === "depth"));
		strictEqual(errors[0].params.limit, 0);
	});

	test("overrideMaxItems keeps error when override is below actual count", async () => {
		const schema = {
			$schema: "https://json-schema.org/draft/2020-12/schema",
			$id: "test",
			type: "string",
			maxLength: 100,
			enum: Array.from({ length: 2000 }, (_, i) => `v${i}`),
		};
		const errors = await analyze(schema, {
			overrideMaxItems: 1500,
			offline: true,
		});
		ok(errors.some((e) => e.keyword === "maxItems"));
	});
});
