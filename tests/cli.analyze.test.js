import { deepStrictEqual, ok, strictEqual } from "node:assert";
import { describe, test } from "node:test";
import schema202012 from "../2020-12.json" with { type: "json" };
import {
	analyze,
	formatSarif,
	resolveInstancePath,
	resolveSSRFRefs,
} from "../cli.js";

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

	test("should throw TypeError for non-numeric maxHostnames", async () => {
		try {
			await analyze(
				{ type: "string", maxLength: 10 },
				{ offline: true, maxHostnames: "abc" },
			);
			ok(false, "should have thrown");
		} catch (err) {
			ok(err instanceof TypeError);
			ok(err.message.includes("maxHostnames"));
			ok(err.message.includes("non-negative integer"));
		}
	});

	test("should throw TypeError for negative dnsTotalTimeoutMs", async () => {
		try {
			await analyze(
				{ type: "string", maxLength: 10 },
				{ offline: true, dnsTotalTimeoutMs: -1 },
			);
			ok(false, "should have thrown");
		} catch (err) {
			ok(err instanceof TypeError);
			ok(err.message.includes("dnsTotalTimeoutMs"));
			ok(err.message.includes("non-negative integer"));
		}
	});

	test("should throw TypeError for non-integer maxSchemaSize", async () => {
		try {
			await analyze(
				{ type: "string", maxLength: 10 },
				{ offline: true, maxSchemaSize: 3.5 },
			);
			ok(false, "should have thrown");
		} catch (err) {
			ok(err instanceof TypeError);
			ok(err.message.includes("maxSchemaSize"));
			ok(err.message.includes("non-negative integer"));
		}
	});

	test("should throw TypeError for negative analysisTimeoutMs", async () => {
		try {
			await analyze(
				{ type: "string", maxLength: 10 },
				{ offline: true, analysisTimeoutMs: -1 },
			);
			ok(false, "should have thrown");
		} catch (err) {
			ok(err instanceof TypeError);
			ok(err.message.includes("analysisTimeoutMs"));
			ok(err.message.includes("non-negative integer"));
		}
	});
});

// --- analyze size guard ---

describe("analyze size guard", () => {
	test("should reject schema exceeding maxSchemaSize with a RangeError", async () => {
		try {
			await analyze(
				{ type: "string", maxLength: 10, pattern: "^[a-z]+$" },
				{ offline: true, maxSchemaSize: 5 },
			);
			ok(false, "should have thrown");
		} catch (err) {
			ok(err instanceof RangeError);
			ok(err.message.includes("size"));
		}
	});

	test("should resolve to an array when within maxSchemaSize", async () => {
		const errors = await analyze(
			{ type: "string", maxLength: 10, pattern: "^[a-z]+$" },
			{ offline: true, maxSchemaSize: 1_000_000 },
		);
		ok(Array.isArray(errors));
	});

	test("should throw TypeError for a circular schema", async () => {
		const o = { type: "object" };
		o.self = o;
		try {
			await analyze(o, { offline: true });
			ok(false, "should have thrown");
		} catch (err) {
			ok(err instanceof TypeError);
			ok(err.message.includes("JSON-serializable"));
		}
	});
});

// --- analyze time budget ---

describe("analyze time budget", () => {
	test("analysisTimeoutMs=0 should emit a timeout error", async () => {
		const errors = await analyze(
			{ type: "string", maxLength: 10, pattern: "^[a-z]+$" },
			{ offline: true, analysisTimeoutMs: 0 },
		);
		const timeout = errors.find((e) => e.keyword === "timeout");
		ok(timeout, "expected a timeout error");
		strictEqual(timeout.schemaPath, "#/timeout");
		strictEqual(timeout.instancePath, "");
		strictEqual(timeout.message, "schema analysis exceeded time budget");
		deepStrictEqual(timeout.params, {});
	});

	test("ignore must NOT suppress the timeout finding (incomplete analysis stays visible)", async () => {
		const errors = await analyze(
			{ type: "string", maxLength: 10, pattern: "^[a-z]+$" },
			{ offline: true, analysisTimeoutMs: 0, ignore: [":timeout", ""] },
		);
		ok(
			errors.some((e) => e.keyword === "timeout"),
			"timeout finding must remain even when explicitly ignored",
		);
	});

	test("ignore must NOT suppress the depth finding", async () => {
		const errors = await analyze(
			{
				type: "object",
				properties: {
					a: { type: "string", maxLength: 10, pattern: "^[a-z]+$" },
				},
			},
			{ offline: true, overrideMaxDepth: 0, ignore: [":depth", ""] },
		);
		ok(
			errors.some((e) => e.keyword === "depth"),
			"depth finding must remain even when explicitly ignored",
		);
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

	test("safeHostnames in analyze options suppresses ssrf for matching $ref hostname", async () => {
		const schema = {
			$schema: "https://json-schema.org/draft/2020-12/schema",
			$id: "https://schema.project-owned.invalid/root.json",
			$ref: "https://schema.project-owned.invalid/defs.json",
		};
		const errors = await analyze(schema, {
			safeHostnames: new Set(["schema.project-owned.invalid"]),
		});
		strictEqual(
			errors.filter((e) => e.keyword === "ssrf").length,
			0,
			"safeHostnames must suppress ssrf for project-owned domain",
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

	test("should skip DNS for hostnames in safeHostnames", async () => {
		const refs = [
			{
				hostname: "schema.unresolvable-project.invalid",
				ref: "https://schema.unresolvable-project.invalid/schema.json",
				path: "/$ref",
			},
		];
		const errors = await resolveSSRFRefs(refs, {
			dnsTimeoutMs: 100,
			safeHostnames: new Set(["schema.unresolvable-project.invalid"]),
		});
		strictEqual(errors.length, 0);
	});

	test("should refuse DNS above maxHostnames cap (no DNS performed)", async () => {
		const refs = Array.from({ length: 60 }, (_, i) => ({
			hostname: `h${i}.invalid`,
			ref: `https://h${i}.invalid/schema.json`,
			path: `/$ref/${i}`,
		}));
		const errors = await resolveSSRFRefs(refs, { maxHostnames: 50 });
		strictEqual(errors.length, 1);
		strictEqual(errors[0].keyword, "ssrf");
		ok(errors[0].message.includes("too many"));
	});

	test("should fail closed when dnsTotalTimeoutMs budget is exceeded (no DNS performed)", async () => {
		const refs = [
			{
				hostname: "h.invalid",
				ref: "https://h.invalid/schema.json",
				path: "/$ref",
			},
		];
		const errors = await resolveSSRFRefs(refs, { dnsTotalTimeoutMs: 0 });
		strictEqual(errors.length, 1);
		strictEqual(errors[0].keyword, "ssrf");
		ok(errors[0].message.includes("budget"));
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

	test("resolves an instancePath segment named 'constructor' (own-property read)", async () => {
		// resolveInstancePath walks /properties/constructor/enum. The "constructor"
		// segment must resolve via a guarded own-property read; if the walk were
		// blocked or diverted onto the prototype, the maxItems error could not be
		// suppressed and the first assertion would fail. Backs the
		// prototype-pollution-loop nosemgrep in cli.js (the walk is a read, never
		// a write, and Object.hasOwn keeps it on own properties).
		const schema = {
			$schema: "https://json-schema.org/draft/2020-12/schema",
			$id: "test",
			type: "object",
			properties: {
				constructor: {
					type: "string",
					maxLength: 50,
					enum: Array.from({ length: 2000 }, (_, i) => `s${i}`),
				},
			},
			required: ["constructor"],
			unevaluatedProperties: false,
			maxProperties: 5,
		};
		const within = await analyze(schema, {
			overrideMaxItems: 2000,
			offline: true,
		});
		ok(!within.some((e) => e.keyword === "maxItems"));
		const below = await analyze(schema, {
			overrideMaxItems: 1500,
			offline: true,
		});
		ok(below.some((e) => e.keyword === "maxItems"));
	});

	test("resolves an instancePath segment named '__proto__' (own-property read)", async () => {
		// JSON.parse makes "__proto__" a real own data property (not the prototype
		// setter), mirroring how a hostile schema reaches the tool. The walk must
		// read it as own data and never traverse the real prototype chain.
		const enumJson = JSON.stringify(
			Array.from({ length: 2000 }, (_, i) => `s${i}`),
		);
		const schema = JSON.parse(
			`{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"test","type":"object","properties":{"__proto__":{"type":"string","maxLength":50,"enum":${enumJson}}},"required":["__proto__"],"unevaluatedProperties":false,"maxProperties":5}`,
		);
		const within = await analyze(schema, {
			overrideMaxItems: 2000,
			offline: true,
		});
		ok(!within.some((e) => e.keyword === "maxItems"));
		const below = await analyze(schema, {
			overrideMaxItems: 1500,
			offline: true,
		});
		ok(below.some((e) => e.keyword === "maxItems"));
	});
});

// --- resolveInstancePath (direct) ---
// The override filters only ever hand resolveInstancePath a JSON pointer that
// AJV emitted for a real array/object location, so they never exercise its
// defensive guards. These cover the helper directly: a non-walkable root, an
// empty pointer, a mid-walk descent into a non-object, and a missing segment.
describe("resolveInstancePath direct", () => {
	test("returns undefined when the root is not a walkable object", () => {
		strictEqual(resolveInstancePath(null, "/a"), undefined);
		strictEqual(resolveInstancePath(42, "/a"), undefined);
		strictEqual(resolveInstancePath("string", "/a"), undefined);
	});

	test("returns the root object for an empty pointer", () => {
		const root = { a: 1 };
		strictEqual(resolveInstancePath(root, ""), root);
	});

	test("returns undefined when a mid-walk segment is not an object", () => {
		strictEqual(resolveInstancePath({ a: 5 }, "/a/b"), undefined);
	});

	test("returns undefined when a segment is not an own property", () => {
		strictEqual(resolveInstancePath({ a: {} }, "/a/missing"), undefined);
	});

	test("walks own properties, unescaping ~1 and ~0 segments", () => {
		const root = { "a/b": { "c~d": 7 } };
		strictEqual(resolveInstancePath(root, "/a~1b/c~0d"), 7);
	});
});

// --- allErrors completeness ---
// The meta-schema validators compile with allErrors:true so a single pass
// surfaces EVERY violation, not just the first. This locks in that behavior,
// which is the justification for the ajv-allerrors-true nosemgrep in cli.js:
// dropping allErrors would silently hide findings from a security report.
describe("analyze allErrors completeness", () => {
	test("reports violations from multiple sibling properties in one pass", async () => {
		const schema = {
			$schema: "https://json-schema.org/draft/2020-12/schema",
			$id: "test",
			type: "object",
			properties: {
				a: { type: "string" },
				b: { type: "string" },
			},
			required: ["a", "b"],
			unevaluatedProperties: false,
			maxProperties: 5,
		};
		const errors = await analyze(schema, { offline: true });
		ok(
			errors.some((e) => e.instancePath === "/properties/a"),
			"expected a violation for property a",
		);
		ok(
			errors.some((e) => e.instancePath === "/properties/b"),
			"expected a violation for property b",
		);
	});
});

// --- resolveSSRFRefs private IP detection ---

describe("resolveSSRFRefs private IP", () => {
	test("should report ssrf error when hostname resolves to private IP", async () => {
		const refs = [
			{
				hostname: "localhost",
				ref: "https://localhost/schema.json",
				path: "/$ref",
			},
		];
		const errors = await resolveSSRFRefs(refs, { dnsTimeoutMs: 5_000 });
		strictEqual(errors.length, 1);
		strictEqual(errors[0].keyword, "ssrf");
		ok(errors[0].params.resolvedIP, "should include the resolved private IP");
		ok(errors[0].message.includes("private IP"));
	});
});

// --- analyze lang as array ---

describe("analyze lang as array", () => {
	test("lang=[] (empty array) should not flag any dangerous names", async () => {
		const schema = {
			$schema: "https://json-schema.org/draft/2020-12/schema",
			$id: "test",
			type: "string",
			maxLength: 10,
			pattern: "^[a-z]+$",
		};
		const errors = await analyze(schema, { offline: true, lang: [] });
		ok(!errors.some((e) => e.schemaPath === "#/dangerous-name"));
	});

	test("lang=['__proto__'] (array) should flag __proto__ in properties", async () => {
		const schema = JSON.parse(
			'{"properties":{"__proto__":{"type":"string","maxLength":10,"pattern":"^[a-z]+$"}},"required":["__proto__"],"maxProperties":5,"unevaluatedProperties":false}',
		);
		const errors = await analyze(schema, {
			offline: true,
			lang: ["__proto__"],
		});
		ok(
			errors.some(
				(e) => e.keyword === "properties" && e.params.name === "__proto__",
			),
		);
	});

	test("analyze with unknown lang should throw TypeError", async () => {
		try {
			await analyze(
				{ type: "string", maxLength: 10 },
				{ offline: true, lang: "elvish" },
			);
			ok(false, "should have thrown");
		} catch (err) {
			ok(err instanceof TypeError);
			ok(err.message.includes("elvish"));
		}
	});
});

// --- formatSarif ---

describe("formatSarif", () => {
	test("should produce valid SARIF 2.1.0 structure", () => {
		const errors = [
			{
				instancePath: "/properties/name",
				schemaPath: "#/maxLength",
				keyword: "maxLength",
				params: { limit: 100 },
				message: "must have maxLength",
			},
		];
		const sarif = formatSarif(errors, "/tmp/schema.json");
		strictEqual(sarif.version, "2.1.0");
		ok(Array.isArray(sarif.runs));
		strictEqual(sarif.runs[0].tool.driver.name, "sast-json-schema");
		strictEqual(sarif.runs[0].results[0].ruleId, "maxLength");
		strictEqual(sarif.runs[0].results[0].level, "error");
	});

	test("should use keyword as ruleId when schemaPath is absent", () => {
		const errors = [
			{
				instancePath: "/",
				keyword: "custom",
				message: "custom error",
				params: {},
			},
		];
		const sarif = formatSarif(errors, "/tmp/schema.json");
		strictEqual(sarif.runs[0].results[0].ruleId, "custom");
		strictEqual(sarif.runs[0].tool.driver.rules[0].id, "custom");
	});

	test("should use 'unknown' as ruleId when both schemaPath and keyword are absent", () => {
		const errors = [
			{
				instancePath: "/",
				message: "error with no keyword",
			},
		];
		const sarif = formatSarif(errors, "/tmp/schema.json");
		strictEqual(sarif.runs[0].results[0].ruleId, "unknown");
	});

	test("should fall back to keyword when schemaPath first segment is empty", () => {
		const errors = [
			{
				instancePath: "/",
				schemaPath: "#/",
				keyword: "fallback",
				message: "test",
			},
		];
		const sarif = formatSarif(errors, "/tmp/schema.json");
		strictEqual(sarif.runs[0].results[0].ruleId, "fallback");
	});

	test("should use keyword as message text when message is absent", () => {
		const errors = [
			{
				instancePath: "/",
				schemaPath: "#/maxLength",
				keyword: "maxLength",
				params: {},
			},
		];
		const sarif = formatSarif(errors, "/tmp/schema.json");
		strictEqual(sarif.runs[0].results[0].message.text, "maxLength");
	});

	test("should use 'schema issue' when both message and keyword are absent", () => {
		const errors = [
			{
				instancePath: "/",
				schemaPath: "#/custom",
			},
		];
		const sarif = formatSarif(errors, "/tmp/schema.json");
		strictEqual(sarif.runs[0].results[0].message.text, "schema issue");
	});

	test("should handle errors without params", () => {
		const errors = [
			{
				instancePath: "/",
				schemaPath: "#/maxLength",
				keyword: "maxLength",
				message: "must have maxLength",
			},
		];
		const sarif = formatSarif(errors, "/tmp/schema.json");
		const props = sarif.runs[0].results[0].properties;
		strictEqual(props.keyword, "maxLength");
		strictEqual(props.instancePath, "/");
	});

	test("should handle errors without instancePath", () => {
		const errors = [
			{
				schemaPath: "#/maxLength",
				keyword: "maxLength",
				message: "must have maxLength",
				params: {},
			},
		];
		const sarif = formatSarif(errors, "/tmp/schema.json");
		strictEqual(sarif.runs[0].results[0].properties.instancePath, "");
		strictEqual(
			sarif.runs[0].results[0].locations[0].logicalLocations[0]
				.fullyQualifiedName,
			"",
		);
	});
});
