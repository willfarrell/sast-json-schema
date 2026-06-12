import { deepStrictEqual, ok, strictEqual } from "node:assert";
import { describe, test } from "node:test";
import { pathToFileURL } from "node:url";
import schema202012 from "../2020-12.json" with { type: "json" };
import {
	analyze,
	formatSarif,
	resolveInstancePath,
	resolveSSRFRefs,
	run,
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

	test("$dynamicRef to a private-resolving hostname yields ssrf error online", async () => {
		const schema = {
			$schema: "https://json-schema.org/draft/2020-12/schema",
			$id: "test",
			$dynamicRef: "https://localhost/schema.json",
		};
		const errors = await analyze(schema, { dnsTimeoutMs: 5_000 });
		const ssrf = errors.filter((e) => e.keyword === "ssrf");
		strictEqual(
			ssrf.length,
			1,
			"localhost $dynamicRef must be flagged as ssrf",
		);
		strictEqual(ssrf[0].instancePath, "/$dynamicRef");
		ok(ssrf[0].params.resolvedIP, "should include the resolved private IP");
	});

	test("offline mode should not emit ssrf errors for remote $dynamicRef", async () => {
		const schema = {
			$schema: "https://json-schema.org/draft/2020-12/schema",
			$id: "test",
			$dynamicRef: "https://localhost/schema.json",
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

	test("rule entry carries id, descriptions and driver metadata", () => {
		const errors = [
			{
				instancePath: "/properties/name",
				schemaPath: "#/maxLength",
				keyword: "maxLength",
				params: { limit: 100 },
				message: "must have maxLength",
			},
		];
		const driver = formatSarif(errors, "/tmp/schema.json").runs[0].tool.driver;
		strictEqual(
			driver.informationUri,
			"https://github.com/willfarrell/sast-json-schema",
		);
		const rule = driver.rules[0];
		strictEqual(rule.id, "maxLength");
		strictEqual(rule.name, "maxLength");
		strictEqual(rule.shortDescription.text, "maxLength");
		strictEqual(rule.fullDescription.text, "must have maxLength");
		strictEqual(rule.defaultConfiguration.level, "error");
	});

	test("rule fullDescription falls back to the ruleId when message is absent", () => {
		const errors = [{ schemaPath: "#/maxLength", keyword: "maxLength" }];
		const rule = formatSarif(errors, "/tmp/schema.json").runs[0].tool.driver
			.rules[0];
		strictEqual(rule.fullDescription.text, "maxLength");
	});

	test("rule id is 'unknown' in the rule table when schemaPath and keyword are absent", () => {
		const errors = [{ instancePath: "/", message: "no rule" }];
		const rule = formatSarif(errors, "/tmp/schema.json").runs[0].tool.driver
			.rules[0];
		strictEqual(rule.id, "unknown");
	});

	test("repeated ruleId is de-duplicated, keeping the first occurrence", () => {
		const errors = [
			{ schemaPath: "#/maxLength", keyword: "maxLength", message: "first" },
			{ schemaPath: "#/maxLength", keyword: "maxLength", message: "second" },
		];
		const driver = formatSarif(errors, "/tmp/schema.json").runs[0].tool.driver;
		strictEqual(driver.rules.length, 1);
		strictEqual(driver.rules[0].id, "maxLength");
		// First-wins: re-adding would overwrite fullDescription with "second".
		strictEqual(driver.rules[0].fullDescription.text, "first");
	});

	test("ruleId is the first schemaPath segment, not the keyword, when both exist", () => {
		const errors = [
			{ schemaPath: "#/required/0", keyword: "required", message: "m" },
		];
		const sarif = formatSarif(errors, "/tmp/schema.json");
		// `... || err.keyword` only fires when the segment is empty; here it is
		// "required" from the path, which happens to differ from a keyword test.
		strictEqual(sarif.runs[0].results[0].ruleId, "required");
		const errors2 = [
			{ schemaPath: "#/properties/x", keyword: "kw", message: "m" },
		];
		const sarif2 = formatSarif(errors2, "/tmp/schema.json");
		strictEqual(sarif2.runs[0].results[0].ruleId, "properties");
		// Same derivation in the rule table: must be the path segment, not keyword.
		strictEqual(sarif2.runs[0].tool.driver.rules[0].id, "properties");
	});

	test("ruleId strips only a leading '#/' from schemaPath", () => {
		// A non-leading "#/" must be preserved: the strip is anchored to the start,
		// so "foo#/bar" keeps its first segment "foo#" rather than collapsing to
		// "foobar". Exercises both the rule-table and the per-result derivations.
		const errors = [{ schemaPath: "foo#/bar", keyword: "kw", message: "m" }];
		const sarif = formatSarif(errors, "/tmp/schema.json");
		strictEqual(sarif.runs[0].results[0].ruleId, "foo#");
		strictEqual(sarif.runs[0].tool.driver.rules[0].id, "foo#");
	});

	test("top-level $schema is the SARIF 2.1.0 schema URL", () => {
		const sarif = formatSarif([{ keyword: "x" }], "/tmp/schema.json");
		strictEqual(
			sarif.$schema,
			"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json",
		);
	});

	test("result location carries the input file URI and value kind", () => {
		const errors = [
			{ instancePath: "/a", schemaPath: "#/maxLength", keyword: "maxLength" },
		];
		const loc = formatSarif(errors, "/tmp/schema.json").runs[0].results[0]
			.locations[0];
		ok(loc.physicalLocation.artifactLocation.uri.startsWith("file://"));
		ok(loc.physicalLocation.artifactLocation.uri.endsWith("/tmp/schema.json"));
		strictEqual(loc.logicalLocations[0].kind, "value");
	});

	test("artifactLocation uri is repo-relative with a SRCROOT uriBaseId when the input is under cwd", () => {
		const errors = [
			{ instancePath: "/a", schemaPath: "#/maxLength", keyword: "maxLength" },
		];
		const sarif = formatSarif(errors, "/repo/schemas/api.json", "/repo");
		const loc = sarif.runs[0].results[0].locations[0];
		strictEqual(loc.physicalLocation.artifactLocation.uri, "schemas/api.json");
		strictEqual(loc.physicalLocation.artifactLocation.uriBaseId, "SRCROOT");
		strictEqual(
			sarif.runs[0].originalUriBaseIds.SRCROOT.uri,
			pathToFileURL("/repo/").href,
		);
	});

	test("relative artifactLocation uri has no leading './' for a file directly in cwd", () => {
		const errors = [
			{ instancePath: "/a", schemaPath: "#/maxLength", keyword: "maxLength" },
		];
		const sarif = formatSarif(errors, "/repo/api.json", "/repo");
		strictEqual(
			sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation
				.uri,
			"api.json",
		);
	});

	test("originalUriBaseIds SRCROOT uri is the cwd as a file:// directory URI", () => {
		const errors = [{ instancePath: "/a", keyword: "x" }];
		const sarif = formatSarif(errors, "/repo/sub/x.json", "/repo");
		strictEqual(
			sarif.runs[0].originalUriBaseIds.SRCROOT.uri,
			pathToFileURL("/repo/").href,
		);
		ok(sarif.runs[0].originalUriBaseIds.SRCROOT.uri.endsWith("/repo/"));
	});

	test("input path equal to cwd (empty relative path) falls back to the absolute file:// uri", () => {
		// resolve(inputPath) === cwd makes relative() return "", which must NOT be
		// treated as inside-cwd (an empty uri is not a usable artifact location);
		// it falls back to the absolute file:// uri with no uriBaseId.
		const errors = [{ instancePath: "/a", keyword: "x" }];
		const sarif = formatSarif(errors, "/repo", "/repo");
		const loc = sarif.runs[0].results[0].locations[0];
		strictEqual(
			loc.physicalLocation.artifactLocation.uri,
			pathToFileURL("/repo").href,
		);
		strictEqual(loc.physicalLocation.artifactLocation.uriBaseId, undefined);
		strictEqual(sarif.runs[0].originalUriBaseIds, undefined);
	});

	test("input outside cwd falls back to the absolute file:// uri with no uriBaseId or originalUriBaseIds", () => {
		const errors = [
			{ instancePath: "/a", schemaPath: "#/maxLength", keyword: "maxLength" },
		];
		const sarif = formatSarif(errors, "/elsewhere/api.json", "/repo");
		const loc = sarif.runs[0].results[0].locations[0];
		strictEqual(
			loc.physicalLocation.artifactLocation.uri,
			pathToFileURL("/elsewhere/api.json").href,
		);
		ok(loc.physicalLocation.artifactLocation.uri.startsWith("file://"));
		strictEqual(loc.physicalLocation.artifactLocation.uriBaseId, undefined);
		strictEqual(sarif.runs[0].originalUriBaseIds, undefined);
	});

	test("result properties carry schemaPath, keyword and spread params", () => {
		const errors = [
			{
				instancePath: "/properties/name",
				schemaPath: "#/maxLength",
				keyword: "maxLength",
				params: { limit: 100 },
				message: "must have maxLength",
			},
		];
		const props = formatSarif(errors, "/tmp/schema.json").runs[0].results[0]
			.properties;
		strictEqual(props.schemaPath, "#/maxLength");
		strictEqual(props.keyword, "maxLength");
		strictEqual(props.instancePath, "/properties/name");
		strictEqual(props.limit, 100);
	});

	test("result properties default schemaPath and keyword to empty strings", () => {
		const errors = [{ instancePath: "/", message: "bare" }];
		const props = formatSarif(errors, "/tmp/schema.json").runs[0].results[0]
			.properties;
		strictEqual(props.schemaPath, "");
		strictEqual(props.keyword, "");
	});
});

// Boundary and valid-value coverage for the integer option validators
// (!Number.isFinite(n) || n < 0 || !Number.isInteger(n)). Existing tests cover
// non-numeric/non-integer; these add the valid, zero and negative-integer cases.
describe("analyze integer option validators", () => {
	const tiny = { type: "string" };

	test("maxHostnames: a valid positive integer is accepted", async () => {
		ok(
			Array.isArray(await analyze(tiny, { offline: true, maxHostnames: 256 })),
		);
	});
	test("maxHostnames: zero is a valid non-negative integer", async () => {
		ok(Array.isArray(await analyze(tiny, { offline: true, maxHostnames: 0 })));
	});
	test("maxHostnames: a negative integer throws TypeError", async () => {
		try {
			await analyze(tiny, { offline: true, maxHostnames: -5 });
			ok(false, "should have thrown");
		} catch (err) {
			ok(err instanceof TypeError);
			ok(err.message.includes("maxHostnames"));
			ok(err.message.includes("non-negative integer"));
		}
	});

	test("dnsTotalTimeoutMs: a valid positive integer is accepted", async () => {
		ok(
			Array.isArray(
				await analyze(tiny, { offline: true, dnsTotalTimeoutMs: 30000 }),
			),
		);
	});
	test("dnsTotalTimeoutMs: zero is a valid non-negative integer", async () => {
		ok(
			Array.isArray(
				await analyze(tiny, { offline: true, dnsTotalTimeoutMs: 0 }),
			),
		);
	});

	test("maxSchemaSize: a large valid integer is accepted", async () => {
		ok(
			Array.isArray(
				await analyze(tiny, { offline: true, maxSchemaSize: 1_000_000 }),
			),
		);
	});
	test("maxSchemaSize: zero is valid (no TypeError) and hits the size guard instead", async () => {
		// 0 passes the n>=0 validator, so the failure must be the RangeError size
		// guard, not the TypeError validator (kills n<0 -> n<=0).
		try {
			await analyze(tiny, { offline: true, maxSchemaSize: 0 });
			ok(false, "should have thrown");
		} catch (err) {
			ok(err instanceof RangeError, `expected RangeError, got ${err.name}`);
			ok(err.message.includes("size"));
		}
	});
	test("maxSchemaSize: a negative integer throws TypeError (not the size guard)", async () => {
		try {
			await analyze(tiny, { offline: true, maxSchemaSize: -5 });
			ok(false, "should have thrown");
		} catch (err) {
			ok(err instanceof TypeError, `expected TypeError, got ${err.name}`);
			ok(err.message.includes("maxSchemaSize"));
		}
	});
});

// The size guard uses a strict `>`; a schema serialized to exactly the limit must
// be accepted (kills the `> sizeLimit` -> `>= sizeLimit` mutation).
describe("analyze size guard boundary", () => {
	test("schema serialized to exactly maxSchemaSize is accepted", async () => {
		const schema = { type: "string" };
		const exact = Buffer.byteLength(JSON.stringify(schema));
		ok(
			Array.isArray(
				await analyze(schema, { offline: true, maxSchemaSize: exact }),
			),
		);
	});
	test("schema one byte over the limit is rejected", async () => {
		const schema = { type: "string" };
		const exact = Buffer.byteLength(JSON.stringify(schema));
		try {
			await analyze(schema, { offline: true, maxSchemaSize: exact - 1 });
			ok(false, "should have thrown");
		} catch (err) {
			ok(err instanceof RangeError);
		}
	});
});

// The depth-exceeded short-circuit returns one synthetic finding; pin its full
// shape so blanking any field is caught.
describe("analyze depth-exceeded payload", () => {
	test("depth-exceeded returns the depth finding with full shape", async () => {
		const schema = {
			type: "object",
			properties: {
				a: { type: "string", maxLength: 10, pattern: "^[a-z]+$" },
			},
		};
		const errors = await analyze(schema, {
			offline: true,
			overrideMaxDepth: 0,
		});
		strictEqual(errors.length, 1);
		const e = errors[0];
		strictEqual(e.instancePath, "");
		strictEqual(e.schemaPath, "#/depth");
		strictEqual(e.keyword, "depth");
		strictEqual(e.params.limit, 0);
		ok(typeof e.params.depth === "number");
		strictEqual(e.message, "must NOT have depth greater than 0");
	});
});

// Full error-shape and boundary locks for resolveSSRFRefs. Existing tests assert
// keyword + a message substring; these pin instancePath, schemaPath and params so
// blanking a field (a mutation) is caught, plus the no-DNS cap/budget boundaries.
describe("resolveSSRFRefs error shapes and boundaries", () => {
	const ref = (hostname, path = "/$ref") => ({
		hostname,
		ref: `https://${hostname}/schema.json`,
		path,
	});

	test("unresolvable hostname error has full shape", async () => {
		const errors = await resolveSSRFRefs([ref("nx-host-abc987.invalid")], {
			dnsTimeoutMs: 100,
		});
		strictEqual(errors.length, 1);
		const e = errors[0];
		strictEqual(e.instancePath, "/$ref");
		strictEqual(e.schemaPath, "#/ssrf");
		strictEqual(e.params.ref, "https://nx-host-abc987.invalid/schema.json");
		strictEqual(e.params.hostname, "nx-host-abc987.invalid");
		strictEqual(
			e.message,
			'$ref hostname "nx-host-abc987.invalid" does not resolve',
		);
	});

	test("private-resolving hostname (localhost) error has full shape", async () => {
		const errors = await resolveSSRFRefs([ref("localhost")], {
			dnsTimeoutMs: 5_000,
		});
		strictEqual(errors.length, 1);
		const e = errors[0];
		strictEqual(e.instancePath, "/$ref");
		strictEqual(e.schemaPath, "#/ssrf");
		strictEqual(e.params.hostname, "localhost");
		ok(e.params.resolvedIP, "must include the resolved private IP");
		ok(e.message.includes("resolves to private IP"));
	});

	test("a public hostname produces no findings at all", async () => {
		// Not just zero resolvedIP findings: dropping the `if (!privateAddr) return []`
		// guard would synthesize spurious findings, so assert a fully empty result.
		const errors = await resolveSSRFRefs([ref("dns.google")], {
			dnsTimeoutMs: 5_000,
		});
		strictEqual(errors.length, 0);
	});

	test("hostname-cap finding has full shape", async () => {
		const refs = Array.from({ length: 3 }, (_, i) => ref(`cap${i}.invalid`));
		const errors = await resolveSSRFRefs(refs, { maxHostnames: 2 });
		strictEqual(errors.length, 1);
		const e = errors[0];
		strictEqual(e.instancePath, "");
		strictEqual(e.schemaPath, "#/ssrf");
		strictEqual(e.params.hostnames, 3);
		strictEqual(e.params.limit, 2);
		ok(e.message.includes("too many distinct remote $ref hostnames (3)"));
		ok(e.message.includes("above 2"));
	});

	test("exactly maxHostnames distinct hosts is under the cap (strict >)", async () => {
		// 2 distinct hosts with maxHostnames 2: must NOT trip the cap. Use
		// dnsTotalTimeoutMs:0 so it fails closed on the budget rather than doing DNS.
		const refs = [ref("a.invalid"), ref("b.invalid")];
		const errors = await resolveSSRFRefs(refs, {
			maxHostnames: 2,
			dnsTotalTimeoutMs: 0,
		});
		ok(
			!errors.some((e) => e.message.includes("too many distinct")),
			"exactly-at-cap must not be reported as over the cap",
		);
		ok(
			errors.every((e) => e.message.includes("budget")),
			"should fall through to the budget-exceeded path",
		);
	});

	test("budget-exceeded finding has full shape", async () => {
		const errors = await resolveSSRFRefs([ref("budget.invalid")], {
			dnsTotalTimeoutMs: 0,
		});
		strictEqual(errors.length, 1);
		const e = errors[0];
		strictEqual(e.instancePath, "/$ref");
		strictEqual(e.schemaPath, "#/ssrf");
		strictEqual(e.params.hostname, "budget.invalid");
		strictEqual(e.params.ref, "https://budget.invalid/schema.json");
		ok(e.message.includes("SSRF DNS budget exceeded"));
	});
});

// --- injectable monotonic clock: total-budget deadline at a batch index > 0 ---
// resolveSSRFRefs reads the clock through options.now (defaulting to Date.now),
// mirroring crawlSchema. With dnsConcurrency:1 each distinct host is its own batch,
// so an injected clock can let the FIRST batch resolve and then expire the budget
// before a LATER batch. That makes batches.slice(i) a proper subset (i > 0) and
// lets us pin the deadline boundary exactly. The hosts are RFC 6761 `.invalid`
// names that never resolve, so the few lookups that do run fail fast and offline.
describe("resolveSSRFRefs injected clock (budget at batch index > 0)", () => {
	const ref = (hostname, path = "/$ref") => ({
		hostname,
		ref: `https://${hostname}/schema.json`,
		path,
	});
	const stepClock = (...values) => {
		let i = 0;
		return () => values[Math.min(i++, values.length - 1)];
	};

	// D-(i): the budget expires at batch index 1, not 0. now() reads: #1 sets the
	// deadline (0 + 100 = 100); #2 (i=0) = 0 -> under, so host0 is resolved via DNS;
	// #3 (i=1) = 200 -> over, so the loop bails with batches.slice(1). Only host1
	// (the second batch) is reported budget-exceeded; host0 got a real DNS finding.
	// Kills the MethodExpression: slice() / slice(0) would mark BOTH hosts as
	// budget-exceeded (and never DNS-resolve host0).
	test("budget expiring at batch index 1 only skips the LATER batch (slice(i) subset)", async () => {
		const errors = await resolveSSRFRefs(
			[
				ref("first-host-aaa.invalid", "/a/$ref"),
				ref("second-host-bbb.invalid", "/b/$ref"),
			],
			{
				dnsConcurrency: 1,
				dnsTimeoutMs: 100,
				dnsTotalTimeoutMs: 100,
				now: stepClock(0, 0, 200),
			},
		);
		strictEqual(errors.length, 2, "one finding per host");
		const first = errors.find(
			(e) => e.params.hostname === "first-host-aaa.invalid",
		);
		const second = errors.find(
			(e) => e.params.hostname === "second-host-bbb.invalid",
		);
		ok(first, "the first host must have a finding");
		ok(second, "the second host must have a finding");
		// host0 was resolved (DNS ran): a `.invalid` host does not resolve, so it is a
		// "does not resolve" finding WITHOUT the incomplete marker.
		ok(
			first.message.includes("does not resolve"),
			"the first batch must have been DNS-resolved, not skipped",
		);
		strictEqual(
			first.params.incomplete,
			undefined,
			"resolved host is not incomplete",
		);
		// host1 was skipped because the budget expired: budget-exceeded + incomplete.
		ok(
			second.message.includes("SSRF DNS budget exceeded"),
			"the later batch must be skipped as budget-exceeded",
		);
		strictEqual(
			second.params.incomplete,
			true,
			"skipped host is marked incomplete",
		);
	});

	// D-(ii): the budget boundary is EXCLUSIVE. now() reads: #1 sets the deadline
	// (0 + 100 = 100); every later read returns EXACTLY 100, so `100 > 100` is false
	// and the loop NEVER bails. Both `.invalid` hosts are therefore DNS-resolved (no
	// budget-exceeded findings). Kills the EqualityOperator `>`->`>=` (which would
	// bail at the boundary and mark both hosts budget-exceeded).
	test("a clock exactly at the overall deadline does not bail (> is exclusive)", async () => {
		const errors = await resolveSSRFRefs(
			[ref("boundary-aaa.invalid"), ref("boundary-bbb.invalid")],
			{
				dnsConcurrency: 1,
				dnsTimeoutMs: 100,
				dnsTotalTimeoutMs: 100,
				now: stepClock(0, 100, 100, 100),
			},
		);
		strictEqual(errors.length, 2, "both hosts produce a finding");
		ok(
			errors.every((e) => e.message.includes("does not resolve")),
			"at the exclusive boundary both hosts must be DNS-resolved, none skipped",
		);
		ok(
			!errors.some((e) => e.params.incomplete === true),
			"no host may be marked budget-exceeded at the boundary",
		);
	});

	// analyze() threads options.now through to BOTH crawlSchema and resolveSSRFRefs.
	// A monotonic counter clock is injected: crawlSchema reads it during its crawl
	// (its deadline is the real Date.now()+60s, so these tiny readings never trip the
	// crawl timeout), and resolveSSRFRefs then reads the SAME injected clock for the
	// SSRF budget. With dnsTotalTimeoutMs:0 the overall deadline is 0, and by the time
	// the SSRF loop runs the counter has already advanced past 0, so `now() > 0` is
	// true and both remote hosts are skipped as budget-exceeded. A forced-constant
	// (equivalent) clock could not produce this, proving options.now flows end to end.
	test("analyze threads options.now into the SSRF budget end to end", async () => {
		let tick = 0;
		const schema = {
			$schema: "https://json-schema.org/draft/2020-12/schema",
			$id: "test",
			$defs: {
				a: { $ref: "https://e2e-first-aaa.invalid/s.json" },
				b: { $ref: "https://e2e-second-bbb.invalid/s.json" },
			},
		};
		const errors = await analyze(schema, {
			dnsConcurrency: 1,
			dnsTimeoutMs: 100,
			dnsTotalTimeoutMs: 0,
			now: () => ++tick,
		});
		ok(tick > 0, "the injected clock must have been read");
		const remote = errors.filter((e) => e.params?.incomplete === true);
		strictEqual(
			remote.length,
			2,
			"both remote hosts are skipped as budget-exceeded",
		);
		ok(
			remote.every((e) => e.message.includes("SSRF DNS budget exceeded")),
			"both must be budget-exceeded via the injected clock",
		);
	});
});

// Additional resolveInstancePath guards the existing direct tests miss: an empty
// pointer with a non-object root (the root guard must win over the !pointer
// shortcut), and a null encountered mid-walk (the guard must return before
// Object.hasOwn(null) throws).
describe("resolveInstancePath extra guards", () => {
	test("non-object root with an empty pointer is still undefined", () => {
		strictEqual(resolveInstancePath(null, ""), undefined);
		strictEqual(resolveInstancePath("string", ""), undefined);
		strictEqual(resolveInstancePath(42, ""), undefined);
	});

	test("a null value mid-walk returns undefined (does not throw)", () => {
		strictEqual(resolveInstancePath({ a: null }, "/a/b"), undefined);
	});

	test("does not walk into a string value by index", () => {
		// {a:"str"} then "/a/0": the typeof guard must stop the walk, not read s[0].
		strictEqual(resolveInstancePath({ a: "str" }, "/a/0"), undefined);
	});

	test("does not resolve inherited prototype keys", () => {
		// Only own keys are walked; a pointer to an inherited member must be undefined.
		strictEqual(resolveInstancePath({}, "/toString"), undefined);
		strictEqual(resolveInstancePath({ a: {} }, "/a/constructor"), undefined);
	});
});

// The SSRF check is gated on `!options.offline`. Use dnsTotalTimeoutMs:0 so the
// SSRF path fails closed on the budget (no real DNS): a remote $ref then yields
// an ssrf finding only when SSRF actually runs.
describe("analyze offline gate", () => {
	const remoteRefSchema = {
		$schema: "https://json-schema.org/draft/2020-12/schema",
		$id: "test",
		$ref: "https://ssrf-gate-test.invalid/s.json",
	};

	test("a remote $ref is SSRF-checked when offline is not set", async () => {
		const errors = await analyze(remoteRefSchema, { dnsTotalTimeoutMs: 0 });
		ok(
			errors.some((e) => e.keyword === "ssrf"),
			"non-offline analysis must run the SSRF check",
		);
	});

	test("offline:true skips the SSRF check entirely", async () => {
		const errors = await analyze(remoteRefSchema, {
			offline: true,
			dnsTotalTimeoutMs: 0,
		});
		strictEqual(
			errors.filter((e) => e.keyword === "ssrf").length,
			0,
			"offline must skip SSRF even when a remote $ref is present",
		);
	});
});

// A2: the two SSRF "incomplete-analysis" findings (the hostname-cap finding and
// the DNS-total-budget finding) mean DNS resolution was skipped, so suppressing
// them would falsely report a partially-analyzed schema as clean. They must NOT
// be droppable by --ignore, exactly like the depth/timeout findings. Normal
// per-host ssrf findings (resolves-to-private / does-not-resolve) SHOULD remain
// ignorable.
describe("analyze SSRF incomplete-analysis findings are not suppressible", () => {
	// Builds a schema with `n` distinct remote $ref hostnames so the hostname cap
	// can be tripped with a small maxHostnames.
	const manyHostSchema = (n) => {
		const schema = {
			$schema: "https://json-schema.org/draft/2020-12/schema",
			$id: "test",
			$defs: {},
		};
		for (let i = 0; i < n; i++) {
			schema.$defs[`d${i}`] = { $ref: `https://cap-host-${i}.invalid/s.json` };
		}
		return schema;
	};

	test('hostname-cap finding survives --ignore "" (cap finding marked incomplete)', async () => {
		const schema = manyHostSchema(5);
		const errors = await analyze(schema, {
			maxHostnames: 2,
			// "" matches the cap finding's empty instancePath; it must NOT suppress it.
			ignore: [""],
		});
		const cap = errors.find((e) => e.message.includes("too many distinct"));
		ok(cap, 'hostname-cap finding must survive --ignore ""');
		strictEqual(cap.params.incomplete, true);
	});

	test("DNS-budget finding survives --ignore <refpath>", async () => {
		const schema = {
			$schema: "https://json-schema.org/draft/2020-12/schema",
			$id: "test",
			$ref: "https://budget-ignore-test.invalid/s.json",
		};
		const errors = await analyze(schema, {
			dnsTotalTimeoutMs: 0,
			// the budget finding's instancePath is the ref path "/$ref".
			ignore: ["/$ref"],
		});
		const budget = errors.find((e) =>
			e.message.includes("SSRF DNS budget exceeded"),
		);
		ok(budget, "DNS-budget finding must survive --ignore on its ref path");
		strictEqual(budget.params.incomplete, true);
	});

	test("a normal per-host ssrf finding IS still suppressible by its instancePath", async () => {
		// localhost resolves to a private IP -> a normal (suppressible) ssrf finding
		// at instancePath "/$ref". Ignoring that path must drop it.
		const schema = {
			$schema: "https://json-schema.org/draft/2020-12/schema",
			$id: "test",
			$ref: "https://localhost/s.json",
		};
		const without = await analyze(schema, { dnsTimeoutMs: 5_000 });
		ok(
			without.some((e) => e.keyword === "ssrf"),
			"baseline: localhost ssrf finding is present",
		);
		const ignored = await analyze(schema, {
			dnsTimeoutMs: 5_000,
			ignore: ["/$ref"],
		});
		strictEqual(
			ignored.filter((e) => e.keyword === "ssrf").length,
			0,
			"a normal per-host ssrf finding must remain suppressible",
		);
	});
});

// The override filters must only suppress their OWN finding type and keep every
// other finding (the `return true` for non-target errors), and must use a strict
// `>` so an instance exactly at the override limit is suppressed.
describe("analyze override filters keep unrelated findings", () => {
	const dangerous = JSON.parse(
		'{"properties":{"__proto__":{"type":"string","maxLength":10,"pattern":"^[a-z]+$"}},"required":["__proto__"],"maxProperties":5,"unevaluatedProperties":false}',
	);

	test("overrideMaxItems does not drop a dangerous-name finding", async () => {
		const errors = await analyze(dangerous, {
			offline: true,
			overrideMaxItems: 100,
		});
		ok(
			errors.some((e) => e.schemaPath === "#/dangerous-name"),
			"a non-maxItems finding must survive the overrideMaxItems filter",
		);
	});

	test("overrideMaxProperties does not drop a dangerous-name finding", async () => {
		const errors = await analyze(dangerous, {
			offline: true,
			overrideMaxProperties: 100,
		});
		ok(
			errors.some((e) => e.schemaPath === "#/dangerous-name"),
			"a non-maxProperties finding must survive the overrideMaxProperties filter",
		);
	});

	test("overrideMaxProperties suppresses at exactly the property count (strict >)", async () => {
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
		// exactly 1100 properties; override of 1100 means 1100 > 1100 is false, so
		// the finding is suppressed. `>=` would keep it.
		const errors = await analyze(schema, {
			offline: true,
			overrideMaxProperties: 1100,
		});
		ok(!errors.some((e) => e.keyword === "maxProperties"));
	});

	test("overrideMaxItems suppresses at exactly the array length (strict >)", async () => {
		const schema = {
			$schema: "https://json-schema.org/draft/2020-12/schema",
			$id: "test",
			type: "string",
			maxLength: 100,
			enum: Array.from({ length: 2000 }, (_, i) => `v${i}`),
		};
		const errors = await analyze(schema, {
			offline: true,
			overrideMaxItems: 2000,
		});
		ok(!errors.some((e) => e.keyword === "maxItems"));
	});
});

// Valid/zero/negative cases for the override integer validators (existing tests
// cover only non-numeric/non-integer).
describe("analyze override validator boundaries", () => {
	const tiny = { type: "string" };
	for (const opt of ["overrideMaxItems", "overrideMaxProperties"]) {
		test(`${opt}: a valid positive integer is accepted`, async () => {
			ok(Array.isArray(await analyze(tiny, { offline: true, [opt]: 100 })));
		});
		test(`${opt}: zero is a valid non-negative integer`, async () => {
			ok(Array.isArray(await analyze(tiny, { offline: true, [opt]: 0 })));
		});
		test(`${opt}: a negative integer throws TypeError`, async () => {
			try {
				await analyze(tiny, { offline: true, [opt]: -5 });
				ok(false, "should have thrown");
			} catch (err) {
				ok(err instanceof TypeError);
				ok(err.message.includes(opt));
				ok(err.message.includes("non-negative integer"));
			}
		});
	}
});

// Cover the deadline/maxDepth defaults and the keep-side of the override filter.
describe("analyze depth/timeout defaults and override keep-side", () => {
	test("a schema deeper than the default MAX_DEPTH is flagged (default maxDepth used)", async () => {
		let deep = { type: "string", maxLength: 10, pattern: "^[a-z]+$" };
		for (let i = 0; i < 40; i++) {
			deep = {
				type: "object",
				properties: { a: deep },
				required: ["a"],
				unevaluatedProperties: false,
				maxProperties: 5,
			};
		}
		const errors = await analyze(deep, { offline: true });
		ok(
			errors.some((e) => e.keyword === "depth"),
			"deep schema must trip the default depth limit",
		);
	});

	test("a large analysisTimeoutMs does not immediately time out", async () => {
		// ms > 0 means the deadline is in the future; the ms<=0 short-circuit to 0
		// (immediate timeout) must not fire.
		const errors = await analyze(
			{ type: "string", maxLength: 10, pattern: "^[a-z]+$" },
			{ offline: true, analysisTimeoutMs: 600000 },
		);
		ok(!errors.some((e) => e.keyword === "timeout"));
	});

	test("overrideMaxProperties below the property count keeps the maxProperties finding", async () => {
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
		const errors = await analyze(schema, {
			offline: true,
			overrideMaxProperties: 500,
		});
		ok(
			errors.some((e) => e.keyword === "maxProperties"),
			"1100 properties still exceeds an override of 500",
		);
	});
});

// A3: resolving attacker-controlled hostnames from an untrusted schema is a
// blind-SSRF / DNS-exfil amplifier. run() must emit a one-line notice to STDERR
// (never STDOUT, to keep json/sarif output clean) whenever it is about to do DNS
// resolution, i.e. NOT --offline AND the schema actually has remote $ref(s).
describe("run() SSRF DNS notice (A3)", () => {
	const runCli = async (argv, files = {}) => {
		const out = { log: [], error: [], write: [] };
		const io = {
			log: (m) => out.log.push(String(m)),
			error: (m) => out.error.push(String(m)),
			write: (s) => out.write.push(String(s)),
			readFile: async (p) => {
				const key = Object.keys(files).find((k) => p.endsWith(k));
				if (key === undefined) throw new Error(`ENOENT ${p}`);
				return files[key];
			},
			stat: async (p) => {
				const key = Object.keys(files).find((k) => p.endsWith(k));
				if (key === undefined) throw new Error(`ENOENT ${p}`);
				return { size: files[key].length };
			},
		};
		const code = await run(argv, io);
		return { code, ...out };
	};

	const REMOTE = JSON.stringify({
		$schema: "https://json-schema.org/draft/2020-12/schema",
		$id: "https://example.test/remote.json",
		$ref: "https://a3-notice-host.invalid/x.json",
	});
	const TWO_REMOTE = JSON.stringify({
		$schema: "https://json-schema.org/draft/2020-12/schema",
		$id: "https://example.test/remote.json",
		$defs: {
			a: { $ref: "https://a3-h1.invalid/x.json" },
			b: { $ref: "https://a3-h2.invalid/x.json" },
		},
	});
	const CLEAN = JSON.stringify({
		$schema: "https://json-schema.org/draft/2020-12/schema",
		$id: "https://example.test/clean.json",
		type: "string",
		maxLength: 10,
		pattern: "^[a-z]+$",
	});

	test("emits the DNS notice to STDERR (not STDOUT) when remote refs exist and not offline", async () => {
		const r = await runCli(
			["s.json", "--dns-total-timeout-ms", "0", "--format", "json"],
			{ "s.json": REMOTE },
		);
		ok(
			r.error.some((m) => m.includes("resolving") && m.includes("DNS")),
			"a DNS notice must be written to error (stderr)",
		);
		ok(
			r.error.some((m) => m.includes("--offline")),
			"the notice should mention --offline as the opt-out",
		);
		// Must NOT pollute stdout (json/sarif consumers parse it).
		ok(
			!r.write.some((s) => s.includes("resolving")),
			"the notice must never go to stdout/write",
		);
		ok(
			!r.log.some((m) => m.includes("resolving")),
			"the notice must never go to the stdout logger",
		);
	});

	test("the notice reports the count of remote ref hostnames", async () => {
		const r = await runCli(
			["s.json", "--dns-total-timeout-ms", "0", "--format", "json"],
			{ "s.json": TWO_REMOTE },
		);
		const notice = r.error.find((m) => m.includes("resolving"));
		ok(notice, "expected a DNS notice");
		ok(notice.includes("2"), `expected count 2 in the notice: ${notice}`);
	});

	test("a safe-listed hostname is NOT counted in the DNS notice", async () => {
		// Two remote ref hosts; one (a3-h1) is marked safe via -r (its $id hostname).
		// The notice must count only the UNSAFE host, so it reports 1, not 2. This
		// pins the `if (!safeHostnames.has(hostname))` guard: forcing it true would
		// count the safe host too and report 2.
		const refSchema = JSON.stringify({
			$id: "https://a3-h1.invalid/ref.json",
		});
		const r = await runCli(
			[
				"s.json",
				"--dns-total-timeout-ms",
				"0",
				"--format",
				"json",
				"-r",
				"ref.json",
			],
			{ "s.json": TWO_REMOTE, "ref.json": refSchema },
		);
		const notice = r.error.find((m) => m.includes("resolving"));
		ok(notice, "expected a DNS notice for the remaining unsafe host");
		ok(
			notice.includes("1"),
			`safe host must be excluded from the count: ${notice}`,
		);
		ok(
			!notice.includes("2"),
			`the safe-listed host must not be counted: ${notice}`,
		);
	});

	test("is absent under --offline", async () => {
		const r = await runCli(["s.json", "--offline", "--format", "json"], {
			"s.json": REMOTE,
		});
		ok(
			!r.error.some((m) => m.includes("resolving")),
			"no DNS notice when --offline is set",
		);
	});

	test("is absent when the schema has no remote refs", async () => {
		const r = await runCli(["s.json", "--format", "json"], { "s.json": CLEAN });
		ok(
			!r.error.some((m) => m.includes("resolving")),
			"a clean schema with no remote refs stays quiet",
		);
	});
});
