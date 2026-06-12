import { deepStrictEqual, ok, strictEqual } from "node:assert";
import { describe, test } from "node:test";
import {
	crawlSchema,
	MAX_COLLECTED_REFS,
	MAX_REDOS_PATTERNS,
	REDOS_HEAP_BUDGET_BYTES,
} from "../cli.js";

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
		ok(r.errors.some((e) => e.keyword === "exclusiveMaximum"));
	});

	test("should catch minimum === exclusiveMaximum (impossible)", () => {
		const r = crawlSchema({
			type: "integer",
			minimum: 5,
			exclusiveMaximum: 5,
		});
		ok(r.errors.some((e) => e.keyword === "exclusiveMaximum"));
	});

	test("should catch exclusiveMinimum === maximum (impossible)", () => {
		const r = crawlSchema({
			type: "number",
			exclusiveMinimum: 5,
			maximum: 5,
		});
		ok(r.errors.some((e) => e.keyword === "exclusiveMinimum"));
	});

	test("range error schemaPath should match offending keyword", () => {
		const exMax = crawlSchema({
			type: "integer",
			minimum: 5,
			exclusiveMaximum: 5,
		});
		const e = exMax.errors.find((err) => err.keyword === "exclusiveMaximum");
		strictEqual(e.schemaPath, "#/exclusiveMaximum");

		const plain = crawlSchema({ type: "integer", minimum: 10, maximum: 5 });
		const p = plain.errors.find((err) => err.keyword === "minimum");
		strictEqual(p.schemaPath, "#/minimum");
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

	// --- range consistency: both inclusive and exclusive bounds ---
	test("should use minimum when exclusiveMinimum < minimum", () => {
		const r = crawlSchema({
			type: "integer",
			minimum: 10,
			exclusiveMinimum: 3,
			maximum: 5,
		});
		ok(r.errors.some((e) => e.keyword === "minimum"));
	});

	test("should use exclusiveMinimum when exclusiveMinimum > minimum (exMin is tighter)", () => {
		const r = crawlSchema({
			type: "integer",
			minimum: 3,
			exclusiveMinimum: 10,
			maximum: 5,
		});
		ok(r.errors.some((e) => e.keyword === "exclusiveMinimum"));
	});

	test("should not flag when exclusiveMinimum > minimum and range is valid", () => {
		const r = crawlSchema({
			type: "integer",
			minimum: 3,
			exclusiveMinimum: 10,
			maximum: 100,
		});
		strictEqual(r.errors.length, 0);
	});

	test("should use maximum when exclusiveMaximum > maximum", () => {
		const r = crawlSchema({
			type: "integer",
			minimum: 50,
			maximum: 10,
			exclusiveMaximum: 95,
		});
		ok(r.errors.some((e) => e.keyword === "minimum"));
	});

	test("should use exclusiveMaximum when exclusiveMaximum < maximum (exMax is tighter)", () => {
		const r = crawlSchema({
			type: "integer",
			minimum: 50,
			exclusiveMaximum: 30,
			maximum: 100,
		});
		ok(r.errors.some((e) => e.keyword === "exclusiveMaximum"));
	});

	test("should not flag when exclusiveMaximum < maximum and range is valid", () => {
		const r = crawlSchema({
			type: "integer",
			minimum: 1,
			exclusiveMaximum: 30,
			maximum: 100,
		});
		strictEqual(r.errors.length, 0);
	});

	test("should not flag when exclusiveMinimum < minimum and range is valid", () => {
		const r = crawlSchema({
			type: "integer",
			minimum: 5,
			exclusiveMinimum: 2,
			maximum: 100,
		});
		strictEqual(r.errors.length, 0);
	});

	test("should not flag when exclusiveMaximum > maximum and range is valid", () => {
		const r = crawlSchema({
			type: "integer",
			minimum: 0,
			maximum: 50,
			exclusiveMaximum: 95,
		});
		strictEqual(r.errors.length, 0);
	});

	// --- range consistency: NaN/Infinity edge cases ---
	test("should ignore NaN minimum", () => {
		const r = crawlSchema({ type: "integer", minimum: NaN, maximum: 5 });
		strictEqual(r.errors.length, 0);
	});

	test("should ignore Infinity exclusiveMinimum", () => {
		const r = crawlSchema({
			type: "number",
			exclusiveMinimum: Infinity,
			maximum: 100,
		});
		// A non-finite bound must be ignored entirely: dropping the Number.isFinite
		// guard would treat exclusiveMinimum:Infinity as the effective minimum and
		// emit a spurious (exclusiveMinimum) range error, so assert no errors at all.
		strictEqual(r.errors.length, 0);
	});

	test("should ignore NaN exclusiveMaximum", () => {
		const r = crawlSchema({
			type: "integer",
			minimum: 0,
			exclusiveMaximum: NaN,
		});
		// Dropping the finiteness guard would make exclusiveMaximum:NaN the
		// effective (exclusive) maximum and emit a bogus range error.
		strictEqual(r.errors.length, 0);
	});

	test("should ignore -Infinity maximum", () => {
		const r = crawlSchema({
			type: "number",
			minimum: 0,
			maximum: -Infinity,
		});
		strictEqual(r.errors.length, 0);
	});

	// --- range consistency: exclusive/inclusive boundary tie-breaks ---
	// When exclusiveMinimum === minimum, the exclusive bound is the effective one
	// (>= picks exclusive). With maximum also at that value the range is empty.
	test("should treat exclusiveMinimum === minimum as the exclusive bound", () => {
		const r = crawlSchema({
			type: "number",
			minimum: 5,
			exclusiveMinimum: 5,
			maximum: 5,
		});
		ok(
			r.errors.some((e) => e.keyword === "exclusiveMinimum"),
			"exclusiveMinimum tie must win and make [5,5) empty",
		);
	});

	// When exclusiveMaximum === maximum, the exclusive bound wins (<= picks it),
	// so (5,5] collapses to an empty range.
	test("should treat exclusiveMaximum === maximum as the exclusive bound", () => {
		const r = crawlSchema({
			type: "number",
			minimum: 5,
			maximum: 5,
			exclusiveMaximum: 5,
		});
		ok(
			r.errors.some((e) => e.keyword === "exclusiveMaximum"),
			"exclusiveMaximum tie must win and make (5,5] empty",
		);
	});

	// --- range error payload (params + message) ---
	test("inclusive impossible range reports both bounds and the message", () => {
		const r = crawlSchema({ type: "number", minimum: 10, maximum: 5 });
		const e = r.errors.find((err) => err.keyword === "minimum");
		ok(e, "expected a minimum range error");
		strictEqual(e.params.minimum, 10);
		strictEqual(e.params.maximum, 5);
		strictEqual(e.message, "numeric range is unsatisfiable");
	});

	test("exclusive impossible range reports both exclusive bounds", () => {
		const r = crawlSchema({
			type: "number",
			exclusiveMinimum: 10,
			exclusiveMaximum: 5,
		});
		const e = r.errors.find((err) => err.keyword === "exclusiveMaximum");
		ok(e, "expected an exclusiveMaximum range error");
		strictEqual(e.params.exclusiveMinimum, 10);
		strictEqual(e.params.exclusiveMaximum, 5);
	});

	// --- bound type guards: non-number bounds must be ignored entirely ---
	// A string bound must not be coerced into a comparison. Each case is impossible
	// only if the typeof guard is dropped (&&→|| would let the string through and
	// numeric coercion would then fabricate a range error), so assert no errors.
	test("should ignore a string minimum", () => {
		const r = crawlSchema({ type: "number", minimum: "10", maximum: 5 });
		strictEqual(r.errors.length, 0);
	});

	test("should ignore a string maximum", () => {
		const r = crawlSchema({ type: "number", minimum: 10, maximum: "5" });
		strictEqual(r.errors.length, 0);
	});

	test("should ignore a string exclusiveMinimum", () => {
		const r = crawlSchema({
			type: "number",
			exclusiveMinimum: "10",
			maximum: 5,
		});
		strictEqual(r.errors.length, 0);
	});

	test("should ignore a string exclusiveMaximum", () => {
		const r = crawlSchema({
			type: "number",
			minimum: 10,
			exclusiveMaximum: "5",
		});
		strictEqual(r.errors.length, 0);
	});

	// --- circular reference protection ---
	test("should handle circular references without hanging", () => {
		const obj = {
			type: "object",
			properties: { a: { type: "string", maxLength: 10 } },
		};
		obj.properties.a.nested = obj;
		const r = crawlSchema(obj);
		ok(r.depth >= 1);
		ok(!r.depthExceeded);
	});

	// --- type arrays ---
	test("should catch minLength > maxLength with type array including string", () => {
		const r = crawlSchema({
			type: ["string", "null"],
			minLength: 10,
			maxLength: 5,
		});
		ok(r.errors.some((e) => e.keyword === "minLength"));
	});

	test("should not catch minLength > maxLength when type array excludes string", () => {
		const r = crawlSchema({
			type: ["integer", "null"],
			minLength: 10,
			maxLength: 5,
		});
		ok(!r.errors.some((e) => e.keyword === "minLength"));
	});

	test("should catch minimum > maximum with type array including number", () => {
		const r = crawlSchema({
			type: ["number", "null"],
			minimum: 10,
			maximum: 5,
		});
		ok(r.errors.some((e) => e.keyword === "minimum"));
	});

	test("should catch minItems > maxItems with type array including array", () => {
		const r = crawlSchema({
			type: ["array", "null"],
			minItems: 10,
			maxItems: 3,
		});
		ok(r.errors.some((e) => e.keyword === "minItems"));
	});

	test("should catch minProperties > maxProperties with type array including object", () => {
		const r = crawlSchema({
			type: ["object", "null"],
			minProperties: 10,
			maxProperties: 5,
		});
		ok(r.errors.some((e) => e.keyword === "minProperties"));
	});

	// --- RFC 6901 JSON Pointer escaping ---
	test("should escape / in property names per RFC 6901", () => {
		const r = crawlSchema({
			type: "object",
			properties: {
				"a/b": { type: "string", minLength: 10, maxLength: 5 },
			},
		});
		const err = r.errors.find((e) => e.keyword === "minLength");
		ok(err);
		strictEqual(err.instancePath, "/properties/a~1b");
	});

	test("should escape ~ in property names per RFC 6901", () => {
		const r = crawlSchema({
			type: "object",
			properties: {
				"a~b": { type: "string", minLength: 10, maxLength: 5 },
			},
		});
		const err = r.errors.find((e) => e.keyword === "minLength");
		ok(err);
		strictEqual(err.instancePath, "/properties/a~0b");
	});

	test("should escape both ~ and / in property names per RFC 6901", () => {
		const r = crawlSchema({
			type: "object",
			properties: {
				"~/": { type: "string", minLength: 10, maxLength: 5 },
			},
		});
		const err = r.errors.find((e) => e.keyword === "minLength");
		ok(err);
		strictEqual(err.instancePath, "/properties/~0~1");
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

	test("ReDoS-vulnerable pattern reports reason: hitMaxScore", () => {
		const r = crawlSchema({ pattern: "^(a+)+$" });
		const err = r.errors.find((e) => e.keyword === "pattern");
		ok(err, "expected a pattern error");
		strictEqual(err.params.reason, "hitMaxScore");
		ok(err.message.includes("vulnerable to ReDoS"));
	});

	test("step-exhaustion pattern reports reason: hitMaxSteps", (t) => {
		const r = crawlSchema({
			pattern: "^(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z)+$",
		});
		const err = r.errors.find((e) => e.keyword === "pattern");
		ok(err, "expected a pattern error");
		if (err.params.reason !== "hitMaxSteps") {
			t.skip(`got reason: ${err.params.reason} (hardware-dependent)`);
			return;
		}
		ok(err.message.includes("step limit"));
	});

	test("step-exhaustion pattern reports reason: timedOut", (t) => {
		const r = crawlSchema({
			pattern: "^(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z)+$",
		});
		const err = r.errors.find((e) => e.keyword === "pattern");
		ok(err, "expected a pattern error");
		if (err.params.reason !== "timedOut") {
			t.skip(`got reason: ${err.params.reason} (hardware-dependent)`);
			return;
		}
		ok(err.message.includes("timed out"));
	});

	test("unparseable pattern reports reason: parseError", () => {
		const r = crawlSchema({
			pattern: "^[a-z]{1,99999999999999999}$",
		});
		const err = r.errors.find((e) => e.keyword === "pattern");
		ok(err, "expected a pattern error");
		strictEqual(err.params.reason, "parseError");
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

	test("should skip $ref that is not a valid URL and does not start with #", () => {
		const r = crawlSchema({ $ref: "relative/path/schema.json" });
		strictEqual(r.refs.length, 0);
	});

	// --- $dynamicRef collection (mirrors $ref) ---
	test("should collect remote $dynamicRef URLs", () => {
		const r = crawlSchema({ $dynamicRef: "https://internal.host/schema.json" });
		strictEqual(r.refs.length, 1);
		strictEqual(r.refs[0].hostname, "internal.host");
		strictEqual(r.refs[0].ref, "https://internal.host/schema.json");
		strictEqual(r.refs[0].path, "/$dynamicRef");
	});

	test("should skip fragment-only $dynamicRef", () => {
		const r = crawlSchema({ $dynamicRef: "#meta" });
		strictEqual(r.refs.length, 0);
	});

	test("should skip $dynamicRef that is not a valid URL and does not start with #", () => {
		const r = crawlSchema({ $dynamicRef: "relative/path/schema.json" });
		strictEqual(r.refs.length, 0);
	});

	test("should not collect $id as a fetch target", () => {
		const r = crawlSchema({ $id: "https://internal.host/schema.json" });
		strictEqual(r.refs.length, 0);
	});

	// --- $ref URL edge cases ---
	test("should collect $ref with IPv6 literal host", () => {
		const r = crawlSchema({ $ref: "https://[::1]/schema.json" });
		strictEqual(r.refs.length, 1);
		// URL.hostname preserves brackets for IPv6 literals
		strictEqual(r.refs[0].hostname, "[::1]");
	});

	test("should collect $ref hostname ignoring credentials", () => {
		const r = crawlSchema({
			$ref: "https://user:pass@example.com/schema.json",
		});
		strictEqual(r.refs.length, 1);
		strictEqual(r.refs[0].hostname, "example.com");
	});

	test("should collect $ref hostname ignoring query string", () => {
		const r = crawlSchema({
			$ref: "https://example.com/schema.json?v=1",
		});
		strictEqual(r.refs.length, 1);
		strictEqual(r.refs[0].hostname, "example.com");
	});

	test("should collect $ref with port in URL", () => {
		const r = crawlSchema({
			$ref: "https://example.com:8443/schema.json",
		});
		strictEqual(r.refs.length, 1);
		strictEqual(r.refs[0].hostname, "example.com");
	});

	// --- numeric boundary values ---
	test("should catch MAX_SAFE_INTEGER minimum > zero maximum", () => {
		const r = crawlSchema({
			type: "integer",
			minimum: Number.MAX_SAFE_INTEGER,
			maximum: 0,
		});
		ok(r.errors.some((e) => e.keyword === "minimum"));
	});

	test("should allow minimum === maximum at MAX_SAFE_INTEGER", () => {
		const r = crawlSchema({
			type: "integer",
			minimum: Number.MAX_SAFE_INTEGER,
			maximum: Number.MAX_SAFE_INTEGER,
		});
		strictEqual(r.errors.length, 0);
	});

	test("should catch exclusiveMinimum === maximum at MAX_SAFE_INTEGER", () => {
		const r = crawlSchema({
			type: "number",
			exclusiveMinimum: Number.MAX_SAFE_INTEGER,
			maximum: Number.MAX_SAFE_INTEGER,
		});
		ok(r.errors.some((e) => e.keyword === "exclusiveMinimum"));
	});

	test("should treat -0 and +0 as equal for min/max", () => {
		const r = crawlSchema({
			type: "number",
			minimum: -0,
			maximum: +0,
		});
		strictEqual(r.errors.length, 0);
	});

	// --- patternProperties prototype-pollution detection ---
	test("should flag patternProperties key matching __proto__ literally", () => {
		const r = crawlSchema({
			patternProperties: { "^__proto__$": { type: "string" } },
		});
		const err = r.errors.find((e) => e.keyword === "patternProperties");
		ok(err, "expected a patternProperties error");
		ok(err.params.matches.includes("__proto__"));
	});

	test("should flag patternProperties key matching constructor literally", () => {
		const r = crawlSchema({
			patternProperties: { "^constructor$": { type: "string" } },
		});
		ok(
			r.errors.some(
				(e) =>
					e.keyword === "patternProperties" &&
					e.params.matches.includes("constructor"),
			),
		);
	});

	test("should flag patternProperties key matching __proto__ via class quantifier (bypass)", () => {
		const r = crawlSchema({
			patternProperties: { "^_{2}proto_{2}$": { type: "string" } },
		});
		ok(
			r.errors.some(
				(e) =>
					e.keyword === "patternProperties" &&
					e.params.matches.includes("__proto__"),
			),
		);
	});

	test("should flag patternProperties key matching __proto__ via length-only pattern (bypass)", () => {
		const r = crawlSchema({
			patternProperties: { "^[a-z_]{9}$": { type: "string" } },
		});
		ok(
			r.errors.some(
				(e) =>
					e.keyword === "patternProperties" &&
					e.params.matches.includes("__proto__"),
			),
		);
	});

	test("should not flag patternProperties keys that don't match denylisted names", () => {
		const r = crawlSchema({
			patternProperties: { "^[A-Z]+$": { type: "string" } },
		});
		ok(!r.errors.some((e) => e.keyword === "patternProperties"));
	});

	test("should not flag _proto_ (single underscores), case-sensitive exact match only", () => {
		const r = crawlSchema({
			patternProperties: { "^_proto_$": { type: "string" } },
		});
		ok(!r.errors.some((e) => e.keyword === "patternProperties"));
	});

	test("should handle unparseable patternProperties keys without crashing", () => {
		const r = crawlSchema({
			patternProperties: { "[unclosed": { type: "string" } },
		});
		ok(Array.isArray(r.errors));
	});

	test("should flag ReDoS-vulnerable patternProperties key before denylist matching", () => {
		const r = crawlSchema({
			patternProperties: { "^(a+)+$": { type: "string" } },
		});
		const err = r.errors.find(
			(e) => e.keyword === "patternProperties" && e.schemaPath === "#/redos",
		);
		ok(err, "expected a patternProperties ReDoS error");
		strictEqual(err.params.reason, "hitMaxScore");
		strictEqual(err.params.pattern, "^(a+)+$");
		ok(err.message.includes("^(a+)+$"));
		ok(err.instancePath.includes("/patternProperties/"));
	});

	test("unsafe patternProperties key is never matched via RegExp (short-circuits first)", () => {
		// new RegExp(patternKey) in cli.js is reached only AFTER isSafePattern
		// clears the key (the `if (!patternSafe) continue;` guard). An unsafe key
		// must therefore yield a ReDoS finding and NO denylist-match finding,
		// proving the dynamic RegExp never runs on a catastrophic pattern. This
		// is the justification for the detect-non-literal-regexp nosemgrep.
		const r = crawlSchema({
			patternProperties: {
				"^(a+)+$": { type: "string" },
				"^(\\w+)*$": { type: "string" },
			},
		});
		const redos = r.errors.filter(
			(e) => e.keyword === "patternProperties" && e.schemaPath === "#/redos",
		);
		const matched = r.errors.filter(
			(e) => e.keyword === "patternProperties" && e.params?.matches,
		);
		strictEqual(redos.length, 2, "both unsafe keys must be flagged as ReDoS");
		strictEqual(matched.length, 0, "no denylist match may run on unsafe keys");
	});

	// --- instance-data keywords are not analyzed as schemas ---
	// const/enum/default/examples hold literal instance values, never
	// subschemas. The crawler must not descend into them, or it reports
	// false positives on data that merely looks like a schema.
	test("should not run ReDoS analysis on a pattern inside const", () => {
		const r = crawlSchema({ const: { pattern: "^(a+)+$" } });
		ok(!r.errors.some((e) => e.keyword === "pattern"));
	});

	test("should not flag a numeric range inside default", () => {
		const r = crawlSchema({
			type: "object",
			default: { type: "integer", minimum: 100, maximum: 1 },
		});
		ok(!r.errors.some((e) => e.keyword === "minimum"));
	});

	test("should not flag dangerous property names inside enum values", () => {
		const r = crawlSchema(
			JSON.parse('{"enum":[{"properties":{"__proto__":{"type":"string"}}}]}'),
		);
		ok(!r.errors.some((e) => e.schemaPath === "#/dangerous-name"));
	});

	test("should not flag dangerous property names inside examples values", () => {
		const r = crawlSchema(
			JSON.parse(
				'{"examples":[{"properties":{"__proto__":{"type":"string"}}}]}',
			),
		);
		ok(!r.errors.some((e) => e.schemaPath === "#/dangerous-name"));
	});

	test("should still analyze real subschemas alongside instance-data keywords", () => {
		// A genuine sibling subschema (in properties) must still be crawled even
		// when const/default/examples are present and skipped.
		const r = crawlSchema(
			JSON.parse(
				'{"properties":{"bad":{"type":"string","minLength":10,"maxLength":5}},"default":{"pattern":"^(a+)+$"}}',
			),
		);
		ok(r.errors.some((e) => e.keyword === "minLength"));
		ok(!r.errors.some((e) => e.keyword === "pattern"));
	});

	// --- analysis time budget (deadline) ---
	test("should fail closed with a timeout error when deadline already passed", () => {
		const r = crawlSchema({ type: "string", pattern: "^[a-z]+$" }, 32, {
			deadline: 0,
		});
		ok(r.errors.some((e) => e.keyword === "timeout"));
		strictEqual(r.timedOut, true);
	});

	// --- dangerous-name detection across all property-key sites (default lang=js) ---
	// Schemas come from JSON.parse in real usage. Object literals like
	// `{ __proto__: x }` set the prototype rather than adding a key, so we
	// build inputs via JSON.parse to exercise the actual attack surface.
	test("should flag __proto__ in properties keys", () => {
		const r = crawlSchema(
			JSON.parse('{"properties":{"__proto__":{"type":"string"}}}'),
		);
		const err = r.errors.find(
			(e) => e.keyword === "properties" && e.params.name === "__proto__",
		);
		ok(err, "expected an error for properties.__proto__");
		strictEqual(err.params.lang, "default");
	});

	test("should flag __proto__ in $defs keys", () => {
		const r = crawlSchema(
			JSON.parse('{"$defs":{"__proto__":{"type":"string"}}}'),
		);
		ok(
			r.errors.some(
				(e) => e.keyword === "$defs" && e.params.name === "__proto__",
			),
		);
	});

	test("should flag __proto__ in definitions keys (legacy)", () => {
		const r = crawlSchema(
			JSON.parse('{"definitions":{"__proto__":{"type":"string"}}}'),
		);
		ok(
			r.errors.some(
				(e) => e.keyword === "definitions" && e.params.name === "__proto__",
			),
		);
	});

	test("should flag __proto__ in dependentSchemas keys", () => {
		const r = crawlSchema(
			JSON.parse('{"dependentSchemas":{"__proto__":{"type":"string"}}}'),
		);
		ok(
			r.errors.some(
				(e) =>
					e.keyword === "dependentSchemas" && e.params.name === "__proto__",
			),
		);
	});

	test("should flag __proto__ in dependentRequired keys", () => {
		const r = crawlSchema(
			JSON.parse('{"dependentRequired":{"__proto__":["x"]}}'),
		);
		ok(
			r.errors.some(
				(e) =>
					e.keyword === "dependentRequired" && e.params.name === "__proto__",
			),
		);
	});

	test("should flag __proto__ in dependentRequired array values", () => {
		const r = crawlSchema({
			dependentRequired: { trigger: ["__proto__"] },
		});
		ok(
			r.errors.some(
				(e) =>
					e.keyword === "dependentRequired" &&
					e.params.name === "__proto__" &&
					e.instancePath.endsWith("/trigger/0"),
			),
		);
	});

	test("should flag __proto__ in required array entries", () => {
		const r = crawlSchema({
			required: ["name", "__proto__"],
		});
		ok(
			r.errors.some(
				(e) =>
					e.keyword === "required" &&
					e.params.name === "__proto__" &&
					e.instancePath.endsWith("/required/1"),
			),
		);
	});

	test("should not flag harmless names with default lang", () => {
		const r = crawlSchema({
			properties: { name: { type: "string" }, _proto_: { type: "string" } },
			required: ["name"],
		});
		ok(!r.errors.some((e) => e.schemaPath === "#/dangerous-name"));
	});

	// --- lang selection ---
	test("lang=py should flag __class__", () => {
		const r = crawlSchema(
			{ properties: { __class__: { type: "string" } } },
			32,
			{ lang: "py" },
		);
		ok(
			r.errors.some(
				(e) => e.keyword === "properties" && e.params.name === "__class__",
			),
		);
	});

	test("lang=js should NOT flag __class__", () => {
		const r = crawlSchema(
			{ properties: { __class__: { type: "string" } } },
			32,
			{ lang: "js" },
		);
		ok(!r.errors.some((e) => e.params.name === "__class__"));
	});

	test("lang=java should flag @type", () => {
		const r = crawlSchema({ properties: { "@type": { type: "string" } } }, 32, {
			lang: "java",
		});
		ok(
			r.errors.some(
				(e) => e.keyword === "properties" && e.params.name === "@type",
			),
		);
	});

	test("lang=cs should flag $type and @odata.type", () => {
		const r = crawlSchema(
			{
				properties: {
					$type: { type: "string" },
					"@odata.type": { type: "string" },
				},
			},
			32,
			{ lang: "cs" },
		);
		ok(r.errors.some((e) => e.params.name === "$type"));
		ok(r.errors.some((e) => e.params.name === "@odata.type"));
	});

	test("lang=php should flag __wakeup", () => {
		const r = crawlSchema(
			{ properties: { __wakeup: { type: "string" } } },
			32,
			{ lang: "php" },
		);
		ok(r.errors.some((e) => e.params.name === "__wakeup"));
	});

	test("lang=rb should flag __send__", () => {
		const r = crawlSchema(
			{ properties: { __send__: { type: "string" } } },
			32,
			{ lang: "rb" },
		);
		ok(r.errors.some((e) => e.params.name === "__send__"));
	});

	test("lang=objc should flag isa", () => {
		const r = crawlSchema({ properties: { isa: { type: "string" } } }, 32, {
			lang: "objc",
		});
		ok(r.errors.some((e) => e.params.name === "isa"));
	});

	test("lang=swift (alias of objc) should flag isa", () => {
		const r = crawlSchema({ properties: { isa: { type: "string" } } }, 32, {
			lang: "swift",
		});
		ok(r.errors.some((e) => e.params.name === "isa"));
	});

	test("lang=ex should flag __struct__", () => {
		const r = crawlSchema(
			JSON.parse('{"properties":{"__struct__":{"type":"string"}}}'),
			32,
			{ lang: "ex" },
		);
		ok(r.errors.some((e) => e.params.name === "__struct__"));
	});

	test("lang=lua should flag __index", () => {
		const r = crawlSchema(
			JSON.parse('{"properties":{"__index":{"type":"string"}}}'),
			32,
			{ lang: "lua" },
		);
		ok(r.errors.some((e) => e.params.name === "__index"));
	});

	test("lang=kotlin (alias of java) should flag @type", () => {
		const r = crawlSchema({ properties: { "@type": { type: "string" } } }, 32, {
			lang: "kotlin",
		});
		ok(r.errors.some((e) => e.params.name === "@type"));
	});

	test("lang=vb (alias of cs) should flag $type", () => {
		const r = crawlSchema({ properties: { $type: { type: "string" } } }, 32, {
			lang: "vb",
		});
		ok(r.errors.some((e) => e.params.name === "$type"));
	});

	test("lang=fsharp (alias of cs) should flag @odata.type", () => {
		const r = crawlSchema(
			{ properties: { "@odata.type": { type: "string" } } },
			32,
			{ lang: "fsharp" },
		);
		ok(r.errors.some((e) => e.params.name === "@odata.type"));
	});

	test("lang=clojure (alias of java) should flag @class", () => {
		const r = crawlSchema(
			{ properties: { "@class": { type: "string" } } },
			32,
			{ lang: "clojure" },
		);
		ok(r.errors.some((e) => e.params.name === "@class"));
	});

	test("lang=default should include objc/ex/lua entries (union)", () => {
		const r = crawlSchema(
			JSON.parse(
				'{"properties":{"isa":{"type":"string"},"__struct__":{"type":"string"},"__index":{"type":"string"}}}',
			),
			32,
			{ lang: "default" },
		);
		ok(r.errors.some((e) => e.params.name === "isa"));
		ok(r.errors.some((e) => e.params.name === "__struct__"));
		ok(r.errors.some((e) => e.params.name === "__index"));
	});

	test("lang=default (union) should flag __class__ and @type from non-js langs", () => {
		const r = crawlSchema(
			JSON.parse(
				'{"properties":{"__class__":{"type":"string"},"@type":{"type":"string"}}}',
			),
			32,
			{ lang: "default" },
		);
		ok(r.errors.some((e) => e.params.name === "__class__"));
		ok(r.errors.some((e) => e.params.name === "@type"));
	});

	test("unknown lang should throw", () => {
		let threw = false;
		try {
			crawlSchema({}, 32, { lang: "elvish" });
		} catch (e) {
			threw = true;
			ok(e.message.includes("elvish"));
		}
		ok(threw, "expected unknown lang to throw");
	});

	test("lang=[] (empty array) should skip all dangerous-name checks", () => {
		const r = crawlSchema(
			JSON.parse('{"properties":{"__proto__":{"type":"string"}}}'),
			32,
			{ lang: [] },
		);
		ok(!r.errors.some((e) => e.schemaPath === "#/dangerous-name"));
	});

	test("lang=['__proto__'] (array) should use array directly as denylist", () => {
		const r = crawlSchema(
			JSON.parse('{"properties":{"__proto__":{"type":"string"}}}'),
			32,
			{ lang: ["__proto__"] },
		);
		ok(
			r.errors.some(
				(e) => e.keyword === "properties" && e.params.name === "__proto__",
			),
		);
	});

	test("lang=['custom-key'] (array) should flag only the custom key", () => {
		const r = crawlSchema(
			{
				properties: {
					"custom-key": { type: "string" },
					safe: { type: "string" },
				},
			},
			32,
			{ lang: ["custom-key"] },
		);
		ok(r.errors.some((e) => e.params.name === "custom-key"));
		ok(!r.errors.some((e) => e.params.name === "safe"));
	});
});

// Regression lock for the DANGEROUS_NAMES_BY_LANG denylist. These names are a
// security contract, so they are duplicated here as literals on purpose: the
// test must fail if any entry is dropped or altered in cli.js. Deriving the
// expectations from the exported table instead would let a mutation hide
// behind itself (the test would read the same mutated value it asserts on).
const EXPECTED_DANGEROUS_NAMES_BY_LANG = {
	js: ["__proto__", "constructor", "prototype"],
	py: [
		"__proto__",
		"constructor",
		"prototype",
		"__class__",
		"__init__",
		"__globals__",
		"__builtins__",
		"__import__",
		"__reduce__",
		"__subclasses__",
		"__dict__",
		"__mro__",
	],
	rb: [
		"__proto__",
		"constructor",
		"prototype",
		"__send__",
		"json_class",
		"instance_eval",
		"instance_variable_set",
		"singleton_class",
	],
	rs: ["__proto__", "constructor", "prototype"],
	java: ["__proto__", "constructor", "prototype", "@type", "@class"],
	kotlin: ["__proto__", "constructor", "prototype", "@type", "@class"],
	clojure: ["__proto__", "constructor", "prototype", "@type", "@class"],
	cs: [
		"__proto__",
		"constructor",
		"prototype",
		"$type",
		"__type",
		"@odata.type",
	],
	vb: [
		"__proto__",
		"constructor",
		"prototype",
		"$type",
		"__type",
		"@odata.type",
	],
	fsharp: [
		"__proto__",
		"constructor",
		"prototype",
		"$type",
		"__type",
		"@odata.type",
	],
	php: [
		"__proto__",
		"constructor",
		"prototype",
		"__construct",
		"__destruct",
		"__wakeup",
		"__sleep",
		"__serialize",
		"__unserialize",
		"__call",
		"__callStatic",
		"__get",
		"__set",
		"__isset",
		"__unset",
		"__toString",
		"__invoke",
		"__set_state",
		"__clone",
		"__debugInfo",
	],
	objc: [
		"__proto__",
		"constructor",
		"prototype",
		"isa",
		"class",
		"superclass",
		"description",
		"init",
		"_cmd",
	],
	swift: [
		"__proto__",
		"constructor",
		"prototype",
		"isa",
		"class",
		"superclass",
		"description",
		"init",
		"_cmd",
	],
	ex: [
		"__proto__",
		"constructor",
		"prototype",
		"__struct__",
		"__exception__",
		"__protocol__",
	],
	lua: [
		"__proto__",
		"constructor",
		"prototype",
		"__index",
		"__newindex",
		"__call",
		"__metatable",
		"__tostring",
		"__name",
		"__pairs",
		"__eq",
		"__lt",
		"__le",
		"__add",
		"__sub",
		"__mul",
		"__div",
		"__mod",
		"__pow",
		"__concat",
		"__len",
		"__unm",
		"__band",
		"__bor",
		"__bxor",
		"__bnot",
		"__shl",
		"__shr",
		"__idiv",
		"__close",
		"__gc",
	],
};

describe("crawlSchema dangerous-name denylist", () => {
	for (const [lang, names] of Object.entries(
		EXPECTED_DANGEROUS_NAMES_BY_LANG,
	)) {
		for (const name of names) {
			test(`lang="${lang}" flags property key ${JSON.stringify(name)}`, () => {
				// Build via JSON.parse so a "__proto__" key is a real own property
				// rather than the object prototype (an object literal would skip it).
				const r = crawlSchema(
					JSON.parse(
						`{"properties":{${JSON.stringify(name)}:{"type":"string"}}}`,
					),
					32,
					{ lang },
				);
				ok(
					r.errors.some(
						(e) => e.keyword === "properties" && e.params.name === name,
					),
					`expected lang="${lang}" to flag dangerous property name ${JSON.stringify(name)}`,
				);
			});
		}
	}

	// The "default" lang is the de-duplicated union of every language's list, so
	// it must flag both a shared name and a name contributed by a single language
	// (guards the spread/Set construction of DANGEROUS_NAMES_BY_LANG.default).
	for (const name of ["__proto__", "constructor", "__bor", "@odata.type"]) {
		test(`lang="default" flags property key ${JSON.stringify(name)}`, () => {
			const r = crawlSchema(
				JSON.parse(
					`{"properties":{${JSON.stringify(name)}:{"type":"string"}}}`,
				),
				32,
				{ lang: "default" },
			);
			ok(
				r.errors.some(
					(e) => e.keyword === "properties" && e.params.name === name,
				),
				`expected lang="default" to flag ${JSON.stringify(name)}`,
			);
		});
	}
});

// Full error-shape locks for crawlSchema. Existing tests mostly assert `keyword`;
// these pin instancePath, schemaPath, params and message so that blanking any of
// them (a mutation) is caught.
describe("crawlSchema error payloads", () => {
	const findByKeyword = (schema, keyword) =>
		crawlSchema(schema).errors.find((e) => e.keyword === keyword);

	test("minLength > maxLength error shape", () => {
		const e = findByKeyword(
			{ type: "string", minLength: 10, maxLength: 5 },
			"minLength",
		);
		strictEqual(e.instancePath, "");
		strictEqual(e.schemaPath, "#/minLength");
		strictEqual(e.params.minLength, 10);
		strictEqual(e.params.maxLength, 5);
		strictEqual(e.message, "minLength must be less than or equal to maxLength");
	});

	test("minItems > maxItems error shape", () => {
		const e = findByKeyword(
			{ type: "array", minItems: 10, maxItems: 3 },
			"minItems",
		);
		strictEqual(e.schemaPath, "#/minItems");
		strictEqual(e.params.minItems, 10);
		strictEqual(e.params.maxItems, 3);
		strictEqual(e.message, "minItems must be less than or equal to maxItems");
	});

	test("minContains > maxContains error shape", () => {
		const e = findByKeyword(
			{ type: "array", minContains: 10, maxContains: 3 },
			"minContains",
		);
		strictEqual(e.schemaPath, "#/minContains");
		strictEqual(e.params.minContains, 10);
		strictEqual(e.params.maxContains, 3);
		strictEqual(
			e.message,
			"minContains must be less than or equal to maxContains",
		);
	});

	test("minProperties > maxProperties error shape", () => {
		const e = findByKeyword(
			{ type: "object", minProperties: 10, maxProperties: 5 },
			"minProperties",
		);
		strictEqual(e.schemaPath, "#/minProperties");
		strictEqual(e.params.minProperties, 10);
		strictEqual(e.params.maxProperties, 5);
		strictEqual(
			e.message,
			"minProperties must be less than or equal to maxProperties",
		);
	});

	test("ReDoS pattern error shape", () => {
		const e = findByKeyword({ type: "string", pattern: "(a+)+$" }, "pattern");
		strictEqual(e.instancePath, "/pattern");
		strictEqual(e.schemaPath, "#/redos");
		strictEqual(e.params.pattern, "(a+)+$");
		ok(typeof e.params.reason === "string" && e.params.reason.length > 0);
		ok(typeof e.message === "string" && e.message.length > 0);
	});

	test("dangerous-name in properties error shape", () => {
		const r = crawlSchema(
			JSON.parse('{"properties":{"__proto__":{"type":"string"}}}'),
		);
		const e = r.errors.find((x) => x.keyword === "properties");
		strictEqual(e.instancePath, "/properties/__proto__");
		strictEqual(e.schemaPath, "#/dangerous-name");
		strictEqual(e.params.name, "__proto__");
		strictEqual(e.params.lang, "default");
		strictEqual(
			e.message,
			'properties key "__proto__" is a deserialization vector for lang="default"',
		);
	});

	test("dangerous-name in required error shape", () => {
		const r = crawlSchema(JSON.parse('{"required":["constructor"]}'));
		const e = r.errors.find((x) => x.keyword === "required");
		strictEqual(e.instancePath, "/required/0");
		strictEqual(e.schemaPath, "#/dangerous-name");
		strictEqual(e.params.name, "constructor");
		strictEqual(
			e.message,
			'required entry "constructor" is a deserialization vector for lang="default"',
		);
	});

	test("dangerous-name in dependentRequired error shape", () => {
		const r = crawlSchema(
			JSON.parse('{"dependentRequired":{"a":["prototype"]}}'),
		);
		const e = r.errors.find((x) => x.keyword === "dependentRequired");
		strictEqual(e.instancePath, "/dependentRequired/a/0");
		strictEqual(e.schemaPath, "#/dangerous-name");
		strictEqual(e.params.name, "prototype");
		strictEqual(
			e.message,
			'dependentRequired entry "prototype" is a deserialization vector for lang="default"',
		);
	});

	test("ReDoS patternProperties key error shape", () => {
		const r = crawlSchema(
			JSON.parse('{"patternProperties":{"(a+)+$":{"type":"string"}}}'),
		);
		const e = r.errors.find(
			(x) => x.keyword === "patternProperties" && x.schemaPath === "#/redos",
		);
		strictEqual(e.instancePath, "/patternProperties/(a+)+$");
		strictEqual(e.params.pattern, "(a+)+$");
		strictEqual(
			e.message,
			'patternProperties key "(a+)+$" is vulnerable to ReDoS',
		);
	});

	test("dangerous-name patternProperties match error shape", () => {
		const r = crawlSchema(
			JSON.parse('{"patternProperties":{"^__proto__$":{"type":"string"}}}'),
		);
		const e = r.errors.find(
			(x) =>
				x.keyword === "patternProperties" &&
				x.schemaPath === "#/dangerous-name",
		);
		strictEqual(e.instancePath, "/patternProperties/^__proto__$");
		strictEqual(e.params.pattern, "^__proto__$");
		ok(e.params.matches.includes("__proto__"));
		strictEqual(e.params.lang, "default");
		strictEqual(
			e.message,
			'patternProperties key "^__proto__$" matches deserialization vector(s) for lang="default": __proto__',
		);
	});
});

// Equal bounds are valid: the range checks use a strict `>` so tightening it to
// `>=` (a mutation) would flag a satisfiable range as impossible.
describe("crawlSchema equal-bound ranges are valid", () => {
	const noError = (schema, keyword) =>
		ok(!crawlSchema(schema).errors.some((e) => e.keyword === keyword));

	test("minLength === maxLength", () =>
		noError({ type: "string", minLength: 5, maxLength: 5 }, "minLength"));
	test("minItems === maxItems", () =>
		noError({ type: "array", minItems: 5, maxItems: 5 }, "minItems"));
	test("minContains === maxContains", () =>
		noError({ type: "array", minContains: 5, maxContains: 5 }, "minContains"));
	test("minProperties === maxProperties", () =>
		noError(
			{ type: "object", minProperties: 5, maxProperties: 5 },
			"minProperties",
		));
});

// Type/own-property guards on the range checks: a non-array (or a schema missing
// one bound) must not trigger array/object range errors.
describe("crawlSchema range guards", () => {
	test("minContains > maxContains ignored on non-array", () => {
		ok(
			!crawlSchema({
				type: "object",
				minContains: 10,
				maxContains: 3,
			}).errors.some((e) => e.keyword === "minContains"),
		);
	});
	test("minContains without maxContains does not error", () => {
		ok(
			!crawlSchema({ type: "array", minContains: 10 }).errors.some(
				(e) => e.keyword === "minContains",
			),
		);
	});
	test("dangerous name as the last required entry is still flagged", () => {
		const r = crawlSchema(JSON.parse('{"required":["safe","__proto__"]}'));
		const e = r.errors.find((x) => x.keyword === "required");
		strictEqual(e.params.name, "__proto__");
		strictEqual(e.instancePath, "/required/1");
	});
});

// Targeted guards and boundaries in crawlSchema that blanket error-shape tests
// don't reach.
describe("crawlSchema guards and boundaries", () => {
	test("non-object, non-null input returns the empty result", () => {
		const r = crawlSchema("not-a-schema");
		strictEqual(r.depth, 0);
		strictEqual(r.errors.length, 0);
		strictEqual(r.refs.length, 0);
	});

	test("a non-string pattern is ignored (no ReDoS analysis)", () => {
		const r = crawlSchema({ type: "string", pattern: 123 });
		ok(!r.errors.some((e) => e.keyword === "pattern"));
	});

	test("an unparseable pattern is reported as a parse-error ReDoS finding", () => {
		const e = crawlSchema({ type: "string", pattern: "(" }).errors.find(
			(x) => x.keyword === "pattern",
		);
		ok(e, "expected a pattern finding for an unparseable regex");
		strictEqual(e.instancePath, "/pattern");
		strictEqual(e.schemaPath, "#/redos");
		strictEqual(e.params.reason, "parseError");
		strictEqual(e.message, "pattern could not be parsed for ReDoS analysis");
	});

	test("required dangerous-name carries the requested lang, not the default", () => {
		const e = crawlSchema(JSON.parse('{"required":["__send__"]}'), 32, {
			lang: "rb",
		}).errors.find((x) => x.keyword === "required");
		ok(e, "expected __send__ flagged for ruby");
		strictEqual(e.params.lang, "rb");
		ok(e.message.includes('lang="rb"'));
	});

	test("dependentRequired dangerous-name carries the requested lang", () => {
		const e = crawlSchema(
			JSON.parse('{"dependentRequired":{"a":["__send__"]}}'),
			32,
			{ lang: "rb" },
		).errors.find((x) => x.keyword === "dependentRequired");
		ok(e, "expected __send__ flagged for ruby");
		strictEqual(e.params.lang, "rb");
	});

	test("external $ref whose URL ends in '#' is still collected", () => {
		const r = crawlSchema(JSON.parse('{"$ref":"http://evil.example/#"}'));
		const ref = r.refs.find((x) => x.hostname === "evil.example");
		ok(ref, "expected the external $ref to be collected");
		strictEqual(ref.ref, "http://evil.example/#");
		strictEqual(ref.path, "/$ref");
	});

	test("internal '#'-prefixed $ref is not collected as remote", () => {
		const r = crawlSchema(JSON.parse('{"$ref":"#/$defs/foo"}'));
		strictEqual(r.refs.length, 0);
	});

	test("a primitive property value is not descended into", () => {
		// { foo: "bar" } — "bar" is a string, so the crawl must not recurse into it
		// (recursing would bump the reported depth).
		const r = crawlSchema({ type: "object", foo: "bar" });
		strictEqual(r.depth, 1);
	});

	test("depth exactly at the limit is not flagged as exceeded", () => {
		// root(1) -> a(2) -> b(3): exactly maxDepth 3, must not be flagged.
		const r = crawlSchema({ a: { b: { type: "string" } } }, 3);
		strictEqual(r.depthExceeded, false);
	});

	test("depth one past the limit is flagged as exceeded", () => {
		const r = crawlSchema({ a: { b: { c: { type: "string" } } } }, 3);
		strictEqual(r.depthExceeded, true);
	});
});

describe("crawlSchema null-value and multi-match guards", () => {
	test("a null property value is not descended into (typeof null is 'object')", () => {
		// Must not throw: dropping the `value !== null` guard would push null onto
		// the stack and then read null.type on the next iteration.
		const r = crawlSchema({ type: "object", foo: null });
		strictEqual(r.depth, 1);
		strictEqual(r.errors.length, 0);
	});

	test("patternProperties matching multiple dangerous names lists them comma-separated", () => {
		// "^(__proto__|constructor)$" matches two denylist entries, exposing the
		// ", " join separator in the message.
		const r = crawlSchema(
			JSON.parse(
				'{"patternProperties":{"^(__proto__|constructor)$":{"type":"string"}}}',
			),
		);
		const e = r.errors.find(
			(x) =>
				x.keyword === "patternProperties" &&
				x.schemaPath === "#/dangerous-name",
		);
		ok(e, "expected a dangerous-name patternProperties finding");
		ok(e.params.matches.includes("__proto__"));
		ok(e.params.matches.includes("constructor"));
		ok(e.message.includes("__proto__, constructor"));
	});
});

// Adversarial / malformed-input guards. These exercise exactly the edge cases
// crawlSchema's defensive type-guards exist for, so each both kills a mutant and
// documents a real robustness/security property (e.g. never analyze inherited or
// non-own keys, never crash on a null sub-schema).
describe("crawlSchema defensive guards", () => {
	test("ReDoS analysis is independent of the denylist (lang:[] still scans)", () => {
		const r = crawlSchema(
			JSON.parse('{"patternProperties":{"(a+)+$":{}}}'),
			32,
			{ lang: [] },
		);
		ok(r.errors.some((e) => e.schemaPath === "#/redos"));
	});

	test("an inherited `pattern` is not analyzed (own-property only)", () => {
		const proto = Object.create({ pattern: "(a+)+$" });
		ok(!crawlSchema(proto).errors.some((e) => e.schemaPath === "#/redos"));
	});

	test("a non-string `pattern` is ignored, not coerced to a regex", () => {
		// String(["(a+)+$"]) === "(a+)+$"; the typeof guard must stop coercion.
		const r = crawlSchema(JSON.parse('{"pattern":["(a+)+$"]}'));
		ok(!r.errors.some((e) => e.schemaPath === "#/redos"));
	});

	test("a null denylist site does not crash the crawl", () => {
		for (const key of [
			"properties",
			"$defs",
			"definitions",
			"dependentSchemas",
			"dependentRequired",
		]) {
			const r = crawlSchema(JSON.parse(`{"${key}":null}`));
			ok(Array.isArray(r.errors), `${key}:null must not throw`);
		}
	});

	test("a denylist site that is an array is not treated as a key map", () => {
		const r = crawlSchema(JSON.parse('{"properties":["__proto__"]}'));
		ok(!r.errors.some((e) => e.schemaPath === "#/dangerous-name"));
	});

	test("a null patternProperties/dependentRequired does not crash", () => {
		ok(
			Array.isArray(
				crawlSchema(JSON.parse('{"patternProperties":null}')).errors,
			),
		);
		ok(
			Array.isArray(
				crawlSchema(JSON.parse('{"dependentRequired":null}')).errors,
			),
		);
	});

	test("a non-string required entry is ignored", () => {
		const r = crawlSchema(JSON.parse('{"required":[123,{"x":1}]}'));
		ok(!r.errors.some((e) => e.schemaPath === "#/dangerous-name"));
	});

	test("an inherited or non-string $ref is not collected", () => {
		ok(
			crawlSchema(Object.create({ $ref: "https://x.example/s" })).refs
				.length === 0,
		);
		ok(crawlSchema(JSON.parse('{"$ref":123}')).refs.length === 0);
	});

	test("an internal '#'-prefixed $ref is not collected as remote", () => {
		ok(crawlSchema(JSON.parse('{"$ref":"#/$defs/x"}')).refs.length === 0);
	});
});

// --- A1: ReDoS-analysis memory/work bounding (OOM defense) ---
// A single sub-1KB schema with multiple evil patternProperties keys used to OOM
// the scanner: the per-pattern work was unbounded (memory grew faster than the
// time deadline could fire), and the deadline was only checked once per stack
// pop, never between patterns. The fix is layered: (1) a per-pattern maxSteps
// bound, (2) a deadline check before each pattern analysis, (3) a hard cap on
// the total number of patterns analyzed.
describe("crawlSchema ReDoS-analysis bounds (A1)", () => {
	const EVIL = "^(a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z)+";

	test("exposes a heap-budget const and MAX_REDOS_PATTERNS cap", () => {
		strictEqual(typeof REDOS_HEAP_BUDGET_BYTES, "number");
		ok(REDOS_HEAP_BUDGET_BYTES > 0, "REDOS_HEAP_BUDGET_BYTES must be positive");
		// Must sit below a single evil pattern's ~270MB footprint (so the breaker
		// fires after the first one) yet leave headroom under a 600MB heap.
		ok(
			REDOS_HEAP_BUDGET_BYTES <= 256 * 1024 * 1024,
			"REDOS_HEAP_BUDGET_BYTES must stay under 256MB so it bails before OOM",
		);
		strictEqual(typeof MAX_REDOS_PATTERNS, "number");
		ok(MAX_REDOS_PATTERNS > 0, "MAX_REDOS_PATTERNS must be positive");
	});

	// REGRESSION: legitimate complex-but-safe patterns must NOT be reported as
	// ReDoS. maxSteps=100 wrongly fail-closed semver (hitMaxSteps); removing it
	// restores the library-default verdict, which is SAFE for all of these.
	test("does not flag legitimate safe patterns as ReDoS", () => {
		const safePatterns = [
			// semver: SAFE at default maxSteps, but hitMaxSteps at maxSteps<=250.
			"^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)$",
			// ISO date.
			"^\\d{4}-\\d{2}-\\d{2}$",
			// uuid.
			"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
			// slug.
			"^[a-z0-9]+(?:-[a-z0-9]+)*$",
		];
		const patternProperties = {};
		for (const p of safePatterns) {
			patternProperties[p] = { type: "string" };
		}
		const r = crawlSchema({ patternProperties });
		const redos = r.errors.filter((e) => e.schemaPath === "#/redos");
		strictEqual(
			redos.length,
			0,
			`safe patterns must not be flagged; got: ${redos
				.map((e) => e.params.pattern)
				.join(", ")}`,
		);
		// Also exercise the top-level `pattern` path for semver specifically.
		const semver = crawlSchema({
			type: "string",
			pattern: "^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)$",
		});
		strictEqual(
			semver.errors.filter((e) => e.schemaPath === "#/redos").length,
			0,
			"semver must not be flagged as ReDoS at the library default",
		);
	});

	// HEAP CIRCUIT BREAKER (primary memory bound): an injected memoryUsage that
	// crosses an injected budget must stop analysis early and emit exactly one
	// incomplete #/redos-budget finding that survives --ignore.
	test("heap budget breaker stops analysis early and emits one incomplete finding", () => {
		const patternProperties = {};
		for (let i = 0; i < 5; i++) {
			patternProperties[`^safe${i}$`] = { type: "string" };
		}
		// Baseline 100, then values stepping up by 50 per read. With a budget of
		// 100, the breaker fires when current-baseline (100) > 100 is first true:
		// reads are 100 (baseline), 150, 200, 250, ... so 250-100=150>100 trips on
		// the 4th read (before the 3rd pattern, since the baseline read is read #1).
		let calls = 0;
		const memoryUsage = () => 100 + 50 * calls++;
		const r = crawlSchema({ patternProperties }, 32, {
			memoryUsage,
			redosHeapBudgetBytes: 100,
		});
		const budget = r.errors.filter(
			(e) => e.schemaPath === "#/redos-budget" && e.keyword === "heap",
		);
		strictEqual(budget.length, 1, "exactly one heap-budget finding");
		strictEqual(budget[0].params.incomplete, true, "must be marked incomplete");
		// Analysis stopped early: fewer than all 5 keys were analyzed. (Safe keys
		// emit no #/redos finding, so we assert via the breaker firing + that the
		// memoryUsage reader was called fewer times than 1 baseline + 5 patterns.)
		ok(
			calls < 6,
			`analysis must stop early; memoryUsage called ${calls} times`,
		);
		// Survives --ignore because it is incomplete.
		const kept = crawlSchema({ patternProperties }, 32, {
			memoryUsage: (() => {
				let c = 0;
				return () => 100 + 50 * c++;
			})(),
			redosHeapBudgetBytes: 100,
			ignore: ["#/redos-budget"],
		});
		// crawlSchema itself does not apply --ignore (analyze() does), so verify the
		// finding shape carries incomplete:true, which applyIgnore honors.
		strictEqual(
			kept.errors.filter(
				(e) => e.schemaPath === "#/redos-budget" && e.keyword === "heap",
			).length,
			1,
			"heap-budget finding is present regardless of ignore",
		);
	});

	// Boundary pin for Stryker: exactly AT the budget (current-baseline == budget)
	// must NOT trip the breaker (`<=` keeps the comparison false). The breaker reads
	// heap once per analyzed pattern, so two patternProperties keys give a baseline
	// read (100) then a second read (200): delta is EXACTLY the budget (100), which
	// must NOT trip. Kills `<=`->`<` (which would fire at exactly the budget).
	test("heap delta exactly equal to budget does not trip the breaker (<=)", () => {
		let calls = 0;
		// Read #1 (baseline) = 100; read #2 = 200 -> delta exactly 100 == budget.
		const memoryUsage = () => (calls++ === 0 ? 100 : 200);
		const r = crawlSchema(
			{
				patternProperties: {
					"^safe1$": { type: "string" },
					"^safe2$": { type: "string" },
				},
			},
			32,
			{ memoryUsage, redosHeapBudgetBytes: 100 },
		);
		strictEqual(
			r.errors.filter((e) => e.schemaPath === "#/redos-budget").length,
			0,
			"delta exactly equal to budget must not trip (<= keeps it false)",
		);
		ok(calls >= 2, "the second pattern's read must have happened");
	});

	// Companion to the boundary: delta = budget + 1 MUST trip, and the emitted heap
	// finding's exact shape is pinned so the message StringLiteral and the
	// incomplete BooleanLiteral mutants are killed.
	test("heap delta of budget+1 trips and emits the exact heap finding", () => {
		let calls = 0;
		// Read #1 (baseline) = 100; read #2 = 201 -> delta 101 = budget + 1.
		const memoryUsage = () => (calls++ === 0 ? 100 : 201);
		const r = crawlSchema(
			{
				patternProperties: {
					"^safe1$": { type: "string" },
					"^safe2$": { type: "string" },
				},
			},
			32,
			{ memoryUsage, redosHeapBudgetBytes: 100 },
		);
		const heap = r.errors.filter(
			(e) => e.schemaPath === "#/redos-budget" && e.keyword === "heap",
		);
		strictEqual(heap.length, 1, "budget+1 must trip exactly once");
		strictEqual(heap[0].keyword, "heap");
		strictEqual(heap[0].schemaPath, "#/redos-budget");
		deepStrictEqual(heap[0].params, { budget: 100, incomplete: true });
		strictEqual(heap[0].params.incomplete, true);
		strictEqual(
			heap[0].message,
			"ReDoS analysis heap budget of 100 bytes exceeded; remaining patterns not analyzed",
		);
	});

	// Single-fire guard: two SEPARATE pattern nodes both over budget must emit only
	// ONE heap finding (the `!redosHeapReported` guard latches). Kills the
	// ConditionalExpression (forcing `true` re-emits) and the BooleanLiteral
	// (`redosHeapReported = false` never latches, so it re-emits).
	test("the heap breaker reports at most once across multiple over-budget pattern nodes", () => {
		let calls = 0;
		// First analyzed pattern (read #1) = 0 baseline; every later read = 1e6,
		// far over the budget, so the SECOND and THIRD pattern nodes both exceed it.
		const memoryUsage = () => (calls++ === 0 ? 0 : 1_000_000);
		const r = crawlSchema(
			{
				properties: {
					a: { type: "string", pattern: "a" },
					b: { type: "string", pattern: "b" },
					c: { type: "string", pattern: "c" },
				},
			},
			32,
			{ memoryUsage, redosHeapBudgetBytes: 100 },
		);
		const heap = r.errors.filter(
			(e) => e.schemaPath === "#/redos-budget" && e.keyword === "heap",
		);
		strictEqual(
			heap.length,
			1,
			"the heap finding must be emitted exactly once even with multiple over-budget nodes",
		);
		// The heap finding's instancePath is the tripping node's `${path}/pattern`,
		// never the empty string (pins the path template passed to redosHeapExceeded).
		ok(
			/^\/properties\/[abc]\/pattern$/.test(heap[0].instancePath),
			`heap instancePath must name the tripping pattern node, got "${heap[0].instancePath}"`,
		);
	});

	// PRIMARY (heap breaker, OOM repro): many distinct evil patternProperties keys
	// each grow the heap by ~270MB at the library default. The heap circuit breaker
	// (default budget) must bail after the first one so the crawl returns WITHOUT
	// crashing, emitting one incomplete heap-budget finding. (The manual 600MB
	// check in the PR confirms no OOM; here the larger test-process heap simply
	// proves we return cleanly and the breaker fired.)
	test("40 distinct evil patternProperties keys return without crashing (heap breaker)", () => {
		const patternProperties = {};
		for (let i = 0; i < 40; i++) {
			patternProperties[`${EVIL}${i}$`] = { type: "string" };
		}
		const r = crawlSchema({ patternProperties });
		strictEqual(r.timedOut, false, "must not have tripped the deadline");
		// The heap breaker bailed: at least one evil pattern was flagged before the
		// budget tripped, and exactly one incomplete heap-budget finding is present.
		const heap = r.errors.filter(
			(e) => e.schemaPath === "#/redos-budget" && e.keyword === "heap",
		);
		strictEqual(heap.length, 1, "the heap breaker must fire exactly once");
		strictEqual(heap[0].params.incomplete, true, "heap finding is incomplete");
		const redos = r.errors.filter(
			(e) => e.keyword === "patternProperties" && e.schemaPath === "#/redos",
		);
		ok(
			redos.length >= 1 && redos.length < 40,
			`breaker must stop early after flagging some keys; got ${redos.length}`,
		);
	});

	// Layer 1 also applies to top-level `pattern`: a single evil pattern is
	// flagged fail-closed and completes quickly under the step bound.
	test("a top-level evil pattern is flagged fail-closed under the step bound", () => {
		const r = crawlSchema({ type: "string", pattern: `${EVIL}$` });
		const err = r.errors.find((e) => e.keyword === "pattern");
		ok(err, "expected a ReDoS finding for the evil pattern");
		strictEqual(err.schemaPath, "#/redos");
	});

	// Once-per-pop deadline (top of the stack loop): an already-passed deadline
	// must bail on the FIRST pop, before ANY structural check runs. The schema has
	// NO pattern, so the per-pattern deadline guards cannot mask this one; a node
	// with minLength > maxLength would emit a finding if the loop body ran. Killing
	// the once-per-pop ConditionalExpression: bailing means the timeout finding is
	// present AND the minLength finding is absent.
	test("an already-passed deadline bails on the first pop before any structural check", () => {
		const r = crawlSchema({ type: "string", minLength: 5, maxLength: 1 }, 32, {
			deadline: 0,
		});
		ok(
			r.errors.some((e) => e.keyword === "timeout"),
			"must emit the timeout finding on the first pop",
		);
		strictEqual(r.timedOut, true);
		ok(
			!r.errors.some((e) => e.keyword === "minLength"),
			"must bail BEFORE the minLength<=maxLength structural check runs",
		);
		strictEqual(r.errors.length, 1, "only the timeout finding is emitted");
	});

	// Layer 2: the deadline is checked before each top-level pattern analysis, so
	// an already-passed deadline bails to the timeout path BEFORE any ReDoS work.
	test("an already-passed deadline bails before analyzing a top-level pattern", () => {
		const r = crawlSchema({ type: "string", pattern: `${EVIL}$` }, 32, {
			deadline: 0,
		});
		ok(
			r.errors.some((e) => e.keyword === "timeout"),
			"must emit the timeout finding",
		);
		strictEqual(r.timedOut, true);
		ok(
			!r.errors.some((e) => e.keyword === "pattern"),
			"must NOT have run ReDoS analysis after the deadline",
		);
	});

	// Layer 2: the deadline is also checked inside the patternProperties key loop.
	test("an already-passed deadline bails before analyzing patternProperties keys", () => {
		const r = crawlSchema(
			{ patternProperties: { [`${EVIL}1$`]: { type: "string" } } },
			32,
			{ deadline: 0 },
		);
		ok(
			r.errors.some((e) => e.keyword === "timeout"),
			"must emit the timeout finding",
		);
		strictEqual(r.timedOut, true);
		ok(
			!r.errors.some((e) => e.schemaPath === "#/redos"),
			"must NOT have run ReDoS analysis after the deadline",
		);
	});

	// Layer 3 (defense in depth): a hard cap on the TOTAL number of patterns
	// analyzed. Once exceeded, no further patterns are analyzed and exactly one
	// fail-closed budget finding is emitted.
	// SAFE keys (cheap, never trip the heap breaker) isolate the count cap. A
	// non-tripping memoryUsage is injected so the heap breaker is out of the way.
	// The reader is called once per ANALYZED pattern (plus the baseline read), so
	// the call count proves analysis stops exactly at the cap.
	test("exceeding MAX_REDOS_PATTERNS stops analysis and emits one incomplete budget finding", () => {
		const patternProperties = {};
		const total = MAX_REDOS_PATTERNS + 5;
		for (let i = 0; i < total; i++) {
			patternProperties[`^ok${i}$`] = { type: "string" };
		}
		let reads = 0;
		const memoryUsage = () => {
			reads++;
			return 0; // never grows, so the heap breaker never fires
		};
		const r = crawlSchema({ patternProperties }, 32, { memoryUsage });
		const budget = r.errors.filter((e) => e.schemaPath === "#/redos-budget");
		strictEqual(budget.length, 1, "exactly one budget finding");
		strictEqual(budget[0].keyword, "pattern");
		strictEqual(budget[0].params.incomplete, true, "count cap is incomplete");
		ok(
			budget[0].message.includes(String(MAX_REDOS_PATTERNS)),
			"budget message names the cap",
		);
		// Per-pattern heap reads stop once the count cap fires. The count check
		// runs BEFORE the heap read and short-circuits it, so the reader is called
		// exactly once per analyzed pattern (MAX_REDOS_PATTERNS) and never for the
		// skipped keys (the first call also captures the baseline).
		strictEqual(
			reads,
			MAX_REDOS_PATTERNS,
			"only the first MAX_REDOS_PATTERNS keys are analyzed; the rest are skipped",
		);
	});

	// Single-fire guard for the COUNT cap: two over-cap top-level `pattern` nodes
	// (the `pattern` path does NOT break on a tripped budget, unlike the
	// patternProperties path) must still emit only ONE budget finding. Kills the
	// `if (!redosBudgetReported)` ConditionalExpression (forcing `true` re-emits).
	test("the count cap reports exactly once across two over-cap pattern nodes", () => {
		const properties = {};
		// MAX analyzed + 2 over-cap nodes. Distinct safe patterns so each is its own
		// analyzed pattern and none is flagged as ReDoS.
		for (let i = 0; i < MAX_REDOS_PATTERNS + 2; i++) {
			properties[`p${i}`] = { type: "string", pattern: `lit${i}` };
		}
		const r = crawlSchema({ properties }, 32, { memoryUsage: () => 0 });
		const budget = r.errors.filter((e) => e.schemaPath === "#/redos-budget");
		strictEqual(
			budget.length,
			1,
			"two over-cap pattern nodes must still emit exactly one budget finding",
		);
		strictEqual(budget[0].keyword, "pattern");
		strictEqual(budget[0].params.incomplete, true);
		// The budget finding's instancePath is the over-cap node's `${path}/pattern`,
		// never the empty string (pins the path template passed to redosBudgetExceeded).
		ok(
			/^\/properties\/p\d+\/pattern$/.test(budget[0].instancePath),
			`budget instancePath must name the over-cap pattern node, got "${budget[0].instancePath}"`,
		);
	});

	// The cap counts top-level `pattern` analyses too (shared budget), so a schema
	// at exactly the cap of patterns does NOT emit a budget finding (strict >).
	test("exactly MAX_REDOS_PATTERNS patterns does not trip the budget (strict >)", () => {
		const patternProperties = {};
		for (let i = 0; i < MAX_REDOS_PATTERNS; i++) {
			patternProperties[`^ok${i}$`] = { type: "string" };
		}
		const r = crawlSchema({ patternProperties }, 32, { memoryUsage: () => 0 });
		ok(
			!r.errors.some((e) => e.schemaPath === "#/redos-budget"),
			"exactly-at-cap must not trip the budget",
		);
	});
});

// --- A4: collected refs are capped before the hostname cap ---
// crawlSchema used to push every remote $ref/$dynamicRef into result.refs with
// no bound; the hostname cap only applies later on the distinct-hostname map.
// A hard cap on result.refs length is a backstop (overall bounded by
// MAX_SCHEMA_SIZE) that stops collecting once exceeded and records one finding.
describe("crawlSchema collected-refs cap (A4)", () => {
	test("exposes a positive MAX_COLLECTED_REFS const", () => {
		strictEqual(typeof MAX_COLLECTED_REFS, "number");
		ok(MAX_COLLECTED_REFS > 0, "MAX_COLLECTED_REFS must be positive");
	});

	// Build a schema carrying MORE distinct remote refs than the cap, nested so the
	// crawl reaches them all. Each ref is to a distinct host so none de-duplicate.
	const manyRefsSchema = (n) => {
		const $defs = {};
		for (let i = 0; i < n; i++) {
			$defs[`d${i}`] = { $ref: `https://refcap-${i}.invalid/s.json` };
		}
		return { $defs };
	};

	test("result.refs is capped at MAX_COLLECTED_REFS and a truncation finding is recorded", () => {
		const r = crawlSchema(manyRefsSchema(MAX_COLLECTED_REFS + 10));
		ok(
			r.refs.length <= MAX_COLLECTED_REFS,
			`refs (${r.refs.length}) must not exceed the cap (${MAX_COLLECTED_REFS})`,
		);
		const trunc = r.errors.filter((e) => e.schemaPath === "#/refs-truncated");
		strictEqual(trunc.length, 1, "exactly one truncation finding");
		ok(
			trunc[0].message.includes(String(MAX_COLLECTED_REFS)),
			"truncation message names the cap",
		);
		// Pin the full finding shape so the instancePath/keyword StringLiteral and the
		// params ObjectLiteral / incomplete BooleanLiteral mutants are all killed.
		const t = trunc[0];
		strictEqual(t.schemaPath, "#/refs-truncated");
		strictEqual(t.keyword, "$ref");
		// instancePath is the path to the ref that first hit the cap; it must be a
		// real JSON pointer ending at a $ref/$dynamicRef site, never the empty string.
		ok(t.instancePath.length > 0, "instancePath must not be empty");
		ok(
			/\/\$(ref|dynamicRef)$/.test(t.instancePath),
			`instancePath must point at a ref site, got ${t.instancePath}`,
		);
		deepStrictEqual(t.params, {
			limit: MAX_COLLECTED_REFS,
			incomplete: true,
		});
		strictEqual(t.params.incomplete, true);
		strictEqual(
			t.message,
			`more than ${MAX_COLLECTED_REFS} remote $ref(s); remaining refs not collected for SSRF analysis`,
		);
	});

	test("a schema with refs at or under the cap collects them all with no truncation finding", () => {
		const r = crawlSchema(manyRefsSchema(MAX_COLLECTED_REFS));
		strictEqual(r.refs.length, MAX_COLLECTED_REFS, "all refs collected");
		ok(
			!r.errors.some((e) => e.schemaPath === "#/refs-truncated"),
			"no truncation finding at exactly the cap (strict >)",
		);
	});
});
