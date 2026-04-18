import { ok, strictEqual } from "node:assert";
import { describe, test } from "node:test";
import { crawlSchema } from "../cli.js";

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

	test("should use maximum when exclusiveMaximum > maximum", () => {
		const r = crawlSchema({
			type: "integer",
			minimum: 50,
			maximum: 10,
			exclusiveMaximum: 95,
		});
		ok(r.errors.some((e) => e.keyword === "minimum"));
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
		ok(!r.errors.some((e) => e.keyword === "minimum"));
	});

	test("should ignore Infinity exclusiveMinimum", () => {
		const r = crawlSchema({
			type: "number",
			exclusiveMinimum: Infinity,
			maximum: 100,
		});
		ok(!r.errors.some((e) => e.keyword === "minimum"));
	});

	test("should ignore NaN exclusiveMaximum", () => {
		const r = crawlSchema({
			type: "integer",
			minimum: 0,
			exclusiveMaximum: NaN,
		});
		ok(!r.errors.some((e) => e.keyword === "minimum"));
	});

	test("should ignore -Infinity maximum", () => {
		const r = crawlSchema({
			type: "number",
			minimum: 0,
			maximum: -Infinity,
		});
		ok(!r.errors.some((e) => e.keyword === "minimum"));
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
});
