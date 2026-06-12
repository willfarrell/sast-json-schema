import assert from "node:assert";
import { describe, it } from "node:test";
import Ajv from "ajv/dist/2020.js";
import schema202012 from "../2020-12.json" with { type: "json" };
import schemaDraft04 from "../draft-04.json" with { type: "json" };

const compile = (schema) =>
	new Ajv({ strictTypes: false, allowUnionTypes: true }).compile(schema);

// Wrap a keyword value (const/default/examples) in a minimal-but-valid 2020-12
// object schema so only the value-size rule under test decides accept/reject.
const wrap2020 = (keyword, value) => ({
	$schema: "https://json-schema.org/draft/2020-12/schema",
	$id: "https://example.com/x",
	type: "object",
	additionalProperties: false,
	required: [],
	unevaluatedProperties: false,
	properties: {
		v: {
			type: "object",
			additionalProperties: false,
			required: [],
			unevaluatedProperties: false,
			properties: {},
			[keyword]: value,
		},
	},
});

const buildDeep = (depth) => {
	const root = {};
	let cur = root;
	for (let i = 0; i < depth; i++) {
		cur.a = {};
		cur = cur.a;
	}
	cur.leaf = "x";
	return root;
};

// === B3: safePattern static rule catches bounded-quantifier ReDoS ===
describe("B3: safePattern bounded-quantifier ReDoS (2020-12)", () => {
	const validate = compile(schema202012);
	const withPattern = (pattern) => ({
		$schema: "https://json-schema.org/draft/2020-12/schema",
		$id: "https://example.com/x",
		type: "object",
		additionalProperties: false,
		required: [],
		unevaluatedProperties: false,
		properties: {
			v: { type: "string", pattern, maxLength: 100 },
		},
	});
	const accepts = (pattern) => validate(withPattern(pattern));

	const rejectCases = [
		["bounded quantifier around a + group", "^(a+){1,5}$"],
		["bounded quantifier around a * group", "^(a*){1,5}$"],
		["bounded quantifier around a + non-capturing group", "^(?:a+){1,5}$"],
		["huge single repetition (5+ digit upper bound)", "^a{1,1000000}$"],
		["huge exact repetition (5+ digits)", "^a{100000}$"],
		["huge char-class repetition (5+ digits)", "^[a-z]{10000}$"],
	];
	for (const [label, pattern] of rejectCases) {
		it(`rejects ${label}: ${pattern}`, () => {
			assert.strictEqual(accepts(pattern), false);
		});
	}

	const acceptCases = [
		["simple bounded char class", "^[a-z]{1,10}$"],
		["bounded group with no inner quantifier", "^(abc){1,5}$"],
		["non-capturing bounded group, no inner quantifier", "^(?:abc){1,5}$"],
		[
			"group with only fixed inner {n} quantifier (uuid)",
			"^(?:urn:uuid:)?[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$",
		],
		["exact small repetition", "^a{2,8}$"],
		["date pattern", "^[0-9]{4}-[0-9]{2}-[0-9]{2}$"],
		["four-digit upper bound (below the 5-digit cap)", "^[a-z]{1,9999}$"],
	];
	for (const [label, pattern] of acceptCases) {
		it(`accepts ${label}: ${pattern}`, () => {
			assert.strictEqual(
				accepts(pattern),
				true,
				`expected ACCEPT, got errors: ${JSON.stringify(validate.errors, null, 2)}`,
			);
		});
	}

	it("KNOWN LIMITATION: nested bounded-quantifier large product is accepted by meta-schema (CLI runtime catches it)", () => {
		// (a{1,1000}){1,1000} has a large product of bounded quantifiers but no
		// unbounded + / * inside the group, so the static meta-schema rule does
		// not reject it. Documented in README Known Limitations; the CLI's
		// redos-detector rejects it at runtime.
		assert.strictEqual(accepts("^(a{1,1000}){1,1000}$"), true);
	});
});

// === B1: nested const/default/examples values are size-bounded recursively ===
describe("B1: recursive value size limits (2020-12)", () => {
	const validate = compile(schema202012);

	for (const keyword of ["const", "default"]) {
		it(`rejects a nested 1MB string inside a ${keyword} object`, () => {
			const value = { a: "X".repeat(1000000) };
			assert.strictEqual(validate(wrap2020(keyword, value)), false);
		});

		it(`does not accept a deeply-nested (2000-level) ${keyword}`, () => {
			// The recursive self-$ref bounds size at every level. Pure depth is
			// bounded by AJV's own runtime recursion limit: a 2000-level value is
			// never accepted, it fails closed (validate returns false or throws a
			// RangeError during validation). Either way it is not treated as safe.
			let accepted = true;
			try {
				accepted = validate(wrap2020(keyword, buildDeep(2000)));
			} catch {
				accepted = false;
			}
			assert.strictEqual(accepted, false);
		});

		it(`rejects a 1MB string nested deep inside a ${keyword} (size, not depth)`, () => {
			const deep = buildDeep(10);
			let cur = deep;
			while (cur.a) cur = cur.a;
			cur.leaf = "X".repeat(1000000);
			assert.strictEqual(validate(wrap2020(keyword, deep)), false);
		});

		it(`accepts a small nested ${keyword} (a few short strings)`, () => {
			const value = { a: "hello", b: "world", c: { d: "ok" } };
			assert.strictEqual(
				validate(wrap2020(keyword, value)),
				true,
				`expected ACCEPT, got errors: ${JSON.stringify(validate.errors, null, 2)}`,
			);
		});
	}

	it("rejects a nested 1MB string inside an examples value", () => {
		const schema = {
			$schema: "https://json-schema.org/draft/2020-12/schema",
			$id: "https://example.com/x",
			type: "object",
			additionalProperties: false,
			required: [],
			unevaluatedProperties: false,
			properties: {
				v: {
					type: "object",
					additionalProperties: false,
					required: [],
					unevaluatedProperties: false,
					properties: {},
					examples: [{ a: "X".repeat(1000000) }],
				},
			},
		};
		assert.strictEqual(validate(schema), false);
	});

	it("accepts a small nested examples value", () => {
		const schema = {
			$schema: "https://json-schema.org/draft/2020-12/schema",
			$id: "https://example.com/x",
			type: "object",
			additionalProperties: false,
			required: [],
			unevaluatedProperties: false,
			properties: {
				v: {
					type: "object",
					additionalProperties: false,
					required: [],
					unevaluatedProperties: false,
					properties: {},
					examples: [{ a: "hi", b: ["ok", "fine"] }],
				},
			},
		};
		assert.strictEqual(
			validate(schema),
			true,
			`expected ACCEPT, got errors: ${JSON.stringify(validate.errors, null, 2)}`,
		);
	});
});

// === B2: draft-04 typed additionalProperties must be satisfiable ===
describe("B2: draft-04 typed additionalProperties (dictionary)", () => {
	const validate = compile(schemaDraft04);
	const dictionary = (overrides = {}) => ({
		$schema: "https://json-schema.org/draft-04/schema",
		id: "https://example.com/dict",
		type: "object",
		additionalProperties: {
			type: "string",
			pattern: "^[a-z]+$",
			maxLength: 10,
		},
		maxProperties: 10,
		required: [],
		...overrides,
	});

	it("accepts a valid draft-04 dictionary schema with maxProperties", () => {
		const valid = validate(dictionary());
		assert.strictEqual(
			valid,
			true,
			`expected ACCEPT, got errors: ${JSON.stringify(validate.errors, null, 2)}`,
		);
	});

	it("rejects the same dictionary schema without maxProperties", () => {
		const noMax = dictionary();
		delete noMax.maxProperties;
		assert.strictEqual(validate(noMax), false);
	});

	it("2020-12 still requires propertyNames for a typed additionalProperties map (unchanged)", () => {
		const validate2020 = compile(schema202012);
		const base = {
			$schema: "https://json-schema.org/draft/2020-12/schema",
			$id: "https://example.com/dict",
			type: "object",
			additionalProperties: {
				type: "string",
				pattern: "^[a-z]+$",
				maxLength: 10,
			},
			maxProperties: 10,
			required: [],
			unevaluatedProperties: false,
		};
		// Without propertyNames: rejected.
		assert.strictEqual(validate2020(base), false);
		// With propertyNames: accepted.
		const withPN = {
			...base,
			propertyNames: { type: "string", pattern: "^[a-z]+$", maxLength: 20 },
		};
		assert.strictEqual(
			validate2020(withPN),
			true,
			`expected ACCEPT, got errors: ${JSON.stringify(validate2020.errors, null, 2)}`,
		);
	});
});
