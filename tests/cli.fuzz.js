import test from "node:test";
import fc from "fast-check";
import { analyze, crawlSchema, isPrivateIP, MAX_DEPTH } from "../cli.js";

// Recursively-generated, schema-shaped objects: keys are drawn from real JSON
// Schema keywords and leaves include adversarial strings (prototype-pollution
// vectors, catastrophic-backtracking regexes, remote $ref URLs). This is the
// untrusted attack surface the analysis engine ingests, so the properties below
// assert the engine's output CONTRACT rather than any specific finding.

const SCHEMA_KEYWORDS = [
	"type",
	"properties",
	"patternProperties",
	"required",
	"$ref",
	"$dynamicRef",
	"pattern",
	"minimum",
	"maximum",
	"minLength",
	"maxLength",
	"items",
	"const",
	"enum",
	"default",
	"$defs",
	"additionalProperties",
	"propertyNames",
	"allOf",
	"anyOf",
	"minItems",
	"maxItems",
	"dependentRequired",
];

const TYPE_NAMES = [
	"string",
	"integer",
	"number",
	"array",
	"object",
	"boolean",
	"null",
];

const ADVERSARIAL_STRINGS = [
	"__proto__",
	"constructor",
	"prototype",
	".*",
	"(a+)+$",
	"^(a|a)*$",
	"^([a-z]+)*$",
	"https://x.example.com/s.json",
	"http://127.0.0.1/s.json",
	"#/$defs/x",
	"",
];

const leafValue = fc.oneof(
	fc.string({ maxLength: 12 }),
	fc.integer({ min: -1000, max: 1000 }),
	fc.boolean(),
	fc.constant(null),
	fc.constantFrom(...TYPE_NAMES),
	fc.constantFrom(...ADVERSARIAL_STRINGS),
);

// A bounded, recursive arbitrary producing schema-shaped objects. Object keys
// are biased toward real keywords; values are nested schema-shaped objects,
// arrays of them, or leaf values.
const schemaArb = fc.letrec((tie) => ({
	node: fc.oneof(
		{ maxDepth: 5, withCrossShrink: true },
		leafValue,
		fc.array(tie("node"), { maxLength: 4 }),
		fc.dictionary(
			fc.oneof(
				fc.constantFrom(...SCHEMA_KEYWORDS),
				fc.constantFrom(...ADVERSARIAL_STRINGS),
				fc.string({ maxLength: 8 }),
			),
			tie("node"),
			{ maxKeys: 6 },
		),
	),
})).node;

// Documented input-validation errors analyze() is allowed to throw. Any OTHER
// throw is an engine bug and fails the property.
const isDocumentedThrow = (err) =>
	err instanceof TypeError || err instanceof RangeError;

const assertErrorContract = (errors) => {
	for (const err of errors) {
		if (typeof err.instancePath !== "string") {
			throw new Error(
				`error.instancePath not a string: ${JSON.stringify(err)}`,
			);
		}
		if (typeof err.schemaPath !== "string") {
			throw new Error(`error.schemaPath not a string: ${JSON.stringify(err)}`);
		}
		if (typeof err.keyword !== "string") {
			throw new Error(`error.keyword not a string: ${JSON.stringify(err)}`);
		}
	}
};

test("fuzz: analyze() never throws (except documented) and resolves to an Array", async () => {
	await fc.assert(
		fc.asyncProperty(schemaArb, async (schema) => {
			let errors;
			try {
				// offline:true => NO network/DNS is ever performed on untrusted input.
				errors = await analyze(schema, {
					offline: true,
					analysisTimeoutMs: 2000,
				});
			} catch (err) {
				if (isDocumentedThrow(err)) return;
				throw new Error(
					`analyze threw undocumented ${err?.constructor?.name}: ${err?.message} for ${JSON.stringify(schema)}`,
				);
			}
			if (!Array.isArray(errors)) {
				throw new Error(
					`analyze did not resolve to an Array for ${JSON.stringify(schema)}`,
				);
			}
			assertErrorContract(errors);
		}),
		{ numRuns: 1000 },
	);
});

test("fuzz: crawlSchema() never throws and honours its result contract", () => {
	fc.assert(
		fc.property(schemaArb, (schema) => {
			let result;
			try {
				result = crawlSchema(schema);
			} catch (err) {
				throw new Error(
					`crawlSchema threw ${err?.constructor?.name}: ${err?.message} for ${JSON.stringify(schema)}`,
				);
			}
			if (!result || typeof result !== "object") {
				throw new Error(
					`crawlSchema did not return an object for ${JSON.stringify(schema)}`,
				);
			}
			if (!Array.isArray(result.errors)) {
				throw new Error("crawlSchema().errors is not an Array");
			}
			if (!Array.isArray(result.refs)) {
				throw new Error("crawlSchema().refs is not an Array");
			}
			if (typeof result.depth !== "number") {
				throw new Error("crawlSchema().depth is not a number");
			}
			// The crawler bails the moment depth would exceed MAX_DEPTH, so the
			// reported depth can reach MAX_DEPTH+1 (the over-cap level that triggered
			// the bail) but never more.
			if (result.depth > MAX_DEPTH + 1) {
				throw new Error(
					`crawlSchema().depth ${result.depth} exceeds MAX_DEPTH+1 (${MAX_DEPTH + 1})`,
				);
			}
			assertErrorContract(result.errors);
		}),
		{ numRuns: 1000 },
	);
});

test("fuzz: isPrivateIP() never throws and always returns a boolean", () => {
	const ipv4Arb = fc
		.tuple(
			fc.integer({ min: 0, max: 300 }),
			fc.integer({ min: 0, max: 300 }),
			fc.integer({ min: 0, max: 300 }),
			fc.integer({ min: 0, max: 300 }),
		)
		.map((octets) => octets.join("."));

	const hexGroup = fc
		.integer({ min: 0, max: 0x1ffff })
		.map((n) => n.toString(16));
	const ipv6Arb = fc
		.array(hexGroup, { minLength: 0, maxLength: 9 })
		.map((groups) => groups.join(":"));

	fc.assert(
		fc.property(fc.oneof(ipv4Arb, ipv6Arb), (ip) => {
			let out;
			try {
				out = isPrivateIP(ip);
			} catch (err) {
				throw new Error(
					`isPrivateIP threw ${err?.constructor?.name}: ${err?.message} for "${ip}"`,
				);
			}
			if (typeof out !== "boolean") {
				throw new Error(`isPrivateIP("${ip}") returned non-boolean: ${out}`);
			}
		}),
		{ numRuns: 1000 },
	);
});
