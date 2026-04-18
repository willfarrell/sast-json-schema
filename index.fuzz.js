import test from "node:test";
import Ajv from "ajv/dist/2020.js";
import fc from "fast-check";
import schema from "./index.json" with { type: "json" };

const ajv = new Ajv({ strictTypes: false });
const validate = ajv.compile(schema);

test("fuzz: random JSON schemas should not throw", () => {
	fc.assert(
		fc.property(
			fc.record({
				type: fc.constantFrom(
					"string",
					"integer",
					"number",
					"array",
					"object",
					"boolean",
					"null",
				),
				properties: fc.option(
					fc.dictionary(
						fc.string({ minLength: 1, maxLength: 10 }),
						fc.record({
							type: fc.constantFrom("string", "integer", "number", "boolean"),
						}),
					),
				),
				required: fc.option(
					fc.array(fc.string({ minLength: 1, maxLength: 10 }), {
						maxLength: 3,
					}),
				),
				maxLength: fc.option(fc.nat({ max: 1000 })),
				minLength: fc.option(fc.nat({ max: 1000 })),
				maximum: fc.option(fc.integer({ min: -1000, max: 1000 })),
				minimum: fc.option(fc.integer({ min: -1000, max: 1000 })),
			}),
			(jsonSchema) => {
				// Should not throw, just validate
				validate(jsonSchema);
			},
		),
		{ numRuns: 1000 },
	);
});

test("fuzz: nested composition schemas should not throw", () => {
	const leafSchema = fc.record({
		type: fc.constantFrom("string", "integer", "boolean"),
		enum: fc.option(
			fc.array(fc.oneof(fc.string(), fc.integer(), fc.boolean()), {
				minLength: 1,
				maxLength: 5,
			}),
		),
		minimum: fc.option(fc.integer({ min: -1000, max: 1000 })),
		maximum: fc.option(fc.integer({ min: -1000, max: 1000 })),
		maxLength: fc.option(fc.nat({ max: 1000 })),
		pattern: fc.option(fc.constantFrom("^[a-z]+$", "^[0-9]+$", "^[\\p{L}]+$")),
		format: fc.option(fc.constantFrom("email", "uuid", "date-time", "uri")),
	});

	const composedSchema = fc.record({
		allOf: fc.option(fc.array(leafSchema, { minLength: 1, maxLength: 3 })),
		anyOf: fc.option(fc.array(leafSchema, { minLength: 1, maxLength: 3 })),
		oneOf: fc.option(fc.array(leafSchema, { minLength: 1, maxLength: 3 })),
		not: fc.option(leafSchema),
	});

	fc.assert(
		fc.property(
			composedSchema.map((s) => JSON.parse(JSON.stringify(s))),
			(jsonSchema) => {
				validate(jsonSchema);
			},
		),
		{ numRuns: 1000 },
	);
});

test("fuzz: boundary values near MAX_SAFE_INTEGER should not throw", () => {
	fc.assert(
		fc.property(
			fc.record({
				type: fc.constantFrom("integer", "number"),
				minimum: fc.option(
					fc.oneof(
						fc.integer({ min: -9007199254740991, max: -9007199254740990 }),
						fc.integer({ min: 9007199254740990, max: 9007199254740991 }),
						fc.integer({ min: -1000, max: 1000 }),
					),
				),
				maximum: fc.option(
					fc.oneof(
						fc.integer({ min: -9007199254740991, max: -9007199254740990 }),
						fc.integer({ min: 9007199254740990, max: 9007199254740991 }),
						fc.integer({ min: -1000, max: 1000 }),
					),
				),
				multipleOf: fc.option(fc.nat({ min: 1, max: 100 })),
			}),
			(jsonSchema) => {
				validate(jsonSchema);
			},
		),
		{ numRuns: 1000 },
	);
});

test("fuzz: completely random objects should not crash validator", () => {
	fc.assert(
		fc.property(fc.anything(), (data) => {
			validate(data);
		}),
		{ numRuns: 1000 },
	);
});

test("fuzz: $ref values should not throw", () => {
	fc.assert(
		fc.property(
			fc.oneof(
				// Valid local refs
				fc
					.string({ minLength: 1, maxLength: 50 })
					.map((s) => `#/definitions/${s.replace(/[^a-zA-Z0-9_$/.+-]/g, "x")}`),
				// Valid HTTPS URLs
				fc
					.string({ minLength: 1, maxLength: 30 })
					.map(
						(s) => `https://example.com/${s.replace(/[^a-zA-Z0-9_/-]/g, "x")}`,
					),
				// Invalid values: http, file, bare strings
				fc.constantFrom(
					"http://example.com/schema",
					"file:///etc/passwd",
					"http://",
					"ftp://example.com",
					"//example.com/schema",
					"",
					"not-a-ref",
					"javascript:alert(1)",
					"data:text/html,<script>",
					"https://127.0.0.1/schema",
					"https://localhost/schema",
					"#",
					"#/",
				),
				// Completely random strings
				fc.string({ minLength: 0, maxLength: 100 }),
			),
			(refValue) => {
				validate({ $ref: refValue });
			},
		),
		{ numRuns: 1000 },
	);
});

test("fuzz: pattern values should not throw", () => {
	fc.assert(
		fc.property(
			fc.oneof(
				// Safe anchored patterns
				fc.constantFrom(
					"^[a-z]+$",
					"^[0-9]+$",
					"^[\\p{L}]+$",
					"^[a-zA-Z0-9_-]+$",
					"^[\\p{L}\\p{N}]+$",
				),
				// Patterns with special chars
				fc.constantFrom(
					"^(a|b|c)+$",
					"^(?:foo|bar)$",
					"^[a-z]{1,10}$",
					".+",
					"(a+)+",
					"^[^a-z]+$",
					"^a*b*$",
					"(?=abc)",
					"\\S+",
					"\\1",
				),
				// Patterns with nested groups
				fc.constantFrom(
					"^((?:a|b){1,3}){1,5}$",
					"^((a)(b)(c))$",
					"^(a(b(c)))$",
				),
				// Random strings as patterns
				fc.string({ minLength: 0, maxLength: 100 }),
			),
			(patternValue) => {
				validate({
					type: "string",
					pattern: patternValue,
					maxLength: 100,
				});
			},
		),
		{ numRuns: 1000 },
	);
});

test("fuzz: format values should not throw", () => {
	fc.assert(
		fc.property(
			fc.oneof(
				// Valid formats from the allowlist
				fc.constantFrom(
					"date-time",
					"date",
					"time",
					"duration",
					"email",
					"idn-email",
					"hostname",
					"idn-hostname",
					"ipv4",
					"ipv6",
					"uri",
					"uri-reference",
					"uri-template",
					"iri",
					"iri-reference",
					"uuid",
					"json-pointer",
					"relative-json-pointer",
					"regex",
				),
				// Random strings as format values
				fc.string({ minLength: 0, maxLength: 50 }),
			),
			(formatValue) => {
				validate({
					type: "string",
					format: formatValue,
					maxLength: 100,
				});
			},
		),
		{ numRuns: 1000 },
	);
});

test("fuzz: additionalProperties values should not throw", () => {
	fc.assert(
		fc.property(
			fc.oneof(
				// false (common secure pattern)
				fc.constant(false),
				// Object with type (allowed by schema)
				fc.record({
					type: fc.constantFrom("string", "integer", "number", "boolean"),
				}),
				// Random values
				fc.constant(true),
				fc.constant(null),
				fc.string({ minLength: 0, maxLength: 20 }),
				fc.integer({ min: -100, max: 100 }),
				fc.anything(),
			),
			(additionalPropsValue) => {
				validate({
					type: "object",
					properties: {
						name: { type: "string", maxLength: 100, pattern: "^[a-z]+$" },
					},
					required: ["name"],
					unevaluatedProperties: false,
					maxProperties: 10,
					additionalProperties: additionalPropsValue,
				});
			},
		),
		{ numRuns: 1000 },
	);
});
