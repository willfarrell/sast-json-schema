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
