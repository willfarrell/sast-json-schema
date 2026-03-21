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

test("fuzz: completely random objects should not crash validator", () => {
	fc.assert(
		fc.property(fc.anything(), (data) => {
			validate(data);
		}),
		{ numRuns: 1000 },
	);
});
