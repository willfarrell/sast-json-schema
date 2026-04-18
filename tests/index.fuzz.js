import test from "node:test";
import Ajv from "ajv/dist/2020.js";
import fc from "fast-check";
import schema201909 from "../2019-09.json" with { type: "json" };
import schema202012 from "../2020-12.json" with { type: "json" };
import schemaDraft04 from "../draft-04.json" with { type: "json" };
import schemaDraft06 from "../draft-06.json" with { type: "json" };
import schemaDraft07 from "../draft-07.json" with { type: "json" };

const drafts = [
	["2020-12", schema202012],
	["2019-09", schema201909],
	["draft-07", schemaDraft07],
	["draft-06", schemaDraft06],
	["draft-04", schemaDraft04],
];

const validators = drafts.map(([name, schema]) => {
	const ajv = new Ajv({ strictTypes: false });
	return [name, ajv.compile(schema)];
});

test("fuzz: SAST-accepted schemas compile under strictTypes:true", () => {
	const strictAjv = new Ajv({ strictTypes: true, strictSchema: false });
	const [, sastValidate] = validators[0];
	fc.assert(
		fc.property(
			fc.record({
				$schema: fc.constant("https://json-schema.org/draft/2020-12/schema"),
				$id: fc.constant("urn:fuzz:test"),
				type: fc.constantFrom("string", "integer", "boolean"),
				maxLength: fc.option(fc.nat({ max: 100 })),
				minimum: fc.option(fc.integer({ min: -100, max: 100 })),
				maximum: fc.option(fc.integer({ min: -100, max: 100 })),
				enum: fc.option(
					fc.array(fc.oneof(fc.string({ maxLength: 10 }), fc.integer()), {
						minLength: 1,
						maxLength: 5,
					}),
				),
			}),
			(candidate) => {
				if (!sastValidate(candidate)) return;
				try {
					strictAjv.compile(candidate);
				} catch (err) {
					if (err?.message?.startsWith("strict mode")) throw err;
				}
			},
		),
		{ numRuns: 1000 },
	);
});

const runAcrossDrafts = (title, arbitrary, body, numRuns = 1000) => {
	for (const [name, validate] of validators) {
		test(`fuzz[${name}]: ${title}`, () => {
			fc.assert(
				fc.property(arbitrary, (input) => body(validate, input)),
				{ numRuns },
			);
		});
	}
};

test("fuzz: schemas valid across drafts remain valid regardless of $schema header", () => {
	const draftHeaders = {
		"2020-12": "https://json-schema.org/draft/2020-12/schema",
		"2019-09": "https://json-schema.org/draft/2019-09/schema",
		"draft-07": "http://json-schema.org/draft-07/schema#",
		"draft-06": "http://json-schema.org/draft-06/schema#",
	};
	fc.assert(
		fc.property(
			fc.record({
				type: fc.constantFrom("string", "integer"),
				maxLength: fc.option(fc.nat({ max: 100 })),
				minimum: fc.option(fc.integer({ min: -100, max: 100 })),
				maximum: fc.option(fc.integer({ min: -100, max: 100 })),
				pattern: fc.option(
					fc.constantFrom("^[a-z]+$", "^[0-9]+$", "^[a-zA-Z0-9]+$"),
				),
			}),
			(core) => {
				const results = {};
				for (const [name, validate] of validators) {
					if (name === "draft-04") continue;
					const candidate = {
						...core,
						$schema: draftHeaders[name],
						$id: "urn:fuzz:cross",
					};
					results[name] = validate(candidate);
				}
				const values = Object.values(results);
				if (values.some((v) => v) && !values.every((v) => v)) {
					throw new Error(
						`draft-inconsistent acceptance: ${JSON.stringify(results)} for ${JSON.stringify(core)}`,
					);
				}
			},
		),
		{ numRuns: 1000 },
	);
});

runAcrossDrafts(
	"random JSON schemas should not throw",
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
	(validate, jsonSchema) => {
		validate(jsonSchema);
	},
);

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

runAcrossDrafts(
	"nested composition schemas should not throw",
	fc
		.record({
			allOf: fc.option(fc.array(leafSchema, { minLength: 1, maxLength: 3 })),
			anyOf: fc.option(fc.array(leafSchema, { minLength: 1, maxLength: 3 })),
			oneOf: fc.option(fc.array(leafSchema, { minLength: 1, maxLength: 3 })),
			not: fc.option(leafSchema),
		})
		.map((s) => JSON.parse(JSON.stringify(s))),
	(validate, jsonSchema) => {
		validate(jsonSchema);
	},
);

runAcrossDrafts(
	"boundary values near MAX_SAFE_INTEGER should not throw",
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
	(validate, jsonSchema) => {
		validate(jsonSchema);
	},
);

runAcrossDrafts(
	"completely random objects should not crash validator",
	fc.anything(),
	(validate, data) => {
		validate(data);
	},
);

runAcrossDrafts(
	"$ref values should not throw",
	fc.oneof(
		fc
			.string({ minLength: 1, maxLength: 50 })
			.map((s) => `#/definitions/${s.replace(/[^a-zA-Z0-9_$/.+-]/g, "x")}`),
		fc
			.string({ minLength: 1, maxLength: 30 })
			.map((s) => `https://example.com/${s.replace(/[^a-zA-Z0-9_/-]/g, "x")}`),
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
		fc.string({ minLength: 0, maxLength: 100 }),
	),
	(validate, refValue) => {
		validate({ $ref: refValue });
	},
);

runAcrossDrafts(
	"pattern values should not throw",
	fc.oneof(
		fc.constantFrom(
			"^[a-z]+$",
			"^[0-9]+$",
			"^[\\p{L}]+$",
			"^[a-zA-Z0-9_-]+$",
			"^[\\p{L}\\p{N}]+$",
		),
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
		fc.constantFrom("^((?:a|b){1,3}){1,5}$", "^((a)(b)(c))$", "^(a(b(c)))$"),
		fc.string({ minLength: 0, maxLength: 100 }),
	),
	(validate, patternValue) => {
		validate({
			type: "string",
			pattern: patternValue,
			maxLength: 100,
		});
	},
);

runAcrossDrafts(
	"format values should not throw",
	fc.oneof(
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
		fc.string({ minLength: 0, maxLength: 50 }),
	),
	(validate, formatValue) => {
		validate({
			type: "string",
			format: formatValue,
			maxLength: 100,
		});
	},
);

runAcrossDrafts(
	"additionalProperties values should not throw",
	fc.oneof(
		fc.constant(false),
		fc.record({
			type: fc.constantFrom("string", "integer", "number", "boolean"),
		}),
		fc.constant(true),
		fc.constant(null),
		fc.string({ minLength: 0, maxLength: 20 }),
		fc.integer({ min: -100, max: 100 }),
		fc.anything(),
	),
	(validate, additionalPropsValue) => {
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
);
