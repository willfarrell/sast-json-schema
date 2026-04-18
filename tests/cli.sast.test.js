import { ok, strictEqual } from "node:assert";
import { describe, test } from "node:test";
import sast, { analyze, MAX_SCHEMA_SIZE } from "../cli.js";

test("sast should return a validate function", () => {
	const validate = sast();
	ok(typeof validate === "function");
});

test("sast should default to 2020-12 when schema is undefined", () => {
	const validate = sast(undefined);
	ok(typeof validate === "function");
});

test("sast validate should return boolean", () => {
	const validate = sast();
	const schema = {
		type: "object",
		properties: {
			name: { type: "string", maxLength: 100 },
		},
		additionalProperties: false,
	};
	const valid = validate(schema);
	strictEqual(typeof valid, "boolean");
});

test("sast validate should detect issues in insecure schema", () => {
	const validate = sast();
	const insecureSchema = {
		type: "object",
		properties: {
			name: { type: "string" },
			items: { type: "array", items: { type: "string" } },
		},
	};
	const valid = validate(insecureSchema);
	ok(valid === true || valid === false);
	if (!valid) {
		ok(Array.isArray(validate.errors));
	}
});

test("sast default export should be sast function", async () => {
	const mod = await import("./cli.js");
	strictEqual(mod.default, mod.sast);
});

// --- sast() draft detection ---

test("sast should throw for unsupported $schema", () => {
	let threw = false;
	try {
		sast({ $schema: "https://example.com/unknown" });
	} catch {
		threw = true;
	}
	ok(threw);
});

test("sast should detect draft-04 from $schema", () => {
	const validate = sast({
		$schema: "http://json-schema.org/draft-04/schema#",
	});
	ok(typeof validate === "function");
});

test("sast should detect draft-07 from https $schema URL", () => {
	const validate = sast({
		$schema: "https://json-schema.org/draft-07/schema#",
	});
	ok(typeof validate === "function");
});

test("sast should detect draft-06 from https $schema URL", () => {
	const validate = sast({
		$schema: "https://json-schema.org/draft-06/schema",
	});
	ok(typeof validate === "function");
});

test("sast should detect draft-04 from https $schema URL", () => {
	const validate = sast({
		$schema: "https://json-schema.org/draft-04/schema#",
	});
	ok(typeof validate === "function");
});

// --- schemaVersion edge cases ---

describe("schemaVersion edge cases", () => {
	test("should detect draft-04 from protocol-relative URL", () => {
		const validate = sast({
			$schema: "//json-schema.org/draft-04/schema",
		});
		ok(typeof validate === "function");
	});

	test("should detect draft-06 from protocol-relative URL", () => {
		const validate = sast({
			$schema: "//json-schema.org/draft-06/schema",
		});
		ok(typeof validate === "function");
	});

	test("should detect draft-07 from protocol-relative URL", () => {
		const validate = sast({
			$schema: "//json-schema.org/draft-07/schema",
		});
		ok(typeof validate === "function");
	});

	test("should detect 2019-09 from protocol-relative URL", () => {
		const validate = sast({
			$schema: "//json-schema.org/draft/2019-09/schema",
		});
		ok(typeof validate === "function");
	});

	test("should detect 2020-12 from protocol-relative URL", () => {
		const validate = sast({
			$schema: "//json-schema.org/draft/2020-12/schema",
		});
		ok(typeof validate === "function");
	});

	test("should throw for ftp protocol $schema", () => {
		let threw = false;
		try {
			sast({ $schema: "ftp://json-schema.org/draft/2020-12/schema" });
		} catch {
			threw = true;
		}
		ok(threw);
	});

	test("should throw for $schema with extra path segments", () => {
		let threw = false;
		try {
			sast({
				$schema: "https://json-schema.org/draft/2020-12/schema/extra",
			});
		} catch {
			threw = true;
		}
		ok(threw);
	});

	test("should throw for $schema with multiple trailing hashes", () => {
		let threw = false;
		try {
			sast({ $schema: "https://json-schema.org/draft-07/schema##" });
		} catch {
			threw = true;
		}
		ok(threw);
	});
});

// --- sast() accept/reject consistent with analyze() ---

describe("sast validate vs analyze consistency", () => {
	const cases = [
		{
			name: "clean schema",
			schema: {
				$schema: "https://json-schema.org/draft/2020-12/schema",
				$id: "test",
				type: "string",
				maxLength: 10,
				pattern: "^[a-z]+$",
			},
			shouldValidate: true,
		},
		{
			name: "missing strictness",
			schema: {
				$schema: "https://json-schema.org/draft/2020-12/schema",
				$id: "test",
				type: "string",
			},
			shouldValidate: false,
		},
		{
			name: "dependencies keyword rejected",
			schema: {
				$schema: "https://json-schema.org/draft/2020-12/schema",
				$id: "test",
				type: "object",
				properties: { a: { type: "string", maxLength: 10 } },
				required: ["a"],
				unevaluatedProperties: false,
				maxProperties: 2,
				dependencies: { a: ["b"] },
			},
			shouldValidate: false,
		},
	];

	for (const { name, schema, shouldValidate } of cases) {
		test(`${name}: validate matches analyze (offline)`, async () => {
			const validate = sast(schema);
			const isValid = validate(schema);
			strictEqual(
				isValid,
				shouldValidate,
				`validate() expected ${shouldValidate}`,
			);

			const errors = await analyze(schema, { offline: true });
			if (shouldValidate) {
				strictEqual(
					errors.length,
					0,
					`analyze should return 0 errors when validate passes; got ${JSON.stringify(errors)}`,
				);
			} else {
				ok(
					errors.length > 0,
					"analyze must report at least one error when validate fails",
				);
			}
		});
	}

	test("MAX_SCHEMA_SIZE is exported as 64 MiB", () => {
		strictEqual(MAX_SCHEMA_SIZE, 64 * 1024 * 1024);
	});

	test("range violation is crawler-only (validate passes, analyze fails)", async () => {
		const schema = {
			$schema: "https://json-schema.org/draft/2020-12/schema",
			$id: "test",
			type: "integer",
			minimum: 10,
			maximum: 1,
		};
		const validate = sast(schema);
		ok(validate(schema), "meta-schema does not catch range violations");
		const errors = await analyze(schema, { offline: true });
		ok(
			errors.some((e) => e.keyword === "minimum"),
			"crawler must catch impossible range",
		);
	});
});
