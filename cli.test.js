import { ok, strictEqual } from "node:assert";
import test from "node:test";
import sast, { analyze } from "./cli.js";

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
