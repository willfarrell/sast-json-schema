import test from "node:test";
import Ajv from "ajv/dist/2020.js";
import { Bench } from "tinybench";
import schema from "./index.json" with { type: "json" };

test("perf: schema validation benchmarks", async () => {
	const ajv = new Ajv({ strictTypes: false });
	const validate = ajv.compile(schema);

	const suite = new Bench({ name: "sast-json-schema" });

	const secureSchema = {
		type: "object",
		properties: {
			name: { type: "string", format: "email", maxLength: 100 },
		},
		required: ["name"],
		unevaluatedProperties: false,
	};

	const insecureSchema = {
		type: "object",
		properties: {
			name: { type: "string" },
			items: { type: "array", items: { type: "string" } },
		},
	};

	const complexSchema = {
		type: "object",
		properties: {
			name: { type: "string", maxLength: 100, pattern: "^[a-z]+$" },
			age: { type: "integer", minimum: 0, maximum: 150 },
			tags: {
				type: "array",
				items: { type: "string", maxLength: 50 },
				maxItems: 10,
				uniqueItems: true,
				unevaluatedItems: false,
			},
		},
		required: ["name"],
		unevaluatedProperties: false,
	};

	suite
		.add("validate secure schema", () => {
			validate(secureSchema);
		})
		.add("validate insecure schema", () => {
			validate(insecureSchema);
		})
		.add("validate complex schema", () => {
			validate(complexSchema);
		})
		.add("compile + validate", () => {
			const v = ajv.compile(schema);
			v(secureSchema);
			ajv.removeSchema();
		});

	await suite.run();
	console.table(suite.table());
});
