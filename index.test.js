import assert from "node:assert";
import { describe } from "node:test";
import Ajv from "ajv/dist/2020.js";
import jsonSchemaTest from "json-schema-test-esm";
import exampleSchema from "./example.json" with { type: "json" };
import schema from "./index.json" with { type: "json" };

const ajv = new Ajv({
	schemas: [schema, exampleSchema],
	strictTypes: false,
});

jsonSchemaTest(ajv, {
	description: "sast-json-schema",
	suites: {
		SAST: "./tests/*.json",
	},
	cwd: import.meta.dirname,
	describe,
	assert,
});
