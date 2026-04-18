import assert from "node:assert";
import { describe } from "node:test";
import Ajv from "ajv/dist/2020.js";
import jsonSchemaTest from "json-schema-test-esm";
import schema201909 from "../2019-09.json" with { type: "json" };
import schema from "../2020-12.json" with { type: "json" };
import schemaDraft04 from "../draft-04.json" with { type: "json" };
import schemaDraft06 from "../draft-06.json" with { type: "json" };
import schemaDraft07 from "../draft-07.json" with { type: "json" };
import exampleSchema from "./example.json" with { type: "json" };

const ajv = new Ajv({
	schemas: [
		schema,
		schema201909,
		schemaDraft07,
		schemaDraft06,
		schemaDraft04,
		exampleSchema,
	],
	strictTypes: false,
});

jsonSchemaTest(ajv, {
	description: "sast-json-schema",
	suites: {
		SAST: "./fixtures/*.json",
	},
	cwd: import.meta.dirname,
	describe,
	assert,
});
