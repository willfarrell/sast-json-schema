import assert from "node:assert";
import { describe, it } from "node:test";
import Ajv from "ajv/dist/2020.js";
import schema201909 from "./2019-09.json" with { type: "json" };
import schema202012 from "./2020-12.json" with { type: "json" };
import schemaDraft04 from "./draft-04.json" with { type: "json" };
import schemaDraft06 from "./draft-06.json" with { type: "json" };
import schemaDraft07 from "./draft-07.json" with { type: "json" };

const builtSchemas = [
	["2020-12", schema202012],
	["2019-09", schema201909],
	["draft-07", schemaDraft07],
	["draft-06", schemaDraft06],
	["draft-04", schemaDraft04],
];

describe("built meta-schemas validate against official JSON Schema 2020-12", () => {
	const ajv = new Ajv({ strictTypes: true });
	for (const [name, schema] of builtSchemas) {
		it(`${name} is a valid 2020-12 schema`, () => {
			const valid = ajv.validateSchema(schema);
			assert.strictEqual(
				valid,
				true,
				`${name}.json invalid under official 2020-12 meta-schema: ${JSON.stringify(ajv.errors, null, 2)}`,
			);
		});
	}
});

describe("built meta-schemas compile without error", () => {
	for (const [name, schema] of builtSchemas) {
		it(`${name} compiles`, () => {
			const ajv = new Ajv({ strictTypes: false });
			assert.doesNotThrow(() => ajv.compile(schema));
		});
	}
});
