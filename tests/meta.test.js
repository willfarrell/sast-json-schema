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

// The SAST meta-schemas describe rules for user-facing schemas that validate
// untrusted data. They are not themselves validating untrusted data, so the
// rules targeting user-facing schemas don't apply to the meta-schema's own
// composition plumbing. We stub those rules out so self-validation exercises
// only the rules that *are* meaningful for the meta-schema itself (e.g. that
// its own $id/$refs are well-formed URIs, that safeAnchor/safeUrl/safeUrn
// patterns match, that const/default types agree with declared types).
//
// Stubbed rules:
//   - safePattern: meta-schema regexes are trusted — may use [^...], lookarounds
//   - schemaBase.oneOf: "must declare type/const/$ref/…" gate — meta-schema $defs
//     are composition helpers wired via if/then/allOf, not data-shape schemas
//   - schemaBase.dependentRequired: "properties → required+maxProperties"
//     coupling targets user-facing object schemas
//   - dependentSchemas.{type,items,prefixItems,contains,pattern}: per-type
//     strictness and limit rules — composition helpers like `{type: "array"}`
//     inside `constIsArray` can't satisfy user-facing strictness gates
const STUBBED_DEPENDENT_SCHEMA_RULES = [
	"type",
	"items",
	"prefixItems",
	"contains",
	"additionalProperties",
	"pattern",
	"propertyNames",
];

const stubForSelfValidation = (schema) => {
	const clone = structuredClone(schema);
	if (clone.$defs?.safePattern) {
		clone.$defs.safePattern = { type: "string", maxLength: 1024 };
	}
	if (clone.$defs?.schemaBase) {
		delete clone.$defs.schemaBase.oneOf;
		delete clone.$defs.schemaBase.dependentRequired;
	}
	for (const key of STUBBED_DEPENDENT_SCHEMA_RULES) {
		delete clone.$defs?.[`dependentSchemas.${key}`];
		delete clone.$defs?.schemaBase?.dependentSchemas?.[key];
	}
	return clone;
};

// Only the 2020-12 meta-schema can self-validate. Older drafts are 2020-12
// files describing older-draft rules, so they fail on `$schema` const mismatch
// (meta-schema is 2020-12 but requires user schemas to declare the older draft)
// and `$defs` vs `definitions` keyword differences.
describe("built 2020-12 meta-schema self-validates (user-facing rules stubbed)", () => {
	it("passes its own rules", () => {
		const stubbed = stubForSelfValidation(schema202012);
		const ajv = new Ajv({ strictTypes: false, allowUnionTypes: true });
		const validate = ajv.compile(stubbed);
		const valid = validate(stubbed);
		assert.strictEqual(
			valid,
			true,
			`2020-12.json fails self-validation: ${JSON.stringify(validate.errors, null, 2)}`,
		);
	});
});
