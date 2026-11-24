import { ok } from "node:assert";
import test from "node:test";
import Ajv from "ajv";
import Ajv2020 from "ajv/dist/2020.js";
import fc from "fast-check";
import { analyze, crawlSchema, isPrivateIP, MAX_DEPTH } from "../cli.js";

// Recursively-generated, schema-shaped objects: keys are drawn from real JSON
// Schema keywords and leaves include adversarial strings (prototype-pollution
// vectors, catastrophic-backtracking regexes, remote $ref URLs). This is the
// untrusted attack surface the analysis engine ingests, so the properties below
// assert the engine's output CONTRACT rather than any specific finding.

const SCHEMA_KEYWORDS = [
	"type",
	"properties",
	"patternProperties",
	"required",
	"$ref",
	"$dynamicRef",
	"pattern",
	"minimum",
	"maximum",
	"minLength",
	"maxLength",
	"items",
	"const",
	"enum",
	"default",
	"$defs",
	"additionalProperties",
	"propertyNames",
	"allOf",
	"anyOf",
	"minItems",
	"maxItems",
	"dependentRequired",
];

const TYPE_NAMES = [
	"string",
	"integer",
	"number",
	"array",
	"object",
	"boolean",
	"null",
];

const ADVERSARIAL_STRINGS = [
	"__proto__",
	"constructor",
	"prototype",
	".*",
	"(a+)+$",
	"^(a|a)*$",
	"^([a-z]+)*$",
	"https://x.example.com/s.json",
	"http://127.0.0.1/s.json",
	"#/$defs/x",
	"",
];

const leafValue = fc.oneof(
	fc.string({ maxLength: 12 }),
	fc.integer({ min: -1000, max: 1000 }),
	fc.boolean(),
	fc.constant(null),
	fc.constantFrom(...TYPE_NAMES),
	fc.constantFrom(...ADVERSARIAL_STRINGS),
);

// A bounded, recursive arbitrary producing schema-shaped objects. Object keys
// are biased toward real keywords; values are nested schema-shaped objects,
// arrays of them, or leaf values.
const schemaArb = fc.letrec((tie) => ({
	node: fc.oneof(
		{ maxDepth: 5, withCrossShrink: true },
		leafValue,
		fc.array(tie("node"), { maxLength: 4 }),
		fc.dictionary(
			fc.oneof(
				fc.constantFrom(...SCHEMA_KEYWORDS),
				fc.constantFrom(...ADVERSARIAL_STRINGS),
				fc.string({ maxLength: 8 }),
			),
			tie("node"),
			{ maxKeys: 6 },
		),
	),
})).node;

// Documented input-validation errors analyze() is allowed to throw. Any OTHER
// throw is an engine bug and fails the property.
const isDocumentedThrow = (err) =>
	err instanceof TypeError || err instanceof RangeError;

const assertErrorContract = (errors) => {
	for (const err of errors) {
		if (typeof err.instancePath !== "string") {
			throw new Error(
				`error.instancePath not a string: ${JSON.stringify(err)}`,
			);
		}
		if (typeof err.schemaPath !== "string") {
			throw new Error(`error.schemaPath not a string: ${JSON.stringify(err)}`);
		}
		if (typeof err.keyword !== "string") {
			throw new Error(`error.keyword not a string: ${JSON.stringify(err)}`);
		}
	}
};

test("fuzz: analyze() never throws (except documented) and resolves to an Array", async () => {
	await fc.assert(
		fc.asyncProperty(schemaArb, async (schema) => {
			let errors;
			try {
				// offline:true => NO network/DNS is ever performed on untrusted input.
				errors = await analyze(schema, {
					offline: true,
					analysisTimeoutMs: 2000,
				});
			} catch (err) {
				if (isDocumentedThrow(err)) return;
				throw new Error(
					`analyze threw undocumented ${err?.constructor?.name}: ${err?.message} for ${JSON.stringify(schema)}`,
				);
			}
			if (!Array.isArray(errors)) {
				throw new Error(
					`analyze did not resolve to an Array for ${JSON.stringify(schema)}`,
				);
			}
			assertErrorContract(errors);
		}),
		{ numRuns: 1000 },
	);
});

test("fuzz: crawlSchema() never throws and honours its result contract", () => {
	fc.assert(
		fc.property(schemaArb, (schema) => {
			let result;
			try {
				result = crawlSchema(schema);
			} catch (err) {
				throw new Error(
					`crawlSchema threw ${err?.constructor?.name}: ${err?.message} for ${JSON.stringify(schema)}`,
				);
			}
			if (!result || typeof result !== "object") {
				throw new Error(
					`crawlSchema did not return an object for ${JSON.stringify(schema)}`,
				);
			}
			if (!Array.isArray(result.errors)) {
				throw new Error("crawlSchema().errors is not an Array");
			}
			if (!Array.isArray(result.refs)) {
				throw new Error("crawlSchema().refs is not an Array");
			}
			if (typeof result.depth !== "number") {
				throw new Error("crawlSchema().depth is not a number");
			}
			// The crawler bails the moment depth would exceed MAX_DEPTH, so the
			// reported depth can reach MAX_DEPTH+1 (the over-cap level that triggered
			// the bail) but never more.
			if (result.depth > MAX_DEPTH + 1) {
				throw new Error(
					`crawlSchema().depth ${result.depth} exceeds MAX_DEPTH+1 (${MAX_DEPTH + 1})`,
				);
			}
			assertErrorContract(result.errors);
		}),
		{ numRuns: 1000 },
	);
});

test("fuzz: isPrivateIP() never throws and always returns a boolean", () => {
	const ipv4Arb = fc
		.tuple(
			fc.integer({ min: 0, max: 300 }),
			fc.integer({ min: 0, max: 300 }),
			fc.integer({ min: 0, max: 300 }),
			fc.integer({ min: 0, max: 300 }),
		)
		.map((octets) => octets.join("."));

	const hexGroup = fc
		.integer({ min: 0, max: 0x1ffff })
		.map((n) => n.toString(16));
	const ipv6Arb = fc
		.array(hexGroup, { minLength: 0, maxLength: 9 })
		.map((groups) => groups.join(":"));

	fc.assert(
		fc.property(fc.oneof(ipv4Arb, ipv6Arb), (ip) => {
			let out;
			try {
				out = isPrivateIP(ip);
			} catch (err) {
				throw new Error(
					`isPrivateIP threw ${err?.constructor?.name}: ${err?.message} for "${ip}"`,
				);
			}
			if (typeof out !== "boolean") {
				throw new Error(`isPrivateIP("${ip}") returned non-boolean: ${out}`);
			}
		}),
		{ numRuns: 1000 },
	);
});

// Differential fuzzing against AJV. The crawler may exclude names from a
// propertyNames pattern finding when a sibling `not` rejects them, so the risk
// is a name it stays silent about while a validator still admits it. AJV is the
// oracle: whenever AJV admits a denylisted name, the crawler must report it.

const JS_DENYLIST = ["__proto__", "constructor", "prototype"];

// Present with probability `weight / (weight + 1)`, else undefined (dropped).
const sometimes = (arb, weight = 1) =>
	fc.oneof(
		{ weight: 1, arbitrary: fc.constant(undefined) },
		{ weight, arbitrary: arb },
	);
const definedOnly = (obj) =>
	Object.fromEntries(Object.entries(obj).filter(([, v]) => v !== undefined));
const merge = (...arbs) =>
	fc.tuple(...arbs).map((parts) => Object.assign({}, ...parts));

const nameValue = fc.oneof(
	{ weight: 4, arbitrary: fc.constantFrom(...JS_DENYLIST) },
	{ weight: 1, arbitrary: fc.constantFrom("x", "", 1, null, ["__proto__"]) },
);
const stringType = fc.constantFrom(
	"string",
	["string"],
	["string", "number"],
	["null", "string"],
);
const nonStringType = fc.constantFrom(
	"number",
	"object",
	["number"],
	["integer", "boolean"],
);
const annotations = fc
	.record({
		$comment: sometimes(fc.constant("reviewed")),
		title: sometimes(fc.constant("t")),
		description: sometimes(fc.constant("d")),
	})
	.map(definedOnly);
// The keywords a `not` may hold for its exclusion to count.
const readableCore = fc
	.record({
		type: sometimes(stringType),
		enum: sometimes(fc.array(nameValue, { minLength: 1, maxLength: 4 })),
		const: sometimes(nameValue),
	})
	.map(definedOnly);
// One keyword that narrows what the `not` rejects (or that the crawler cannot
// read), so the names in its enum/const may still be admitted.
const voidingKeyword = fc.oneof(
	fc.record({ type: nonStringType }),
	fc.record({ maxLength: fc.nat(12) }),
	fc.record({ minLength: fc.nat(12) }),
	fc.record({ pattern: fc.constantFrom("^_", "^c", "e$", "^$") }),
	fc.record({ not: readableCore }),
	fc.record({ anyOf: fc.array(readableCore, { minLength: 1, maxLength: 2 }) }),
	fc.record({ allOf: fc.array(readableCore, { minLength: 1, maxLength: 2 }) }),
	fc.record({ "x-vendor": fc.constant(true) }),
);
const notArb = fc.oneof(
	{ weight: 4, arbitrary: merge(readableCore, annotations) },
	{ weight: 4, arbitrary: merge(readableCore, annotations, voidingKeyword) },
	{ weight: 1, arbitrary: annotations },
	{ weight: 1, arbitrary: fc.constantFrom(true, false) },
);
const NAME_PATTERNS = [
	"^[a-z_]+$",
	"^[\\x21-\\x7E]+$",
	"^\\p{L}+$",
	"_",
	"o",
	"^c",
	"e$",
	"^(?:constructor|prototype)$",
	"^x$",
];
const propertyNamesArb = fc
	.record({
		type: sometimes(fc.constant("string")),
		pattern: sometimes(fc.constantFrom(...NAME_PATTERNS), 5),
		enum: fc.oneof(
			{ weight: 4, arbitrary: fc.constant(undefined) },
			{
				weight: 1,
				arbitrary: fc.array(nameValue, { minLength: 1, maxLength: 4 }),
			},
		),
		const: fc.oneof(
			{ weight: 6, arbitrary: fc.constant(undefined) },
			{ weight: 1, arbitrary: nameValue },
		),
		not: sometimes(notArb, 5),
	})
	.map(definedOnly);

// Compiles with AJV, or returns null for a schema AJV refuses; the property
// counts those so a generator drift cannot hollow the test out unnoticed.
const compileOracle = (ajv, schema) => {
	try {
		return ajv.compile(schema);
	} catch {
		return null;
	}
};

const reportedNames = (errors, instancePath) =>
	new Set(
		errors
			.filter(
				(e) =>
					e.schemaPath === "#/dangerous-name" &&
					e.instancePath.startsWith(instancePath),
			)
			.flatMap((e) => e.params.matches ?? [e.params.name]),
	);

test("fuzz: crawlSchema() reports every denylisted name AJV admits through propertyNames", (t) => {
	const ajv = new Ajv2020({ strict: false, logger: false });
	const stats = { runs: 0, refused: 0, admitted: 0, pastNot: 0, excluded: 0 };
	fc.assert(
		fc.property(propertyNamesArb, (propertyNames) => {
			stats.runs++;
			const validate = compileOracle(ajv, propertyNames);
			if (!validate) {
				stats.refused++;
				return;
			}
			const { errors } = crawlSchema({ propertyNames }, undefined, {
				lang: "js",
			});
			// The crawler's fail-closed verdict: nothing it can check, so it
			// reports the whole propertyNames instead of naming anything.
			const failClosed = errors.some(
				(e) =>
					e.instancePath === "/propertyNames" &&
					e.keyword === "propertyNames" &&
					e.params.matches === undefined &&
					e.params.name === undefined,
			);
			const reported = reportedNames(errors, "/propertyNames");
			const re =
				typeof propertyNames.pattern === "string"
					? new RegExp(propertyNames.pattern, "u")
					: null;
			for (const name of JS_DENYLIST) {
				if (validate(name)) {
					stats.admitted++;
					if (propertyNames.not !== undefined) stats.pastNot++;
					if (!failClosed && !reported.has(name)) {
						throw new Error(
							`AJV admits "${name}" but crawlSchema is silent: ${JSON.stringify(propertyNames)}`,
						);
					}
				} else if (re?.test(name) && !reported.has(name)) {
					// The pattern matches but the `not` excluded the name.
					stats.excluded++;
				}
			}
		}),
		{ numRuns: 1000 },
	);
	t.diagnostic(JSON.stringify(stats));
	ok(stats.refused / stats.runs < 0.05, `AJV refused ${JSON.stringify(stats)}`);
	ok(stats.admitted >= 300, `too few admitted names: ${JSON.stringify(stats)}`);
	ok(
		stats.pastNot >= 100,
		`too few names past a not: ${JSON.stringify(stats)}`,
	);
	ok(stats.excluded >= 50, `too few exclusions: ${JSON.stringify(stats)}`);
});

// A propertyNames `not` also clears the patternProperties key finding of the
// same object, except in draft-04, where propertyNames does not exist and a
// validator ignores it. The oracle validates an object whose only key is the
// name, so the key must pass both propertyNames and the patternProperties key.
const KEY_PATTERNS = [
	"^[a-z_]+$",
	"^_",
	"o",
	"e$",
	"^(?:constructor|prototype)$",
	"^x$",
];
const DRAFT_04 = "http://json-schema.org/draft-04/schema#";

test("fuzz: crawlSchema() reports every denylisted name AJV admits through a patternProperties key", (t) => {
	const ajv = new Ajv2020({ strict: false, logger: false });
	const stats = {
		runs: 0,
		refused: 0,
		admitted: 0,
		pastNot: 0,
		draft04: 0,
		excluded: 0,
	};
	fc.assert(
		fc.property(
			propertyNamesArb,
			fc.constantFrom(...KEY_PATTERNS),
			fc.oneof(
				{ weight: 3, arbitrary: fc.constant(false) },
				{ weight: 1, arbitrary: fc.constant(true) },
			),
			(propertyNames, key, isDraft04) => {
				stats.runs++;
				const keyed = {
					type: "object",
					patternProperties: { [key]: {} },
					additionalProperties: false,
				};
				const object = { ...keyed, propertyNames };
				// A draft-04 validator ignores propertyNames, so the oracle does too.
				const validate = compileOracle(ajv, isDraft04 ? keyed : object);
				if (!validate) {
					stats.refused++;
					return;
				}
				const { errors } = crawlSchema(
					isDraft04 ? { $schema: DRAFT_04, ...object } : object,
					undefined,
					{ lang: "js" },
				);
				const reported = reportedNames(
					errors.filter((e) => e.keyword === "patternProperties"),
					"/patternProperties/",
				);
				const keyRe = new RegExp(key, "u");
				for (const name of JS_DENYLIST) {
					// JSON.parse makes "__proto__" an own key, as a request body would.
					const instance = JSON.parse(`{${JSON.stringify(name)}:0}`);
					if (!Object.hasOwn(instance, name)) {
						throw new Error(`"${name}" is not an own key of the instance`);
					}
					if (validate(instance)) {
						stats.admitted++;
						if (isDraft04) stats.draft04++;
						else if (propertyNames.not !== undefined) stats.pastNot++;
						if (!reported.has(name)) {
							throw new Error(
								`AJV admits key "${name}" but crawlSchema does not report patternProperties "${key}"${isDraft04 ? " (draft-04)" : ""}: ${JSON.stringify(object)}`,
							);
						}
					} else if (keyRe.test(name) && !reported.has(name)) {
						// The key matches but the propertyNames `not` excluded the name.
						stats.excluded++;
					}
				}
			},
		),
		{ numRuns: 1000 },
	);
	t.diagnostic(JSON.stringify(stats));
	ok(stats.refused / stats.runs < 0.05, `AJV refused ${JSON.stringify(stats)}`);
	ok(stats.admitted >= 300, `too few admitted keys: ${JSON.stringify(stats)}`);
	ok(stats.pastNot >= 100, `too few keys past a not: ${JSON.stringify(stats)}`);
	ok(stats.draft04 >= 150, `too few draft-04 keys: ${JSON.stringify(stats)}`);
	ok(stats.excluded >= 50, `too few exclusions: ${JSON.stringify(stats)}`);
});

// Metamorphic fuzzing of the name-map role. The entries of a name map
// (properties, $defs, ...) are ordinary schemas whatever their name, so renaming
// one entry from a neutral name to a keyword name must change nothing in the
// crawl but the renamed path segment. lang "js" keeps every keyword name off
// the denylist, so the rename itself adds no name finding. patternProperties is
// left out: its entry names are regexes, so "type" matches "prototype".
const ENTRY_CONTAINERS = [
	"properties",
	"$defs",
	"definitions",
	"dependentSchemas",
	"dependencies",
];
const KEYWORD_ENTRY_NAMES = [
	"properties",
	"patternProperties",
	"$defs",
	"definitions",
	"dependentSchemas",
	"dependentRequired",
	"dependencies",
	"propertyNames",
	"required",
	"enum",
	"pattern",
	"items",
	"not",
	"const",
	"default",
	"examples",
	"type",
	"$id",
	"$ref",
];
const NEUTRAL_ENTRY_NAME = "neutral";
const entryName = fc.constantFrom(...JS_DENYLIST, "a", "b");
// A subschema with a good chance of findings that each depend on its keywords
// being checked: denylisted required entries and property keys, a propertyNames
// with a broad pattern or no key rule, a ReDoS or unanchored pattern, and an
// unsatisfiable length range.
const findingSubschemaArb = fc
	.record({
		type: sometimes(fc.constantFrom("string", "object", ["string", "object"])),
		required: sometimes(fc.array(entryName, { minLength: 1, maxLength: 3 })),
		properties: sometimes(
			fc.dictionary(entryName, fc.constant({}), { minKeys: 1, maxKeys: 2 }),
		),
		propertyNames: sometimes(
			fc.constantFrom(
				{ type: "string", pattern: "^[a-z_]+$" },
				{ type: "string", pattern: "^x$" },
				{ type: "string", format: "email" },
			),
		),
		pattern: sometimes(fc.constantFrom("^(a+)+$", "^a|b$", "^[a-z]+$")),
		minLength: sometimes(fc.constantFrom(2, 8)),
		maxLength: sometimes(fc.constantFrom(1, 64)),
	})
	.map(definedOnly);

// Places `entry` at `name` in a name map, with a sibling entry and optionally
// one level of nesting, and returns the schema and the entry's path.
const placeEntry = (container, name, entry, sibling, nested) => {
	const map = { [name]: entry, other: sibling };
	return nested
		? {
				schema: { properties: { outer: { [container]: map } } },
				path: `/properties/outer/${container}/${name}`,
			}
		: { schema: { [container]: map }, path: `/${container}/${name}` };
};

// Sorted findings with the entry's path segment replaced by a placeholder.
const normalizedFindings = (errors, entryPath) =>
	errors
		.map((e) => {
			const p = e.instancePath;
			const inEntry =
				p === entryPath || p.startsWith(`${entryPath}/`)
					? `<entry>${p.slice(entryPath.length)}`
					: p;
			return JSON.stringify({ ...e, instancePath: inEntry });
		})
		.sort();

test("fuzz: crawlSchema() checks a name-map entry the same whatever its name", (t) => {
	const stats = { runs: 0, withFindings: 0, keywordNames: new Set() };
	fc.assert(
		fc.property(
			fc.constantFrom(...ENTRY_CONTAINERS),
			fc.constantFrom(...KEYWORD_ENTRY_NAMES),
			findingSubschemaArb,
			findingSubschemaArb,
			fc.boolean(),
			(container, keywordName, entry, sibling, nested) => {
				stats.runs++;
				stats.keywordNames.add(keywordName);
				const crawl = (name) => {
					// structuredClone: the two runs must not share nodes, since the
					// crawler's visited set skips an object it has seen.
					const placed = placeEntry(
						container,
						name,
						structuredClone(entry),
						structuredClone(sibling),
						nested,
					);
					const result = crawlSchema(placed.schema, undefined, { lang: "js" });
					return {
						findings: normalizedFindings(result.errors, placed.path),
						depth: result.depth,
					};
				};
				const neutral = crawl(NEUTRAL_ENTRY_NAME);
				const renamed = crawl(keywordName);
				if (neutral.findings.some((f) => f.includes('"<entry>'))) {
					stats.withFindings++;
				}
				const a = JSON.stringify(neutral);
				const b = JSON.stringify(renamed);
				if (a !== b) {
					throw new Error(
						`renaming /${container} entry "${NEUTRAL_ENTRY_NAME}" to "${keywordName}" changed the crawl:\n${a}\n${b}`,
					);
				}
			},
		),
		{ numRuns: 1000 },
	);
	const summary = { ...stats, keywordNames: stats.keywordNames.size };
	t.diagnostic(JSON.stringify(summary));
	ok(
		stats.withFindings >= 600,
		`too few runs with findings in the entry: ${JSON.stringify(summary)}`,
	);
	ok(
		stats.keywordNames.size === KEYWORD_ENTRY_NAMES.length,
		`not every keyword name was tried: ${JSON.stringify(summary)}`,
	);
});

// A propertyNames that is a bare local $ref shares the key rule of the root
// definition it names, so the crawler reports that definition's matches at the
// definition's path and honours the definition's `not`. AJV is the oracle again:
// it validates an object whose only key is the name, through the $ref. draft-07
// has no $defs, so it is covered with #/definitions/<name> only.
const SHARED_KEY_RULE_FORMS = [
	{ draft: "2020-12", container: "$defs" },
	{ draft: "2020-12", container: "definitions" },
	{ draft: "draft-07", container: "definitions" },
];
const DRAFT_07 = "https://json-schema.org/draft-07/schema";
// The draft-07 meta-schema requires unique enum items, so AJV refuses a
// generated enum with a repeat. Dropping repeats keeps what the enum admits.
const uniqueEnum = (schema) =>
	Array.isArray(schema?.enum)
		? {
				...schema,
				enum: schema.enum.filter(
					(v, i, all) =>
						all.findIndex((w) => JSON.stringify(w) === JSON.stringify(v)) === i,
				),
			}
		: schema;
const draft07Definition = (definition) => {
	const unique = uniqueEnum(definition);
	return typeof unique.not === "object" && unique.not !== null
		? { ...unique, not: uniqueEnum(unique.not) }
		: unique;
};

test("fuzz: crawlSchema() reports every denylisted name AJV admits through a propertyNames $ref", (t) => {
	const oracles = {
		"2020-12": new Ajv2020({ strict: false, logger: false }),
		"draft-07": new Ajv({ strict: false, logger: false }),
	};
	const stats = {
		runs: 0,
		refused: 0,
		followed: 0,
		admitted: 0,
		atDefinition: 0,
		draft07: 0,
		pastNot: 0,
		excluded: 0,
	};
	fc.assert(
		fc.property(
			propertyNamesArb,
			fc.constantFrom(...SHARED_KEY_RULE_FORMS),
			(generated, { draft, container }) => {
				stats.runs++;
				const definition =
					draft === "draft-07" ? draft07Definition(generated) : generated;
				const definitionPath = `/${container}/key`;
				const schema = {
					propertyNames: { $ref: `#${definitionPath}` },
					[container]: { key: definition },
				};
				const validate = compileOracle(oracles[draft], schema);
				if (!validate) {
					stats.refused++;
					return;
				}
				const { errors } = crawlSchema(
					draft === "draft-07" ? { $schema: DRAFT_07, ...schema } : schema,
					undefined,
					{ lang: "js" },
				);
				const failClosed = errors.some(
					(e) =>
						e.instancePath === "/propertyNames" &&
						e.keyword === "propertyNames" &&
						e.params.matches === undefined &&
						e.params.name === undefined,
				);
				if (!failClosed) stats.followed++;
				const atPropertyNames = reportedNames(errors, "/propertyNames");
				const atDefinition = reportedNames(errors, `${definitionPath}/`);
				const re =
					typeof definition.pattern === "string"
						? new RegExp(definition.pattern, "u")
						: null;
				for (const name of JS_DENYLIST) {
					const instance = JSON.parse(`{${JSON.stringify(name)}:0}`);
					if (!Object.hasOwn(instance, name)) {
						throw new Error(`"${name}" is not an own key of the instance`);
					}
					const reported = atPropertyNames.has(name) || atDefinition.has(name);
					if (validate(instance)) {
						stats.admitted++;
						if (atDefinition.has(name)) stats.atDefinition++;
						if (draft === "draft-07") stats.draft07++;
						if (definition.not !== undefined) stats.pastNot++;
						if (!failClosed && !reported) {
							throw new Error(
								`AJV admits key "${name}" through ${draft} propertyNames $ref but crawlSchema is silent: ${JSON.stringify(schema)}`,
							);
						}
					} else if (re?.test(name) && !reported) {
						// The pattern matches but the definition's `not` excluded the name.
						stats.excluded++;
					}
				}
			},
		),
		{ numRuns: 1000 },
	);
	t.diagnostic(JSON.stringify(stats));
	ok(stats.refused / stats.runs < 0.05, `AJV refused ${JSON.stringify(stats)}`);
	ok(stats.followed >= 500, `too few $refs followed: ${JSON.stringify(stats)}`);
	ok(stats.admitted >= 300, `too few admitted keys: ${JSON.stringify(stats)}`);
	ok(
		stats.atDefinition >= 400,
		`too few names reported at the definition: ${JSON.stringify(stats)}`,
	);
	ok(stats.draft07 >= 150, `too few draft-07 keys: ${JSON.stringify(stats)}`);
	ok(stats.pastNot >= 100, `too few keys past a not: ${JSON.stringify(stats)}`);
	ok(stats.excluded >= 50, `too few exclusions: ${JSON.stringify(stats)}`);
});
