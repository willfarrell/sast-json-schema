#!/usr/bin/env node
// Copyright 2026 will Farrell, and sast-json-schema contributors.
// SPDX-License-Identifier: MIT
import { lookup as dnsLookup } from "node:dns/promises";
import { readFile, stat } from "node:fs/promises";
import { relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import Ajv from "ajv/dist/2020.js";
import { isSafePattern } from "redos-detector";
import schema201909 from "./2019-09.json" with { type: "json" };
import schema202012 from "./2020-12.json" with { type: "json" };
import schemaDraft04 from "./draft-04.json" with { type: "json" };
import schemaDraft06 from "./draft-06.json" with { type: "json" };
import schemaDraft07 from "./draft-07.json" with { type: "json" };
import pkg from "./package.json" with { type: "json" };

const defaultOptions = {
	strictTypes: false,
	allErrors: true,
};

const DEFAULT_VERSION = "2020-12";

export const DNS_TIMEOUT_MS = 5_000;
export const DNS_CONCURRENCY = 10;
export const MAX_SSRF_HOSTNAMES = 256;
export const DNS_TOTAL_TIMEOUT_MS = 30_000;

// Pre-compiled SAST meta-schema validators, keyed by draft version. Compiled
// once at module load so every sast() / analyze() call reuses the same
// validator.
const builtSchemas = new Map(
	[
		["2020-12", schema202012],
		["2019-09", schema201909],
		["draft-07", schemaDraft07],
		["draft-06", schemaDraft06],
		["draft-04", schemaDraft04],
	].map(([version, metaSchema]) => [
		version,
		// allErrors:true is required so a single pass surfaces EVERY meta-schema
		// violation for the security report; the schemas are trusted, not attacker
		// input, so unbounded error allocation is not a DoS vector here.
		// nosemgrep: javascript.ajv.security.audit.ajv-allerrors-true.ajv-allerrors-true
		new Ajv(defaultOptions).compile(metaSchema),
	]),
);

// Known $schema URLs mapped to their draft version. URLs are stored in
// normalised form (no protocol, no trailing #) so callers can pass any
// http/https variant with or without a fragment.
const knownSchemaUrls = new Map([
	["json-schema.org/draft/2020-12/schema", "2020-12"],
	["json-schema.org/draft/2019-09/schema", "2019-09"],
	["json-schema.org/draft-07/schema", "draft-07"],
	["json-schema.org/draft-06/schema", "draft-06"],
	["json-schema.org/draft-04/schema", "draft-04"],
]);

// Maps a user schema's $schema URL to the matching draft version.
const schemaVersion = (url) => {
	if (!url) return DEFAULT_VERSION;
	// Stryker disable next-line Regex: dropping the ^/$ anchors only changes the
	// result for URLs with an interior "//" or "#", none of which are in the known
	// set, so they resolve to the same (unsupported) lookup either way.
	const normalized = url.replace(/^(?:https?:)?\/\//, "").replace(/#$/, "");
	return knownSchemaUrls.get(normalized);
};

export const MAX_DEPTH = 32;
export const MAX_SCHEMA_SIZE = 64 * 1024 * 1024; // 64 MiB
// Hard cap on the total number of remote $ref/$dynamicRef entries crawlSchema
// will collect into result.refs. The distinct-hostname cap (MAX_SSRF_HOSTNAMES)
// only applies later, after every ref has already been buffered, so a schema
// with a huge number of refs to the same few hosts would still accumulate an
// unbounded array. This is a backstop (overall bounded by MAX_SCHEMA_SIZE); set
// well above what realistic schemas need (multiple refs per distinct host).
export const MAX_COLLECTED_REFS = 4 * MAX_SSRF_HOSTNAMES;
// Per-pattern budget for ReDoS analysis. Patterns that exceed this are
// fail-closed (reported as unsafe with reason "timedOut") to keep total
// scan time bounded on adversarial input.
export const REDOS_TIMEOUT_MS = 1_000;
// HEAP CIRCUIT BREAKER: the PRIMARY memory bound for ReDoS analysis. The
// `timeout` option bounds time but NOT memory, and redos-detector's `maxSteps`
// cannot serve as the memory control: a value low enough to bound a catastrophic
// pattern (which retains ~7MB post-GC and ~270MB pre-GC each, so a handful OOM a
// 600MB heap) also wrongly fail-closes legitimate complex-but-safe patterns
// (e.g. semver is reported hitMaxSteps at maxSteps<=250 but is SAFE at the
// library default). So we drop maxSteps and instead read the live heap before
// each pattern: once it has grown beyond this budget above the phase baseline,
// analysis STOPS and one fail-closed (incomplete) finding is emitted. Chosen at
// 128MB: a single catastrophic pattern grows the heap by ~270MB at the default,
// so the breaker fires after the FIRST evil pattern (delta ~270MB > 128MB) and
// before the second, keeping peak well under --max-old-space-size=600; meanwhile
// realistic schemas with many SIMPLE patterns retain almost nothing and never
// approach 128MB. Injectable via crawlSchema options for deterministic testing.
export const REDOS_HEAP_BUDGET_BYTES = 128 * 1024 * 1024;
// Defense in depth: a hard cap on the TOTAL number of regex patterns crawlSchema
// will ReDoS-analyze in a single crawl. The heap circuit breaker above is the
// primary memory control; this is an independent backstop against an adversary
// supplying a huge number of patterns. Set well above what realistic schemas
// need (they can legitimately carry hundreds of simple patterns, which are
// cheap).
export const MAX_REDOS_PATTERNS = 256;
export const ANALYSIS_TIMEOUT_MS = 60_000;

// Property names that act as deserialization / type-confusion vectors in
// each downstream language ecosystem. Selected at the analyze() / CLI layer
// via the `lang` option (default: "default", the union of every named lang,
// because JSON specs typically flow through multiple language toolchains
// and the safe default is to catch them all). Set --lang explicitly to
// narrow scope when you control the consumer environment.
//
// "default": union of every named language entry below. Most paranoid baseline.
// "js":      V8 prototype-pollution: __proto__, constructor, prototype.
// "py":      js + Python introspection / pickle gadget keys.
// "rb":      js + Ruby reflection / JSON.load(create_additions: true).
// "rs":      js baseline (Rust serde itself is type-safe, but specs often
//            pass through JS tooling that is not).
// "java":    js + Jackson/Fastjson polymorphic deserialization markers.
// "kotlin":  alias of java (JVM/Jackson).
// "clojure": alias of java (JVM/Cheshire).
// "cs":      js + .NET JSON deserialization markers. Covers C#, VB.NET,
//            ASP.NET, and ASPX (they all share the same serializer stack:
//            Json.NET $type, DataContractJsonSerializer __type, OData @odata.type).
// "vb":      alias of cs (.NET stack).
// "fsharp":  alias of cs (.NET stack).
// "php":     js + PHP magic methods invoked during object hydration
//            (Symfony Serializer / JMS Serializer / unserialize gadget chains).
// "objc":    js + Objective-C runtime keys: isa, class, superclass,
//            description, init, _cmd (KVC + performSelector: vectors).
// "swift":   alias of objc (Obj-C runtime exposure via interop; pure Codable
//            is type-safe but mixed projects share the same surface).
// "ex":      js + Elixir/BEAM struct-identifier keys: __struct__,
//            __exception__, __protocol__ (auto-recognized when JSON is
//            decoded with :keys => :atoms and hydrated into a struct).
// "lua":     js + Lua metamethod names (__index, __newindex, __call,
//            __metatable, __tostring, __gc, __close, etc.) for libraries
//            that auto-bind metatables onto JSON-decoded tables.
//
// There is no "off" switch: the meta-schema enforces __proto__/constructor/
// prototype universally, so the narrowest opt-out is --lang js (which adds
// no extras over the meta-schema baseline). For per-path false positives,
// use --ignore <instancePath>.
export const DANGEROUS_NAMES_BY_LANG = {
	js: ["__proto__", "constructor", "prototype"],
	py: [
		"__proto__",
		"constructor",
		"prototype",
		"__class__",
		"__init__",
		"__globals__",
		"__builtins__",
		"__import__",
		"__reduce__",
		"__subclasses__",
		"__dict__",
		"__mro__",
	],
	rb: [
		"__proto__",
		"constructor",
		"prototype",
		"__send__",
		"json_class",
		"instance_eval",
		"instance_variable_set",
		"singleton_class",
	],
	rs: ["__proto__", "constructor", "prototype"],
	java: ["__proto__", "constructor", "prototype", "@type", "@class"],
	kotlin: ["__proto__", "constructor", "prototype", "@type", "@class"],
	clojure: ["__proto__", "constructor", "prototype", "@type", "@class"],
	cs: [
		"__proto__",
		"constructor",
		"prototype",
		"$type",
		"__type",
		"@odata.type",
	],
	vb: [
		"__proto__",
		"constructor",
		"prototype",
		"$type",
		"__type",
		"@odata.type",
	],
	fsharp: [
		"__proto__",
		"constructor",
		"prototype",
		"$type",
		"__type",
		"@odata.type",
	],
	php: [
		"__proto__",
		"constructor",
		"prototype",
		"__construct",
		"__destruct",
		"__wakeup",
		"__sleep",
		"__serialize",
		"__unserialize",
		"__call",
		"__callStatic",
		"__get",
		"__set",
		"__isset",
		"__unset",
		"__toString",
		"__invoke",
		"__set_state",
		"__clone",
		"__debugInfo",
	],
	objc: [
		"__proto__",
		"constructor",
		"prototype",
		"isa",
		"class",
		"superclass",
		"description",
		"init",
		"_cmd",
	],
	swift: [
		"__proto__",
		"constructor",
		"prototype",
		"isa",
		"class",
		"superclass",
		"description",
		"init",
		"_cmd",
	],
	ex: [
		"__proto__",
		"constructor",
		"prototype",
		"__struct__",
		"__exception__",
		"__protocol__",
	],
	lua: [
		"__proto__",
		"constructor",
		"prototype",
		"__index",
		"__newindex",
		"__call",
		"__metatable",
		"__tostring",
		"__name",
		"__pairs",
		"__eq",
		"__lt",
		"__le",
		"__add",
		"__sub",
		"__mul",
		"__div",
		"__mod",
		"__pow",
		"__concat",
		"__len",
		"__unm",
		"__band",
		"__bor",
		"__bxor",
		"__bnot",
		"__shl",
		"__shr",
		"__idiv",
		"__close",
		"__gc",
	],
};
DANGEROUS_NAMES_BY_LANG.default = [
	...new Set(Object.values(DANGEROUS_NAMES_BY_LANG).flat()),
];
export const DEFAULT_LANG = "default";

const resolveDangerousNames = (lang) => {
	if (lang == null) return DANGEROUS_NAMES_BY_LANG[DEFAULT_LANG];
	if (Array.isArray(lang)) return lang;
	const list = DANGEROUS_NAMES_BY_LANG[lang];
	if (!list) {
		throw new TypeError(
			`unknown lang "${lang}", expected one of: ${Object.keys(DANGEROUS_NAMES_BY_LANG).join(", ")}`,
		);
	}
	return list;
};

// AJV schema paths used by override filters. Verified by regression tests
// in cli.analyze.test.js to match what AJV actually emits.
const SCHEMA_PATH_MAX_ITEMS = "#/$defs/safeArrayItemsLimits/maxItems";
const SCHEMA_PATH_MAX_PROPERTIES =
	"#/$defs/safeObjectPropertiesLimits/maxProperties";

// Returns the pre-compiled SAST validator for the draft declared by
// `schema.$schema`. Defaults to 2020-12 when $schema is absent.
export const sast = (schema) => {
	const version = schemaVersion(schema?.$schema);
	const validate = builtSchemas.get(version);
	if (!validate) {
		// Stryker disable next-line OptionalChaining: reaching this throw requires a
		// non-null schema object (a null schema resolves to the default and validates),
		// so schema?.$schema and schema.$schema are equivalent here.
		throw new Error(`Unsupported $schema: ${schema?.$schema}`);
	}
	return validate;
};

export default sast;

// Checks whether a numeric schema's min/max bounds describe an impossible
// range. Returns an AJV-style error object when they do, or null otherwise.
const checkNumericRange = (current, path) => {
	// Number.isFinite is true only for an actual finite number, so it already
	// implies `typeof === "number"`; no separate type check is needed.
	const hasMin =
		Object.hasOwn(current, "minimum") && Number.isFinite(current.minimum);
	const hasExMin =
		Object.hasOwn(current, "exclusiveMinimum") &&
		Number.isFinite(current.exclusiveMinimum);
	const hasMax =
		Object.hasOwn(current, "maximum") && Number.isFinite(current.maximum);
	const hasExMax =
		Object.hasOwn(current, "exclusiveMaximum") &&
		Number.isFinite(current.exclusiveMaximum);

	if (!(hasMin || hasExMin) || !(hasMax || hasExMax)) return null;

	let effectiveMin;
	let minIsExclusive = false;
	if (hasMin && hasExMin) {
		if (current.exclusiveMinimum >= current.minimum) {
			effectiveMin = current.exclusiveMinimum;
			minIsExclusive = true;
		} else {
			effectiveMin = current.minimum;
		}
	} else if (hasExMin) {
		effectiveMin = current.exclusiveMinimum;
		minIsExclusive = true;
	} else {
		effectiveMin = current.minimum;
	}

	let effectiveMax;
	let maxIsExclusive = false;
	if (hasMax && hasExMax) {
		if (current.exclusiveMaximum <= current.maximum) {
			effectiveMax = current.exclusiveMaximum;
			maxIsExclusive = true;
		} else {
			effectiveMax = current.maximum;
		}
	} else if (hasExMax) {
		effectiveMax = current.exclusiveMaximum;
		maxIsExclusive = true;
	} else {
		effectiveMax = current.maximum;
	}

	const impossible =
		minIsExclusive || maxIsExclusive
			? !(effectiveMin < effectiveMax)
			: effectiveMin > effectiveMax;

	if (!impossible) return null;

	const keyword = maxIsExclusive
		? "exclusiveMaximum"
		: minIsExclusive
			? "exclusiveMinimum"
			: "minimum";

	return {
		instancePath: path,
		schemaPath: `#/${keyword}`,
		keyword,
		params: {
			...(hasMin && { minimum: current.minimum }),
			...(hasExMin && { exclusiveMinimum: current.exclusiveMinimum }),
			...(hasMax && { maximum: current.maximum }),
			...(hasExMax && { exclusiveMaximum: current.exclusiveMaximum }),
		},
		message: "numeric range is unsatisfiable",
	};
};

const INSTANCE_DATA_KEYS = new Set(["const", "enum", "default", "examples"]);

// RFC 6901 JSON Pointer token escaping: ~ → ~0, / → ~1.
// https://datatracker.ietf.org/doc/html/rfc6901#section-3
const escapeJsonPointer = (token) =>
	token.replace(/~/g, "~0").replace(/\//g, "~1");

// Single-pass crawler that records: max depth, range/length inconsistencies,
// ReDoS patterns, and remote $ref URLs (for later SSRF resolution).
// Depth semantics: each object-valued key counts as one level, so a schema
// `{properties: {a: {properties: {b: {...}}}}}` reaches depth 5 (root,
// properties, a, properties, b). With MAX_DEPTH=32 this corresponds to roughly
// 16 levels of real schema nesting.
export const crawlSchema = (obj, maxDepth = MAX_DEPTH, options = {}) => {
	const result = {
		depth: 0,
		depthExceeded: false,
		timedOut: false,
		errors: [],
		refs: [],
	};
	if (typeof obj !== "object" || obj === null) return result;

	const deadline = options.deadline;
	// Injectable monotonic clock (defaults to the real wall clock). Reading the
	// clock through this indirection lets tests drive the deadline branches
	// deterministically (the same pattern as options.memoryUsage below).
	const now = typeof options.now === "function" ? options.now : Date.now;

	const denylist = resolveDangerousNames(options.lang);
	const denySet = new Set(denylist);

	const visited = new WeakSet();
	visited.add(obj);
	result.depth = 1;
	const stack = [[obj, "", 1]];

	// Defense in depth: total number of regex patterns ReDoS-analyzed so far.
	// Shared across top-level `pattern` and patternProperties keys. Once it
	// exceeds MAX_REDOS_PATTERNS, no further pattern is analyzed and a single
	// fail-closed budget finding is emitted (see redosBudgetExceeded).
	let redosPatternCount = 0;
	let redosBudgetReported = false;
	// One-time flag: have we already recorded the collected-refs truncation
	// finding? (See MAX_COLLECTED_REFS in the $ref/$dynamicRef collection below.)
	let refsTruncated = false;
	// Pushes the timeout finding and flags the result as timed out. Used both at
	// the top of the stack loop and before each individual ReDoS analysis (the
	// per-pattern loops can run many isSafePattern() calls in one stack frame, so
	// the once-per-pop check is not enough on adversarial input).
	const timeoutBail = () => {
		result.errors.push({
			instancePath: "",
			schemaPath: "#/timeout",
			keyword: "timeout",
			params: {},
			message: "schema analysis exceeded time budget",
		});
		result.timedOut = true;
	};
	// True when a deadline is configured and has passed. The `> deadline` boundary
	// is exclusive (a clock reading EXACTLY at the deadline does NOT bail), pinned by
	// the injected-clock deadline tests in cli.crawl.test.js, which also kill the
	// whole-condition ConditionalExpression mutant (expired clock bails, future clock
	// does not). The `deadline != null` guard sits on its own line so ONLY its
	// genuinely-equivalent mutant is disabled.
	const deadlineConfigured = () =>
		// Stryker disable next-line ConditionalExpression: forcing this `!= null` guard
		// true is equivalent; when deadline is absent, now() > undefined is false anyway
		// (deadlinePassed short-circuits the same way), so no input distinguishes it.
		deadline != null;
	const deadlinePassed = () => deadlineConfigured() && now() > deadline;

	// Returns true (and emits one #/redos-budget finding the first time) when the
	// total-pattern cap has been exceeded, so callers can skip further analysis.
	// Marked incomplete:true so --ignore cannot suppress it (analysis stopped).
	const redosBudgetExceeded = (path) => {
		if (redosPatternCount <= MAX_REDOS_PATTERNS) return false;
		if (!redosBudgetReported) {
			redosBudgetReported = true;
			result.errors.push({
				instancePath: path,
				schemaPath: "#/redos-budget",
				keyword: "pattern",
				params: { limit: MAX_REDOS_PATTERNS, incomplete: true },
				message: `refusing to ReDoS-analyze more than ${MAX_REDOS_PATTERNS} patterns; remaining patterns not analyzed`,
			});
		}
		return true;
	};

	// HEAP CIRCUIT BREAKER (primary memory bound). Reads live heap usage before
	// each pattern; once it has grown beyond redosHeapBudgetBytes above the
	// baseline captured at the first pattern, analysis stops and one fail-closed
	// finding is emitted. Marked incomplete:true so --ignore cannot suppress it.
	// Injectable: options.memoryUsage / options.redosHeapBudgetBytes for tests.
	const memoryUsage =
		typeof options.memoryUsage === "function"
			? options.memoryUsage
			: () => process.memoryUsage().heapUsed;
	const redosHeapBudgetBytes =
		// Stryker disable next-line ConditionalExpression: when absent the default
		// const is used; any test exercising the override passes it explicitly.
		options.redosHeapBudgetBytes != null
			? options.redosHeapBudgetBytes
			: REDOS_HEAP_BUDGET_BYTES;
	let redosHeapBaseline = null;
	let redosHeapReported = false;
	// Returns true (and emits one #/redos-budget heap finding the first time) when
	// the heap has grown more than the budget above the baseline. The first call
	// captures the baseline (delta 0, never trips), so the breaker only fires once
	// a real allocation has crossed the budget.
	const redosHeapExceeded = (path) => {
		const current = memoryUsage();
		if (redosHeapBaseline === null) redosHeapBaseline = current;
		if (current - redosHeapBaseline <= redosHeapBudgetBytes) return false;
		if (!redosHeapReported) {
			redosHeapReported = true;
			result.errors.push({
				instancePath: path,
				schemaPath: "#/redos-budget",
				keyword: "heap",
				params: { budget: redosHeapBudgetBytes, incomplete: true },
				message: `ReDoS analysis heap budget of ${redosHeapBudgetBytes} bytes exceeded; remaining patterns not analyzed`,
			});
		}
		return true;
	};

	while (stack.length > 0) {
		if (deadlinePassed()) {
			timeoutBail();
			return result;
		}

		const [current, path, currentDepth] = stack.pop();

		const currentType = current.type;
		const isType = (t) =>
			currentType === t ||
			(Array.isArray(currentType) && currentType.includes(t));

		if (
			isType("string") &&
			Object.hasOwn(current, "minLength") &&
			Object.hasOwn(current, "maxLength") &&
			current.minLength > current.maxLength
		) {
			result.errors.push({
				instancePath: path,
				schemaPath: "#/minLength",
				keyword: "minLength",
				params: {
					minLength: current.minLength,
					maxLength: current.maxLength,
				},
				message: "minLength must be less than or equal to maxLength",
			});
		}

		if (isType("integer") || isType("number")) {
			const rangeError = checkNumericRange(current, path);
			if (rangeError) result.errors.push(rangeError);
		}

		if (
			isType("array") &&
			Object.hasOwn(current, "minItems") &&
			Object.hasOwn(current, "maxItems") &&
			current.minItems > current.maxItems
		) {
			result.errors.push({
				instancePath: path,
				schemaPath: "#/minItems",
				keyword: "minItems",
				params: {
					minItems: current.minItems,
					maxItems: current.maxItems,
				},
				message: "minItems must be less than or equal to maxItems",
			});
		}

		if (
			isType("array") &&
			Object.hasOwn(current, "minContains") &&
			Object.hasOwn(current, "maxContains") &&
			current.minContains > current.maxContains
		) {
			result.errors.push({
				instancePath: path,
				schemaPath: "#/minContains",
				keyword: "minContains",
				params: {
					minContains: current.minContains,
					maxContains: current.maxContains,
				},
				message: "minContains must be less than or equal to maxContains",
			});
		}

		if (
			isType("object") &&
			Object.hasOwn(current, "minProperties") &&
			Object.hasOwn(current, "maxProperties") &&
			current.minProperties > current.maxProperties
		) {
			result.errors.push({
				instancePath: path,
				schemaPath: "#/minProperties",
				keyword: "minProperties",
				params: {
					minProperties: current.minProperties,
					maxProperties: current.maxProperties,
				},
				message: "minProperties must be less than or equal to maxProperties",
			});
		}

		if (
			Object.hasOwn(current, "pattern") &&
			typeof current.pattern === "string"
		) {
			// Check the deadline BEFORE the (potentially expensive) analysis: the
			// once-per-pop check above is not enough when one stack frame holds many
			// patterns. Bail to the timeout path on an expired deadline. Exercised
			// deterministically by an injected clock that is under-deadline at the
			// once-per-pop check and over it here (see cli.crawl.test.js).
			if (deadlinePassed()) {
				timeoutBail();
				return result;
			}
			redosPatternCount++;
			// Skip analysis (of this and every later pattern) once a backstop trips:
			// the total-pattern cap or the heap circuit breaker (primary memory bound).
			if (
				!redosBudgetExceeded(`${path}/pattern`) &&
				!redosHeapExceeded(`${path}/pattern`)
			) {
				try {
					// The timeout bounds analysis TIME; the heap breaker above bounds
					// MEMORY. No maxSteps: it would fail-close legitimate safe patterns.
					// Stryker disable next-line ObjectLiteral: the timeout option bounds
					// analysis TIME only; for any pattern fast enough for a test the
					// safe/unsafe verdict is identical with or without it, so dropping it
					// (-> {}) is an equivalent (timing-only) mutant.
					const patternResult = isSafePattern(current.pattern, {
						timeout: REDOS_TIMEOUT_MS,
					});
					if (!patternResult.safe) {
						// Stryker disable next-line LogicalOperator,StringLiteral: redos-detector
						// always reports error:"hitMaxScore" for these, so the ?? fallback is
						// defensive dead-weight here.
						const reason = patternResult.error ?? "hitMaxScore";
						// timedOut/hitMaxSteps reasons only arise on a real library timeout,
						// which cannot be triggered deterministically in a fast test.
						// Stryker disable ConditionalExpression,StringLiteral
						const message =
							reason === "timedOut"
								? `pattern analysis timed out after ${REDOS_TIMEOUT_MS}ms (fail-closed as ReDoS)`
								: reason === "hitMaxSteps"
									? "pattern analysis exceeded step limit (fail-closed as ReDoS)"
									: "pattern is vulnerable to ReDoS";
						// Stryker restore ConditionalExpression,StringLiteral
						result.errors.push({
							instancePath: `${path}/pattern`,
							schemaPath: "#/redos",
							keyword: "pattern",
							params: { pattern: current.pattern, reason },
							message,
						});
					}
				} catch {
					result.errors.push({
						instancePath: `${path}/pattern`,
						schemaPath: "#/redos",
						keyword: "pattern",
						params: { pattern: current.pattern, reason: "parseError" },
						message: "pattern could not be parsed for ReDoS analysis",
					});
				}
			}
		}

		// Stryker disable next-line ConditionalExpression,EqualityOperator: this only
		// skips the dangerous-name loops when the denylist is empty; entering with an
		// empty denySet matches nothing, so it is a pure (equivalent) optimization.
		if (denylist.length > 0) {
			for (const siteKey of [
				"properties",
				"$defs",
				"definitions",
				"dependentSchemas",
				"dependentRequired",
			]) {
				const site = current[siteKey];
				if (typeof site === "object" && site !== null && !Array.isArray(site)) {
					for (const name of Object.keys(site)) {
						if (denySet.has(name)) {
							result.errors.push({
								instancePath: `${path}/${siteKey}/${escapeJsonPointer(name)}`,
								schemaPath: "#/dangerous-name",
								keyword: siteKey,
								params: { name, lang: options.lang ?? DEFAULT_LANG },
								message: `${siteKey} key "${name}" is a deserialization vector for lang="${options.lang ?? DEFAULT_LANG}"`,
							});
						}
					}
				}
			}

			if (Array.isArray(current.required)) {
				for (const [i, name] of current.required.entries()) {
					// Stryker disable next-line ConditionalExpression: denySet only holds
					// strings, so denySet.has(non-string) is already false.
					if (typeof name === "string" && denySet.has(name)) {
						result.errors.push({
							instancePath: `${path}/required/${i}`,
							schemaPath: "#/dangerous-name",
							keyword: "required",
							params: { name, lang: options.lang ?? DEFAULT_LANG },
							message: `required entry "${name}" is a deserialization vector for lang="${options.lang ?? DEFAULT_LANG}"`,
						});
					}
				}
			}

			if (
				typeof current.dependentRequired === "object" &&
				current.dependentRequired !== null &&
				!Array.isArray(current.dependentRequired)
			) {
				for (const [trigger, deps] of Object.entries(
					current.dependentRequired,
				)) {
					// Stryker disable next-line ConditionalExpression: a non-array deps has
					// no length, so the loop below simply never runs.
					if (Array.isArray(deps)) {
						for (const [i, name] of deps.entries()) {
							// Stryker disable next-line ConditionalExpression,LogicalOperator: denySet
							// only holds strings, so has(non-string) is already false.
							if (typeof name === "string" && denySet.has(name)) {
								result.errors.push({
									instancePath: `${path}/dependentRequired/${escapeJsonPointer(trigger)}/${i}`,
									schemaPath: "#/dangerous-name",
									keyword: "dependentRequired",
									params: { name, lang: options.lang ?? DEFAULT_LANG },
									message: `dependentRequired entry "${name}" is a deserialization vector for lang="${options.lang ?? DEFAULT_LANG}"`,
								});
							}
						}
					}
				}
			}
		}

		// ReDoS scanning of patternProperties keys is independent of the
		// dangerous-name denylist, so it runs unconditionally; the dangerous-name
		// match below self-gates (filtering an empty denylist yields no matches).
		if (
			typeof current.patternProperties === "object" &&
			current.patternProperties !== null &&
			!Array.isArray(current.patternProperties)
		) {
			for (const patternKey of Object.keys(current.patternProperties)) {
				const keyPath = `${path}/patternProperties/${escapeJsonPointer(patternKey)}`;
				// Check the deadline before each key: a single object can carry many
				// patternProperties keys, all analyzed in ONE stack frame, so the
				// once-per-pop check above never fires between them. Exercised with an
				// injected clock that crosses the deadline before a later key (see
				// cli.crawl.test.js).
				if (deadlinePassed()) {
					timeoutBail();
					return result;
				}
				redosPatternCount++;
				// Stop analyzing further patterns once a backstop trips: the
				// total-pattern cap or the heap circuit breaker (primary memory bound).
				if (redosBudgetExceeded(keyPath) || redosHeapExceeded(keyPath)) break;
				let patternSafe = true;
				try {
					// The timeout bounds analysis TIME; the heap breaker above bounds
					// MEMORY. No maxSteps: it would fail-close legitimate safe patterns.
					// Stryker disable next-line ObjectLiteral: the timeout option bounds
					// analysis TIME only; for any key fast enough for a test the verdict
					// is identical with or without it, so dropping it is timing-equivalent.
					const patternResult = isSafePattern(patternKey, {
						timeout: REDOS_TIMEOUT_MS,
					});
					if (!patternResult.safe) {
						patternSafe = false;
						result.errors.push({
							instancePath: keyPath,
							schemaPath: "#/redos",
							keyword: "patternProperties",
							params: {
								pattern: patternKey,
								// Stryker disable next-line LogicalOperator,StringLiteral: redos-detector
								// always reports error:"hitMaxScore"; the ?? fallback is dead-weight.
								reason: patternResult.error ?? "hitMaxScore",
							},
							message: `patternProperties key "${patternKey}" is vulnerable to ReDoS`,
						});
					}
				} catch {}
				if (!patternSafe) continue;
				try {
					// nosemgrep: javascript.lang.security.audit.detect-non-literal-regexp.detect-non-literal-regexp
					const re = new RegExp(patternKey);
					const matches = denylist.filter((n) => re.test(n));
					if (matches.length > 0) {
						result.errors.push({
							instancePath: keyPath,
							schemaPath: "#/dangerous-name",
							keyword: "patternProperties",
							params: {
								pattern: patternKey,
								matches,
								lang: options.lang ?? DEFAULT_LANG,
							},
							message: `patternProperties key "${patternKey}" matches deserialization vector(s) for lang="${options.lang ?? DEFAULT_LANG}": ${matches.join(", ")}`,
						});
					}
				} catch {
					// unparseable regex; meta-schema safePattern rejects it
				}
			}
		}

		// Collect remote $ref and $dynamicRef (2020-12) URLs as SSRF fetch targets.
		// $id is deliberately NOT collected: it declares a base URI identifier, not
		// a fetch target, and the -r/--ref-schema-files flag uses $id hostnames as
		// the SAFE list, so flagging $id would self-flag the user's own schema.
		for (const refKey of ["$ref", "$dynamicRef"]) {
			const refValue = current[refKey];
			if (
				Object.hasOwn(current, refKey) &&
				typeof refValue === "string" &&
				!refValue.startsWith("#")
			) {
				try {
					const url = new URL(refValue);
					if (url.hostname) {
						// Backstop: stop buffering once the collected-refs cap is reached,
						// recording one truncation finding. Without this, a schema with a
						// huge number of refs could accumulate an unbounded array before
						// the later distinct-hostname cap ever applies.
						if (result.refs.length >= MAX_COLLECTED_REFS) {
							if (!refsTruncated) {
								refsTruncated = true;
								result.errors.push({
									instancePath: `${path}/${refKey}`,
									schemaPath: "#/refs-truncated",
									keyword: "$ref",
									params: { limit: MAX_COLLECTED_REFS, incomplete: true },
									message: `more than ${MAX_COLLECTED_REFS} remote $ref(s); remaining refs not collected for SSRF analysis`,
								});
							}
						} else {
							result.refs.push({
								hostname: url.hostname,
								ref: refValue,
								path: `${path}/${refKey}`,
							});
						}
					}
				} catch {
					// not a valid URL, skip
				}
			}
		}

		for (const key in current) {
			if (Object.hasOwn(current, key) && !INSTANCE_DATA_KEYS.has(key)) {
				const value = current[key];
				if (
					typeof value === "object" &&
					value !== null &&
					!visited.has(value)
				) {
					visited.add(value);
					const newDepth = currentDepth + 1;
					// Stryker disable next-line ConditionalExpression,EqualityOperator: this only
					// tracks the max depth seen; > vs >= and always-assign reach the same maximum.
					if (newDepth > result.depth) result.depth = newDepth;
					if (result.depth > maxDepth) {
						result.depthExceeded = true;
						return result;
					}
					stack.push([value, `${path}/${escapeJsonPointer(key)}`, newDepth]);
				}
			}
		}
	}

	return result;
};

// RFC 1918 + loopback + link-local + CGN + TEST-NETs + multicast + reserved.
// IPv6 covered: :: and ::1, unique-local fc00::/7, link-local fe80::/10 and
// site-local fec0::/10 (combined fe80-feff), multicast ff00::/8, IPv4-mapped
// ::ffff:0:0/96, NAT64 64:ff9b::/96, 6to4 2002::/16, and documentation
// 2001:db8::/32. NAT64/6to4/IPv4-mapped recurse on their embedded IPv4.
// Used to block $ref URLs whose hostname resolves to an internal/private IP.
// Fail-closed: malformed IPv6 (e.g. invalid hex groups, wrong group count) is
// treated as private (returns true) so it is blocked rather than allowed
// through as a forged public address. Tests in cli.ip.test.js pin the
// boundary cases.
export const isPrivateIP = (ip) => {
	const parts = ip.split(".").map(Number);
	if (
		parts.length === 4 &&
		parts.every((p) => Number.isInteger(p) && p >= 0 && p <= 255)
	) {
		const [a, b] = parts;
		if (a === 0) return true; // 0.0.0.0/8 "this" network
		if (a === 10) return true; // 10.0.0.0/8 private
		if (a === 127) return true; // 127.0.0.0/8 loopback
		if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGN
		if (a === 169 && b === 254) return true; // 169.254.0.0/16 link-local
		if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12 private
		if (a === 192 && b === 0 && parts[2] === 0) return true; // 192.0.0.0/24 IETF
		if (a === 192 && b === 0 && parts[2] === 2) return true; // 192.0.2.0/24 TEST-NET-1
		if (a === 192 && b === 168) return true; // 192.168.0.0/16 private
		if (a === 198 && (b === 18 || b === 19)) return true; // 198.18.0.0/15 benchmark
		if (a === 198 && b === 51 && parts[2] === 100) return true; // 198.51.100.0/24 TEST-NET-2
		if (a === 203 && b === 0 && parts[2] === 113) return true; // 203.0.113.0/24 TEST-NET-3
		// Stryker disable next-line ConditionalExpression: octets are validated to
		// 0-255 and 240-255 is already private via the next line, so the `a <= 239`
		// bound is redundant; dropping it is an equivalent mutant (no input changes).
		if (a >= 224 && a <= 239) return true; // 224.0.0.0/4 multicast
		if (a >= 240) return true; // 240.0.0.0/4 reserved + 255.255.255.255 broadcast
	}

	// Normalize IPv6: expand :: and remove leading zeros for consistent matching
	const lower = ip.toLowerCase();
	if (lower.includes(":")) {
		// Strip IPv6 zone ID (e.g. %eth0) before further parsing
		const zoneIdx = lower.indexOf("%");
		const addr = zoneIdx !== -1 ? lower.slice(0, zoneIdx) : lower;

		// Handle IPv4-mapped forms with dotted notation (e.g. ::ffff:127.0.0.1)
		// before general expansion since the dotted part counts as 2 groups
		const lastColon = addr.lastIndexOf(":");
		const tail = addr.slice(lastColon + 1);
		if (tail.includes(".")) {
			// Recursively check the IPv4 portion
			return isPrivateIP(tail);
		}

		// Expand :: notation to full 8-group form
		let groups;
		if (addr.includes("::")) {
			const [left, right] = addr.split("::");
			const leftGroups = left ? left.split(":") : [];
			const rightGroups = right ? right.split(":") : [];
			const missing = 8 - leftGroups.length - rightGroups.length;
			groups = [...leftGroups, ...Array(missing).fill("0"), ...rightGroups].map(
				(g) => g.replace(/^0+(?=.)/, ""),
			);
		} else {
			groups = addr.split(":").map((g) => g.replace(/^0+(?=.)/, ""));
		}
		if (groups.length === 8) {
			const normalized = groups.join(":");
			if (normalized === "0:0:0:0:0:0:0:0" || normalized === "0:0:0:0:0:0:0:1")
				return true;
			// Decode two normalized hex groups into a dotted IPv4 and recurse.
			// Fail-closed: invalid hex parses as NaN, and NaN bit-math would forge a
			// public-looking IPv4. Block (return true) instead.
			const embeddedIPv4Private = (hiGroup, loGroup) => {
				const hi = Number.parseInt(hiGroup, 16);
				const lo = Number.parseInt(loGroup, 16);
				if (Number.isNaN(hi) || Number.isNaN(lo)) return true;
				return isPrivateIP(`${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`);
			};
			if (groups[0].startsWith("fc") || groups[0].startsWith("fd")) return true; // unique local fc00::/7
			if (groups[0].startsWith("ff")) return true; // multicast ff00::/8
			// First-group numeric ranges. Fail-closed on NaN (malformed hex) and on
			// values > 0xffff (an over-long group such as "fe800" is malformed IPv6).
			const g0 = Number.parseInt(groups[0], 16);
			// Stryker disable next-line EqualityOperator: 0xffff (and above) starts with
			// "ff" and is already returned by the multicast check, so the boundary value
			// is unreachable here; `>` vs `>=` is an equivalent mutant.
			if (Number.isNaN(g0) || g0 > 0xffff) return true;
			// fe80-feff covers link-local fe80::/10 (fe80-febf) and site-local
			// fec0::/10 (fec0-feff); the old check only matched the literal "fe80".
			// Stryker disable next-line ConditionalExpression,EqualityOperator: the "ff"
			// startsWith and `g0 > 0xffff` returns above already exclude every g0 above
			// 0xfeff, so the upper-bound conjunct is always true here; dropping or
			// loosening it is an equivalent mutant (no reachable input changes).
			if (g0 >= 0xfe80 && g0 <= 0xfeff) return true;
			// 2002::/16 6to4: embedded IPv4 sits in groups 1 and 2.
			if (groups[0] === "2002")
				return embeddedIPv4Private(groups[1], groups[2]);
			// 2001:db8::/32 documentation (the IPv6 analog of the IPv4 TEST-NETs).
			if (groups[0] === "2001" && groups[1] === "db8") return true;
			// 64:ff9b::/96 NAT64 well-known prefix (RFC 6052): normalized form is
			// 64:ff9b:0:0:0:0:X:Y with the IPv4 embedded in the last two groups.
			if (normalized.startsWith("64:ff9b:0:0:0:0:")) {
				return embeddedIPv4Private(groups[6], groups[7]);
			}
			// IPv4-mapped with hex groups (e.g. 0:0:0:0:0:ffff:7f00:1)
			if (normalized.startsWith("0:0:0:0:0:ffff:")) {
				return embeddedIPv4Private(groups[6], groups[7]);
			}
		}
	}
	return false;
};

const lookupHostname = async (hostname, entries, timeoutMs) => {
	try {
		const results = await dnsLookup(hostname, {
			all: true,
			signal: AbortSignal.timeout(timeoutMs),
		});
		const privateAddr = results.find((r) => isPrivateIP(r.address));
		if (!privateAddr) return [];
		return entries.map(({ ref, path }) => ({
			instancePath: path,
			schemaPath: "#/ssrf",
			keyword: "ssrf",
			params: { ref, hostname, resolvedIP: privateAddr.address },
			message: `$ref hostname "${hostname}" resolves to private IP ${privateAddr.address}`,
		}));
	} catch {
		return entries.map(({ ref, path }) => ({
			instancePath: path,
			schemaPath: "#/ssrf",
			keyword: "ssrf",
			params: { ref, hostname },
			message: `$ref hostname "${hostname}" does not resolve`,
		}));
	}
};

export const resolveSSRFRefs = async (refs, options = {}) => {
	// Stryker disable next-line LogicalOperator: ?? vs && only changes the DNS
	// timeout magnitude, never the resolve/abort outcome; equivalent mutant.
	const timeoutMs = options.dnsTimeoutMs ?? DNS_TIMEOUT_MS;
	const concurrency = options.dnsConcurrency ?? DNS_CONCURRENCY;
	const safeHostnames = options.safeHostnames ?? new Set();
	const hostnameMap = new Map();
	for (const entry of refs) {
		if (safeHostnames.has(entry.hostname)) continue;
		if (!hostnameMap.has(entry.hostname)) {
			hostnameMap.set(entry.hostname, []);
		}
		hostnameMap.get(entry.hostname).push(entry);
	}

	const maxHostnames = options.maxHostnames ?? MAX_SSRF_HOSTNAMES;
	if (hostnameMap.size > maxHostnames) {
		return [
			{
				instancePath: "",
				schemaPath: "#/ssrf",
				keyword: "ssrf",
				// `incomplete: true` marks this as an INCOMPLETE-analysis finding: DNS
				// was entirely skipped, so analyze() must never let --ignore drop it
				// (same protection depth/timeout get). The normal per-host findings
				// below deliberately omit this marker and stay ignorable.
				params: {
					hostnames: hostnameMap.size,
					limit: maxHostnames,
					incomplete: true,
				},
				message: `too many distinct remote $ref hostnames (${hostnameMap.size}); refusing SSRF DNS resolution above ${maxHostnames}`,
			},
		];
	}

	const totalMs =
		// Stryker disable next-line ConditionalExpression: with the option absent the
		// default branch and Number(undefined)=NaN both yield "never time out".
		options.dnsTotalTimeoutMs != null
			? Number(options.dnsTotalTimeoutMs)
			: DNS_TOTAL_TIMEOUT_MS;
	// Injectable monotonic clock (defaults to the real wall clock), mirroring
	// crawlSchema's options.now so the total-budget deadline can be crossed
	// deterministically in tests, including at a batch index > 0.
	const now = typeof options.now === "function" ? options.now : Date.now;
	const overallDeadline = totalMs <= 0 ? 0 : now() + totalMs;

	const results = [];
	const batches = [...hostnameMap.entries()];
	// Stryker disable next-line EqualityOperator: < vs <= only adds one empty
	// trailing batch (slice past the end), so it is an equivalent mutant.
	for (let i = 0; i < batches.length; i += concurrency) {
		// The budget boundary is exclusive; pinned by an injected-clock test that
		// puts now() exactly at overallDeadline (no bail).
		if (now() > overallDeadline) {
			// slice(i) skips the batches already resolved; an injected clock that
			// expires the budget at a batch index > 0 makes this a proper subset,
			// pinned by a test in cli.analyze.test.js.
			for (const [hostname, entries] of batches.slice(i)) {
				for (const { ref, path } of entries) {
					results.push([
						{
							instancePath: path,
							schemaPath: "#/ssrf",
							keyword: "ssrf",
							// Incomplete-analysis marker: this host's DNS was skipped because
							// the total budget was exhausted, so analyze() must not let
							// --ignore drop it (see applyIgnore).
							params: { ref, hostname, incomplete: true },
							message: `$ref hostname "${hostname}" not checked: SSRF DNS budget exceeded`,
						},
					]);
				}
			}
			break;
		}
		const batch = batches.slice(i, i + concurrency);
		const batchResults = await Promise.all(
			batch.map(([hostname, entries]) =>
				lookupHostname(hostname, entries, timeoutMs),
			),
		);
		results.push(...batchResults);
	}
	return results.flat();
};

export const resolveInstancePath = (obj, pointer) => {
	if (typeof obj !== "object" || obj === null) return undefined;
	// Stryker disable next-line ConditionalExpression: an empty pointer also yields
	// zero parts below, so returning obj early vs falling through is equivalent.
	if (!pointer) return obj;
	const parts = pointer
		.split("/")
		.slice(1)
		.map((p) => p.replace(/~1/g, "/").replace(/~0/g, "~"));
	let current = obj;
	for (const part of parts) {
		if (typeof current !== "object" || current === null) return undefined;
		if (!Object.hasOwn(current, part)) return undefined;
		// Read-only walk: this never assigns INTO current, and the Object.hasOwn
		// guard above keeps it on own properties, so inherited prototype keys are
		// never traversed. Prototype pollution requires a write; there is none.
		// Resolution of own keys named constructor/__proto__ is covered by the
		// "own-property read" tests in tests/cli.analyze.test.js.
		// nosemgrep: javascript.lang.security.audit.prototype-pollution.prototype-pollution-loop.prototype-pollution-loop
		current = current[part];
	}
	return current;
};

// Runs a full SAST analysis on `schema`. Returns an array of AJV-style error
// objects. Never touches the filesystem, never prints, never exits the process.
export const analyze = async (schema, options = {}) => {
	if (options.overrideMaxDepth != null) {
		const n = Number(options.overrideMaxDepth);
		if (n < 0 || !Number.isInteger(n)) {
			throw new TypeError("overrideMaxDepth must be a non-negative integer");
		}
	}
	if (options.overrideMaxItems != null) {
		const n = Number(options.overrideMaxItems);
		if (n < 0 || !Number.isInteger(n)) {
			throw new TypeError("overrideMaxItems must be a non-negative integer");
		}
	}
	if (options.overrideMaxProperties != null) {
		const n = Number(options.overrideMaxProperties);
		if (n < 0 || !Number.isInteger(n)) {
			throw new TypeError(
				"overrideMaxProperties must be a non-negative integer",
			);
		}
	}
	if (options.maxSchemaSize != null) {
		const n = Number(options.maxSchemaSize);
		if (n < 0 || !Number.isInteger(n)) {
			throw new TypeError("maxSchemaSize must be a non-negative integer");
		}
	}
	if (options.analysisTimeoutMs != null) {
		const n = Number(options.analysisTimeoutMs);
		if (n < 0 || !Number.isInteger(n)) {
			throw new TypeError("analysisTimeoutMs must be a non-negative integer");
		}
	}
	if (options.maxHostnames != null) {
		const n = Number(options.maxHostnames);
		if (n < 0 || !Number.isInteger(n)) {
			throw new TypeError("maxHostnames must be a non-negative integer");
		}
	}
	if (options.dnsTotalTimeoutMs != null) {
		const n = Number(options.dnsTotalTimeoutMs);
		if (n < 0 || !Number.isInteger(n)) {
			throw new TypeError("dnsTotalTimeoutMs must be a non-negative integer");
		}
	}

	const applyIgnore = (errs) => {
		// Stryker disable next-line ConditionalExpression,LogicalOperator: the
		// length checks are short-circuit guards; filtering with an empty/no ignore
		// set is a no-op, so dropping them yields the same returned array.
		if (Array.isArray(options.ignore) && options.ignore.length && errs.length) {
			const ignore = new Set(options.ignore);
			return errs.filter(
				(err) =>
					// Findings marked incomplete (SSRF hostname-cap / DNS-budget) mean
					// analysis was NOT completed, so they are never suppressible by
					// --ignore, exactly like the depth/timeout findings.
					// Stryker disable next-line OptionalChaining: every finding that reaches
					// applyIgnore (AJV errors, crawl findings, SSRF findings) carries a
					// `params` object, so `?.` and a plain access are equivalent here; the
					// guard is defensive against a hypothetical param-less finding only.
					err.params?.incomplete === true ||
					(!ignore.has(err.instancePath) &&
						!ignore.has(`${err.instancePath}:${err.keyword}`)),
			);
		}
		return errs;
	};

	const sizeLimit =
		// Stryker disable next-line ConditionalExpression: when absent, Number(undefined)
		// = NaN, and `bytes > NaN` is false, matching the MAX_SCHEMA_SIZE default for any
		// schema small enough to test.
		options.maxSchemaSize != null
			? Number(options.maxSchemaSize)
			: MAX_SCHEMA_SIZE;
	let serialized;
	try {
		serialized = JSON.stringify(schema);
	} catch (err) {
		throw new TypeError(
			`schema must be JSON-serializable (circular reference?): ${err.message}`,
		);
	}
	if (
		// Stryker disable next-line ConditionalExpression: JSON.stringify only returns a
		// non-string (undefined) for undefined/function input, which a parsed schema
		// never is, so this defensive check is always true here.
		typeof serialized === "string" &&
		Buffer.byteLength(serialized) > sizeLimit
	) {
		throw new RangeError(`schema exceeds ${sizeLimit} byte size limit`);
	}

	const maxDepth =
		options.overrideMaxDepth != null
			? Number(options.overrideMaxDepth)
			: MAX_DEPTH;

	resolveDangerousNames(options.lang); // throws on unknown lang

	// Default budget first, then narrow it if the caller set one (avoids an else
	// branch whose only job is the default).
	let deadline = Date.now() + ANALYSIS_TIMEOUT_MS;
	// Stryker disable next-line ConditionalExpression: without the option,
	// Number(undefined)=NaN gives a NaN deadline that never fires, the same
	// observable result (no timeout) as the default budget within a fast test.
	if (options.analysisTimeoutMs != null) {
		const ms = Number(options.analysisTimeoutMs);
		deadline = ms <= 0 ? 0 : Date.now() + ms;
	}

	const crawl = crawlSchema(schema, maxDepth, {
		lang: options.lang,
		deadline,
		now: options.now,
	});

	// Depth and timeout signal INCOMPLETE analysis: the crawl bailed early and
	// AJV validation plus SSRF checks were skipped. They are deliberately NOT
	// passed through applyIgnore, because suppressing them would falsely report
	// a partially-analyzed schema as clean (empty errors, exit 0).
	if (crawl.depthExceeded) {
		return [
			{
				instancePath: "",
				schemaPath: "#/depth",
				keyword: "depth",
				params: { depth: crawl.depth, limit: maxDepth },
				message: `must NOT have depth greater than ${maxDepth}`,
			},
		];
	}

	if (crawl.timedOut) {
		return crawl.errors;
	}

	let errors = [];
	const validate = sast(schema);
	validate(schema);
	if (validate.errors) errors.push(...validate.errors);
	errors.push(...crawl.errors);

	if (!options.offline) {
		// Notify the caller (e.g. run(), to print a STDERR notice) of the remote
		// refs about to be DNS-resolved, BEFORE any lookup happens. Opt-in: absent
		// callback means no-op, keeping analyze() pure for library consumers.
		// Stryker disable next-line OptionalChaining: with no callback the ?. and a
		// plain call are equivalent (no observable effect) for library callers.
		options.onRemoteRefs?.(crawl.refs);
		const ssrfErrors = await resolveSSRFRefs(crawl.refs, {
			dnsTimeoutMs: options.dnsTimeoutMs,
			dnsConcurrency: options.dnsConcurrency,
			safeHostnames: options.safeHostnames,
			maxHostnames: options.maxHostnames,
			dnsTotalTimeoutMs: options.dnsTotalTimeoutMs,
			now: options.now,
		});
		errors.push(...ssrfErrors);
	}

	if (options.overrideMaxItems != null && errors.length) {
		const limit = Number(options.overrideMaxItems);
		errors = errors.filter((err) => {
			// Stryker disable next-line ConditionalExpression: treating a non-maxItems
			// error as maxItems still resolves a non-array instance, so !Array.isArray
			// keeps it — the same outcome as the `return true` fall-through.
			if (err.schemaPath === SCHEMA_PATH_MAX_ITEMS) {
				const arr = resolveInstancePath(schema, err.instancePath);
				return !Array.isArray(arr) || arr.length > limit;
			}
			return true;
		});
	}
	if (options.overrideMaxProperties != null && errors.length) {
		const limit = Number(options.overrideMaxProperties);
		errors = errors.filter((err) => {
			// Stryker disable next-line ConditionalExpression: as above, a non-target
			// error resolves to a non-object instance and is kept either way.
			if (err.schemaPath === SCHEMA_PATH_MAX_PROPERTIES) {
				const obj = resolveInstancePath(schema, err.instancePath);
				// a real maxProperties finding always resolves to a non-null object, so
				// these two defensive guards are false and the length check decides.
				return (
					// Stryker disable next-line ConditionalExpression,LogicalOperator
					typeof obj !== "object" ||
					// Stryker disable next-line ConditionalExpression
					obj === null ||
					Object.keys(obj).length > limit
				);
			}
			return true;
		});
	}
	return applyIgnore(errors);
};

// Maps the analyze() error array to SARIF 2.1.0. Designed for GitHub
// code-scanning, SonarQube, and other security pipelines that consume SARIF.
// instancePath is encoded as logicalLocations.fullyQualifiedName (JSON Pointer)
// since SARIF doesn't natively model JSON-pointer regions.
export const formatSarif = (errors, inputPath, cwd = process.cwd()) => {
	// GitHub code scanning / SonarQube match results to repo files via a path
	// RELATIVE to the repo root, so prefer a relative uri + SRCROOT uriBaseId
	// (resolvable via originalUriBaseIds). Only fall back to an absolute file://
	// uri when the input lives OUTSIDE cwd (relative would escape with "..").
	// Stryker disable next-line StringLiteral: relative() only yields backslash
	// separators on Windows; on the POSIX test platform the input never contains a
	// "\\", so this replacement is a no-op and the mutant is equivalent there.
	const relPath = relative(cwd, resolve(inputPath)).replaceAll("\\", "/");
	const insideCwd = relPath !== "" && !relPath.startsWith("../");
	const artifactLocation = insideCwd
		? { uri: relPath, uriBaseId: "SRCROOT" }
		: { uri: pathToFileURL(resolve(inputPath)).href };
	const ruleMap = new Map();
	for (const err of errors) {
		const ruleId = err.schemaPath
			? err.schemaPath.replace(/^#\//, "").split("/")[0] || err.keyword
			: (err.keyword ?? "unknown");
		if (!ruleMap.has(ruleId)) {
			ruleMap.set(ruleId, {
				id: ruleId,
				name: ruleId,
				shortDescription: { text: ruleId },
				fullDescription: { text: err.message ?? ruleId },
				defaultConfiguration: { level: "error" },
			});
		}
	}
	return {
		$schema:
			"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json",
		version: "2.1.0",
		runs: [
			{
				tool: {
					driver: {
						name: "sast-json-schema",
						informationUri: "https://github.com/willfarrell/sast-json-schema",
						version: pkg.version,
						rules: [...ruleMap.values()],
					},
				},
				...(insideCwd
					? {
							originalUriBaseIds: {
								SRCROOT: { uri: pathToFileURL(`${resolve(cwd)}/`).href },
							},
						}
					: {}),
				results: errors.map((err) => {
					const ruleId = err.schemaPath
						? err.schemaPath.replace(/^#\//, "").split("/")[0] || err.keyword
						: (err.keyword ?? "unknown");
					return {
						ruleId,
						level: "error",
						message: { text: err.message ?? err.keyword ?? "schema issue" },
						locations: [
							{
								physicalLocation: {
									artifactLocation,
								},
								logicalLocations: [
									{
										fullyQualifiedName: err.instancePath ?? "",
										kind: "value",
									},
								],
							},
						],
						properties: {
							instancePath: err.instancePath ?? "",
							schemaPath: err.schemaPath ?? "",
							keyword: err.keyword ?? "",
							...(err.params ?? {}),
						},
					};
				}),
			},
		],
	};
};

// --- CLI entrypoint ---

// Thrown by `die` to unwind to run()'s handler with an exit code, instead of
// calling process.exit (which would make the entrypoint untestable in-process).
class CliExit extends Error {
	constructor(code) {
		// Stryker disable next-line StringLiteral: this sentinel's message is never
		// read (only .code is), so its exact text is unobservable.
		super(`cli exit ${code}`);
		this.code = code;
	}
}

// Parses argv, reads the schema file, runs analyze(), and writes the report.
// Returns the exit code (0 = no issues, 1 = issues, 2 = usage/tool error). All
// I/O is injectable via `io` ({ log, error, write, readFile, stat }) so the whole
// entrypoint is unit-testable without spawning a subprocess.
export const run = async (argv, io = {}) => {
	const log = io.log ?? ((m) => console.log(m));
	const errorLog = io.error ?? ((m) => console.error(m));
	const write = io.write ?? ((s) => process.stdout.write(s));
	const readFileFn = io.readFile ?? readFile;
	const statFn = io.stat ?? stat;

	const die = (msg) => {
		errorLog(`Error: ${msg}`);
		throw new CliExit(2);
	};

	const readJsonFile = async (filePath, label) => {
		let content;
		try {
			// Stryker disable next-line StringLiteral: JSON.parse coerces a Buffer the
			// same as a string, so the "utf8" encoding hint is not observable here.
			content = await readFileFn(filePath, "utf8");
		} catch (err) {
			die(`cannot read ${label}: ${err.message}`);
		}
		try {
			return JSON.parse(content);
		} catch {
			die(`invalid JSON in ${label}`);
		}
	};

	try {
		let values;
		let positionals;
		try {
			({ values, positionals } = parseArgs({
				args: argv,
				allowPositionals: true,
				options: {
					"override-max-items": { type: "string" },
					"override-max-depth": { type: "string" },
					"override-max-properties": { type: "string" },
					"max-schema-size": { type: "string" },
					"analysis-timeout-ms": { type: "string" },
					"max-ssrf-hostnames": { type: "string" },
					"dns-total-timeout-ms": { type: "string" },
					ignore: { type: "string", multiple: true },
					offline: { type: "boolean", default: false },
					lang: { type: "string", default: DEFAULT_LANG },
					format: { type: "string", default: "human" },
					"ref-schema-files": { type: "string", multiple: true, short: "r" },
					version: { type: "boolean", short: "v", default: false },
					help: { type: "boolean", short: "h", default: false },
				},
			}));
		} catch (err) {
			die(err.message);
		}

		if (values.help) {
			log(`Usage: sast-json-schema [options] <file>

Options:
  --override-max-items <n>         Override max items limit (default: 1024)
  --override-max-depth <n>         Override max depth limit (default: 32)
  --override-max-properties <n>    Override max properties limit (default: 1024)
  --max-schema-size <bytes>        Max serialized schema size in bytes (default: 67108864 = 64 MiB)
  --analysis-timeout-ms <ms>       Wall-clock budget for the schema crawl (default: 60000)
  --max-ssrf-hostnames <n>         Max distinct remote $ref hostnames resolved for SSRF (default: 256)
  --dns-total-timeout-ms <ms>      Total budget for all SSRF DNS lookups (default: 30000)
  --ignore <instancePath>          Suppress errors by instancePath or instancePath:keyword (repeatable).
                                   Depth and timeout findings cannot be suppressed (they mean analysis was incomplete)
  --offline                        Skip SSRF DNS resolution for remote $ref URLs
  -r, --ref-schema-files <file>    Load a reference schema; its $id hostname is treated as safe
                                   and skipped during SSRF DNS checks (repeatable)
  --lang <default|js|py|rb|rs|java|kotlin|clojure|cs|vb|fsharp|php|objc|swift|ex|lua>
                                   Downstream language whose deserialization-vector names
                                   to deny in property keys. "default" is the union of
                                   every named language. (default: default)
  --format <human|json|sarif>      Output format. "sarif" emits SARIF 2.1.0 for
                                   GitHub code-scanning / SonarQube / Semgrep (default: human)
  -v, --version                    Show version
  -h, --help                       Show this help

Exit codes:
  0    no issues found
  1    schema has issues, including depth-exceeded, analysis timeout, and SSRF hostname-cap / DNS-budget findings
  2    usage / tool error: bad args, unreadable file, invalid JSON, unsupported $schema, oversized schema, or non-JSON-serializable (circular) schema`);
			return 0;
		}

		if (values.version) {
			log(pkg.version);
			return 0;
		}

		if (
			values.format !== "human" &&
			values.format !== "json" &&
			values.format !== "sarif"
		) {
			die(
				`--format must be "human", "json", or "sarif", got "${values.format}"`,
			);
		}

		if (!Object.hasOwn(DANGEROUS_NAMES_BY_LANG, values.lang)) {
			die(
				`--lang must be one of: ${Object.keys(DANGEROUS_NAMES_BY_LANG).join(", ")}, got "${values.lang}"`,
			);
		}

		const input = positionals[0];
		if (!input) die("missing required argument <file>");

		const filePath = resolve(input);
		let fileStat;
		try {
			fileStat = await statFn(filePath);
		} catch (err) {
			die(`cannot read file "${input}": ${err.message}`);
		}
		// Only enforce --max-schema-size at the file gate when it parses to a valid
		// non-negative integer. For invalid values (e.g. 3.5 or a negative), fall
		// back to the default here and let analyze() raise the proper validation
		// error instead of a misleading "file exceeds N byte" message.
		const parsedMaxSchemaSize =
			// Stryker disable next-line ConditionalExpression: when absent, Number(undefined)
			// = NaN, which the !Number.isInteger guard below rejects to MAX just like null does.
			values["max-schema-size"] != null
				? Number(values["max-schema-size"])
				: null;
		const fileSizeLimit =
			// Stryker disable next-line ConditionalExpression: the != null head is
			// redundant with Number.isInteger(null) === false on the next line.
			parsedMaxSchemaSize != null &&
			Number.isInteger(parsedMaxSchemaSize) &&
			parsedMaxSchemaSize >= 0
				? parsedMaxSchemaSize
				: MAX_SCHEMA_SIZE;
		if (fileStat.size > fileSizeLimit) {
			die(`schema file exceeds ${fileSizeLimit} byte size limit: "${input}"`);
		}
		const schema = await readJsonFile(filePath, `file "${input}"`);

		const safeHostnames = new Set();
		if (values["ref-schema-files"]) {
			for (const refFile of values["ref-schema-files"]) {
				const refSchema = await readJsonFile(
					resolve(refFile),
					`--ref-schema-files file "${refFile}"`,
				);
				// Stryker disable next-line ConditionalExpression: a non-string $id makes
				// `new URL` throw into the catch below, so skipping vs trying is the same.
				if (typeof refSchema.$id === "string") {
					try {
						const url = new URL(refSchema.$id);
						// Stryker disable next-line ConditionalExpression: an empty hostname
						// is never a real $ref host, so adding "" to the safe set is a no-op.
						if (url.hostname) safeHostnames.add(url.hostname);
					} catch {}
				}
			}
		}

		// Pass options straight through; analyze() already treats undefined (an
		// absent flag) as "use the default" via its own `!= null` guards, so a
		// conditional copy here would only add equivalent-mutant noise.
		const options = {
			offline: values.offline,
			lang: values.lang,
			overrideMaxItems: values["override-max-items"],
			overrideMaxDepth: values["override-max-depth"],
			overrideMaxProperties: values["override-max-properties"],
			maxSchemaSize: values["max-schema-size"],
			analysisTimeoutMs: values["analysis-timeout-ms"],
			maxHostnames: values["max-ssrf-hostnames"],
			dnsTotalTimeoutMs: values["dns-total-timeout-ms"],
			ignore: values.ignore,
			safeHostnames,
			// Resolving attacker-controlled hostnames from an untrusted schema is a
			// blind-SSRF / DNS-exfil amplifier. Warn on STDERR (never STDOUT, to keep
			// json/sarif output clean) right before DNS runs, but only when there is
			// at least one non-safe remote hostname to resolve.
			onRemoteRefs: (refs) => {
				const hostnames = new Set();
				for (const { hostname } of refs) {
					if (!safeHostnames.has(hostname)) hostnames.add(hostname);
				}
				if (hostnames.size > 0) {
					errorLog(
						`note: resolving ${hostnames.size} remote $ref hostname(s) via DNS; pass --offline to skip`,
					);
				}
			},
		};

		let errors;
		try {
			errors = await analyze(schema, options);
		} catch (err) {
			die(`analyzing schema "${input}": ${err.message}`);
		}

		if (values.format === "json") {
			write(`${JSON.stringify(errors)}\n`);
			if (errors.length) {
				errorLog(`${input} has ${errors.length} issue(s)`);
				return 1;
			}
			return 0;
		}
		if (values.format === "sarif") {
			write(`${JSON.stringify(formatSarif(errors, input))}\n`);
			if (errors.length) {
				errorLog(`${input} has ${errors.length} issue(s)`);
				return 1;
			}
			return 0;
		}
		if (errors.length) {
			log(`${input} has issues`);
			log(JSON.stringify(errors, null, 2));
			return 1;
		}
		log(`${input} has no issues`);
		return 0;
	} catch (err) {
		if (err instanceof CliExit) return err.code;
		throw err;
	}
};

// Stryker disable ConditionalExpression,LogicalOperator,BlockStatement,MethodExpression: the
// main-module guard and its body only run when cli.js IS the process entry, which the
// in-process tests (which import run() directly) never are; the spawned subprocess in
// cli.test.js exercises it but perTest cannot attribute that coverage back here.
if (process.argv[1] && resolve(process.argv[1]) === import.meta.filename) {
	process.exitCode = await run(process.argv.slice(2));
}
// Stryker restore all
