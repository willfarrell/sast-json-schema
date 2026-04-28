#!/usr/bin/env node
// Copyright 2026 will Farrell, and sast-json-schema contributors.
// SPDX-License-Identifier: MIT
import { lookup as dnsLookup } from "node:dns/promises";
import { readFile, stat } from "node:fs/promises";
import { resolve } from "node:path";
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
	const normalized = url.replace(/^(?:https?:)?\/\//, "").replace(/#$/, "");
	return knownSchemaUrls.get(normalized);
};

export const MAX_DEPTH = 32;
export const MAX_SCHEMA_SIZE = 64 * 1024 * 1024; // 64 MiB
// Per-pattern budget for ReDoS analysis. Patterns that exceed this are
// fail-closed (reported as unsafe with reason "timedOut") to keep total
// scan time bounded on adversarial input.
export const REDOS_TIMEOUT_MS = 1_000;

// Names with prototype semantics in V8. Property keys (or patternProperties
// regex keys that match these literals) can be vectors for prototype pollution
// in downstream validators that copy keys onto plain objects.
const PROTOTYPE_POLLUTION_NAMES = ["__proto__", "constructor", "prototype"];

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
		throw new Error(`Unsupported $schema: ${schema?.$schema}`);
	}
	return validate;
};

export default sast;

// Checks whether a numeric schema's min/max bounds describe an impossible
// range. Returns an AJV-style error object when they do, or null otherwise.
const checkNumericRange = (current, path) => {
	const hasMin =
		Object.hasOwn(current, "minimum") &&
		typeof current.minimum === "number" &&
		Number.isFinite(current.minimum);
	const hasExMin =
		Object.hasOwn(current, "exclusiveMinimum") &&
		typeof current.exclusiveMinimum === "number" &&
		Number.isFinite(current.exclusiveMinimum);
	const hasMax =
		Object.hasOwn(current, "maximum") &&
		typeof current.maximum === "number" &&
		Number.isFinite(current.maximum);
	const hasExMax =
		Object.hasOwn(current, "exclusiveMaximum") &&
		typeof current.exclusiveMaximum === "number" &&
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
export const crawlSchema = (obj, maxDepth = MAX_DEPTH) => {
	const result = { depth: 0, depthExceeded: false, errors: [], refs: [] };
	if (typeof obj !== "object" || obj === null) return result;

	const visited = new WeakSet();
	visited.add(obj);
	result.depth = 1;
	const stack = [[obj, "", 1]];

	while (stack.length > 0) {
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
			try {
				const patternResult = isSafePattern(current.pattern, {
					timeout: REDOS_TIMEOUT_MS,
				});
				if (!patternResult.safe) {
					const reason = patternResult.error ?? "hitMaxScore";
					const message =
						reason === "timedOut"
							? `pattern analysis timed out after ${REDOS_TIMEOUT_MS}ms (fail-closed as ReDoS)`
							: reason === "hitMaxSteps"
								? "pattern analysis exceeded step limit (fail-closed as ReDoS)"
								: "pattern is vulnerable to ReDoS";
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

		if (
			Object.hasOwn(current, "patternProperties") &&
			typeof current.patternProperties === "object" &&
			current.patternProperties !== null
		) {
			for (const patternKey of Object.keys(current.patternProperties)) {
				try {
					const re = new RegExp(patternKey);
					const matches = PROTOTYPE_POLLUTION_NAMES.filter((n) => re.test(n));
					if (matches.length > 0) {
						result.errors.push({
							instancePath: `${path}/patternProperties/${escapeJsonPointer(patternKey)}`,
							schemaPath: "#/prototype-pollution",
							keyword: "patternProperties",
							params: { pattern: patternKey, matches },
							message: `patternProperties key "${patternKey}" matches prototype-pollution-prone name(s): ${matches.join(", ")}`,
						});
					}
				} catch {
					// unparseable regex — safePattern at the meta-schema layer rejects it
				}
			}
		}

		if (
			Object.hasOwn(current, "$ref") &&
			typeof current.$ref === "string" &&
			!current.$ref.startsWith("#")
		) {
			try {
				const url = new URL(current.$ref);
				if (url.hostname) {
					result.refs.push({
						hostname: url.hostname,
						ref: current.$ref,
						path: `${path}/$ref`,
					});
				}
			} catch {
				// not a valid URL, skip
			}
		}

		for (const key in current) {
			if (Object.hasOwn(current, key)) {
				const value = current[key];
				if (
					typeof value === "object" &&
					value !== null &&
					!visited.has(value)
				) {
					visited.add(value);
					const newDepth = currentDepth + 1;
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
// Used to block $ref URLs whose hostname resolves to an internal/private IP.
// Fail-closed: malformed IPv6 (e.g. invalid hex groups, wrong group count)
// returns false, but the upstream DNS lookup will already have rejected such
// addresses; we only see well-formed IPs here. Tests in cli.ip.test.js pin
// the boundary cases.
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
			if (groups[0].startsWith("fc") || groups[0].startsWith("fd")) return true; // unique local
			if (groups[0].startsWith("fe80")) return true; // link-local
			if (groups[0].startsWith("ff")) return true; // multicast
			// IPv4-mapped with hex groups (e.g. 0:0:0:0:0:ffff:7f00:1)
			if (normalized.startsWith("0:0:0:0:0:ffff:")) {
				const hi = Number.parseInt(groups[6], 16);
				const lo = Number.parseInt(groups[7], 16);
				const mappedIP = `${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`;
				return isPrivateIP(mappedIP);
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
	const timeoutMs = options.dnsTimeoutMs ?? DNS_TIMEOUT_MS;
	const concurrency = options.dnsConcurrency ?? DNS_CONCURRENCY;
	const hostnameMap = new Map();
	for (const entry of refs) {
		if (!hostnameMap.has(entry.hostname)) {
			hostnameMap.set(entry.hostname, []);
		}
		hostnameMap.get(entry.hostname).push(entry);
	}

	const results = [];
	const batches = [...hostnameMap.entries()];
	for (let i = 0; i < batches.length; i += concurrency) {
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

const resolveInstancePath = (obj, pointer) => {
	if (typeof obj !== "object" || obj === null) return undefined;
	if (!pointer) return obj;
	const parts = pointer
		.split("/")
		.slice(1)
		.map((p) => p.replace(/~1/g, "/").replace(/~0/g, "~"));
	let current = obj;
	for (const part of parts) {
		if (typeof current !== "object" || current === null) return undefined;
		if (!Object.hasOwn(current, part)) return undefined;
		current = current[part];
	}
	return current;
};

// Runs a full SAST analysis on `schema`. Returns an array of AJV-style error
// objects. Never touches the filesystem, never prints, never exits the process.
export const analyze = async (schema, options = {}) => {
	if (options.overrideMaxDepth != null) {
		const n = Number(options.overrideMaxDepth);
		if (!Number.isFinite(n) || n < 0 || !Number.isInteger(n)) {
			throw new TypeError("overrideMaxDepth must be a non-negative integer");
		}
	}
	if (options.overrideMaxItems != null) {
		const n = Number(options.overrideMaxItems);
		if (!Number.isFinite(n) || n < 0 || !Number.isInteger(n)) {
			throw new TypeError("overrideMaxItems must be a non-negative integer");
		}
	}
	if (options.overrideMaxProperties != null) {
		const n = Number(options.overrideMaxProperties);
		if (!Number.isFinite(n) || n < 0 || !Number.isInteger(n)) {
			throw new TypeError(
				"overrideMaxProperties must be a non-negative integer",
			);
		}
	}

	const maxDepth =
		options.overrideMaxDepth != null
			? Number(options.overrideMaxDepth)
			: MAX_DEPTH;

	const crawl = crawlSchema(schema, maxDepth);

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

	let errors = [];
	const validate = sast(schema);
	validate(schema);
	if (validate.errors) errors.push(...validate.errors);
	errors.push(...crawl.errors);

	if (!options.offline) {
		const ssrfErrors = await resolveSSRFRefs(crawl.refs, {
			dnsTimeoutMs: options.dnsTimeoutMs,
			dnsConcurrency: options.dnsConcurrency,
		});
		errors.push(...ssrfErrors);
	}

	if (options.overrideMaxItems != null && errors.length) {
		const limit = Number(options.overrideMaxItems);
		errors = errors.filter((err) => {
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
			if (err.schemaPath === SCHEMA_PATH_MAX_PROPERTIES) {
				const obj = resolveInstancePath(schema, err.instancePath);
				if (typeof obj !== "object" || obj === null) return true;
				return Object.keys(obj).length > limit;
			}
			return true;
		});
	}
	if (Array.isArray(options.ignore) && options.ignore.length && errors.length) {
		const ignore = new Set(options.ignore);
		errors = errors.filter((err) => {
			const pathKey = err.instancePath;
			const keywordKey = `${err.instancePath}:${err.keyword}`;
			return !ignore.has(pathKey) && !ignore.has(keywordKey);
		});
	}

	return errors;
};

// --- CLI entrypoint ---
if (process.argv[1] && resolve(process.argv[1]) === import.meta.filename) {
	const die = (msg) => {
		console.error(`Error: ${msg}`);
		process.exit(2);
	};

	let values;
	let positionals;
	try {
		({ values, positionals } = parseArgs({
			allowPositionals: true,
			options: {
				"override-max-items": { type: "string" },
				"override-max-depth": { type: "string" },
				"override-max-properties": { type: "string" },
				ignore: { type: "string", multiple: true },
				offline: { type: "boolean", default: false },
				format: { type: "string", default: "human" },
				version: { type: "boolean", short: "v", default: false },
				help: { type: "boolean", short: "h", default: false },
			},
		}));
	} catch (err) {
		die(err.message);
	}

	if (values.help) {
		console.log(`Usage: sast-json-schema [options] <file>

Options:
  --override-max-items <n>         Override max items limit (default: 1024)
  --override-max-depth <n>         Override max depth limit (default: 32)
  --override-max-properties <n>    Override max properties limit (default: 1024)
  --ignore <instancePath>          Suppress errors by instancePath or instancePath:keyword (repeatable)
  --offline                        Skip SSRF DNS resolution for remote $ref URLs
  --format <human|json>            Output format (default: human)
  -v, --version                    Show version
  -h, --help                       Show this help

Exit codes:
  0    no issues found
  1    schema has issues
  2    usage / tool error`);
		process.exit(0);
	}

	if (values.version) {
		console.log(pkg.version);
		process.exit(0);
	}

	if (values.format !== "human" && values.format !== "json") {
		die(`--format must be "human" or "json", got "${values.format}"`);
	}

	const input = positionals[0];
	if (!input) die("missing required argument <file>");

	const filePath = resolve(input);
	let fileStat;
	try {
		fileStat = await stat(filePath);
	} catch (err) {
		die(`cannot read file "${input}": ${err.message}`);
	}
	if (fileStat.size > MAX_SCHEMA_SIZE) {
		die(`schema file exceeds ${MAX_SCHEMA_SIZE} byte limit: "${input}"`);
	}
	let content;
	try {
		content = await readFile(filePath, "utf8");
	} catch (err) {
		die(`cannot read file "${input}": ${err.message}`);
	}
	let schema;
	try {
		schema = JSON.parse(content);
	} catch {
		die(`invalid JSON in "${input}"`);
	}

	const options = { offline: values.offline };
	if (values["override-max-items"] != null)
		options.overrideMaxItems = values["override-max-items"];
	if (values["override-max-depth"] != null)
		options.overrideMaxDepth = values["override-max-depth"];
	if (values["override-max-properties"] != null)
		options.overrideMaxProperties = values["override-max-properties"];
	if (values.ignore) options.ignore = values.ignore;

	let errors;
	try {
		errors = await analyze(schema, options);
	} catch (err) {
		die(`analyzing schema "${input}": ${err.message}`);
	}

	if (values.format === "json") {
		process.stdout.write(`${JSON.stringify(errors)}\n`);
		if (errors.length) {
			console.error(`${input} has ${errors.length} issue(s)`);
			process.exit(1);
		}
	} else if (errors.length) {
		console.log(`${input} has issues`);
		console.log(JSON.stringify(errors, null, 2));
		process.exit(1);
	} else {
		console.log(`${input} has no issues`);
	}
}
