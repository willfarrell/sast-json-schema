#!/usr/bin/env node
// Copyright 2026 will Farrell, and sast-json-schema contributors.
// SPDX-License-Identifier: MIT
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { parseArgs } from "node:util";
import Ajv from "ajv/dist/2020.js";
import schema201909 from "./2019-09.json" with { type: "json" };
import schema202012 from "./2020-12.json" with { type: "json" };
import schemaDraft04 from "./draft-04.json" with { type: "json" };
import schemaDraft06 from "./draft-06.json" with { type: "json" };
import schemaDraft07 from "./draft-07.json" with { type: "json" };
import { crawlSchema, MAX_DEPTH } from "./lib/crawl.js";
import { resolveSSRFRefs } from "./lib/ssrf.js";

export { crawlSchema, MAX_DEPTH } from "./lib/crawl.js";
export { isPrivateIP, resolveSSRFRefs } from "./lib/ssrf.js";

const defaultOptions = {
	strictTypes: false,
	allErrors: true,
};

const DEFAULT_VERSION = "2020-12";

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

// Known $schema URLs mapped to their draft version.
const knownSchemaUrls = new Map([
	["https://json-schema.org/draft/2020-12/schema", "2020-12"],
	["https://json-schema.org/draft/2019-09/schema", "2019-09"],
	["http://json-schema.org/draft-07/schema#", "draft-07"],
	["http://json-schema.org/draft-07/schema", "draft-07"],
	["http://json-schema.org/draft-06/schema#", "draft-06"],
	["http://json-schema.org/draft-06/schema", "draft-06"],
	["http://json-schema.org/draft-04/schema#", "draft-04"],
	["http://json-schema.org/draft-04/schema", "draft-04"],
]);

// Maps a user schema's $schema URL to the matching draft version.
const schemaVersion = (url) => {
	if (!url) return DEFAULT_VERSION;
	return knownSchemaUrls.get(url);
};

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
	if (
		options.overrideMaxDepth != null &&
		Number.isNaN(Number(options.overrideMaxDepth))
	) {
		throw new TypeError("overrideMaxDepth must be a number");
	}
	if (
		options.overrideMaxItems != null &&
		Number.isNaN(Number(options.overrideMaxItems))
	) {
		throw new TypeError("overrideMaxItems must be a number");
	}
	if (
		options.overrideMaxProperties != null &&
		Number.isNaN(Number(options.overrideMaxProperties))
	) {
		throw new TypeError("overrideMaxProperties must be a number");
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

	const ssrfErrors = await resolveSSRFRefs(crawl.refs);
	errors.push(...ssrfErrors);

	if (options.overrideMaxItems != null && errors.length) {
		const limit = Number(options.overrideMaxItems);
		errors = errors.filter((err) => {
			if (err.schemaPath === "#/$defs/safeArrayItemsLimits/maxItems") {
				const arr = resolveInstancePath(schema, err.instancePath);
				return !Array.isArray(arr) || arr.length > limit;
			}
			return true;
		});
	}
	if (options.overrideMaxProperties != null && errors.length) {
		const limit = Number(options.overrideMaxProperties);
		errors = errors.filter((err) => {
			if (
				err.schemaPath === "#/$defs/safeObjectPropertiesLimits/maxProperties"
			) {
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
if (process.argv[1] === import.meta.filename) {
	const { values, positionals } = parseArgs({
		allowPositionals: true,
		options: {
			output: { type: "string", short: "o" },
			"override-max-items": { type: "string" },
			"override-max-depth": { type: "string" },
			"override-max-properties": { type: "string" },
			ignore: { type: "string", multiple: true },
			version: { type: "boolean", short: "v", default: false },
			help: { type: "boolean", short: "h", default: false },
		},
	});

	if (values.help) {
		console.log(`Usage: sast-json-schema [options] <file>

Options:
  -o, --output <path>              Write issues to JSON file
  --override-max-items <n>         Override max items limit (default: 1024)
  --override-max-depth <n>         Override max depth limit (default: 32)
  --override-max-properties <n>    Override max properties limit (default: 1024)
  --ignore <instancePath>          Suppress errors by instancePath or instancePath:keyword (repeatable)
  -v, --version                    Show version
  -h, --help                       Show this help`);
		process.exit(0);
	}

	if (values.version) {
		const { createRequire } = await import("node:module");
		const require = createRequire(import.meta.url);
		const pkg = require("./package.json");
		console.log(pkg.version);
		process.exit(0);
	}

	const input = positionals[0];
	if (!input) {
		console.error("Error: missing required argument <file>");
		process.exit(1);
	}

	const filePath = resolve(input);
	let content;
	try {
		content = await readFile(filePath, "utf8");
	} catch (err) {
		console.error(`Error: cannot read file "${input}": ${err.message}`);
		process.exit(1);
	}
	let schema;
	try {
		schema = JSON.parse(content);
	} catch (err) {
		console.error(`Error: invalid JSON in "${input}": ${err.message}`);
		process.exit(1);
	}

	const options = {};
	if (values["override-max-items"] != null)
		options.overrideMaxItems = values["override-max-items"];
	if (values["override-max-depth"] != null)
		options.overrideMaxDepth = values["override-max-depth"];
	if (values["override-max-properties"] != null)
		options.overrideMaxProperties = values["override-max-properties"];
	if (values.ignore) options.ignore = values.ignore;

	const errors = await analyze(schema, options);

	if (errors.length) {
		if (values.output) {
			await writeFile(values.output, JSON.stringify(errors, null, 2), "utf8");
		} else {
			console.log(input, "has issues", JSON.stringify(errors, null, 2));
		}
		process.exit(1);
	} else {
		console.log(input, "has no issues");
	}
}
