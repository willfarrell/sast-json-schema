// Copyright 2026 will Farrell, and sast-json-schema contributors.
// SPDX-License-Identifier: MIT
import { isSafePattern } from "redos-detector";

export const MAX_DEPTH = 32;

// Checks whether a numeric schema's min/max bounds describe an impossible
// range. Returns an AJV-style error object when they do, or null otherwise.
const checkNumericRange = (current, path) => {
	const hasMin = Object.hasOwn(current, "minimum");
	const hasExMin =
		Object.hasOwn(current, "exclusiveMinimum") &&
		typeof current.exclusiveMinimum === "number";
	const hasMax = Object.hasOwn(current, "maximum");
	const hasExMax =
		Object.hasOwn(current, "exclusiveMaximum") &&
		typeof current.exclusiveMaximum === "number";

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

	return {
		instancePath: path,
		schemaPath: "#/minimum",
		keyword: "minimum",
		params: {
			...(hasMin && { minimum: current.minimum }),
			...(hasExMin && { exclusiveMinimum: current.exclusiveMinimum }),
			...(hasMax && { maximum: current.maximum }),
			...(hasExMax && { exclusiveMaximum: current.exclusiveMaximum }),
		},
		message: "minimum must be less than maximum",
	};
};

// Single-pass crawler that records: max depth, range/length inconsistencies,
// ReDoS patterns, and remote $ref URLs (for later SSRF resolution).
// Depth semantics: each object-valued key counts as one level, so a schema
// `{properties: {a: {properties: {b: {...}}}}}` reaches depth 5 (root,
// properties, a, properties, b). With MAX_DEPTH=32 this corresponds to roughly
// 16 levels of real schema nesting.
export const crawlSchema = (obj, maxDepth = MAX_DEPTH) => {
	const result = { depth: 0, depthExceeded: false, errors: [], refs: [] };
	if (typeof obj !== "object" || obj === null) return result;

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
				const patternResult = isSafePattern(current.pattern);
				if (!patternResult.safe) {
					result.errors.push({
						instancePath: `${path}/pattern`,
						schemaPath: "#/redos",
						keyword: "pattern",
						params: { pattern: current.pattern },
						message: "pattern is vulnerable to ReDoS",
					});
				}
			} catch {
				result.errors.push({
					instancePath: `${path}/pattern`,
					schemaPath: "#/redos",
					keyword: "pattern",
					params: { pattern: current.pattern },
					message: "pattern could not be parsed for ReDoS analysis",
				});
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
				if (typeof value === "object" && value !== null) {
					const newDepth = currentDepth + 1;
					if (newDepth > result.depth) result.depth = newDepth;
					if (result.depth > maxDepth) {
						result.depthExceeded = true;
						return result;
					}
					stack.push([value, `${path}/${key}`, newDepth]);
				}
			}
		}
	}

	return result;
};
