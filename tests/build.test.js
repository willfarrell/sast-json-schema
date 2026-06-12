import { strictEqual, throws } from "node:assert";
import { describe, test } from "node:test";
import { verifyRefs } from "../bin/build.js";

describe("verifyRefs", () => {
	test("passes when every $defs ref resolves", () => {
		const schema = {
			$defs: {
				a: { type: "string" },
				b: { $ref: "#/$defs/a" },
			},
			properties: {
				x: { $ref: "#/$defs/b" },
			},
		};
		strictEqual(verifyRefs(schema, "ok.json"), undefined);
	});

	test("throws naming the dangling pointer", () => {
		const schema = {
			$defs: { a: { type: "string" } },
			properties: { x: { $ref: "#/$defs/nope" } },
		};
		throws(
			() => verifyRefs(schema, "bad.json"),
			(err) => {
				strictEqual(err instanceof Error, true);
				strictEqual(err.message.includes("#/$defs/nope"), true);
				strictEqual(err.message.includes("bad.json"), true);
				return true;
			},
		);
	});

	test("finds refs nested in properties, allOf arrays, and items", () => {
		const schema = {
			$defs: { present: { type: "string" } },
			allOf: [{ properties: { y: { items: { $ref: "#/$defs/missing" } } } }],
		};
		throws(() => verifyRefs(schema, "nested.json"), /#\/\$defs\/missing/);
	});

	test("ignores non-local refs (http and #/properties)", () => {
		const schema = {
			$defs: { a: { type: "string" } },
			properties: {
				x: { $ref: "http://example.com/other.json#/$defs/whatever" },
				y: { $ref: "#/properties/x" },
			},
		};
		strictEqual(verifyRefs(schema, "ignore.json"), undefined);
	});

	test("resolves #/definitions/ pointers against definitions", () => {
		const ok = {
			definitions: { a: { type: "string" } },
			properties: { x: { $ref: "#/definitions/a" } },
		};
		strictEqual(verifyRefs(ok, "defs-ok.json"), undefined);
		const bad = {
			definitions: { a: { type: "string" } },
			properties: { x: { $ref: "#/definitions/missing" } },
		};
		throws(() => verifyRefs(bad, "defs-bad.json"), /#\/definitions\/missing/);
	});
});
