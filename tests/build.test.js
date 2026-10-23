import { doesNotThrow, strictEqual, throws } from "node:assert";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
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
		doesNotThrow(() => verifyRefs(schema, "ok.json"));
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
		doesNotThrow(() => verifyRefs(schema, "ignore.json"));
	});

	test("resolves #/definitions/ pointers against definitions", () => {
		const ok = {
			definitions: { a: { type: "string" } },
			properties: { x: { $ref: "#/definitions/a" } },
		};
		doesNotThrow(() => verifyRefs(ok, "defs-ok.json"));
		const bad = {
			definitions: { a: { type: "string" } },
			properties: { x: { $ref: "#/definitions/missing" } },
		};
		throws(() => verifyRefs(bad, "defs-bad.json"), /#\/definitions\/missing/);
	});
});

describe("build", () => {
	// The built meta-schemas are gitignored artifacts; building them must not
	// depend on npm/npx being on PATH (e.g. a bare node container). The test
	// builds into a temp dir: rewriting the repo's copies would race the other
	// test files, which import them concurrently.
	test("runs with only node available (empty PATH), into a given dir", () => {
		const out = mkdtempSync(join(tmpdir(), "sast-build-"));
		try {
			const r = spawnSync(process.execPath, ["bin/build.js", out], {
				cwd: new URL("..", import.meta.url),
				env: { PATH: "" },
				encoding: "utf8",
			});
			strictEqual(r.status, 0, r.stderr);
			const built = JSON.parse(readFileSync(join(out, "2020-12.json"), "utf8"));
			strictEqual(built.$id, "urn:willfarrell:sast-json-schema:2020-12");
		} finally {
			rmSync(out, { recursive: true, force: true });
		}
	});
});
