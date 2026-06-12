import { ok, rejects, strictEqual } from "node:assert";
import { describe, test } from "node:test";
import { run } from "../cli.js";
import pkg from "../package.json" with { type: "json" };

// Drives the CLI entrypoint in-process with injected I/O, so the whole arg
// parsing / file reading / output formatting path is unit-testable (the spawned
// subprocess tests in cli.test.js can't attribute coverage to it).
const CLEAN = JSON.stringify({
	$schema: "https://json-schema.org/draft/2020-12/schema",
	$id: "https://example.test/clean.json",
	type: "string",
	maxLength: 10,
	pattern: "^[a-z]+$",
});
const DIRTY = JSON.stringify({
	$schema: "https://json-schema.org/draft/2020-12/schema",
	$id: "https://example.test/dirty.json",
	type: "string",
});

// files: map matched by path suffix -> file content; sizes: suffix -> byte size.
const runCli = async (argv, { files = {}, sizes = {} } = {}) => {
	const out = { log: [], error: [], write: [] };
	const match = (map, p) => {
		const key = Object.keys(map).find((k) => p.endsWith(k));
		return key === undefined ? undefined : map[key];
	};
	const io = {
		log: (m) => out.log.push(String(m)),
		error: (m) => out.error.push(String(m)),
		write: (s) => out.write.push(String(s)),
		readFile: async (p) => {
			const c = match(files, p);
			if (c === undefined) {
				const e = new Error(`ENOENT: no such file, open '${p}'`);
				throw e;
			}
			return c;
		},
		stat: async (p) => {
			const s = match(sizes, p);
			if (s === undefined) {
				if (match(files, p) !== undefined)
					return { size: match(files, p).length };
				throw new Error(`ENOENT: no such file, stat '${p}'`);
			}
			return { size: s };
		},
	};
	const code = await run(argv, io);
	return { code, ...out };
};

describe("run() argument handling", () => {
	test("--help prints usage and exits 0", async () => {
		const r = await runCli(["--help"]);
		strictEqual(r.code, 0);
		ok(r.log.join("\n").includes("Usage: sast-json-schema [options] <file>"));
		ok(r.log.join("\n").includes("--format <human|json|sarif>"));
	});

	test("-h is the help alias", async () => {
		const r = await runCli(["-h"]);
		strictEqual(r.code, 0);
		ok(r.log.join("\n").includes("Usage:"));
	});

	test("--version prints the package version and exits 0", async () => {
		const r = await runCli(["--version"]);
		strictEqual(r.code, 0);
		strictEqual(r.log.join(""), pkg.version);
	});

	test("-v is the version alias", async () => {
		const r = await runCli(["-v"]);
		strictEqual(r.code, 0);
		strictEqual(r.log.join(""), pkg.version);
	});

	test("an unknown flag is a usage error (exit 2)", async () => {
		const r = await runCli(["--no-such-flag", "x.json"]);
		strictEqual(r.code, 2);
		ok(r.error.join("\n").startsWith("Error: "));
	});

	test("an invalid --format is rejected", async () => {
		const r = await runCli(["--format", "xml", "x.json"]);
		strictEqual(r.code, 2);
		ok(
			r.error
				.join("\n")
				.includes('--format must be "human", "json", or "sarif", got "xml"'),
		);
	});

	test("an invalid --lang is rejected", async () => {
		const r = await runCli(["--lang", "elvish", "x.json"]);
		strictEqual(r.code, 2);
		ok(r.error.join("\n").includes("--lang must be one of"));
		ok(r.error.join("\n").includes('got "elvish"'));
	});

	test("a missing file argument is a usage error", async () => {
		const r = await runCli([]);
		strictEqual(r.code, 2);
		ok(r.error.join("\n").includes("missing required argument <file>"));
	});
});

describe("run() file handling", () => {
	test("an unreadable file exits 2", async () => {
		const r = await runCli(["missing.json"]);
		strictEqual(r.code, 2);
		ok(r.error.join("\n").includes('cannot read file "missing.json"'));
	});

	test("invalid JSON in the file exits 2", async () => {
		const r = await runCli(["bad.json"], {
			files: { "bad.json": "{not json" },
		});
		strictEqual(r.code, 2);
		ok(r.error.join("\n").includes('invalid JSON in file "bad.json"'));
	});

	test("a file larger than the size limit exits 2 at the gate", async () => {
		const r = await runCli(["big.json", "--max-schema-size", "10"], {
			files: { "big.json": CLEAN },
			sizes: { "big.json": 100 },
		});
		strictEqual(r.code, 2);
		ok(r.error.join("\n").includes("schema file exceeds 10 byte size limit"));
	});

	test("an invalid --max-schema-size defers to analyze (no misleading gate error)", async () => {
		// 3.5 is invalid; the file gate falls back to the default and lets analyze()
		// raise the TypeError, surfaced as an "analyzing schema" error.
		const r = await runCli(["s.json", "--max-schema-size", "3.5"], {
			files: { "s.json": CLEAN },
			sizes: { "s.json": 50 },
		});
		strictEqual(r.code, 2);
		ok(r.error.join("\n").includes("analyzing schema"));
		ok(r.error.join("\n").includes("maxSchemaSize"));
	});

	test("an unsupported $schema surfaces as an analyze error (exit 2)", async () => {
		const r = await runCli(["s.json"], {
			files: { "s.json": JSON.stringify({ $schema: "http://bogus/v1" }) },
		});
		strictEqual(r.code, 2);
		ok(r.error.join("\n").includes("analyzing schema"));
	});
});

describe("run() output formats", () => {
	test("a clean schema reports no issues and exits 0 (human)", async () => {
		const r = await runCli(["clean.json", "--offline"], {
			files: { "clean.json": CLEAN },
		});
		strictEqual(r.code, 0);
		ok(r.log.join("\n").includes("clean.json has no issues"));
	});

	test("a schema with issues exits 1 (human)", async () => {
		const r = await runCli(["dirty.json", "--offline"], {
			files: { "dirty.json": DIRTY },
		});
		strictEqual(r.code, 1);
		ok(r.log.join("\n").includes("dirty.json has issues"));
		// the human format dumps the error array as pretty JSON
		ok(r.log.join("\n").includes("instancePath"));
	});

	test("json format with no issues writes [] and exits 0", async () => {
		const r = await runCli(["clean.json", "--offline", "--format", "json"], {
			files: { "clean.json": CLEAN },
		});
		strictEqual(r.code, 0);
		strictEqual(r.write.join("").trim(), "[]");
		strictEqual(r.error.length, 0);
	});

	test("json format with issues writes the array and exits 1", async () => {
		const r = await runCli(["dirty.json", "--offline", "--format", "json"], {
			files: { "dirty.json": DIRTY },
		});
		strictEqual(r.code, 1);
		const parsed = JSON.parse(r.write.join(""));
		ok(Array.isArray(parsed) && parsed.length > 0);
		ok(r.error.join("\n").includes("issue(s)"));
	});

	test("sarif format with issues writes SARIF 2.1.0 and exits 1", async () => {
		const r = await runCli(["dirty.json", "--offline", "--format", "sarif"], {
			files: { "dirty.json": DIRTY },
		});
		strictEqual(r.code, 1);
		const sarif = JSON.parse(r.write.join(""));
		strictEqual(sarif.version, "2.1.0");
		ok(sarif.runs[0].results.length > 0);
		ok(r.error.join("\n").includes("issue(s)"));
	});

	test("sarif format with no issues writes an empty-results SARIF and exits 0", async () => {
		const r = await runCli(["clean.json", "--offline", "--format", "sarif"], {
			files: { "clean.json": CLEAN },
		});
		strictEqual(r.code, 0);
		const sarif = JSON.parse(r.write.join(""));
		strictEqual(sarif.runs[0].results.length, 0);
		strictEqual(r.error.length, 0);
	});
});

describe("run() option plumbing", () => {
	test("--ignore suppresses a matching finding", async () => {
		const dirty = await runCli(["d.json", "--offline"], {
			files: { "d.json": DIRTY },
		});
		strictEqual(dirty.code, 1);
		// Discover an instancePath to ignore, then suppress it.
		const errs = JSON.parse(
			(
				await runCli(["d.json", "--offline", "--format", "json"], {
					files: { "d.json": DIRTY },
				})
			).write.join(""),
		);
		const target = errs[0].instancePath;
		const r = await runCli(
			["d.json", "--offline", "--format", "json", "--ignore", target],
			{ files: { "d.json": DIRTY } },
		);
		const remaining = JSON.parse(r.write.join(""));
		ok(!remaining.some((e) => e.instancePath === target));
	});

	test("--ref-schema-files marks its $id hostname safe (skips that SSRF host)", async () => {
		const schema = JSON.stringify({
			$schema: "https://json-schema.org/draft/2020-12/schema",
			$id: "https://example.test/root.json",
			$ref: "https://safe-ref-host.invalid/x.json",
		});
		const refSchema = JSON.stringify({
			$id: "https://safe-ref-host.invalid/ref.json",
		});
		const r = await runCli(
			[
				"s.json",
				"--dns-total-timeout-ms",
				"0",
				"--format",
				"json",
				"-r",
				"ref.json",
			],
			{ files: { "s.json": schema, "ref.json": refSchema } },
		);
		const errs = JSON.parse(r.write.join(""));
		ok(
			!errs.some((e) => e.keyword === "ssrf"),
			"the ref-schema-files $id hostname must be treated as safe",
		);
	});

	test("a non-URL $id in a ref-schema-file is ignored (no crash)", async () => {
		const schema = JSON.stringify({
			$schema: "https://json-schema.org/draft/2020-12/schema",
			$id: "https://example.test/root.json",
			type: "string",
			maxLength: 5,
			pattern: "^[a-z]+$",
		});
		const r = await runCli(["s.json", "--offline", "-r", "ref.json"], {
			files: {
				"s.json": schema,
				"ref.json": JSON.stringify({ $id: "not-a-url" }),
			},
		});
		strictEqual(r.code, 0);
	});
});

const ENUM_BIG = JSON.stringify({
	$schema: "https://json-schema.org/draft/2020-12/schema",
	$id: "https://example.test/enum.json",
	type: "string",
	maxLength: 100,
	enum: Array.from({ length: 2000 }, (_, i) => `v${i}`),
});
const PROPS_BIG = (() => {
	const props = {};
	for (let i = 0; i < 1100; i++)
		props[`p${i}`] = { type: "string", maxLength: 10, pattern: "^[a-z]+$" };
	return JSON.stringify({
		$schema: "https://json-schema.org/draft/2020-12/schema",
		$id: "https://example.test/props.json",
		type: "object",
		properties: props,
		required: ["p0"],
		unevaluatedProperties: false,
		maxProperties: 2000,
	});
})();
const REMOTE = JSON.stringify({
	$schema: "https://json-schema.org/draft/2020-12/schema",
	$id: "https://example.test/remote.json",
	$ref: "https://run-ssrf-host.invalid/x.json",
});

const jsonErrors = (r) => JSON.parse(r.write.join(""));

// Re-uses the runCli helper and CLEAN/DIRTY fixtures defined above.
describe("run() default I/O wiring", () => {
	test("--version uses the default logger (no injected io)", async () => {
		strictEqual(await run(["--version"]), 0);
	});
	test("an arg error uses the default error logger", async () => {
		strictEqual(await run(["--nope", "x.json"]), 2);
	});
	test("reading a real fixture uses default readFile/stat/write", async () => {
		// No io injected: exercises the real fs + process.stdout.write defaults.
		const code = await run([
			"tests/fixtures/boolean.json",
			"--offline",
			"--format",
			"json",
		]);
		ok(code === 0 || code === 1, `expected 0 or 1, got ${code}`);
	});
});

describe("run() readJsonFile read failure", () => {
	test("a file that stats but cannot be read exits 2", async () => {
		// stat succeeds (size provided) but readFile has no entry -> throws.
		const r = await runCli(["x.json"], { sizes: { "x.json": 10 } });
		strictEqual(r.code, 2);
		ok(r.error.join("\n").includes('cannot read file "x.json"'));
	});
});

describe("run() offline defaults to false", () => {
	test("a remote $ref is SSRF-checked when --offline is omitted", async () => {
		const r = await runCli(
			["s.json", "--dns-total-timeout-ms", "0", "--format", "json"],
			{ files: { "s.json": REMOTE } },
		);
		ok(
			jsonErrors(r).some((e) => e.keyword === "ssrf"),
			"default (non-offline) run must perform the SSRF check",
		);
	});
});

describe("run() --lang error lists the languages", () => {
	test("the error enumerates langs comma-separated", async () => {
		const r = await runCli(["--lang", "elvish", "x.json"]);
		ok(r.error.join("\n").includes("js, py"));
	});
});

describe("run() file-size gate boundaries", () => {
	test("--max-schema-size 0 fails at the gate (not analyze)", async () => {
		const r = await runCli(["s.json", "--max-schema-size", "0"], {
			files: { "s.json": CLEAN },
			sizes: { "s.json": 50 },
		});
		strictEqual(r.code, 2);
		ok(r.error.join("\n").includes("schema file exceeds 0 byte size limit"));
	});
	test("a negative --max-schema-size defers to analyze", async () => {
		// `=` form so parseArgs reads -1 as the value, not a flag.
		const r = await runCli(["s.json", "--max-schema-size=-1"], {
			files: { "s.json": CLEAN },
			sizes: { "s.json": 50 },
		});
		strictEqual(r.code, 2);
		ok(r.error.join("\n").includes("analyzing schema"));
	});
	test("a file exactly at the limit passes the gate (strict >)", async () => {
		const size = CLEAN.length;
		const r = await runCli(["s.json", "--max-schema-size", String(size)], {
			files: { "s.json": CLEAN },
			sizes: { "s.json": size },
		});
		strictEqual(r.code, 0);
		ok(r.log.join("\n").includes("no issues"));
	});
});

describe("run() override option plumbing", () => {
	test("--override-max-items is forwarded to analyze", async () => {
		const without = jsonErrors(
			await runCli(["e.json", "--offline", "--format", "json"], {
				files: { "e.json": ENUM_BIG },
			}),
		);
		ok(without.some((x) => x.keyword === "maxItems"));
		const withOv = jsonErrors(
			await runCli(
				[
					"e.json",
					"--offline",
					"--format",
					"json",
					"--override-max-items",
					"5000",
				],
				{ files: { "e.json": ENUM_BIG } },
			),
		);
		ok(!withOv.some((x) => x.keyword === "maxItems"));
	});

	test("--override-max-properties is forwarded to analyze", async () => {
		const withOv = jsonErrors(
			await runCli(
				[
					"p.json",
					"--offline",
					"--format",
					"json",
					"--override-max-properties",
					"5000",
				],
				{ files: { "p.json": PROPS_BIG } },
			),
		);
		ok(!withOv.some((x) => x.keyword === "maxProperties"));
	});

	test("--override-max-depth is forwarded to analyze", async () => {
		// a nested schema so maxDepth 0 actually trips depth-exceeded.
		const nested = JSON.stringify({
			$schema: "https://json-schema.org/draft/2020-12/schema",
			$id: "https://example.test/nested.json",
			type: "object",
			properties: { a: { type: "string", maxLength: 10, pattern: "^[a-z]+$" } },
			required: ["a"],
			unevaluatedProperties: false,
			maxProperties: 5,
		});
		const r = await runCli(
			["c.json", "--offline", "--format", "json", "--override-max-depth", "0"],
			{ files: { "c.json": nested } },
		);
		ok(jsonErrors(r).some((x) => x.keyword === "depth"));
	});

	test("--analysis-timeout-ms is forwarded to analyze", async () => {
		const r = await runCli(
			["c.json", "--offline", "--format", "json", "--analysis-timeout-ms", "0"],
			{ files: { "c.json": CLEAN } },
		);
		ok(jsonErrors(r).some((x) => x.keyword === "timeout"));
	});

	test("--max-ssrf-hostnames is forwarded to analyze", async () => {
		const r = await runCli(
			["s.json", "--format", "json", "--max-ssrf-hostnames", "0"],
			{ files: { "s.json": REMOTE } },
		);
		const ssrf = jsonErrors(r).find((x) => x.keyword === "ssrf");
		ok(ssrf, "max-ssrf-hostnames 0 must trip the hostname cap");
		ok(ssrf.message.includes("too many distinct"));
	});
});

describe("run() propagates unexpected (non-CliExit) errors", () => {
	test("an io error during output is not swallowed", async () => {
		await rejects(
			run(["clean.json", "--offline"], {
				readFile: async () => CLEAN,
				stat: async () => ({ size: CLEAN.length }),
				log: () => {
					throw new Error("boom");
				},
			}),
		);
	});
});

describe("run() default I/O actually writes to the console", () => {
	test("default log goes to console.log", async () => {
		const orig = console.log;
		const cap = [];
		console.log = (m) => cap.push(String(m));
		try {
			await run(["--version"]);
		} finally {
			console.log = orig;
		}
		ok(cap.join("").includes(pkg.version));
	});

	test("default error goes to console.error", async () => {
		const orig = console.error;
		const cap = [];
		console.error = (m) => cap.push(String(m));
		try {
			await run(["--bad-flag", "x.json"]);
		} finally {
			console.error = orig;
		}
		ok(cap.join("").startsWith("Error: "));
	});

	test("default write goes to process.stdout.write", async () => {
		const orig = process.stdout.write;
		const cap = [];
		process.stdout.write = (s) => {
			cap.push(String(s));
			return true;
		};
		try {
			await run([
				"tests/fixtures/boolean.json",
				"--offline",
				"--format",
				"json",
			]);
		} finally {
			process.stdout.write = orig;
		}
		// the test runner also writes to stdout, so look for the JSON chunk.
		ok(cap.some((s) => s.trimStart().startsWith("[")));
	});
});

describe("run() ref-schema-files and dns budget specifics", () => {
	test("an unreadable --ref-schema-files file errors with its label", async () => {
		const r = await runCli(["s.json", "--offline", "-r", "no-ref.json"], {
			files: {
				"s.json": JSON.stringify({
					$schema: "https://json-schema.org/draft/2020-12/schema",
					$id: "https://example.test/s.json",
					type: "string",
					maxLength: 5,
					pattern: "^[a-z]+$",
				}),
			},
		});
		strictEqual(r.code, 2);
		ok(
			r.error
				.join("\n")
				.includes('cannot read --ref-schema-files file "no-ref.json"'),
		);
	});

	test("--dns-total-timeout-ms 0 produces a budget-exceeded ssrf finding", async () => {
		const r = await runCli(
			["s.json", "--dns-total-timeout-ms", "0", "--format", "json"],
			{ files: { "s.json": REMOTE } },
		);
		const ssrf = jsonErrors(r).find((e) => e.keyword === "ssrf");
		ok(ssrf, "expected an ssrf finding");
		ok(
			ssrf.message.includes("budget"),
			"dnsTotalTimeoutMs:0 must fail closed on the budget (proves the key is read)",
		);
	});

	test("without --max-schema-size a normal file passes the size gate", async () => {
		const r = await runCli(["clean.json", "--offline"], {
			files: { "clean.json": CLEAN },
		});
		strictEqual(r.code, 0);
		ok(!r.error.join("\n").includes("byte size limit"));
	});
});
