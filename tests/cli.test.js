import { ok, strictEqual } from "node:assert";
import { execFile } from "node:child_process";
import { describe, test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const cliPath = fileURLToPath(new URL("../cli.js", import.meta.url));

const runCli = async (args, { cwd } = {}) => {
	try {
		const { stdout, stderr } = await execFileAsync("node", [cliPath, ...args], {
			cwd,
		});
		return { code: 0, stdout, stderr };
	} catch (err) {
		return {
			code: err.code ?? 1,
			stdout: err.stdout ?? "",
			stderr: err.stderr ?? "",
		};
	}
};

describe("cli.", () => {
	test("--help prints usage and exits 0", async () => {
		const r = await runCli(["--help"]);
		strictEqual(r.code, 0);
		ok(r.stdout.includes("Usage: sast-json-schema"));
		ok(r.stdout.includes("--offline"));
		ok(r.stdout.includes("--format"));
	});

	test("--help documents exit codes", async () => {
		const r = await runCli(["--help"]);
		strictEqual(r.code, 0);
		ok(r.stdout.includes("Exit codes"));
		ok(/0\b.*no issues/i.test(r.stdout));
		ok(/1\b.*issues/i.test(r.stdout));
		ok(/2\b.*(usage|tool)/i.test(r.stdout));
	});

	test("--version prints a semver-looking string", async () => {
		const r = await runCli(["--version"]);
		strictEqual(r.code, 0);
		ok(/^\d+\.\d+\.\d+/.test(r.stdout.trim()));
	});

	test("missing file argument exits 2", async () => {
		const r = await runCli([]);
		strictEqual(r.code, 2);
		ok(r.stderr.includes("missing required argument"));
	});

	test("nonexistent file exits 2", async () => {
		const r = await runCli(["--offline", "/tmp/does-not-exist-xyz.json"]);
		strictEqual(r.code, 2);
		ok(r.stderr.includes("cannot read file"));
	});

	test("oversized file is rejected before being read", async () => {
		const { mkdtemp, open } = await import("node:fs/promises");
		const { tmpdir } = await import("node:os");
		const { join } = await import("node:path");
		const { MAX_SCHEMA_SIZE } = await import("../cli.js");
		const dir = await mkdtemp(join(tmpdir(), "sast-test-"));
		const path = join(dir, "oversize.json");
		const fh = await open(path, "w");
		try {
			await fh.truncate(MAX_SCHEMA_SIZE + 1);
		} finally {
			await fh.close();
		}
		const r = await runCli(["--offline", path]);
		strictEqual(r.code, 2);
		ok(r.stderr.includes("exceeds"));
	});

	test("invalid JSON exits 2", async () => {
		const { writeFile, mkdtemp } = await import("node:fs/promises");
		const { tmpdir } = await import("node:os");
		const { join } = await import("node:path");
		const dir = await mkdtemp(join(tmpdir(), "sast-test-"));
		const path = join(dir, "bad.json");
		await writeFile(path, "{not json");
		const r = await runCli(["--offline", path]);
		strictEqual(r.code, 2);
		ok(r.stderr.includes("invalid JSON"));
	});

	test("invalid JSON error does not leak parser internals", async () => {
		const { writeFile, mkdtemp } = await import("node:fs/promises");
		const { tmpdir } = await import("node:os");
		const { join } = await import("node:path");
		const dir = await mkdtemp(join(tmpdir(), "sast-test-"));
		const path = join(dir, "bad.json");
		await writeFile(path, "{not json");
		const r = await runCli(["--offline", path]);
		strictEqual(r.code, 2);
		ok(!/position\s+\d+/i.test(r.stderr));
		ok(!/line\s+\d+/i.test(r.stderr));
	});

	test("unsupported $schema exits 2", async () => {
		const { writeFile, mkdtemp } = await import("node:fs/promises");
		const { tmpdir } = await import("node:os");
		const { join } = await import("node:path");
		const dir = await mkdtemp(join(tmpdir(), "sast-test-"));
		const path = join(dir, "unsupported.json");
		await writeFile(
			path,
			JSON.stringify({ $schema: "https://example.com/unknown" }),
		);
		const r = await runCli(["--offline", path]);
		strictEqual(r.code, 2);
		ok(r.stderr.includes("Unsupported $schema"));
	});

	test("invalid --format value exits 2", async () => {
		const r = await runCli(["--format", "xml", "foo.json"]);
		strictEqual(r.code, 2);
		ok(r.stderr.includes("--format"));
	});

	test("--format json emits a JSON array on stdout", async () => {
		const { writeFile, mkdtemp } = await import("node:fs/promises");
		const { tmpdir } = await import("node:os");
		const { join } = await import("node:path");
		const dir = await mkdtemp(join(tmpdir(), "sast-test-"));
		const path = join(dir, "insecure.json");
		await writeFile(
			path,
			JSON.stringify({
				$schema: "https://json-schema.org/draft/2020-12/schema",
				$id: "test",
				type: "string",
			}),
		);
		const r = await runCli(["--offline", "--format", "json", path]);
		strictEqual(r.code, 1);
		const parsed = JSON.parse(r.stdout);
		ok(Array.isArray(parsed));
		ok(parsed.length > 0);
	});

	test("--format sarif emits a SARIF 2.1.0 log on stdout", async () => {
		const { writeFile, mkdtemp } = await import("node:fs/promises");
		const { tmpdir } = await import("node:os");
		const { join } = await import("node:path");
		const dir = await mkdtemp(join(tmpdir(), "sast-test-"));
		const path = join(dir, "insecure.json");
		await writeFile(
			path,
			JSON.stringify({
				$schema: "https://json-schema.org/draft/2020-12/schema",
				$id: "test",
				type: "string",
			}),
		);
		const r = await runCli(["--offline", "--format", "sarif", path]);
		strictEqual(r.code, 1);
		const parsed = JSON.parse(r.stdout);
		strictEqual(parsed.version, "2.1.0");
		ok(Array.isArray(parsed.runs) && parsed.runs.length === 1);
		const run = parsed.runs[0];
		strictEqual(run.tool.driver.name, "sast-json-schema");
		ok(typeof run.tool.driver.version === "string");
		ok(Array.isArray(run.tool.driver.rules));
		ok(Array.isArray(run.results) && run.results.length > 0);
		const result = run.results[0];
		ok(typeof result.ruleId === "string");
		strictEqual(result.level, "error");
		ok(typeof result.message.text === "string");
		ok(result.locations[0].physicalLocation.artifactLocation.uri.startsWith("file://"));
		ok(typeof result.locations[0].logicalLocations[0].fullyQualifiedName === "string");
	});

	test("clean schema with --offline exits 0", async () => {
		const { writeFile, mkdtemp } = await import("node:fs/promises");
		const { tmpdir } = await import("node:os");
		const { join } = await import("node:path");
		const dir = await mkdtemp(join(tmpdir(), "sast-test-"));
		const path = join(dir, "clean.json");
		await writeFile(
			path,
			JSON.stringify({
				$schema: "https://json-schema.org/draft/2020-12/schema",
				$id: "test",
				type: "string",
				maxLength: 10,
				pattern: "^[a-z]+$",
			}),
		);
		const r = await runCli(["--offline", path]);
		strictEqual(r.code, 0);
		ok(r.stdout.includes("has no issues"));
	});

	test("--override-max-depth with non-integer exits 2", async () => {
		const { writeFile, mkdtemp } = await import("node:fs/promises");
		const { tmpdir } = await import("node:os");
		const { join } = await import("node:path");
		const dir = await mkdtemp(join(tmpdir(), "sast-test-"));
		const path = join(dir, "schema.json");
		await writeFile(
			path,
			JSON.stringify({
				$schema: "https://json-schema.org/draft/2020-12/schema",
				$id: "test",
				type: "string",
				maxLength: 10,
				pattern: "^[a-z]+$",
			}),
		);
		const r = await runCli(["--offline", "--override-max-depth", "3.5", path]);
		strictEqual(r.code, 2);
		ok(r.stderr.includes("non-negative integer"));
	});

	test("--override-max-depth with negative value exits 2", async () => {
		const { writeFile, mkdtemp } = await import("node:fs/promises");
		const { tmpdir } = await import("node:os");
		const { join } = await import("node:path");
		const dir = await mkdtemp(join(tmpdir(), "sast-test-"));
		const path = join(dir, "schema.json");
		await writeFile(
			path,
			JSON.stringify({
				$schema: "https://json-schema.org/draft/2020-12/schema",
				$id: "test",
				type: "string",
				maxLength: 10,
				pattern: "^[a-z]+$",
			}),
		);
		const r = await runCli(["--offline", "--override-max-depth", "-1", path]);
		strictEqual(r.code, 2);
	});

	test("--override-max-depth 0 reports depth error", async () => {
		const { writeFile, mkdtemp } = await import("node:fs/promises");
		const { tmpdir } = await import("node:os");
		const { join } = await import("node:path");
		const dir = await mkdtemp(join(tmpdir(), "sast-test-"));
		const path = join(dir, "schema.json");
		await writeFile(
			path,
			JSON.stringify({
				$schema: "https://json-schema.org/draft/2020-12/schema",
				$id: "test",
				type: "object",
				properties: {
					a: { type: "string", maxLength: 10, pattern: "^[a-z]+$" },
				},
				required: ["a"],
				unevaluatedProperties: false,
				maxProperties: 5,
			}),
		);
		const r = await runCli(["--offline", "--override-max-depth", "0", path]);
		strictEqual(r.code, 1);
	});

	test("--ignore can be repeated to suppress multiple paths", async () => {
		const { writeFile, mkdtemp } = await import("node:fs/promises");
		const { tmpdir } = await import("node:os");
		const { join } = await import("node:path");
		const dir = await mkdtemp(join(tmpdir(), "sast-test-"));
		const path = join(dir, "schema.json");
		await writeFile(
			path,
			JSON.stringify({
				type: "object",
				properties: {
					a: { type: "string", maxLength: 10, pattern: "[a-z]+\\w+" },
					b: { type: "string", maxLength: 10, pattern: "[a-z]+\\w+" },
				},
				required: ["a", "b"],
				maxProperties: 10,
				unevaluatedProperties: false,
			}),
		);
		const r = await runCli([
			"--offline",
			"--format",
			"json",
			"--ignore",
			"/properties/a/pattern",
			"--ignore",
			"/properties/b/pattern",
			path,
		]);
		const errors = JSON.parse(r.stdout);
		ok(!errors.some((e) => e.instancePath.includes("/pattern")));
	});
});
