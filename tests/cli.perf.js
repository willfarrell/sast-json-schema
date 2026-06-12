import test from "node:test";
import { Bench } from "tinybench";
import { analyze, crawlSchema, MAX_DEPTH } from "../cli.js";

// Benchmarks the ANALYSIS ENGINE (analyze / crawlSchema), the code that ingests
// untrusted input. Like index.perf.js these are tracked numbers, not gated
// thresholds: the suite only fails if a benchmark throws. All runs use
// offline:true so no network/DNS occurs.

test("perf: analyze engine benchmarks", async () => {
	const suite = new Bench({ name: "sast-json-schema-engine" });

	const smallCleanSchema = {
		$schema: "https://json-schema.org/draft/2020-12/schema",
		type: "object",
		properties: {
			name: { type: "string", maxLength: 100, pattern: "^[a-z]+$" },
			age: { type: "integer", minimum: 0, maximum: 150 },
		},
		required: ["name"],
		unevaluatedProperties: false,
	};

	// 200 distinct SIMPLE, safe patternProperties keys. This is the regression
	// watch for the heap circuit breaker: analyze() calls process.memoryUsage()
	// before EVERY pattern, so this case measures that per-pattern overhead on a
	// realistic many-pattern schema that should never trip the breaker.
	const manyPatternProps = {};
	for (let i = 0; i < 200; i++) {
		// Each pattern is distinct and trivially safe (anchored literal prefix).
		manyPatternProps[`^k${i}_[a-z0-9]{1,8}$`] = {
			type: "string",
			maxLength: 64,
		};
	}
	const manyPatternsSchema = {
		$schema: "https://json-schema.org/draft/2020-12/schema",
		type: "object",
		patternProperties: manyPatternProps,
	};

	// A linear chain of nested object properties reaching close to MAX_DEPTH.
	// Each `properties`+child level adds two depth steps, so build ~MAX_DEPTH-2
	// levels to stay just under the bail cap (so the full tree is crawled).
	const buildDeepSchema = (levels) => {
		let node = { type: "string", maxLength: 10 };
		for (let i = 0; i < levels; i++) {
			node = {
				type: "object",
				properties: { child: node },
			};
		}
		return node;
	};
	const deepSchema = buildDeepSchema(Math.floor((MAX_DEPTH - 2) / 2));

	suite
		.add("analyze small clean schema", async () => {
			await analyze(smallCleanSchema, { offline: true });
		})
		.add(
			"analyze 200 simple patternProperties (heap-breaker watch)",
			async () => {
				await analyze(manyPatternsSchema, { offline: true });
			},
		)
		.add("crawlSchema deeply-nested schema near MAX_DEPTH", () => {
			crawlSchema(deepSchema);
		});

	await suite.run();
	console.table(suite.table());
});
