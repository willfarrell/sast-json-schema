#!/usr/bin/env node
// Copyright 2026 will Farrell, and sast-json-schema contributors.
// SPDX-License-Identifier: MIT
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
let defsLib;
try {
	defsLib = JSON.parse(readFileSync(`${root}/src/$defs.json`, "utf8"));
} catch (err) {
	console.error(`Error loading src/$defs.json: ${err.message}`);
	process.exit(1);
}
const drafts = ["draft-04", "draft-06", "draft-07", "2019-09", "2020-12"];
const outputs = [];
const REF_PREFIX = "#/$defs/";

const collectRefs = (node, acc) => {
	if (Array.isArray(node)) {
		for (const child of node) collectRefs(child, acc);
		return;
	}
	if (node === null || typeof node !== "object") return;
	for (const [k, v] of Object.entries(node)) {
		if (k === "$ref" && typeof v === "string" && v.startsWith(REF_PREFIX)) {
			acc.add(v.slice(REF_PREFIX.length));
		} else {
			collectRefs(v, acc);
		}
	}
};

for (const draft of drafts) {
	let src;
	let manifest;
	try {
		src = readFileSync(`${root}/src/${draft}.json`, "utf8");
		manifest = JSON.parse(src);
	} catch (err) {
		console.error(`Error loading src/${draft}.json: ${err.message}`);
		process.exit(1);
	}
	const authored =
		manifest.$defs &&
		typeof manifest.$defs === "object" &&
		!Array.isArray(manifest.$defs)
			? { ...manifest.$defs }
			: {};

	const needed = new Set();
	collectRefs(manifest, needed);
	const seen = new Set();
	let grew = true;
	while (grew) {
		grew = false;
		for (const name of [...needed]) {
			if (seen.has(name)) continue;
			seen.add(name);
			const entry = authored[name] ?? defsLib[name];
			if (entry === undefined)
				throw new Error(`${draft}: unknown $defs entry "${name}"`);
			const before = needed.size;
			collectRefs(entry, needed);
			if (needed.size > before) grew = true;
		}
	}
	const finalDefs = {};
	for (const name of [...needed].sort()) {
		finalDefs[name] = authored[name] ?? defsLib[name];
	}
	manifest.$defs = finalDefs;
	const outPath = `${root}/${draft}.json`;
	writeFileSync(outPath, `${JSON.stringify(manifest, null, "\t")}\n`);
	outputs.push(outPath);
	console.log(
		`built ${draft}.json (${Object.keys(finalDefs).length} defs, ${Object.keys(authored).length} local)`,
	);
}

execFileSync("npx", ["biome", "format", "--write", ...outputs], {
	cwd: root,
	stdio: "inherit",
});
