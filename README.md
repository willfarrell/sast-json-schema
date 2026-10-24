<div align="center">

<h1>sast-json-schema</h1>
<p>Meta-schema for the Static Application Security Testing (SAST) of JSON Schemas</p>
<br />
<p>
  <a href="https://github.com/willfarrell/sast-json-schema/actions/workflows/test-unit.yml"><img src="https://github.com/willfarrell/sast-json-schema/actions/workflows/test-unit.yml/badge.svg" alt="GitHub Actions unit test status"></a>
  <a href="https://github.com/willfarrell/sast-json-schema/actions/workflows/test-dast.yml"><img src="https://github.com/willfarrell/sast-json-schema/actions/workflows/test-dast.yml/badge.svg" alt="GitHub Actions dast test status"></a>
  <a href="https://github.com/willfarrell/sast-json-schema/actions/workflows/test-bench.yml"><img src="https://github.com/willfarrell/sast-json-schema/actions/workflows/test-bench.yml/badge.svg" alt="GitHub Actions bench test status"></a>
  <a href="https://github.com/willfarrell/sast-json-schema/actions/workflows/test-sast.yml"><img src="https://github.com/willfarrell/sast-json-schema/actions/workflows/test-sast.yml/badge.svg" alt="GitHub Actions SAST test status"></a>
  <a href="https://github.com/willfarrell/sast-json-schema/actions/workflows/test-lint.yml"><img src="https://github.com/willfarrell/sast-json-schema/actions/workflows/test-lint.yml/badge.svg" alt="GitHub Actions lint test status"></a>
  <br/>
  <a href="https://www.npmjs.com/package/sast-json-schema"><img alt="npm version" src="https://img.shields.io/npm/v/sast-json-schema.svg"></a>
  <a href="https://packagephobia.com/result?p=sast-json-schema"><img src="https://packagephobia.com/badge?p=sast-json-schema" alt="npm install size"></a>
  <a href="https://www.npmjs.com/package/sast-json-schema">
  <img alt="npm weekly downloads" src="https://img.shields.io/npm/dw/sast-json-schema.svg"></a>
  <a href="https://www.npmjs.com/package/sast-json-schema#provenance">
  <img alt="npm provenance" src="https://img.shields.io/badge/provenance-Yes-brightgreen"></a>
  <br/>
  <a href="https://scorecard.dev/viewer/?uri=github.com/willfarrell/sast-json-schema"><img src="https://api.scorecard.dev/projects/github.com/willfarrell/sast-json-schema/badge" alt="Open Source Security Foundation (OpenSSF) Scorecard"></a>
  <a href="https://slsa.dev"><img src="https://slsa.dev/images/gh-badge-level3.svg" alt="SLSA 3"></a>
  <a href="https://biomejs.dev"><img alt="Checked with Biome" src="https://img.shields.io/badge/Checked_with-Biome-60a5fa?style=flat&logo=biome"></a>
  <a href="https://conventionalcommits.org"><img alt="Conventional Commits" src="https://img.shields.io/badge/Conventional%20Commits-1.0.0-%23FE5196?logo=conventionalcommits&logoColor=white"></a>
</p>
</div>

## High-level functionality

- Ensure strictness of interpretation.
- Ensure `integer` or `number` are within a safe range.
- Ensure `string` have defined allowed values, and `maxLength`.
- Ensure `arrays` have defined properties and maxItems.
- Ensure `object` have defined properties and maxProperties when needed.
- An `object` or `array` whose value is pinned by `const` or `enum` needs no further strictness keywords.
- Ensure `pattern` follow safe RegExp usage.
- Ensure `$id` and `$refs` resolve safely.

## Installation

Requires **Node.js >=26**.

```bash
npm install sast-json-schema
```

## How to run

### Manually

```javascript
import Ajv from "ajv/dist/2020.js"
import sastSchema from "sast-json-schema" with { type: "json" }
import schema from "path/to/schema.json" with { type: "json" }

// Your schema should compile under strictTypes:true. validateSchema() does
// not apply strictTypes; only compile() does.
const userAjv = new Ajv({ strictTypes: true })
try {
  userAjv.compile(schema)
} catch (err) {
  console.error(err.message)
}

// The meta-schema itself uses strictTypes:false because it validates
// subschemas that may legally be `false` (boolean-schema form).
const sastAjv = new Ajv({ strictTypes: false })
const isSchemaSecure = sastAjv.compile(sastSchema)
if (!isSchemaSecure(schema)) {
  console.error(isSchemaSecure.errors)
}
```

Per-draft entry points are also exported: `sast-json-schema/2020-12`, `/2019-09`, `/draft-07`, `/draft-06`, `/draft-04`. These are JSON exports, so they require an import attribute:

```javascript
import schema2020 from "sast-json-schema/2020-12" with { type: "json" }
```

Each meta-schema is identified by a `urn:willfarrell:sast-json-schema:<spec>` URN. Shared primitives (`safePattern`, `safeUrl`, etc.) are available via `sast-json-schema/$defs`.

Every meta-schema requires a root `$schema` and a root `$id` (`id` in draft-04). A root with no `type`, `const`, `$ref` or combinator is accepted only as a definitions library: metadata plus a non-empty `$defs`/`definitions` map.

### Library API

The CLI's analysis (meta-schema plus the checks a meta-schema cannot express: ReDoS, SSRF DNS, dangerous property names, unsatisfiable ranges, regex anchoring and control characters) is available as a function:

```javascript
import { analyze, formatSarif } from "sast-json-schema/cli"

const errors = await analyze(schema, { offline: true, lang: "js" })
// errors: AJV-style { instancePath, schemaPath, keyword, params, message }[]
```

`analyze()` never prints or exits. It throws on a tool error (unsupported `$schema`, oversized or non-serializable schema, invalid option). Options mirror the CLI flags in camelCase: `offline`, `lang`, `ignore` (array), `safeHostnames` (Set), `overrideMaxDepth`, `overrideMaxItems`, `overrideMaxProperties`, `maxSchemaSize`, `analysisTimeoutMs`, `maxHostnames`, `dnsTotalTimeoutMs`, `redosTimeoutMs`, `redosHeapBudgetBytes`, `maxRedosPatterns`. When `$schema` is absent, the 2020-12 meta-schema is used (and reports the missing `$schema`).

### `$schema` must use https

Every meta-schema requires `$schema` to be the `https://json-schema.org/...` URI without a trailing `#`, for example `https://json-schema.org/draft-07/schema`. The CLI maps the `http://` and `#` spellings to the right draft and then reports the value as a finding. AJV registers the draft-04/06/07 meta-schemas under their original `http://...#` identifiers, so register the https identifier as an alias before compiling a classic-draft schema:

```javascript
import Ajv from "ajv"

const ajv = new Ajv()
ajv.addMetaSchema({
  $id: "https://json-schema.org/draft-07/schema",
  $ref: "http://json-schema.org/draft-07/schema#",
})
```

### CLI

```bash
npx sast-json-schema path/to/schema.json

# Many files in one invocation: the fixed startup cost (Node boot + validator
# compile) is paid once, so this is the fast way to scan a schema directory.
npx sast-json-schema schemas/*.json

# A pattern the shell does not expand (quoted, Windows, bash without globstar)
# is expanded by the CLI itself, so recursive scans work everywhere.
npx sast-json-schema 'schemas/**/*.json'
```

Options:
- `--override-max-depth <n>`: Override max depth limit (default: 32)
- `--override-max-items <n>`: Raise the `maxItems` limit (default: 1024). It only drops `maxItems` findings that are within the new limit; it cannot lower the limit
- `--override-max-properties <n>`: Raise the `maxProperties` limit (default: 1024), the same way
- `--ignore <instancePath>`: Suppress errors by instancePath or instancePath:keyword (repeatable). Paths use [RFC 6901](https://datatracker.ietf.org/doc/html/rfc6901) JSON Pointer encoding (`~` to `~0`, `/` to `~1`). Findings that mean analysis was incomplete cannot be suppressed: depth-exceeded, timeout, the ReDoS pattern-count and heap budgets, the collected-refs cap, and the SSRF hostname-cap and DNS-budget findings
- `--offline`: Skip SSRF DNS resolution for remote `$ref` URLs (useful in airgapped CI)
- `-r, --ref-schema-files <file>`: Load a reference schema; its `$id` hostname is treated as safe and skipped during SSRF DNS checks (repeatable)
- `--lang <code>`: Downstream language whose deserialization-vector names to deny in property keys. Default is `default` (union of every named language). See [language coverage](#language-coverage) below
- `--format <human|json|sarif>`: Output format. `json` emits a JSON array of error objects on stdout (with several files: one object mapping each input path to its error array); `sarif` emits a [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) log for GitHub code-scanning, SonarQube, Semgrep and other security pipelines, with one run per input file; a finding under a meta-schema definition gets that definition's name as its rule (e.g. `safePattern`), and any other finding gets its full check path (e.g. `allOf/3/then/required`, or `redos` for the CLI's own checks); `human` (the default) prints a count per file and one line per finding: `<instancePath>  <message> [<keyword>]`. In `json` and `sarif` mode the per-file issue counts and the DNS notice go to stderr, so stdout stays machine-readable
- `--max-schema-size <bytes>`: Maximum serialized schema size in bytes. Default 67108864 (64 MiB). Larger schemas are rejected as a tool error (exit 2)
- `--analysis-timeout-ms <ms>`: Wall-clock budget for the schema crawl. Default 60000. Exceeding it produces a `timeout` finding (exit 1)
- `--max-ssrf-hostnames <n>`: Maximum distinct remote `$ref` hostnames resolved during SSRF checks. Default 256. Above this, DNS resolution is refused and reported as a finding
- `--dns-total-timeout-ms <ms>`: Total wall-clock budget for all SSRF DNS lookups. Default 30000. Hosts not checked within the budget are reported (fail-closed)
- `--redos-timeout-ms <ms>`: Per-pattern time budget for ReDoS analysis. Default 1000, minimum 1. A pattern that exceeds it is reported as unsafe (fail-closed)
- `--max-redos-patterns <n>`: Maximum regex patterns ReDoS-analyzed per schema. Default 256. Beyond it the remaining patterns are not analyzed and a finding that `--ignore` cannot suppress is reported
- `--redos-heap-budget-bytes <n>`: Retained-heap budget for ReDoS analysis. Default 134217728 (128 MiB). Once exceeded, the remaining patterns are not analyzed and a finding that `--ignore` cannot suppress is reported. Raise both ReDoS budgets only for trusted first-party schemas, and keep the process heap (`--max-old-space-size`) well above the heap budget
- `-v, --version`: Show version
- `-h, --help`: Show this help

#### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | No issues found |
| `1`  | Any input schema has security findings, including depth-exceeded, analysis timeout, and SSRF hostname-cap / DNS-budget conditions (a schema too expensive or unsafe to fully analyze is itself a finding) |
| `2`  | Usage/tool error: bad args, unreadable file, invalid JSON, unsupported `$schema`, an oversized schema (over `--max-schema-size`), or a non-JSON-serializable (circular or too deeply nested) schema. With several files, the others are still analyzed and reported, and exit 2 wins over exit 1 |

Exit 1 means a problem was found in the schema, including the resource-limit conditions above; exit 2 means the tool could not analyze the input at all.

The `--max-schema-size`, `--analysis-timeout-ms`, `--max-ssrf-hostnames`, `--dns-total-timeout-ms`, `--redos-timeout-ms`, `--max-redos-patterns`, and `--redos-heap-budget-bytes` flags, together with the existing `--override-max-*` limits, are the tool's resource budgets.

Also available via [`ajv-cmd`](https://github.com/willfarrell/ajv-cmd):

```bash
ajv sast --fail path/to/schema.json
```

## Known Limitations

- **Local `$ref` must name a definition.** A local `$ref` must be `#/$defs/<name>` (2019-09, 2020-12) or `#/definitions/<name>`; anchors (`#foo`), other JSON Pointers (`#/properties/a`) and bare self-references (`#`) are rejected, the last to prevent infinite recursion in validators. If you need a self-referencing schema, use a named `$defs` entry and reference it explicitly.
- **`contentMediaType` does not flag XSS-risky media types.** The meta-schema validates that `contentMediaType` follows IANA format ([RFC 6838](https://www.rfc-editor.org/rfc/rfc6838)) but does not warn about types whose content can execute scripts when rendered, such as `text/html`, `application/xhtml+xml`, or `image/svg+xml`. If your application renders content based on this annotation, ensure it is sanitized to prevent XSS.
- **`contentMediaType` does not flag XXE-risky media types.** XML-family types (`application/xml`, `text/xml`, `application/soap+xml`, `application/xml-dtd`, `application/xml-external-parsed-entity`, `image/svg+xml`) are accepted without warning. If your consumer parses these payloads, configure the XML parser to disable external entity resolution and DTD processing. See [SECURITY.md](./SECURITY.md#xml-family-contentmediatype-xxe).
- **`format: "regex"` does not validate regex safety.** A schema using `format: "regex"` validates that input strings are syntactically valid regular expressions, but the meta-schema does not ensure those regex strings are safe from ReDoS. If your application compiles user-provided regex strings, use runtime ReDoS checking on the input. i.e. JavaScript: `redos-detector`.

### Meta-schema only

- **Prototype-pollution denylist does not cover `patternProperties` keys or `propertyNames`.** The meta-schema rejects `__proto__`, `constructor`, and `prototype` as literal keys in `properties`, `$defs`, `definitions`, `dependentSchemas`, `dependentRequired`, `dependencies`, and `required`. It does NOT reject these names when introduced via a `patternProperties` regex key, because any literal denylist (`^__proto__$`) is trivially bypassed by equivalent regexes (`^_{2}proto_{2}$`, `^[_][_]proto__$`, `^.{9}$`). The same holds for a `propertyNames` `enum`, `const` or `pattern` that admits one of these names. Enforced by the CLI: `crawlSchema` tests each `patternProperties` key and `propertyNames` pattern (after ReDoS analysis) and each `propertyNames` `enum`/`const` entry against the denylisted names. A `propertyNames` with none of `enum`, `const` or `pattern` (for example only `format`, a `$ref` or a combinator) cannot be checked, so the CLI reports it (fail-closed; suppress with `--ignore` once reviewed). Consumers using the meta-schema standalone (without `cli.js` / `analyze()`) get property-key protection but not this.
- **Language-specific deserialization-vector names are not in the meta-schema.** Only `__proto__`, `constructor`, `prototype` are rejected at the meta-schema layer (the universal baseline). Names like `@type` (Java), `$type` (.NET), `__class__` (Python), `isa` (Objective-C), `__struct__` (Elixir), or PHP magic methods are enforced only at the CLI / `analyze()` layer via `--lang`. See [Language coverage](#language-coverage).
- **Depth limits are a runtime concern.** Deeply nested schemas could cause stack overflow during recursive validation. Configure your validator's depth limits (e.g. AJV does not limit recursion depth by default). Enforced by the CLI, see `--override-max-depth`.
- **`const` / `default` / `enum` / `examples` value sizes are bounded recursively, but value nesting depth is a runtime concern.** The meta-schema bounds nested string length (`maxLength`), array length (`maxItems`), and object property counts (`maxProperties`) at every level of a literal value, so an oversized nested string, array, or object is rejected (ASVS 1.3.3). It does NOT cap the nesting *depth* of a literal value: a value nested thousands of levels deep is not given a clean rejection by the meta-schema rule itself (it fails closed via the validator's own recursion limit). Schema-nesting depth is enforced by the CLI, see `--override-max-depth`.
- **Min/max logical consistency not enforced.** A schema with `minimum: 100, maximum: 1` (impossible range) will pass validation. This cannot be reliably enforced in JSON Schema alone and would require a wrapper function. Having unit tests for your schema is recommended, this would catch this type of error. Enforced by the CLI.
- **`pattern` regex validation has known gaps.** The check rejects negated character classes `[^...]` as broad denylist matchers (use allowlist patterns like `[\p{L}\p{N}]` instead), blocks nested quantifiers like `(a+)+`, a bounded quantifier wrapped around a group with an unbounded inner quantifier like `(a+){1,5}`, absurd quantifier upper bounds (5+ digits, e.g. `a{1,1000000}` or `[a-z]{10000}`), backreferences, identical overlapping quantifiers like `[a-z]+[a-z]+`, semantically identical overlapping quantifiers like `\d+[0-9]+`, and superset overlaps like `\w+\d+` (where `\w` ⊃ `\d`). Top-level alternation (`^a|b$`, which means `(^a)|(b$)`) is rejected when the groups around the `|` are nested up to 3 deep; deeper nesting is only detected by the CLI, which checks any depth. Control characters are rejected by escape (`\x00`, `\u0085`, `\cA`), by property (`\p{Cc}`, `\p{gc=Control}`, `\p{Any}`, `\p{ASCII}`) and as raw characters, but a range that spans them (e.g. `[ -\uffff]`) is only detected by the CLI, which asks the regex engine whether any character class or escape can match one. The check cannot detect non-identical overlapping quantifiers (e.g. `[a-z]+\\w+` where `\\w` ⊃ `[a-z]`). It also does NOT reject a bounded quantifier wrapped around a group whose inner quantifier is itself bounded with a large product (e.g. `(a{1,1000}){1,1000}`); this nested-bounded-quantifier shape is caught by the CLI runtime (`redos-detector`) but not by the standalone meta-schema. Use runtime ReDoS checking for full protection.
- **Remote `$ref` URLs can be SSRF vectors.** The meta-schema restricts `$ref`, `$dynamicRef`, and `$recursiveRef` to `#` (local) or `https://` URLs and blocks private IP ranges (dotted-decimal, hex `0x`, and decimal representations), and rejects special-use local names (`.localhost`, `.local`, `.internal`, `.home.arpa`, `.onion`, in any case), but DNS-based bypasses (domains resolving to internal IPs) cannot be detected at the schema level. Ensure your validator is configured to disallow or restrict remote schema loading (e.g., use `ajv.addSchema()` instead of allowing external fetches). Dereferencing before running SAST is recommended. Enforced by the CLI, which DNS-checks remote refs, including relative refs resolved against an absolute `$id` base.

## Language coverage

JSON Schemas are language-agnostic, but the JSON they validate gets deserialized into objects in many different languages, each of which has its own set of "magic" property names that downstream libraries may interpret as type discriminators, runtime hooks, or pollution vectors. The `--lang` flag selects which language's deserialization-vector names to deny in property keys (`properties`, `$defs`, `definitions`, `dependentSchemas`, `dependentRequired`, `dependencies`, `required`, `patternProperties` regex keys, and `propertyNames` `enum`/`const`/`pattern`).

The meta-schema itself enforces a universal baseline of `__proto__`, `constructor`, `prototype` regardless of `--lang`: those names are dangerous in every named entry below. Language-specific extras are enforced additively at the CLI / `analyze()` layer.

For a list of JSON-Schema validators per language, see [json-schema.org/tools#validator](https://json-schema.org/tools#validator).

| Language | `--lang` | Extras over JS baseline |
|---|---|---|
| JavaScript / TypeScript / Node.js | `js` | (none, the universal baseline) |
| Python | `py` | `__class__`, `__init__`, `__globals__`, `__builtins__`, `__import__`, `__reduce__`, `__subclasses__`, `__dict__`, `__mro__` |
| Ruby | `rb` | `__send__`, `json_class`, `instance_eval`, `instance_variable_set`, `singleton_class` |
| Rust | `rs` | (none. `serde` is type-safe; baseline applies because specs often pass through JS tooling) |
| Java | `java` | `@type`, `@class` (Jackson / Fastjson polymorphic markers) |
| Kotlin | `kotlin` | alias of `java` (JVM/Jackson) |
| Clojure | `clojure` | alias of `java` (JVM/Cheshire) |
| C# | `cs` | `$type`, `__type`, `@odata.type` (Json.NET, DataContractJsonSerializer, OData) |
| VB.NET | `vb` | alias of `cs` |
| F# | `fsharp` | alias of `cs` |
| ASP.NET / ASPX | `cs` | shares the .NET serializer stack |
| PHP | `php` | `__construct`, `__destruct`, `__wakeup`, `__sleep`, `__serialize`, `__unserialize`, `__call`, `__callStatic`, `__get`, `__set`, `__isset`, `__unset`, `__toString`, `__invoke`, `__set_state`, `__clone`, `__debugInfo` |
| Objective-C | `objc` | `isa`, `class`, `superclass`, `description`, `init`, `_cmd` (Obj-C runtime + KVC + `performSelector:`) |
| Swift | `swift` | alias of `objc` (mixed Obj-C interop; pure `Codable` is type-safe) |
| Elixir | `ex` | `__struct__`, `__exception__`, `__protocol__` (BEAM struct-identifier keys when JSON is decoded with `:keys => :atoms`) |
| Lua | `lua` | metamethod names: `__index`, `__newindex`, `__call`, `__metatable`, `__tostring`, `__name`, `__pairs`, `__eq`, `__lt`, `__le`, `__add`, `__sub`, `__mul`, `__div`, `__mod`, `__pow`, `__concat`, `__len`, `__unm`, `__band`, `__bor`, `__bxor`, `__bnot`, `__shl`, `__shr`, `__idiv`, `__close`, `__gc` |
| _Union of every named language above_ | `default` | every extra above (the implicit default) |

### Languages without a dedicated entry

These ecosystems have JSON-Schema validators but either deserialize type-safely (no magic-name attack class) or their deserialization risks aren't expressible as a property-name denylist. The universal `__proto__` / `constructor` / `prototype` baseline still applies via the meta-schema.

| Language | Reason |
|---|---|
| Go | `encoding/json` is reflection-by-struct-tag; no magic keys |
| C / C++ | `nlohmann/json` + `valijson` are type-safe; no runtime polymorphism via key names |
| Erlang / Elixir (BEAM, raw `:atoms` mode) | Attack class is **atom-table exhaustion DoS** when user keys are interned via `binary_to_atom/1`. Use `binary_to_existing_atom/1`, or `Jason.decode/2` without `:keys => :atoms`. See [SECURITY.md](./SECURITY.md#atom-table--symbol-package-exhaustion-beam-common-lisp). |
| Common Lisp | `cl-json` symbol-interning has the same exhaustion shape. Set `cl-json:*json-symbols-package*` to `:keyword` or `nil`. See [SECURITY.md](./SECURITY.md#atom-table--symbol-package-exhaustion-beam-common-lisp). |
| Perl | `JSON::PP` does not auto-`bless`; magic only kicks in if `convert_blessed` is set, and the marker key is library-defined |
| Julia | `JSONSchema.jl` + `JSON3.jl` are type-safe |

If you have a language-specific deserialization vector that fits the magic-name pattern and isn't covered, please open an issue.

## Supported keywords per draft

All meta-schemas reject keywords not listed in their respective JSON Schema spec (e.g. draft-04 rejects `const` because it was introduced in draft-06). Keywords that ARE in a given spec but are rejected here on security grounds are flagged below.

| Keyword                | draft-04 | draft-06 | draft-07 | 2019-09 | 2020-12 | Notes |
|------------------------|:-:|:-:|:-:|:-:|:-:|---|
| `type`, `enum`, `not`  | ✓ | ✓ | ✓ | ✓ | ✓ | |
| `allOf`/`anyOf`/`oneOf`| ✓ | ✓ | ✓ | ✓ | ✓ | |
| `$ref`                 | ✓ | ✓ | ✓ | ✓ | ✓ | Local refs must be `#/$defs/<name>` or `#/definitions/<name>`; remote refs must be HTTPS; SSRF-checked |
| `$id` / `id`           | ✓ | ✓ | ✓ | ✓ | ✓ | HTTPS URL, URN, or plain name |
| `definitions`          | ✓ | ✓ | ✓ | ✓ | ✓ | Root only |
| `$defs`                | n/a | n/a | n/a | ✓ | ✓ | Root only |
| `items` (array form)   | ✓ | ✓ | ✓ | ✓ | n/a | draft-04/06/07 require `additionalItems` so items past the tuple are constrained; 2019-09 requires `unevaluatedItems` |
| `title`, `description`, `default` | ✓ | ✓ | ✓ | ✓ | ✓ | |
| `const`                | n/a | ✓ | ✓ | ✓ | ✓ | Type-locked to declared `type` |
| `contains`             | n/a | ✓ | ✓ | ✓ | ✓ | draft-06/07 require `items` + `maxItems` + `uniqueItems`; 2019-09/2020-12 additionally require `maxContains` + `unevaluatedItems` |
| `propertyNames`        | n/a | ✓ | ✓ | ✓ | ✓ | |
| `if`/`then`/`else`     | n/a | n/a | ✓ | ✓ | ✓ | |
| `contentMediaType`, `contentEncoding` | n/a | n/a | ✓ | ✓ | ✓ | Allow-listed per RFC 6838 / RFC-standard |
| `contentSchema`        | n/a | n/a | n/a | ✓ | ✓ | |
| `readOnly` / `writeOnly` | n/a | n/a | ✓ | ✓ | ✓ | Annotation-only (added in draft-07); accepted but ignored |
| `deprecated`           | n/a | n/a | n/a | ✓ | ✓ | Annotation-only; type-checked as boolean. Rejected in older drafts where it isn't in spec |
| `dependencies`         | ✓ | ✓ | ✓ | n/a | n/a | Array or subschema form; removed in 2019-09+, prefer `dependentRequired` / `dependentSchemas` |
| `dependentRequired`    | n/a | n/a | n/a | ✓ | ✓ | |
| `dependentSchemas`     | n/a | n/a | n/a | ✓ | ✓ | |
| `prefixItems`          | n/a | n/a | n/a | n/a | ✓ | |
| `unevaluatedProperties`/`unevaluatedItems` | n/a | n/a | n/a | ✓ | ✓ | Required for object/array strictness. draft-04/06/07 have no such keyword, so every `type: "object"` there requires `additionalProperties` instead |

Legend: ✓ supported · **✗** rejected on security grounds · `n/a` not in spec for that draft.

## OWASP ASVS 5.0.0 (2026-03)

The following requirements should be considered when writing JSON Schemas used for input validation of an API endpoint.

### V1 Encoding and Sanitization

- **1.2.9:** Verify that the application escapes special characters in regular expressions to prevent them from being misinterpreted as metacharacters.
- **1.3.3:** Verify that data being passed to a potentially dangerous context is sanitized beforehand to enforce safety measures, such as only allowing characters which are safe for this context and trimming input which is too long.
- **1.3.6:** Verify that the application protects against Server-side Request Forgery (SSRF) attacks, by validating untrusted data against an allowlist of protocols, domains, paths and ports and sanitizing potentially dangerous characters before using the data to call another service.
- **1.3.12:** Verify that regular expressions are free from elements causing exponential backtracking, and ensure untrusted input is sanitized to mitigate ReDoS or Runaway Regex attacks.
- **1.4.2:** Verify that sign, range, and input validation techniques are used to prevent integer overflows.
- **1.5.2:** Verify that deserialization of untrusted data enforces safe input handling, such as using an allowlist of object types or restricting client-defined object types, to prevent deserialization attacks.

### V2 Validation and Business Logic

- **2.1.1:** Verify that the application's documentation defines input validation rules for how to check the validity of data items against an expected structure. This could be common data formats such as credit card numbers, email addresses, telephone numbers, or it could be an internal data format.
- **2.1.2:** Verify that the application's documentation defines how to validate the logical and contextual consistency of combined data items, such as checking that suburb and ZIP code match.
- **2.2.1:** Verify that input is validated to enforce business or functional expectations for that input. This should either use positive validation against an allow list of values, patterns, and ranges, or be based on comparing the input to an expected structure and logical limits according to predefined rules.
- **2.2.3:** Verify that the application ensures that combinations of related data items are reasonable according to the pre-defined rules.

### V4 API and Web Service

- **4.1.1:** Verify that every HTTP response with a message body contains a Content-Type header field that matches the actual content of the response, including the charset parameter to specify safe character encoding (e.g., UTF-8, ISO-8859-1).
- **4.1.4:** Verify that only HTTP methods that are explicitly supported by the application or its API (including OPTIONS during preflight requests) can be used and that unused methods are blocked.
- **4.2.2:** Verify that when generating HTTP messages, the Content-Length header field does not conflict with the length of the content as determined by the framing of the HTTP protocol, in order to prevent request smuggling attacks.
- **4.2.5:** Verify that, if the application builds and sends requests, it uses validation, sanitization, or other mechanisms to avoid creating URIs or HTTP request header fields which are too long to be accepted by the receiving component.

### V15 Secure Coding and Architecture

- **15.3.3:** Verify that the application has countermeasures to protect against mass assignment attacks by limiting allowed fields per controller and action, e.g., it is not possible to insert or update a field value when it was not intended to be part of that action.
- **15.3.5:** Verify that the application explicitly ensures that variables are of the correct type and performs strict equality and comparator operations to avoid type juggling or type confusion vulnerabilities.
- **15.3.7:** Verify that the application has defenses against HTTP parameter pollution attacks, particularly if the application framework makes no distinction about the source of request parameters (query string, body parameters, cookies, or header fields).

## Sources

- [OWASP ASVS 5.0](https://github.com/OWASP/ASVS/tree/v5.0.0/5.0/en)
- [AJV Security](https://github.com/ajv-validator/ajv/blob/master/docs/security.md)
- [Input Validation With JSON Schemas: Best Practices](https://ventral.digital/posts/2021/2/20/input-validation-json-schemas-best-practices/)

## Contributions
Contributions are most welcome. Something missed, please reach out. I'd also love for security experts to give it an audit.
