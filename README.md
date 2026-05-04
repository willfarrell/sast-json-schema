<div align="center">

<h1>sast-json-schema</h1>
<p>Meta-schema for the Static Application Security Testing (SAST) of JSON Schemas</p>
<br />
<p>
  <a href="https://github.com/willfarrell/sast-json-schema/actions/workflows/test-unit.yml"><img src="https://github.com/willfarrell/sast-json-schema/actions/workflows/test-unit.yml/badge.svg" alt="GitHub Actions unit test status"></a>
  <a href="https://github.com/willfarrell/sast-json-schema/actions/workflows/test-dast.yml"><img src="https://github.com/willfarrell/sast-json-schema/actions/workflows/test-dast.yml/badge.svg" alt="GitHub Actions dast test status"></a>
  <a href="https://github.com/willfarrell/sast-json-schema/actions/workflows/test-perf.yml"><img src="https://github.com/willfarrell/sast-json-schema/actions/workflows/test-perf.yml/badge.svg" alt="GitHub Actions perf test status"></a>
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
- Ensure `pattern` follow safe RegExp usage.
- Ensure `$id` and `$refs` resolve safely.

## Installation

Requires **Node.js >=24**.

```bash
npm install sast-json-schema
```

## How to run

### Manually

```javascript
import Ajv from "ajv/dist/2020.js"
import sastSchema from "sast-json-schema" with { type: "json" }
import schema from "path/to/schema.json" with { type: "json" }

// Your schema should compile under strictTypes:true.
const userAjv = new Ajv({ strictTypes: true })
if (!userAjv.validateSchema(schema)) {
  console.error(userAjv.errors)
}

// The meta-schema itself uses strictTypes:false because it validates
// subschemas that may legally be `false` (boolean-schema form).
const sastAjv = new Ajv({ strictTypes: false })
const isSchemaSecure = sastAjv.compile(sastSchema)
if (!isSchemaSecure(schema)) {
  console.error(isSchemaSecure.errors)
}
```

Per-draft entry points are also exported: `sast-json-schema/2020-12`, `/2019-09`, `/draft-07`, `/draft-06`, `/draft-04`. Each meta-schema is identified by a `urn:willfarrell:sast-json-schema:<spec>` URN. Shared primitives (`safePattern`, `safeUrl`, etc.) are available via `sast-json-schema/$defs`.

### CLI

```bash
npx sast-json-schema path/to/schema.json
```

Options:
- `--override-max-depth <n>`: Override max depth limit (default: 32)
- `--override-max-items <n>`: Override max items limit (default: 1024)
- `--override-max-properties <n>`: Override max properties limit (default: 1024)
- `--ignore <instancePath>`: Suppress errors by instancePath or instancePath:keyword (repeatable). Paths use [RFC 6901](https://datatracker.ietf.org/doc/html/rfc6901) JSON Pointer encoding (`~` to `~0`, `/` to `~1`)
- `--offline`: Skip SSRF DNS resolution for remote `$ref` URLs (useful in airgapped CI)
- `--lang <code>`: Downstream language whose deserialization-vector names to deny in property keys. Default is `default` (union of every named language). See [language coverage](#language-coverage) below
- `--format <human|json|sarif>`: Output format. `json` emits a JSON array of error objects on stdout; `sarif` emits a [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) log for GitHub code-scanning, SonarQube, Semgrep and other security pipelines; `human` is the default
- `-v, --version`: Show version
- `-h, --help`: Show this help

#### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | No issues found |
| `1`  | Schema has security issues |
| `2`  | Usage/tool error (bad args, unreadable file, invalid JSON, unsupported `$schema`) |

Also available via [`ajv-cmd`](https://github.com/willfarrell/ajv-cmd):

```bash
ajv sast --fail path/to/schema.json
```

## Known Limitations

- **`$ref: "#"` (self-reference) is rejected.** The meta-schema requires `$ref` values to have at least one character after `#`. Bare self-references (`$ref: "#"`) are blocked to prevent infinite recursion in validators. If you need a self-referencing schema, use a named `$defs` entry and reference it explicitly.
- **`contentMediaType` does not flag XSS-risky media types.** The meta-schema validates that `contentMediaType` follows IANA format ([RFC 6838](https://www.rfc-editor.org/rfc/rfc6838)) but does not warn about types whose content can execute scripts when rendered, such as `text/html`, `application/xhtml+xml`, or `image/svg+xml`. If your application renders content based on this annotation, ensure it is sanitized to prevent XSS.
- **`contentMediaType` does not flag XXE-risky media types.** XML-family types (`application/xml`, `text/xml`, `application/soap+xml`, `application/xml-dtd`, `application/xml-external-parsed-entity`, `image/svg+xml`) are accepted without warning. If your consumer parses these payloads, configure the XML parser to disable external entity resolution and DTD processing. See [SECURITY.md](./SECURITY.md#xml-family-contentmediatype-xxe).
- **`format: "regex"` does not validate regex safety.** A schema using `format: "regex"` validates that input strings are syntactically valid regular expressions, but the meta-schema does not ensure those regex strings are safe from ReDoS. If your application compiles user-provided regex strings, use runtime ReDoS checking on the input. i.e. JavaScript: `redos-detector`.

### Meta-schema only

- **Prototype-pollution denylist does not cover `patternProperties` keys.** The meta-schema rejects `__proto__`, `constructor`, and `prototype` as literal keys in `properties`, `$defs`, `definitions`, `dependentSchemas`, `dependentRequired`, and `required`. It does NOT reject these names when introduced via a `patternProperties` regex key, because any literal denylist (`^__proto__$`) is trivially bypassed by equivalent regexes (`^_{2}proto_{2}$`, `^[_][_]proto__$`, `^.{9}$`). Enforced by the CLI: `crawlSchema` compiles each `patternProperties` key and tests it against the denylisted names. Consumers using the meta-schema standalone (without `cli.js` / `analyze()`) get property-key protection but not `patternProperties` protection.
- **Language-specific deserialization-vector names are not in the meta-schema.** Only `__proto__`, `constructor`, `prototype` are rejected at the meta-schema layer (the universal baseline). Names like `@type` (Java), `$type` (.NET), `__class__` (Python), `isa` (Objective-C), `__struct__` (Elixir), or PHP magic methods are enforced only at the CLI / `analyze()` layer via `--lang`. See [Language coverage](#language-coverage).
- **Depth limits are a runtime concern.** Deeply nested schemas could cause stack overflow during recursive validation. Configure your validator's depth limits (e.g. AJV does not limit recursion depth by default). Enforced by the CLI, see `--override-max-depth`.
- **Min/max logical consistency not enforced.** A schema with `minimum: 100, maximum: 1` (impossible range) will pass validation. This cannot be reliably enforced in JSON Schema alone and would require a wrapper function. Having unit tests for your schema is recommended, this would catch this type of error. Enforced by the CLI.
- **`pattern` regex validation has known gaps.** The check rejects negated character classes `[^...]` as broad denylist matchers (use allowlist patterns like `[\p{L}\p{N}]` instead), blocks nested quantifiers like `(a+)+`, backreferences, identical overlapping quantifiers like `[a-z]+[a-z]+`, semantically identical overlapping quantifiers like `\d+[0-9]+`, and superset overlaps like `\w+\d+` (where `\w` ⊃ `\d`). Bare alternation at the top level (`^a|b$`) is rejected, but alternation across sibling groups (`^(a)|(b)$`) is not detected at the meta-schema level (it is enforced by the CLI). The check cannot detect non-identical overlapping quantifiers (e.g. `[a-z]+\\w+` where `\\w` ⊃ `[a-z]`). Use runtime ReDoS checking for full protection.
- **Remote `$ref` URLs can be SSRF vectors.** The meta-schema restricts `$ref` to `#` (local) or `https://` URLs and blocks private IP ranges (dotted-decimal, hex `0x`, and decimal representations), but DNS-based bypasses (domains resolving to internal IPs) cannot be detected at the schema level. Ensure your validator is configured to disallow or restrict remote schema loading (e.g., use `ajv.addSchema()` instead of allowing external fetches). Dereferencing before running SAST is recommended. Enforced by the CLI.

## Language coverage

JSON Schemas are language-agnostic, but the JSON they validate gets deserialized into objects in many different languages, each of which has its own set of "magic" property names that downstream libraries may interpret as type discriminators, runtime hooks, or pollution vectors. The `--lang` flag selects which language's deserialization-vector names to deny in property keys (`properties`, `$defs`, `definitions`, `dependentSchemas`, `dependentRequired`, `required`, and `patternProperties` regex keys).

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
| `$ref`                 | ✓ | ✓ | ✓ | ✓ | ✓ | Restricted to local `#…` or HTTPS; SSRF-checked |
| `$id` / `id`           | ✓ | ✓ | ✓ | ✓ | ✓ | HTTPS URL, URN, or plain name |
| `definitions`          | ✓ | ✓ | ✓ | ✓ | ✓ | |
| `$defs`                | n/a | n/a | n/a | ✓ | ✓ | |
| `title`, `description`, `default` | ✓ | ✓ | ✓ | ✓ | ✓ | |
| `const`                | n/a | ✓ | ✓ | ✓ | ✓ | Type-locked to declared `type` |
| `contains`             | n/a | ✓ | ✓ | ✓ | ✓ | Requires `maxContains` + `uniqueItems` |
| `propertyNames`        | n/a | ✓ | ✓ | ✓ | ✓ | |
| `if`/`then`/`else`     | n/a | n/a | ✓ | ✓ | ✓ | |
| `contentMediaType`, `contentEncoding` | n/a | n/a | ✓ | ✓ | ✓ | Allow-listed per RFC 6838 / RFC-standard |
| `contentSchema`        | n/a | n/a | n/a | ✓ | ✓ | |
| `readOnly` / `writeOnly` | n/a | **✗** | ✓ | ✓ | ✓ | Rejected in draft-06 (annotation-only, misleading for strictness); accepted but ignored later |
| `deprecated`           | n/a | n/a | n/a | ✓ | ✓ | Annotation-only; type-checked as boolean. Rejected in older drafts where it isn't in spec |
| `dependencies`         | ✓ | ✓ | ✓ | n/a | n/a | Array or subschema form; removed in 2019-09+, prefer `dependentRequired` / `dependentSchemas` |
| `dependentRequired`    | n/a | n/a | n/a | ✓ | ✓ | |
| `dependentSchemas`     | n/a | n/a | n/a | ✓ | ✓ | |
| `prefixItems`          | n/a | n/a | n/a | n/a | ✓ | |
| `unevaluatedProperties`/`unevaluatedItems` | n/a | n/a | n/a | ✓ | ✓ | Required for object/array strictness |

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
