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
- Ensure `string` have defined allowed values and length.
- Ensure `arrays` have defined properties and maxLength.
- Ensure `object` have defined properties and maxProperties when needed.

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

Per-draft entry points are also exported: `sast-json-schema/2020-12`, `/2019-09`, `/draft-07`, `/draft-06`, `/draft-04`. Each meta-schema is identified by a `urn:sast-json-schema:<draft>` URN. Shared primitives (`safePattern`, `safeUrl`, etc.) are available via `sast-json-schema/$defs`.

### CLI

```bash
npx sast-json-schema path/to/schema.json
```

Options:
- `-o, --output <path>` — Write issues to JSON file
- `--override-max-items <n>` — Override max items limit (default: 1024)
- `--override-max-depth <n>` — Override max depth limit (default: 32)
- `--override-max-properties <n>` — Override max properties limit (default: 1024)
- `--ignore <instancePath>` — Suppress errors by instancePath or instancePath:keyword (repeatable)

Also available via [`ajv-cmd`](https://github.com/willfarrell/ajv-cmd):

```bash
ajv sast --fail path/to/schema.json
```

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

## Known Limitations

- **Depth limits are a runtime concern.** Deeply nested schemas could cause stack overflow during recursive validation. Configure your validator's depth limits (e.g. AJV does not limit recursion depth by default). Enforced by the CLI, see `--override-max-depth`.
- **`enum` size bounded to 1024 items.** Large `enum` arrays could cause memory/performance issues. Keep enums small and consider application-level limits. Can be overridden via the CLI, see `--override-max-items`.
- **`properties` size bounded to 1024 items.** Large `properties` objects could cause memory/performance issues. Keep properties small and consider application-level limits. Can be overridden via the CLI, see `--override-max-properties`.
- **Min/max logical consistency not enforced.** A schema with `minimum: 100, maximum: 1` (impossible range) will pass validation. This cannot be reliably enforced in JSON Schema alone and would require a wrapper function. Having unit tests for your schema is recommended, this would catch this type of error. Enforced by the CLI.
- **`safePattern` regex validation has known gaps.** The check rejects negated character classes `[^...]` as broad denylist matchers (use allowlist patterns like `[\p{L}\p{N}]` instead), blocks nested quantifiers like `(a+)+`, backreferences, identical overlapping quantifiers like `[a-z]+[a-z]+`, semantically identical overlapping quantifiers like `\d+[0-9]+`, and superset overlaps like `\w+\d+` (where `\w` ⊃ `\d`). Bare alternation at the top level (`^a|b$`) is rejected, but alternation across sibling groups (`^(a)|(b)$`) is not detected at the meta-schema level — it is enforced by the CLI. The check cannot detect non-identical overlapping quantifiers (e.g. `[a-z]+\\w+` where `\\w` ⊃ `[a-z]`). Use runtime ReDoS checking for full protection.
- **Remote `$ref` URLs can be SSRF vectors.** The meta-schema restricts `$ref` to `#` (local) or `https://` URLs and blocks private IP ranges (dotted-decimal, hex `0x`, and decimal representations), but DNS-based bypasses (domains resolving to internal IPs) cannot be detected at the schema level. Ensure your validator is configured to disallow or restrict remote schema loading (e.g., use `ajv.addSchema()` instead of allowing external fetches). Dereferencing before running SAST is recommended. Enforced by the CLI.
- **`safeUrl` hostname constraints.** Only HTTPS URLs are allowed. Explicit ports are rejected entirely. The TLD may be upper-case or lower-case; the rest of the hostname is matched case-sensitively on the ASCII-label charset. Internationalized domain names (IDN / punycode) are not specifically handled and should be converted to ASCII labels.
- **Plain-name `$id` / `id` values** must match `^[a-zA-Z0-9_-]+$` with a maximum length of 1024. Non-ASCII identifiers, dots, slashes, and other RFC 3986 path characters are not permitted in the plain-name form — use a full URL or URN if you need those.
- **`contentMediaType` does not flag XSS-risky media types.** The meta-schema validates that `contentMediaType` follows IANA format (RFC 6838) but does not warn about types whose content can execute scripts when rendered, such as `text/html`, `application/xhtml+xml`, or `image/svg+xml`. If your application renders content based on this annotation, ensure it is sanitized to prevent XSS.
- **`$ref: "#"` (self-reference) is rejected.** The meta-schema requires `$ref` values to have at least one character after `#`. Bare self-references (`$ref: "#"`) are blocked to prevent infinite recursion in validators. If you need a self-referencing schema, use a named `$defs` entry and reference it explicitly.
- **`format: "regex"` does not validate regex safety.** A schema using `format: "regex"` validates that input strings are syntactically valid regular expressions, but the meta-schema does not ensure those regex strings are safe from ReDoS. If your application compiles user-provided regex strings, use runtime ReDoS checking on the input. i.e. JavaScript: `redos-detector`.
- **Draft-07 `dependencies` keyword is rejected.** Use `dependentRequired` (array form) or `dependentSchemas` (schema form) instead. Only JSON Schema drafts 2019-09 and 2020-12 are supported.

## Sources

- [OWASP ASVS 5.0](https://github.com/OWASP/ASVS/tree/v5.0.0/5.0/en)
- [AJV Security](https://github.com/ajv-validator/ajv/blob/master/docs/security.md)
- [Input Validation With JSON Schemas: Best Practices](https://ventral.digital/posts/2021/2/20/input-validation-json-schemas-best-practices/)

## Contributions
Contributions are most welcome. Something missed, please reach out. I'd also love for security experts to give it an audit.
