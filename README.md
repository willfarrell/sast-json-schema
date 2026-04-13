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
ajv = new Ajv({strictTypes: false})
const isSchemaSecure = ajv.compile(require("sast-json-schema/index.json"))
isSchemaSecure(schema)
```

### cli
Using [`ajv-cmd`](https://github.com/willfarrell/ajv-cmd)
```bash
ajv sast path/to/schema.json
```

## OWASP ASVS 5.0 (2024-10)

The following criteria should be considered when writing JSON Schemas used for input validation of an API endpoint.

- **1.5.1:** Verify that input validation rules define how to check the validity of data items against an expected structure. This could be common data formats such as credit card numbers, e-mail addresses, telephone numbers, or it could be an internal data format.
- **1.5.5:** Verify that input validation rules are documented and define how to ensure the logical and contextual consistency of combined data items, such as checking that suburb and zipcode match.
- **5.1.1:** Verify that the application has defenses against HTTP parameter pollution attacks, particularly if the application framework makes no distinction about the source of request parameters (query string, body parameters, cookies, or headers).
- **5.1.3:** Verify that all input is validated using positive validation, against an allowed list of values, patterns or ranges to enforce business or functional expectations for that input.
- **5.1.4:** Verify that data items with an expected structure are validated according to the pre-defined rules.
- **5.1.6:** Verify that untrusted input is validated for length before being included in a cookie (including as part of a JWT) and that the cookie name and value length combined are not over 4096 bytes.
- **5.1.8:** Verify that the application validates that user-controlled input in HTTP request header fields does not exceed the server's maximum header field size limit (usually 4kB or 8kB) to prevent client-based denial of service attacks.
- **5.2.2:** Verify that data being passed to a potentially dangerous context is sanitized beforehand to enforce safety measures, such as only allowing characters which are safe for this context and trimming input which is too long.
- **5.4.3:** Verify that sign, range, and input validation techniques are used to prevent integer overflows.
- **5.5.3:** Verify that if deserialization is used when communicating with untrusted clients, the input is handled safely. For example, by only allowing a allowlist of object types or not allowing the client to define the object type to deserialize to, in order to prevent deserialization attacks.
- **10.4.4:** Verify that the application has countermeasures to protect against mass assignment attacks by limiting allowed fields per controller and action, e.g. it is not possible to insert or update a field value when it was not intended to be part of that action.
- **13.2.2:** Verify that JSON schema validation is in place and verified before accepting input.
- **13.2.5:** Verify that REST services explicitly check the incoming Content-Type to be the expected one, such as application/xml or application/json.
- **13.6.1:** Verify that the application only responds to HTTP methods in use by the application or by the API (including OPTIONS during preflight requests) and unused methods (e.g. TRACE) are blocked.
- **13.7.1:** Verify that the value in the Content-Length request header matches the calculated length using the built-in mechanism.

## Known Limitations

- **Depth limits are a runtime concern.** Deeply nested schemas could cause stack overflow during recursive validation. Configure your validator's depth limits (e.g. AJV does not limit recursion depth by default).
- **`enum` size bounded to 1024 items.** Large `enum` arrays could cause memory/performance issues. Keep enums small and consider application-level limits. TODO need way to bypass for edge cases.
- **Remote `$ref` safety depends on validator configuration.** Schemas can reference external URLs via `$ref`. Ensure your validator is configured to disallow or restrict remote schema loading (e.g., use `ajv.addSchema()` instead of allowing external fetches). Dereferencing before running SAST is recommended.
- **Remote `$ref` URLs can be SSRF vectors.** The meta-schema restricts `$ref` to `#` (local) or `https://` URLs and blocks private IP ranges (dotted-decimal, hex `0x`, and decimal representations), but DNS-based bypasses (domains resolving to internal IPs) cannot be detected at the schema level. Validators should independently restrict or disable remote schema loading.
- **Min/max logical consistency not enforced.** A schema with `minimum: 100, maximum: 1` (impossible range) will pass validation. This cannot be reliably enforced in JSON Schema alone and would require a wrapper function. Having unit tests for your schema is recommended, this would catch this type of error.
- **`not` keyword must be paired with explicit constraints.** Standalone `not` schemas (e.g., `{ "not": { "type": "null" } }`) are rejected because the negation semantics would accept nearly all input. Use `not` alongside `type`, `const`, `$ref`, or composition keywords. Prefer allowlist approaches (`enum`, `pattern`, `const`) over `not`.
- **Literal `.` inside character classes is rejected.** The `safePattern` check rejects `.` everywhere, including inside character classes like `[a-z.]` where it is a literal dot (not a wildcard). Use the escaped form `[a-z\.]` instead.
- **Negated character classes `[^...]` are rejected.** Negated character classes like `[^a]` are broad denylist matchers (equivalent to `.` in scope). Use allowlist patterns like `[\p{L}\p{N}]` instead.
- **Overlapping regex quantifiers not fully detected.** The `safePattern` check blocks nested quantifiers like `(a+)+` and backreferences, but cannot detect overlapping quantifiers like `^[a-z]+[a-z]+$` which cause O(n^2) backtracking. Use runtime ReDoS checking (e.g. safe-regex2, recheck) for full protection.
- **`format: "regex"` does not validate regex safety.** A schema using `format: "regex"` validates that input strings are syntactically valid regular expressions, but the meta-schema does not ensure those regex strings are safe from ReDoS. If your application compiles user-provided regex strings, use runtime ReDoS checking on the input.

## Sources

- [OWASP ASVS 5.0](https://github.com/OWASP/ASVS/tree/master/5.0/en)
- [AJV Security](https://github.com/ajv-validator/ajv/blob/master/docs/security.md)
- [Input Validation With JSON Schemas: Best Practices](https://ventral.digital/posts/2021/2/20/input-validation-json-schemas-best-practices/)

## Contributions
Contributions are most welcome. Something missed, please reach out. I'd also love for security experts to give it an audit.
