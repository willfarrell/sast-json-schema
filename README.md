# sast-json-schema
Meta-schema for the Static Application Security Testing (SAST) of JSON Schemas

## High-level functionality

- Ensure strictness of inperputation.
- Ensure `integer` or `number` are within a safe range.
- Ensure `string` have defined allowed values and length.
- Ensure `arrays` have defined types and lenth.
- Ensure `object` have defined properties and count.

## How to run

### Manually

```javascript
ajv = new Ajv({strictTypes: false})
const isSchemaSecure = ajv.compile(require("sast-json-schema/index.json"))
isSchemaSecure(schema)
```

### cli
Using `ajv-cmd`
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

## Sources

- [OWASP ASVS 5.0](https://github.com/OWASP/ASVS/tree/master/5.0/en)
- [AJV Security](https://github.com/ajv-validator/ajv/blob/master/docs/security.md)
- [Input Validation With JSON Schemas: Best Practices](https://ventral.digital/posts/2021/2/20/input-validation-json-schemas-best-practices/)

## Contributions
Contributions are most welcome. Something missed, please reach out. I'd also love for security experts to give it an audit.
