# Security Policy

This document outlines security procedures and general policies for the sast-json-schema Open Source projects as found on https://github.com/willfarrell/sast-json-schema.

* [Security Goals](#security-goals)
* [Supported Versions](#supported-versions)
* [Reporting a Vulnerability](#reporting-a-vulnerability)
* [Disclosure Policy](#disclosure-policy)

## Security Goals
Our goal is to ensure OSS follows secure design principles and meets security best practices as outlined by the following [OWASP ASVS v5.0 Level 3](https://github.com/OWASP/ASVS/tree/master/5.0/en).

Standards are evaluated using automated scans (Linting, Unit tests, SAST, SCA, DAST, Perf) and manual self-audits. 3rd party audits are welcome.

## Secure design principles

- secure by default
- use white lists
- no backdoors
- follow least privilege
- keep it simple

## Supported Versions
Only the latest version is supported for security updates.

## Reporting a Vulnerability

The sast-json-schema OSS team and community take all security vulnerabilities
seriously. Thank you for improving the security of our open source
software. We appreciate your efforts and responsible disclosure and will
make every effort to acknowledge your contributions.

Report security vulnerabilities by emailing the lead maintainer at:
```
willfarrell@proton.me
```
The lead maintainer will acknowledge your email within 24 hours, and will
send a more detailed response within 48 hours indicating the next steps in
handling your report. After the initial reply to your report, the security
team will endeavour to keep you informed of the progress towards a fix and
full announcement, and may ask for additional information or guidance.

Report security vulnerabilities in third-party modules to the person or
team maintaining the module.

## Out-of-scope attack classes

The meta-schema and CLI catch many security-relevant misconfigurations, but the following classes cannot be fully addressed at the schema layer. They are documented here so consumers can apply mitigations at the appropriate layer.

### XML-family `contentMediaType` (XXE)

When a schema declares `contentMediaType: application/xml` (or any of `text/xml`, `application/soap+xml`, `application/xml-dtd`, `application/xml-external-parsed-entity`, `image/svg+xml`), a downstream consumer that decodes and parses the payload with default XML parser settings is exposed to XML External Entity (XXE) attacks: file disclosure, SSRF, billion-laughs DoS.

The meta-schema cannot prevent this. `contentMediaType` is purely an annotation, and the consumer's XML parser is what creates the vulnerability. Mitigations are at the consumer layer:

- **libxml2-based parsers** (Python `lxml`, PHP `DOMDocument`): set `XML_PARSE_NOENT` to `0`, `XML_PARSE_NOCDATA`, disable DTD loading via `XML_PARSE_NONET`.
- **Java**: `XMLInputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false)` and `XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES = false`. For SAX, `XMLReader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`.
- **.NET**: `XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit`, `XmlResolver = null`.
- **Node.js**: avoid `xmldom` (XXE history); prefer `fast-xml-parser` with default-secure settings.

Parallel guidance applies to XSS-risky types (`text/html`, `application/xhtml+xml`, `image/svg+xml`): sanitize before rendering.

### Atom-table / symbol-package exhaustion (BEAM, Common Lisp)

If your consumer opts into key-to-atom decoding (`Jason.decode(json, keys: :atoms)` in Elixir, `cl-json:decode-json` with the default `*json-symbols-package*` in Common Lisp), every novel key gets interned into a runtime-global table that is never freed. An attacker submitting unique keys across many requests can fill it and crash the runtime.

Schema keywords that admit unbounded distinct keys:

- `additionalProperties: <typed schema>`: any key matching the typed schema is accepted.
- `patternProperties`: any key matching the regex, generally infinite.

Schema keywords that keep the keyset finite and are safe to pair with atom-keyed decoding:

- `additionalProperties: false` + an explicit `properties` allowlist.

The validator and the schema cannot fix this; the choice is in your decoder. Use `Jason.decode(json, keys: :atoms!)` (existing atoms only) or string keys; in Common Lisp set `*json-symbols-package*` to `nil`.

## Disclosure Policy

When the security team receives a security bug report, they will assign it
to a primary handler. This person will coordinate the fix and release
process, involving the following steps:

  * Confirm the problem and determine the affected versions.
  * Audit code to find any potential similar problems.
  * Prepare fixes for all releases still under maintenance. These fixes
    will be released as fast as possible to NPM.
